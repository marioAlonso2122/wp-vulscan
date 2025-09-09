<?php
// Seguridad: evitar acceso directo
defined('ABSPATH') or die('Acceso no permitido.');

/**
 * Normaliza el slug de plugin a partir de la ruta "carpeta/archivo.php".
 */
function wpvulscan_normalize_plugin_slug($plugin_path) {
    // get_plugins() usa keys como "akismet/akismet.php" -> slug "akismet"
    $slug = dirname((string)$plugin_path);
    return $slug === '.' ? basename((string)$plugin_path, '.php') : $slug;
}

/**
 * Devuelve una lista de plugins instalados con nombre, versión, estado y slug
 */
function wp_vulscan_get_plugins_info() {
    if (!function_exists('get_plugins')) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }

    $all_plugins    = get_plugins();
    $active_plugins = (array) get_option('active_plugins', []);
    $info = [];

    foreach ($all_plugins as $plugin_path => $plugin_data) {
        $slug = wpvulscan_normalize_plugin_slug($plugin_path);
        $file_abs = trailingslashit(WP_PLUGIN_DIR) . $plugin_path;

        $info[] = [
            'name'    => $plugin_data['Name'],
            'version' => $plugin_data['Version'],
            'active'  => in_array($plugin_path, $active_plugins, true),
            'slug'    => $slug,
            'path'    => $plugin_path,  // relativo a WP_PLUGIN_DIR
            'abs'     => $file_abs,
            'hash'    => file_exists($file_abs) ? md5_file($file_abs) : null,
        ];
    }

    return $info;
}

/**
 * Refresca la tabla de activos (vulscan_assets) con los plugins actuales.
 */
function wpvulscan_refresh_assets() {
    global $wpdb;
    $table = $wpdb->prefix . 'vulscan_assets';
    $exists = $wpdb->get_var($wpdb->prepare(
        "SHOW TABLES LIKE %s", $table
    ));
    if ($exists !== $table) {
        return; // tabla no creada aún (dbDelta en activación)
    }

    $plugins = wp_vulscan_get_plugins_info();

    foreach ($plugins as $p) {
        // ¿Existe ya?
        $id = $wpdb->get_var($wpdb->prepare(
            "SELECT id FROM {$table} WHERE type = 'plugin' AND slug = %s LIMIT 1", $p['slug']
        ));

        $data = [
            'type'   => 'plugin',
            'slug'   => $p['slug'],
            'name'   => $p['name'],
            'version'=> $p['version'],
            'path'   => $p['path'],
            'hash'   => $p['hash'],
            'active' => $p['active'] ? 1 : 0,
        ];

        if ($id) {
            $wpdb->update($table, $data, ['id' => $id]);
        } else {
            $wpdb->insert($table, $data);
        }
    }
}

/**
 * Helper: obtiene el ID de asset por slug (si existe).
 */
function wpvulscan_get_asset_id_by_slug($slug) {
    global $wpdb;
    $table = $wpdb->prefix . 'vulscan_assets';
    return $wpdb->get_var($wpdb->prepare(
        "SELECT id FROM {$table} WHERE type = 'plugin' AND slug = %s LIMIT 1", $slug
    ));
}

/**
 * Consulta WPScan API para un plugin concreto (cacheado con transient).
 * Requiere guardar la API key en 'wpvulscan_wpscan_api_key'.
 */
function wpvulscan_wpscan_get_plugin_vulns($slug, $version = null) {
    $api_key = get_option('wpvulscan_wpscan_api_key', '');
    $cache_key = 'wpvulscan_wpscan_' . md5($slug . '|' . (string)$version);
    $cached = get_transient($cache_key);
    if ($cached !== false) {
        return $cached; // array o []
    }

    $vulns = [];

    if (!empty($api_key)) {
        $url = "https://wpscan.com/api/v3/plugins/" . rawurlencode($slug);
        // Nota: WPScan filtra por versión en el lado cliente; si pasas versión,
        // la evaluaremos localmente comparando ranges si el payload lo permite.
        $resp = wp_remote_get($url, [
            'timeout' => 12,
            'headers' => [
                'Authorization' => 'Token token=' . $api_key,
                'Accept'        => 'application/json',
                'User-Agent'    => 'WP-VulScan/1.0 (+WPScan)',
            ],
            'sslverify' => false,
        ]);

        if (!is_wp_error($resp)) {
            $code = (int) wp_remote_retrieve_response_code($resp);
            if ($code === 200) {
                $body = json_decode(wp_remote_retrieve_body($resp), true);
                // Estructura típica: ['vulnerabilities' => [ { 'title','cvss_score','references'=>['cve'=>[]], 'fixed_in', ... } ]]
                if (is_array($body) && !empty($body['vulnerabilities'])) {
                    // Si tenemos versión local, filtramos las que apliquen (heurística simple por 'fixed_in')
                    foreach ((array)$body['vulnerabilities'] as $v) {
                        if ($version && !empty($v['fixed_in'])) {
                            // Si la vulnerable está "fixed_in" = 2.1.0, entonces versiones < 2.1.0 son vulnerables.
                            if (version_compare($version, (string)$v['fixed_in'], '>=')) {
                                continue; // ya corregido en esta versión
                            }
                        }
                        $vulns[] = $v;
                    }
                }
            }
        }
    }

    // Fallback mínimo: catálogo local (opcional). Puedes crear /includes/data/wpscan_local.json
    // con estructura {"slug":{"vulnerabilities":[...]}}
    if (empty($vulns)) {
        $local = WP_VULSCAN_INC . 'data/wpscan_local.json';
        if (file_exists($local)) {
            $json = json_decode(file_get_contents($local), true);
            if (!empty($json[$slug]['vulnerabilities'])) {
                foreach ($json[$slug]['vulnerabilities'] as $v) {
                    if ($version && !empty($v['fixed_in'])
                        && version_compare($version, (string)$v['fixed_in'], '>=')) {
                        continue;
                    }
                    $vulns[] = $v;
                }
            }
        }
    }

    // Cachea 12h para evitar rate limit
    set_transient($cache_key, $vulns, 12 * HOUR_IN_SECONDS);
    return $vulns;
}

/**
 * Inserta hallazgo en vulscan_findings (si existe la tabla).
 */
function wpvulscan_insert_finding($args) {
    global $wpdb;
    $table = $wpdb->prefix . 'vulscan_findings';
    $exists = $wpdb->get_var($wpdb->prepare(
        "SHOW TABLES LIKE %s", $table
    ));
    if ($exists !== $table) {
        return;
    }

    $defaults = [
        'asset_id'       => null,
        'rule_id'        => 'catalog_wpscan',
        'cve_id'         => null,
        'cwe'            => null,
        'owasp'          => null,
        'severity'       => null,
        'confidence'     => 'high',
        'path'           => null,
        'line'           => null,
        'function_name'  => null,
        'hook_name'      => null,
        'trace_json'     => null,
        'sample_payload' => null,
        'created_at'     => current_time('mysql'),
    ];
    $data = wp_parse_args($args, $defaults);
    $wpdb->insert($table, $data);
}

/**
 * Devuelve listado de vulnerabilidades en plugins instalados (para el panel),
 * refresca la tabla de activos y persiste hallazgos en findings.
 *
 * @return string[] líneas tipo "akismet 5.3 — CVE-2023-XXXX (CVSS 7.5) — Title"
 */
function wpvulscan_check_plugins_vulnerables() {
    $out = [];

    // Asegura que la tabla de assets está alineada con el estado actual
    wpvulscan_refresh_assets();

    $plugins = wp_vulscan_get_plugins_info();
    foreach ($plugins as $p) {
        $slug    = $p['slug'];
        $name    = $p['name'];
        $version = $p['version'];

        $vulns = wpvulscan_wpscan_get_plugin_vulns($slug, $version);
        if (empty($vulns)) {
            continue;
        }

        $asset_id = wpvulscan_get_asset_id_by_slug($slug);

        foreach ($vulns as $v) {
            $title = isset($v['title']) ? $v['title'] : 'Vulnerabilidad';
            $cvss  = isset($v['cvss_score']) ? $v['cvss_score'] : null;

            // CVE(s)
            $cve = null;
            if (!empty($v['references']['cve']) && is_array($v['references']['cve'])) {
                $cve = implode(', ', $v['references']['cve']);
            }

            // Severidad aproximada a partir de CVSS
            $severity = null;
            if ($cvss !== null) {
                $cvss_f = floatval($cvss);
                if ($cvss_f >= 9.0)      $severity = 'critical';
                elseif ($cvss_f >= 7.0) $severity = 'high';
                elseif ($cvss_f >= 4.0) $severity = 'medium';
                else                    $severity = 'low';
            }

            // Línea para el panel
            $line = sprintf(
                '%s %s — %s%s%s',
                $name,
                $version,
                $cve ? ('CVE ' . $cve . ' — ') : '',
                $cvss ? ('CVSS ' . $cvss . ' — ') : '',
                $title
            );
            $out[] = $line;

            // Persistimos en findings (si tabla existe)
            wpvulscan_insert_finding([
                'asset_id'   => $asset_id,
                'rule_id'    => 'catalog_wpscan',
                'cve_id'     => $cve,
                'severity'   => $severity,
                'created_at' => current_time('mysql'),
                'path'       => $p['path'],
            ]);
        }
    }

    return $out;
}

function wp_vulscan_mostrar_plugins_tabla() {
    $plugins = wp_vulscan_get_plugins_info();

    echo '<h2>Plugins instalados</h2>';
    echo '<table class="widefat fixed striped">';
    echo '<thead><tr><th>Nombre</th><th>Versión</th><th>Estado</th><th>Slug</th></tr></thead><tbody>';

    foreach ($plugins as $plugin) {
        echo '<tr>';
        echo '<td>' . esc_html($plugin['name']) . '</td>';
        echo '<td>' . esc_html($plugin['version']) . '</td>';
        echo '<td>' . ($plugin['active'] ? 'Activo' : 'Inactivo') . '</td>';
        echo '<td>' . esc_html($plugin['slug']) . '</td>';
        echo '</tr>';
    }

    echo '</tbody></table>';
}
