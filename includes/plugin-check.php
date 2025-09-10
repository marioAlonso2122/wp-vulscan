<?php
defined('ABSPATH') or die('Acceso no permitido.');

if ( ! function_exists('wpvulscan_get_plugins_info') ) {
    // Por si no tienes scan.php cargado
    function wpvulscan_get_plugins_info() {
        if (!function_exists('get_plugins')) {
            require_once ABSPATH . 'wp-admin/includes/plugin.php';
        }
        $all     = get_plugins();
        $actives = (array) get_option('active_plugins', []);
        $out     = [];
        foreach ($all as $path => $data) {
            $slug = dirname($path);
            if ($slug === '.' || $slug === '') {
                // slug fallback para plugins de un solo archivo en la raíz
                $slug = strtolower(preg_replace('/\.php$/', '', basename($path)));
            }
            $out[] = [
                'name'    => $data['Name'] ?? $slug,
                'version' => $data['Version'] ?? '',
                'slug'    => $slug,
                'path'    => $path,
                'active'  => in_array($path, $actives, true),
            ];
        }
        return $out;
    }
}

/**
 * Llama a la API de WPScan por plugin y filtra vulnerabilidades que afectan a la versión instalada.
 * Cachea el resultado 6h en el transient 'wpvulscan_plugins_vulns'.
 */
if ( ! function_exists('wpvulscan_check_plugins_vulnerables') ) {
    function wpvulscan_check_plugins_vulnerables($force = false) {
        $key = (string) get_option('wpvulscan_wpscan_api_key', '');
        if ($key === '') {
            return ['(Configura la API Key de WPScan para habilitar este análisis)'];
        }

        $tkey = 'wpvulscan_plugins_vulns';
        if (!$force) {
            $cached = get_transient($tkey);
            if ($cached !== false) return $cached;
        }

        $plugins  = wpvulscan_get_plugins_info();
        $findings = [];

        foreach ($plugins as $p) {
            // Endpoint oficial: https://wpscan.com/api/v3/plugins/{slug}
            $url  = 'https://wpscan.com/api/v3/plugins/' . rawurlencode($p['slug']);
            $resp = wp_remote_get($url, [
                'timeout'   => 12,
                'headers'   => ['Authorization' => 'Token token=' . $key],
                'sslverify' => false, // en local a veces hace falta
            ]);
            if (is_wp_error($resp)) {
                continue;
            }
            if ((int) wp_remote_retrieve_response_code($resp) !== 200) {
                continue;
            }

            $data = json_decode(wp_remote_retrieve_body($resp), true);
            if (!is_array($data) || empty($data['vulnerabilities'])) {
                continue;
            }

            foreach ($data['vulnerabilities'] as $v) {
                $fixed  = $v['fixed_in'] ?? null;
                $cve    = $v['cve'] ?? '';
                $cvss   = $v['cvss'] ?? '';
                $title  = $v['title'] ?? '';
                $affect = true;

                // Heurística: si hay fixed_in y la instalada >= fixed_in => no afecta
                if ($fixed && $p['version'] !== '' && version_compare($p['version'], $fixed, '>=')) {
                    $affect = false;
                }

                if ($affect) {
                    $findings[] = [
                        'plugin'    => $p['name'],
                        'slug'      => $p['slug'],
                        'installed' => $p['version'],
                        'active'    => $p['active'],
                        'cve'       => $cve,
                        'cvss'      => $cvss,
                        'fixed_in'  => $fixed,
                        'title'     => $title,
                    ];
                }
            }
        }

        set_transient($tkey, $findings, 6 * HOUR_IN_SECONDS);
        return $findings;
    }
}

/** Render con botón “Analizar ahora” */
if ( ! function_exists('wpvulscan_render_plugins_vulns_section') ) {
    function wpvulscan_render_plugins_vulns_section() {
        echo '<h2 id="plugins">Vulnerabilidades en plugins instalados</h2>';
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="margin-bottom:10px;">';
        echo '<input type="hidden" name="action" value="wpvulscan_check_plugins_now">';
        wp_nonce_field('wpvulscan_check_plugins_now', '_wpvulscan');
        echo '<button type="submit" class="button button-secondary">Analizar ahora (WPScan)</button>';
        echo '</form>';

        $rows = wpvulscan_check_plugins_vulnerables(false);
        if (empty($rows)) {
            echo "<p class='ok'>No se han detectado vulnerabilidades en los plugins instalados (según WPScan).</p>";
            return;
        }
        if (count($rows) === 1 && is_string($rows[0])) {
            echo '<p>' . esc_html($rows[0]) . '</p>';
            return;
        }

        echo '<table class="widefat fixed striped">';
        echo '<thead><tr>'
            . '<th>Plugin</th><th>Slug</th><th>Versión instalada</th>'
            . '<th>CVE</th><th>CVSS</th><th>Fixed in</th><th>Título</th>'
            . '</tr></thead><tbody>';

        foreach ($rows as $r) {
            echo '<tr>';
            echo '<td>' . esc_html($r['plugin']) . ($r['active'] ? ' <em>(activo)</em>' : '') . '</td>';
            echo '<td>' . esc_html($r['slug']) . '</td>';
            echo '<td>' . esc_html($r['installed']) . '</td>';
            echo '<td>' . esc_html($r['cve']) . '</td>';
            echo '<td>' . esc_html((string)$r['cvss']) . '</td>';
            echo '<td>' . esc_html($r['fixed_in'] ?? '') . '</td>';
            echo '<td>' . esc_html($r['title']) . '</td>';
            echo '</tr>';
        }
        echo '</tbody></table>';
    }
}

/** Handler del botón */
add_action('admin_post_wpvulscan_check_plugins_now', function () {
    if (!current_user_can('manage_options')) wp_die('Acceso denegado.');
    check_admin_referer('wpvulscan_check_plugins_now', '_wpvulscan');
    delete_transient('wpvulscan_plugins_vulns');
    wpvulscan_check_plugins_vulnerables(true);
    wp_safe_redirect(admin_url('admin.php?page=wp-vulscan#plugins'));
    exit;
});
