<?php
defined('ABSPATH') or die('Acceso no permitido.');

/**
 * Acumulador global de incidencias del sistema.
 */
function wpvulscan_add_issue($type, $message, $meta = []) {
    $issues = get_option('wpvulscan_system_issues', []);
    $issues[] = [
        'type'    => $type,
        'message' => $message,
        'meta'    => $meta,
        'time'    => current_time('mysql'),
    ];
    update_option('wpvulscan_system_issues', $issues, false);
}

/**
 * 1. Comprobar versión de WordPress
 */
function wp_vulscan_check_wp_version() {
    global $wp_version;

    echo '<h2>Versión de WordPress</h2>';
    echo '<p>Versión instalada: <strong>' . esc_html($wp_version) . '</strong></p>';

    // Última versión conocida (mantener manualmente si no tiras de API)
    $ultima = '6.5.4'; // TODO: actualizar si procede
    if (version_compare($wp_version, $ultima, '<')) {
        echo '<p style="color:red;">Tu instalación está desactualizada respecto a la versión ' . esc_html($ultima) . '</p>';
        wpvulscan_add_issue('core', "WordPress desactualizado (instalada $wp_version, última $ultima)");
    } else {
        echo '<p style="color:green;">WordPress está actualizado.</p>';
    }
}

/**
 * 2. Detectar usuarios comunes
 */
function wp_vulscan_check_usuarios_predecibles() {
    $usuarios_obj = get_users(['fields' => ['user_login']]);
    $usuarios = wp_list_pluck($usuarios_obj, 'user_login');
    $nombres_riesgo = ['admin', 'administrator', 'root', 'editor'];

    $coincidencias = array_intersect($nombres_riesgo, array_map('strtolower', $usuarios));

    echo '<h2>Usuarios con nombres predecibles</h2>';

    if (empty($coincidencias)) {
        echo '<p style="color:green;">No se han detectado usuarios con nombres peligrosos.</p>';
    } else {
        echo '<ul>';
        foreach ($coincidencias as $nombre) {
            echo '<li style="color:red;">Usuario "' . esc_html($nombre) . '" detectado.</li>';
            wpvulscan_add_issue('users', "Usuario con nombre predecible: $nombre");
        }
        echo '</ul>';
    }
}

/**
 * 3. Verificar permisos de archivos clave
 */
function wp_vulscan_check_permisos_archivos() {
    $base = trailingslashit(ABSPATH);
    $archivos = [
        'wp-config.php',
        '.htaccess',
        'index.php'
    ];

    echo '<h2>Permisos de archivos críticos</h2>';
    echo '<table class="widefat fixed striped">';
    echo '<thead><tr><th>Archivo</th><th>Permisos</th><th>Estado</th></tr></thead><tbody>';

    foreach ($archivos as $a) {
        $ruta = $base . $a;
        if (file_exists($ruta)) {
            $permisos = substr(sprintf('%o', @fileperms($ruta)), -3);
            $ok = in_array($permisos, ['644', '640', '600'], true);
            echo '<tr>';
            echo '<td>' . esc_html($a) . '</td>';
            echo '<td>' . esc_html($permisos) . '</td>';
            echo '<td>' . ($ok ? 'Seguro' : '<span style="color:red;">Inseguro</span>') . '</td>';
            echo '</tr>';

            if (!$ok) {
                wpvulscan_add_issue('filesystem', "Permisos inseguros en $a ($permisos)");
            }
        }
    }

    echo '</tbody></table>';
}

/**
 * 4. Detectar plugins abandonados (>2 años)
 */
function wp_vulscan_check_plugins_abandonados() {
    if (!function_exists('get_plugins')) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }

    $todos = get_plugins();
    echo '<h2>Plugins potencialmente abandonados</h2>';
    echo '<table class="widefat fixed striped">';
    echo '<thead><tr><th>Nombre</th><th>Versión</th><th>Última modificación</th><th>Estado</th></tr></thead><tbody>';

    $limite = strtotime('-2 years');

    foreach ($todos as $ruta => $datos) {
        $plugin_path = WP_PLUGIN_DIR . '/' . dirname($ruta);
        if (file_exists($plugin_path)) {
            $mtime = @filemtime($plugin_path);
            $es_antiguo = ($mtime !== false && $mtime < $limite);

            echo '<tr>';
            echo '<td>' . esc_html($datos['Name']) . '</td>';
            echo '<td>' . esc_html($datos['Version']) . '</td>';
            echo '<td>' . ($mtime ? esc_html(date('Y-m-d', $mtime)) : '—') . '</td>';
            echo '<td>' . ($es_antiguo
                ? '<span style="color:red;">Inactivo/antiguo</span>'
                : 'Reciente') . '</td>';
            echo '</tr>';

            if ($es_antiguo) {
                wpvulscan_add_issue('plugins', "Posible plugin abandonado: {$datos['Name']} ({$datos['Version']})");
            }
        }
    }

    echo '</tbody></table>';
}

/**
 * 5. REST API: rutas sin permission_callback o con __return_true
 *    - Recorre todas las rutas registradas y marca las inseguras.
 */
function wp_vulscan_check_rest_api_permissions() {
    echo '<h2>REST API: Validación de permission_callback</h2>';

    if (!function_exists('rest_get_server')) {
        echo '<p>No se pudo acceder al servidor REST.</p>';
        return;
    }

    $server = rest_get_server();
    if (!$server) {
        echo '<p>No se pudo obtener el servidor REST.</p>';
        return;
    }

    $routes = $server->get_routes();

    echo '<table class="widefat fixed striped">';
    echo '<thead><tr><th>Ruta</th><th>Métodos</th><th>permission_callback</th><th>Estado</th></tr></thead><tbody>';

    foreach ($routes as $route => $handlers) {
        // $handlers suele ser un array de endpoints; cada endpoint tiene keys como methods/callback/permission_callback/args
        $endpoints = is_array($handlers) ? $handlers : [];

        foreach ($endpoints as $endpoint) {
            if (!is_array($endpoint)) {
                continue;
            }

            // Normalizar métodos
            $methods = 'GET';
            if (!empty($endpoint['methods'])) {
                if (is_array($endpoint['methods'])) {
                    // En algunas versiones es array asociativo de constantes
                    $methods = implode(',', array_keys($endpoint['methods']));
                } else {
                    $methods = (string) $endpoint['methods'];
                }
            }

            $perm = $endpoint['permission_callback'] ?? null;

            $insecure  = false;
            $perm_desc = '—';

            if ($perm === null) {
                $insecure  = true;
                $perm_desc = '<span style="color:red;">(faltante)</span>';
                wpvulscan_add_issue('rest', "Ruta REST sin permission_callback: $route", [
                    'methods' => $methods
                ]);
            } elseif (is_string($perm) && strtolower($perm) === '__return_true') {
                $insecure  = true;
                $perm_desc = '<span style="color:red;">__return_true</span>';
                wpvulscan_add_issue('rest', "Ruta REST con acceso universal (__return_true): $route", [
                    'methods' => $methods
                ]);
            } else {
                // Mostramos algo legible
                if (is_string($perm)) {
                    $perm_desc = esc_html($perm);
                } elseif (is_array($perm)) {
                    // ['Clase','método'] // o ['obj','método']
                    $perm_desc = esc_html(implode('::', array_map('strval', $perm)));
                } elseif ($perm instanceof Closure) {
                    $perm_desc = 'closure';
                } elseif (is_callable($perm)) {
                    $perm_desc = 'callable';
                } else {
                    $perm_desc = 'definido';
                }
                if ($insecure && function_exists('wpvulscan_insert_finding_with_rule')) {
                    wpvulscan_insert_finding_with_rule('rule_rest_permission_missing', [
                        'path'      => $route,
                        'function_name' => 'REST ' . $methods,
                        'sample_payload' => is_string($perm) ? $perm : (is_array($perm) ? implode('::', $perm) : '—')
                    ]);
                }
            }

            echo '<tr>';
            echo '<td>' . esc_html($route) . '</td>';
            echo '<td>' . esc_html($methods) . '</td>';
            echo '<td>' . $perm_desc . '</td>';
            echo '<td>' . ($insecure ? '<strong style="color:red;">Riesgo</strong>' : '<span style="color:green;">OK</span>') . '</td>';
            echo '</tr>';
        }
    }

    echo '</tbody></table>';
}

/**
 * Runner: ejecuta todos los chequeos y deja incidencias en wp_vulscan_system_issues
 */
function wp_vulscan_run_system_checks() {
    // Limpia incidencias previas opcionalmente
    update_option('wp_vulscan_system_issues', [], false);

    wp_vulscan_check_wp_version();
    wp_vulscan_check_usuarios_predecibles();
    wp_vulscan_check_permisos_archivos();
    wp_vulscan_check_plugins_abandonados();
    wp_vulscan_check_rest_api_permissions();
}
