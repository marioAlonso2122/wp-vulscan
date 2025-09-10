<?php
defined('ABSPATH') or die('Acceso no permitido.');

/**
 * Acumulador global de incidencias del sistema.
 */
function wpvulscan_add_issue($type, $message, $meta = []) {
    $issues   = get_option('wpvulscan_system_issues', []);
    $issues[] = [
        'type'    => $type,
        'message' => $message,
        'meta'    => $meta,
        'time'    => current_time('mysql'),
    ];
    update_option('wpvulscan_system_issues', $issues, false);
}

/** =========================================================
 * Helpers seguros para representar callbacks y métodos HTTP
 * ========================================================= */

/**
 * Convierte cualquier callback a una cadena imprimible sin provocar errores.
 */
if ( ! function_exists('wpvulscan_callback_to_string') ) {
    function wpvulscan_callback_to_string($cb) {
        if (is_string($cb)) {
            return $cb; // '__return_true', 'mi_funcion'
        }
        if (is_array($cb)) {
            // Formatos típicos: [$obj, 'metodo'] o ['Clase', 'metodo']
            $obj = $cb[0] ?? null;
            $met = $cb[1] ?? '';
            if (is_object($obj)) return get_class($obj) . '::' . (string) $met;
            if (is_string($obj)) return $obj . '::' . (string) $met;
            return 'callable[]';
        }
        if ($cb instanceof Closure) {
            return 'Closure';
        }
        if (is_object($cb)) {
            return get_class($cb);
        }
        return gettype($cb); // NULL, boolean, integer...
    }
}

/**
 * Normaliza el campo 'methods' de un endpoint REST a texto.
 */
if ( ! function_exists('wpvulscan_methods_to_string') ) {
    function wpvulscan_methods_to_string($methods) {
        if (is_string($methods)) {
            return $methods; // 'GET', 'POST'
        }
        if (is_array($methods)) {
            $out = [];
            foreach ($methods as $k => $v) {
                // Puede venir como ['GET' => true, 'POST' => true] o ['GET','POST']
                if (is_string($k)) {
                    $out[] = $k;
                } elseif (is_string($v) || is_int($v)) {
                    $out[] = (string) $v;
                }
            }
            $out = array_unique($out);
            return implode(', ', $out);
        }
        if (is_int($methods)) {
            // En algunas versiones es un bitmask; lo mostramos como entero
            return (string) $methods;
        }
        return '';
    }
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
    $usuarios_obj   = get_users(['fields' => ['user_login']]);
    $usuarios       = wp_list_pluck($usuarios_obj, 'user_login');
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
            $mtime      = @filemtime($plugin_path);
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
 */
function wp_vulscan_check_rest_api_permissions() {
    echo '<h2>REST API: Validación de <code>permission_callback</code></h2>';

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
    if (empty($routes) || !is_array($routes)) {
        echo '<p>No se encontraron rutas REST.</p>';
        return;
    }

    echo '<table class="widefat fixed striped">';
    echo '<thead><tr><th>Ruta</th><th>Métodos</th><th>permission_callback</th><th>Estado</th></tr></thead><tbody>';

    $issues = get_option('wpvulscan_system_issues', []);
    if (!is_array($issues)) $issues = [];

    foreach ($routes as $route => $endpoints) {
        if (!is_array($endpoints)) continue;

        foreach ($endpoints as $endpoint) {
            if (!is_array($endpoint)) continue;

            // Métodos normalizados
            $methods = isset($endpoint['methods'])
                ? wpvulscan_methods_to_string($endpoint['methods'])
                : '';

            // permission_callback a texto seguro
            $perm_cb  = $endpoint['permission_callback'] ?? null;
            $perm_str = is_null($perm_cb) ? '(faltante)' : wpvulscan_callback_to_string($perm_cb);

            // Inseguro si falta o es __return_true
            $insecure = (is_null($perm_cb) || (is_string($perm_cb) && strtolower($perm_cb) === '__return_true'));

            echo '<tr>';
            echo '<td>' . esc_html($route)   . '</td>';
            echo '<td>' . esc_html($methods) . '</td>';
            echo '<td>' . esc_html($perm_str). '</td>';
            echo '<td>' . ($insecure ? '<strong style="color:red;">Riesgo</strong>' : '<span style="color:green;">OK</span>') . '</td>';
            echo '</tr>';

            if ($insecure) {
                $issues[] = [
                    'type'    => 'rest',
                    'message' => "Ruta REST insegura: $route",
                    'meta'    => ['methods' => $methods, 'perm' => $perm_str],
                    'time'    => current_time('mysql'),
                ];
                // Opcional: registrar también como "finding" si tienes el motor de reglas
                if (function_exists('wpvulscan_insert_finding_with_rule')) {
                    wpvulscan_insert_finding_with_rule('rule_rest_permission_missing', [
                        'path'           => $route,
                        'function_name'  => 'REST ' . $methods,
                        'sample_payload' => $perm_str,
                    ]);
                }
            }
        }
    }

    echo '</tbody></table>';

    update_option('wpvulscan_system_issues', $issues, false);
}

/**
 * Runner: ejecuta todos los chequeos y deja incidencias en wpvulscan_system_issues
 */
function wp_vulscan_run_system_checks() {
    // Limpia incidencias previas opcionalmente
    update_option('wpvulscan_system_issues', [], false);

    wp_vulscan_check_wp_version();
    wp_vulscan_check_usuarios_predecibles();
    wp_vulscan_check_permisos_archivos();
    wp_vulscan_check_plugins_abandonados();
    wp_vulscan_check_rest_api_permissions();
}
