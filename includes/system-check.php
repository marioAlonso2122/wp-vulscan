<?php
defined('ABSPATH') or die('Acceso no permitido.');

/**
 * 1. Comprobar versión de WordPress
 */
function wp_vulscan_check_wp_version() {
    global $wp_version;

    echo '<h2>Versión de WordPress</h2>';
    echo '<p>Versión instalada: <strong>' . esc_html($wp_version) . '</strong></p>';

    // Última versión conocida (puede mantenerse manualmente)
    $ultima = '6.5.4'; // Cambiar si hay versión más reciente
    if (version_compare($wp_version, $ultima, '<')) {
        echo '<p style="color:red;">Tu instalación está desactualizada respecto a la versión ' . $ultima . '</p>';
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
        }
        echo '</ul>';
    }
}

/**
 * 3. Verificar permisos de archivos clave
 */
function wp_vulscan_check_permisos_archivos() {
    $base = ABSPATH;
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
            $permisos = substr(sprintf('%o', fileperms($ruta)), -3);
            $ok = in_array($permisos, ['644', '640', '600']);
            echo '<tr>';
            echo '<td>' . esc_html($a) . '</td>';
            echo '<td>' . esc_html($permisos) . '</td>';
            echo '<td>' . ($ok ? 'Seguro' : '<span style="color:red;">Inseguro</span>') . '</td>';
            echo '</tr>';
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
            $mtime = filemtime($plugin_path);
            echo '<tr>';
            echo '<td>' . esc_html($datos['Name']) . '</td>';
            echo '<td>' . esc_html($datos['Version']) . '</td>';
            echo '<td>' . date('Y-m-d', $mtime) . '</td>';
            echo '<td>' . ($mtime < $limite
                ? '<span style="color:red;">Inactivo/antiguo</span>'
                : 'Reciente') . '</td>';
            echo '</tr>';
        }
    }

    echo '</tbody></table>';
}


update_option('wpvulscan_system_issues', $system_warnings);