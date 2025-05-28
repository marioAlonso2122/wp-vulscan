<?php
// Seguridad: evitar acceso directo
defined('ABSPATH') or die('Acceso no permitido.');

/**
 * Devuelve una lista de plugins instalados con nombre, versión y estado
 */
function wp_vulscan_get_plugins_info() {
    if (!function_exists('get_plugins')) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }

    $todos_los_plugins = get_plugins();
    $plugins_activos = get_option('active_plugins', []);
    $info_plugins = [];

    foreach ($todos_los_plugins as $plugin_path => $plugin_data) {
        $info_plugins[] = [
            'nombre' => $plugin_data['Name'],
            'version' => $plugin_data['Version'],
            'activo' => in_array($plugin_path, $plugins_activos),
            'slug'   => dirname($plugin_path),
        ];
    }

    return $info_plugins;
}

/**
 * Muestra los plugins en la página de administración
 */
function wp_vulscan_mostrar_plugins_tabla() {
    $plugins = wp_vulscan_get_plugins_info();

    echo '<h2>Plugins instalados</h2>';
    echo '<table class="widefat fixed striped">';
    echo '<thead><tr><th>Nombre</th><th>Versión</th><th>Estado</th></tr></thead><tbody>';

    foreach ($plugins as $plugin) {
        echo '<tr>';
        echo '<td>' . esc_html($plugin['nombre']) . '</td>';
        echo '<td>' . esc_html($plugin['version']) . '</td>';
        echo '<td>' . ($plugin['activo'] ? 'Activo' : 'Inactivo') . '</td>';
        echo '</tr>';
    }

    echo '</tbody></table>';
}
