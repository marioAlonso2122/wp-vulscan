<?php
// Seguridad: evitar el acceso directo
defined('ABSPATH') or die('Acceso no permitido.');

// Ruta base del plugin
define('WP_VULSCAN_PATH', plugin_dir_path(__DIR__));
define('WP_VULSCAN_URL', plugin_dir_url(__DIR__));

// Cargar archivos principales del plugin
require_once plugin_dir_path(__FILE__) . 'admin-menu.php';
require_once plugin_dir_path(__FILE__) . 'config-check.php';
require_once plugin_dir_path(__FILE__) . 'form-check-remote.php';
require_once plugin_dir_path(__FILE__) . 'system-check.php';
require_once plugin_dir_path(__FILE__) . 'hardening-recommendations.php';

// Hook de activación del plugin
register_activation_hook(WP_VULSCAN_PATH . 'wp-vulscan.php', 'wp_vulscan_activate');

function wp_vulscan_activate() {
    
    error_log('WP-VulScan activado correctamente');
}

// Hook de desactivación del plugin (opcional)
register_deactivation_hook(WP_VULSCAN_PATH . 'wp-vulscan.php', 'wp_vulscan_deactivate');

function wp_vulscan_deactivate() {
    error_log('WP-VulScan desactivado correctamente');
}
