<?php
/**
 * Plugin Name: WP-VulScan
 * Plugin URI: https://github.com/marioAlonso2122/wp-vulscan
 * Description: Detección heurística de configuración, formularios, REST y cabeceras; correlación con WPScan (CVE/CVSS); motor de reglas JSON; informe HTML y score global.
 * Version: 0.9.0
 * Requires at least: 5.8
 * Requires PHP: 7.4
 * Author: Mario Alonso Pulgar
 * Author URI: https://github.com/marioAlonso2122
 * License: GPLv2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: wp-vulscan
 * Domain Path: /languages
 */

if ( ! defined('ABSPATH') ) {
    exit; // No acceso directo
}

/**
 * Ruta base del plugin (esto evita redefinir constantes usadas en includes/init.php)
 */
define('WP_VULSCAN_FILE', __FILE__);

/**
 * Carga i18n (si añades /languages con .mo/.po)
 */
add_action('plugins_loaded', function () {
    load_plugin_textdomain('wp-vulscan', false, dirname(plugin_basename(__FILE__)) . '/languages');
});

/**
 * Cargar el bootstrap real del plugin
 * (init.php define constantes, requiere el resto de módulos y registra hooks).
 */
$__wpvulscan_base = plugin_dir_path(__FILE__);
$__wpvulscan_init = $__wpvulscan_base . 'includes/init.php';

if ( file_exists($__wpvulscan_init) ) {
    require_once $__wpvulscan_init;
} else {
    // Aviso en el panel si falta includes/init.php
    add_action('admin_notices', function () {
        echo '<div class="notice notice-error"><p><strong>WP-VulScan:</strong> no se encontró <code>includes/init.php</code>. Verifica la instalación del plugin.</p></div>';
    });
    return;
}

/**
 * Enlace rápido “Abrir WP-VulScan” en la lista de plugins
 */
add_filter('plugin_action_links_' . plugin_basename(__FILE__), function ($links) {
    $url = admin_url('admin.php?page=wp-vulscan');
    $links[] = '<a href="' . esc_url($url) . '">' . esc_html__('Abrir WP-VulScan', 'wp-vulscan') . '</a>';
    return $links;
});
