<?php
// Seguridad: evitar acceso directo
defined('ABSPATH') or die('Acceso no permitido.');

/**
 * Constantes del plugin
 * - WP_VULSCAN_DIR: ruta absoluta al directorio raíz del plugin (…/wp-vulscan/)
 * - WP_VULSCAN_URL: URL pública al directorio raíz del plugin
 * - WP_VULSCAN_INC: ruta absoluta al directorio de includes (…/wp-vulscan/includes/)
 * - WP_VULSCAN_MAIN_FILE: archivo principal del plugin (…/wp-vulscan/wp-vulscan.php)
 */
if (!defined('WP_VULSCAN_VERSION')) {
    define('WP_VULSCAN_VERSION', '1.0.0');
}
if (!defined('WP_VULSCAN_DIR')) {
    define('WP_VULSCAN_DIR', trailingslashit(plugin_dir_path(__DIR__)));
}
if (!defined('WP_VULSCAN_URL')) {
    define('WP_VULSCAN_URL', trailingslashit(plugin_dir_url(__DIR__)));
}
if (!defined('WP_VULSCAN_INC')) {
    define('WP_VULSCAN_INC', trailingslashit(plugin_dir_path(__FILE__)));
}
if (!defined('WP_VULSCAN_MAIN_FILE')) {
    define('WP_VULSCAN_MAIN_FILE', WP_VULSCAN_DIR . 'wp-vulscan.php');
}

/**
 * Carga de módulos
 * (Asegúrate de que estos archivos existen en /includes; ajusta nombres si difieren)
 */
require_once WP_VULSCAN_INC . 'admin-menu.php';
require_once WP_VULSCAN_INC . 'config-check.php';
require_once WP_VULSCAN_INC . 'form-check-remote.php';
require_once WP_VULSCAN_INC . 'system-check.php';
require_once WP_VULSCAN_INC . 'hardening-recommendations.php';
require_once WP_VULSCAN_INC . 'security-score.php';
require_once WP_VULSCAN_INC . 'plugin-check.php';
require_once WP_VULSCAN_INC . 'external-url-scan.php';
require_once WP_VULSCAN_INC . 'export.php';            
require_once WP_VULSCAN_INC . 'rules-loader.php';
require_once WP_VULSCAN_INC . 'findings.php';

add_action('admin_init', function () {
    wpvulscan_rules_load_all();
});


/**
 * Hooks de activación / desactivación
 * Nota: Al estar este archivo en /includes/, usamos WP_VULSCAN_MAIN_FILE para registrar los hooks.
 */
register_activation_hook(WP_VULSCAN_MAIN_FILE, 'wp_vulscan_activate');
register_deactivation_hook(WP_VULSCAN_MAIN_FILE, 'wp_vulscan_deactivate');

/**
 * Activación: crear tablas personalizadas si no existen
 */
function wp_vulscan_activate() {
    global $wpdb;

    $charset_collate = $wpdb->get_charset_collate();

    $table_scans    = $wpdb->prefix . 'vulscan_scans';
    $table_assets   = $wpdb->prefix . 'vulscan_assets';
    $table_findings = $wpdb->prefix . 'vulscan_findings';
    $table_rules    = $wpdb->prefix . 'vulscan_rules';
    $table_logs     = $wpdb->prefix . 'vulscan_logs';

    $sql = [];

    // Escaneos (histórico)
    $sql[] = "CREATE TABLE IF NOT EXISTS {$table_scans} (
        id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
        started_at DATETIME NOT NULL,
        finished_at DATETIME NULL,
        scope VARCHAR(50) NOT NULL,
        status VARCHAR(20) NOT NULL,
        PRIMARY KEY (id),
        KEY idx_scope (scope),
        KEY idx_status (status)
    ) {$charset_collate};";

    // Activos (plugins/temas/core)
    $sql[] = "CREATE TABLE IF NOT EXISTS {$table_assets} (
        id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
        type VARCHAR(20) NOT NULL,          -- plugin|theme|core
        slug VARCHAR(191) NOT NULL,
        name VARCHAR(191) NOT NULL,
        version VARCHAR(50) NULL,
        path TEXT NULL,
        hash VARCHAR(64) NULL,
        active TINYINT(1) NOT NULL DEFAULT 0,
        PRIMARY KEY (id),
        KEY idx_type (type),
        KEY idx_slug (slug),
        KEY idx_active (active)
    ) {$charset_collate};";

    // Hallazgos
    $sql[] = "CREATE TABLE IF NOT EXISTS {$table_findings} (
        id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
        asset_id BIGINT(20) UNSIGNED NULL,
        rule_id VARCHAR(100) NULL,
        cve_id VARCHAR(50) NULL,
        cwe VARCHAR(50) NULL,
        owasp VARCHAR(50) NULL,
        severity VARCHAR(10) NULL,          -- low|medium|high|critical
        confidence VARCHAR(10) NULL,        -- low|medium|high
        path TEXT NULL,
        line INT(11) NULL,
        function_name VARCHAR(191) NULL,
        hook_name VARCHAR(191) NULL,
        trace_json LONGTEXT NULL,
        sample_payload TEXT NULL,
        created_at DATETIME NOT NULL,
        PRIMARY KEY (id),
        KEY idx_asset (asset_id),
        KEY idx_rule (rule_id),
        KEY idx_severity (severity),
        KEY idx_created_at (created_at)
    ) {$charset_collate};";

    // Reglas (catálogo DSL)
    $sql[] = "CREATE TABLE IF NOT EXISTS {$table_rules} (
        id VARCHAR(100) NOT NULL,           -- id lógico de la regla (p.ej. rule_xss_reflected)
        name VARCHAR(191) NOT NULL,
        category VARCHAR(50) NULL,
        severity_default VARCHAR(10) NULL,
        pattern_json LONGTEXT NULL,
        enabled TINYINT(1) NOT NULL DEFAULT 1,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY idx_enabled (enabled),
        KEY idx_category (category)
    ) {$charset_collate};";

    // Logs operativos
    $sql[] = "CREATE TABLE IF NOT EXISTS {$table_logs} (
        id BIGINT(20) UNSIGNED NOT NULL AUTO_INCREMENT,
        level VARCHAR(20) NOT NULL,         -- info|warning|error
        message TEXT NOT NULL,
        ctx_json LONGTEXT NULL,
        created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        KEY idx_level (level),
        KEY idx_created_at (created_at)
    ) {$charset_collate};";

    require_once ABSPATH . 'wp-admin/includes/upgrade.php';
    foreach ($sql as $statement) {
        dbDelta($statement);
    }

    // Inicializar opciones usadas por el dashboard (si no existen)
    add_option('wpvulscan_history', [], '', false);
    add_option('wpvulscan_config_issues', [], '', false);
    add_option('wpvulscan_form_issues', [], '', false);
    add_option('wpvulscan_hardening_issues', [], '', false);
    add_option('wpvulscan_system_issues', [], '', false);
    add_option('wpvulscan_external_url_issues', [], '', false);

    // Marcador en log
    if (function_exists('error_log')) {
        error_log('WP-VulScan activado: tablas creadas y opciones inicializadas.');
    }
}

/**
 * Desactivación: aquí podrías desprogramar cron o limpiar temporales (no borrar datos)
 */
function wp_vulscan_deactivate() {
    // Ejemplo: desprogramar tareas si las tuvieras
    // wp_clear_scheduled_hook('wpvulscan_scheduled_scan');

    if (function_exists('error_log')) {
        error_log('WP-VulScan desactivado correctamente.');
    }
}

