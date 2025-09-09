<?php
// Seguridad: evitar acceso directo
defined('ABSPATH') or die('Acceso no permitido.');

/**
 * Inicia un escaneo y devuelve su ID (tabla wp_vulscan_scans).
 */
function wpvulscan_start_scan($scope = 'full') {
    global $wpdb;
    $table = $wpdb->prefix . 'vulscan_scans';
    // Comprueba que la tabla existe
    $exists = $wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $table));
    if ($exists !== $table) {
        return 0;
    }
    $wpdb->insert($table, [
        'started_at' => current_time('mysql'),
        'finished_at'=> null,
        'scope'      => sanitize_text_field($scope),
        'status'     => 'running',
    ]);
    return (int) $wpdb->insert_id;
}

/**
 * Finaliza un escaneo (actualiza finished_at y status).
 */
function wpvulscan_finish_scan($scan_id, $status = 'finished') {
    global $wpdb;
    $table = $wpdb->prefix . 'vulscan_scans';
    if ($scan_id <= 0) return;
    $wpdb->update($table, [
        'finished_at' => current_time('mysql'),
        'status'      => sanitize_text_field($status),
    ], ['id' => (int)$scan_id]);
}

/**
 * Añade una entrada al historial (opción wpvulscan_history) para la UI.
 */
function wpvulscan_history_add_entry($score_data) {
    $history = get_option('wpvulscan_history', []);
    $history[] = [
        'fecha' => current_time('mysql'),
        'score' => (int)($score_data['score'] ?? 0),
        'nivel' => (string)($score_data['riesgo']['nivel'] ?? 'N/A'),
    ];
    // Limitar a últimas 100 entradas
    if (count($history) > 100) {
        $history = array_slice($history, -100);
    }
    update_option('wpvulscan_history', $history, false);
}

/**
 * Construye el array $results que espera security-score y el generador de informes.
 */
function wpvulscan_build_results_payload() {
    $results = [
        'Configuración insegura'                    => (array) get_option('wpvulscan_config_issues', []),
        'Formularios inseguros'                     => (array) get_option('wpvulscan_form_issues', []),
        'Hardening'                                 => (array) get_option('wpvulscan_hardening_issues', []),
        'Usuarios predecibles / permisos inseguros' => (array) get_option('wpvulscan_system_issues', []),
        'Rutas externas sensibles'                  => (array) get_option('wpvulscan_external_url_issues', []),
    ];

    // Opcional: añade listado plano de vulnerabilidades de plugins si lo quieres en informes.
    if (function_exists('wpvulscan_check_plugins_vulnerables')) {
        $results['Vulnerabilidades en plugins'] = (array) wpvulscan_check_plugins_vulnerables();
    }

    return $results;
}

/**
 * Ejecuta los módulos de análisis SIN imprimir HTML (silencioso) y persiste sus issues en opciones.
 * - Configuración (exposición de rutas) -> wpvulscan_config_issues
 * - Sistema (versión, usuarios, permisos, plugins abandonados, REST) -> wpvulscan_system_issues
 * - Hardening (constantes, ficheros, cabeceras) -> wpvulscan_hardening_issues
 * - URLs externas (si hay guardadas) -> wpvulscan_external_url_issues
 * - Plugins vulnerables -> listado y findings (scan.php)
 */
function wpvulscan_run_modules_silently() {
    // --- Configuración (exposición de rutas)
    if (function_exists('wpvulscan_reset_config_issues')) {
        wpvulscan_reset_config_issues();
    }
    if (function_exists('wp_vulscan_check_sensitive_paths')) {
        // Esta función ya añade a wpvulscan_config_issues al encontrar problemas
        wp_vulscan_check_sensitive_paths();
    }

    // --- Sistema (su runner imprime HTML; lo silenciamos con output buffering)
    if (function_exists('update_option')) {
        update_option('wpvulscan_system_issues', [], false);
    }
    if (function_exists('wp_vulscan_check_wp_version')
        || function_exists('wp_vulscan_check_usuarios_predecibles')
        || function_exists('wp_vulscan_check_permisos_archivos')
        || function_exists('wp_vulscan_check_plugins_abandonados')
        || function_exists('wp_vulscan_check_rest_api_permissions')) {

        ob_start();
        if (function_exists('wp_vulscan_check_wp_version'))             wp_vulscan_check_wp_version();
        if (function_exists('wp_vulscan_check_usuarios_predecibles'))   wp_vulscan_check_usuarios_predecibles();
        if (function_exists('wp_vulscan_check_permisos_archivos'))      wp_vulscan_check_permisos_archivos();
        if (function_exists('wp_vulscan_check_plugins_abandonados'))    wp_vulscan_check_plugins_abandonados();
        if (function_exists('wp_vulscan_check_rest_api_permissions'))   wp_vulscan_check_rest_api_permissions();
        ob_end_clean();
    }

    // --- Hardening (esta no imprime; sólo persiste)
    if (function_exists('wpvulscan_collect_hardening_findings')) {
        wpvulscan_collect_hardening_findings();
    } elseif (function_exists('wp_vulscan_mostrar_recomendaciones_hardening')) {
        // Fallback: la versión que imprime. Silenciamos output.
        ob_start();
        wp_vulscan_mostrar_recomendaciones_hardening();
        ob_end_clean();
    }

    // --- URLs externas: re-ejecuta sobre la lista guardada (si existe)
    if (function_exists('wpvulscan_scan_sensitive_urls')) {
        wpvulscan_scan_sensitive_urls(); // usa wpvulscan_external_urls (opción)
    }

    // --- Plugins vulnerables: se añade más tarde al results (y findings a BD) en build_results_payload()
    //     (ya lo hace wpvulscan_check_plugins_vulnerables()).
}

/**
 * Ejecuta un escaneo completo, calcula score y guarda histórico.
 * Devuelve array con ['scan_id'=>..., 'score_data'=>..., 'results'=>...]
 */
function wpvulscan_run_full_scan($scope = 'full') {
    $scan_id = wpvulscan_start_scan($scope);
    try {
        wpvulscan_run_modules_silently();

        // Construir payload de resultados para scoring e informes
        $results = wpvulscan_build_results_payload();

        // Calcular puntuación global
        $score_data = function_exists('wpvulscan_calculate_score')
            ? wpvulscan_calculate_score($results)
            : ['score' => 0, 'riesgo' => ['nivel' => 'N/A', 'color' => '#607d8b']];

        // Guardar en histórico (opción)
        wpvulscan_history_add_entry($score_data);

        // Finaliza escaneo
        wpvulscan_finish_scan($scan_id, 'finished');

        return [
            'scan_id'   => $scan_id,
            'score_data'=> $score_data,
            'results'   => $results,
        ];
    } catch (\Throwable $e) {
        wpvulscan_finish_scan($scan_id, 'failed');
        return [
            'scan_id'   => $scan_id,
            'error'     => $e->getMessage(),
        ];
    }
}

/**
 * Endpoint para lanzar escaneo desde el backend:
 * GET/POST: admin-post.php?action=wpvulscan_run_scan
 */
add_action('admin_post_wpvulscan_run_scan', function () {
    if (!current_user_can('manage_options')) {
        wp_die('Acceso denegado.');
    }

    check_admin_referer('wpvulscan_run_scan_action');

    $result = wpvulscan_run_full_scan('full');

    // Mensaje flash y redirección al dashboard del plugin
    $args = ['page' => 'wp-vulscan'];
    if (!empty($result['error'])) {
        $args['wpvulscan_msg'] = 'scan_failed';
    } else {
        $args['wpvulscan_msg'] = 'scan_ok';
        $args['score']         = (string)($result['score_data']['score'] ?? 0);
        $args['nivel']         = (string)($result['score_data']['riesgo']['nivel'] ?? 'N/A');
    }

    wp_safe_redirect(add_query_arg($args, admin_url('admin.php')));
    exit;
});

