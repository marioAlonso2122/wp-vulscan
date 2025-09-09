<?php
// includes/export.php
defined('ABSPATH') or die('Acceso no permitido.');

// Dependencias necesarias para generar el informe y calcular el score
require_once plugin_dir_path(__FILE__) . 'report-generator.php';
if ( ! function_exists('wpvulscan_calculate_score') ) {
    require_once plugin_dir_path(__FILE__) . 'security-score.php';
}

/**
 * Construye el payload de resultados que consumen el generador de informes y el score.
 * Mantiene el mismo esquema de claves usado en el panel (admin-menu.php).
 */
function wpvulscan_export_build_results_payload( $include_plugins = true ) {
    $results = [
        'Configuración insegura'                    => (array) get_option('wpvulscan_config_issues', []),
        'Formularios inseguros'                     => (array) get_option('wpvulscan_form_issues', []),
        'Hardening'                                 => (array) get_option('wpvulscan_hardening_issues', []),
        'Usuarios predecibles / permisos inseguros' => (array) get_option('wpvulscan_system_issues', []),
        'Rutas externas sensibles'                  => (array) get_option('wpvulscan_external_url_issues', []),
    ];

    // Opcional: añadir “Vulnerabilidades en plugins” si la función está disponible
    if ( $include_plugins && function_exists('wpvulscan_check_plugins_vulnerables') ) {
        $results['Vulnerabilidades en plugins'] = (array) wpvulscan_check_plugins_vulnerables();
    }

    return $results;
}

/**
 * Handler: Exportar informe HTML
 * Form: <form method="post" action="admin-post.php"> <input type="hidden" name="action" value="wpvulscan_export_html"> ...
 */
add_action('admin_post_wpvulscan_export_html', function () {
    if ( ! current_user_can('manage_options') ) {
        wp_die('Acceso denegado.');
    }

    // Montar datos
    $results    = wpvulscan_export_build_results_payload(true);
    $score_data = function_exists('wpvulscan_calculate_score')
        ? wpvulscan_calculate_score($results)
        : ['score' => 0, 'riesgo' => ['nivel' => 'N/A', 'color' => '#607d8b']];

    // Generar HTML
    $html = wpvulscan_generate_html_report($results, $score_data);
    if ( ! is_string($html) || $html === '' ) {
        wp_die('No se pudo generar el informe HTML.');
    }

    // Nombre de archivo
    $site     = preg_replace('~https?://~i', '', home_url('/'));
    $site     = trim($site, '/');
    $site     = preg_replace('~[^a-zA-Z0-9\.\-_]+~', '_', $site);
    $datetime = date('Ymd_His');
    $filename = sprintf('wpvulscan_report_%s_%s.html', $site ?: 'site', $datetime);

    // Cabeceras de descarga
    nocache_headers();
    header('Content-Type: text/html; charset=UTF-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('X-Content-Type-Options: nosniff');

    echo $html;
    exit;
});

/**
 * (Opcional) Exportar CSV plano con resumen ejecutivo por secciones.
 * Añade un botón en tu UI si quieres usarlo.
 */
add_action('admin_post_wpvulscan_export_csv', function () {
    if ( ! current_user_can('manage_options') ) {
        wp_die('Acceso denegado.');
    }

    $results    = wpvulscan_export_build_results_payload(true);
    $score_data = function_exists('wpvulscan_calculate_score')
        ? wpvulscan_calculate_score($results)
        : ['score' => 0, 'riesgo' => ['nivel' => 'N/A', 'color' => '#607d8b']];

    $rows = [];
    $rows[] = ['Sección', 'Conteo', 'Detalle breve'];

    // Conteos por sección (resumen simple)
    foreach ($results as $section => $items) {
        $count = is_array($items) ? count($items) : 0;
        $rows[] = [$section, $count, $count > 0 ? 'Ver informe HTML para detalle' : 'Sin incidencias'];
    }

    // Línea con el score
    $rows[] = [];
    $rows[] = ['Puntuación global', (string)($score_data['score'] ?? 0), 'Nivel: ' . ($score_data['riesgo']['nivel'] ?? 'N/A')];

    // Preparar descarga CSV
    $site     = preg_replace('~https?://~i', '', home_url('/'));
    $site     = trim($site, '/');
    $site     = preg_replace('~[^a-zA-Z0-9\.\-_]+~', '_', $site);
    $datetime = date('Ymd_His');
    $filename = sprintf('wpvulscan_summary_%s_%s.csv', $site ?: 'site', $datetime);

    nocache_headers();
    header('Content-Type: text/csv; charset=UTF-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('X-Content-Type-Options: nosniff');

    // Salida con BOM UTF-8 para Excel
    echo "\xEF\xBB\xBF";
    $out = fopen('php://output', 'w');
    foreach ($rows as $r) {
        fputcsv($out, $r, ';');
    }
    fclose($out);
    exit;
});
