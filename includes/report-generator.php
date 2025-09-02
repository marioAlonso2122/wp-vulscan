<?php
if (!defined('ABSPATH')) exit;

/**
 * Genera el informe HTML con resultados y nivel de riesgo.
 *
 * @param array $results Resultados del análisis clasificados por sección.
 * @param array $score_data Resultado del cálculo de puntuación global.
 * @return string HTML completo del informe.
 */
function wpvulscan_generate_html_report($results = [], $score_data = []) {
    $html  = "<!DOCTYPE html><html><head><meta charset='UTF-8'>";
    $html .= "<title>Informe de Seguridad - WP-VulScan</title>";
    $html .= "<style>
        body { font-family: Arial, sans-serif; margin: 30px; }
        h1, h2 { color: #1e88e5; }
        .section { margin-bottom: 30px; }
        .critical { color: red; }
        .warning { color: orange; }
        .ok { color: green; }
        .badge { display: inline-block; padding: 6px 12px; border-radius: 6px; font-weight: bold; }
        .green { background-color: #c8e6c9; color: #2e7d32; }
        .orange { background-color: #ffe0b2; color: #ef6c00; }
        .red { background-color: #ffcdd2; color: #c62828; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
    </style></head><body>";

    $html .= "<h1>Informe de Seguridad - WP-VulScan</h1>";
    $html .= "<p><strong>Fecha:</strong> " . date('Y-m-d H:i:s') . "</p>";

    if (!empty($score_data)) {
        $nivel = esc_html($score_data['riesgo']['nivel']);
        $color = esc_html($score_data['riesgo']['color']);
        $puntuacion = esc_html($score_data['score']);

        $html .= "<p><strong>Evaluación Global:</strong> ";
        $html .= "<span class='badge $color'>Nivel: $nivel – Puntuación: $puntuacion</span></p>";
    }

    foreach ($results as $section => $items) {
        $html .= "<div class='section'><h2>$section</h2>";
        if (is_array($items) && count($items) > 0) {
            $html .= "<ul>";
            foreach ($items as $item) {
                $html .= "<li>" . esc_html($item) . "</li>";
            }
            $html .= "</ul>";
        } else {
            $html .= "<p class='ok'>Sin problemas detectados.</p>";
        }
        $html .= "</div>";
    }

    $html .= "</body></html>";
    return $html;
}
