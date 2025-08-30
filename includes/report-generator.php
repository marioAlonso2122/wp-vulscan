<?php
if (!defined('ABSPATH')) exit;

function wpvulscan_generate_html_report($results = []) {
    $html  = "<!DOCTYPE html><html><head><meta charset='UTF-8'>";
    $html .= "<title>Informe de Seguridad - WP-VulScan</title>";
    $html .= "<style>
        body { font-family: Arial, sans-serif; margin: 30px; }
        h1, h2 { color: #1e88e5; }
        .section { margin-bottom: 30px; }
        .critical { color: red; }
        .warning { color: orange; }
        .ok { color: green; }
        table { width: 100%; border-collapse: collapse; }
        th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
    </style></head><body>";

    $html .= "<h1>Informe de Seguridad - WP-VulScan</h1>";
    $html .= "<p><strong>Fecha:</strong> " . date('Y-m-d H:i:s') . "</p>";

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
