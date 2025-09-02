<?php
if (!defined('ABSPATH')) exit;

require_once ABSPATH . 'wp-admin/includes/plugin.php';

/**
 * Escanea los plugins instalados usando la API de WPScan.
 */
function wpvulscan_check_plugins_vulnerables() {
    if (!defined('WPVULSCAN_WPSCAN_API_KEY') || empty(WPVULSCAN_WPSCAN_API_KEY)) {
        return ['No se ha configurado la API Key de WPScan.'];
    }

    $plugins = get_plugins();
    $resultados = [];

    foreach ($plugins as $path => $plugin_data) {
        $plugin_slug = dirname($path);
        $plugin_version = $plugin_data['Version'];

        $api_url = "https://wpscan.com/api/v3/plugins/" . urlencode($plugin_slug);
        $response = wp_remote_get($api_url, [
            'headers' => [
                'Authorization' => 'Token token=' . $api_key
            ],
            'timeout' => 15
        ]);

        if (is_wp_error($response)) {
            $resultados[] = "Error al consultar WPScan para $plugin_slug.";
            continue;
        }

        $body = json_decode(wp_remote_retrieve_body($response), true);

        if (!empty($body['error'])) {
            $resultados[] = "No se encontró información para el plugin $plugin_slug.";
            continue;
        }

        if (!empty($body['vulnerabilities'])) {
            foreach ($body['vulnerabilities'] as $vuln) {
                if (version_compare($plugin_version, $vuln['fixed_in'], '<')) {
                    $resultados[] = "🔴 Plugin <strong>$plugin_slug</strong> v$plugin_version tiene vulnerabilidad: " .
                        esc_html($vuln['title']) . " (CVE: " . esc_html(implode(', ', $vuln['cve'] ?? [])) . ").";
                }
            }
        }
    }

    update_option('wpvulscan_plugin_vulns', $resultados);
    return $resultados;
}
