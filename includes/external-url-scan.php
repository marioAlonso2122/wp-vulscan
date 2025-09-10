<?php
defined('ABSPATH') or die('Acceso no permitido.');

/**
 * Rutas sensibles externas a comprobar sobre la URL base del sitio.
 * Ajusta/añade según tus necesidades.
 */
if ( ! function_exists('wpvulscan_get_sensitive_external_paths') ) {
    function wpvulscan_get_sensitive_external_paths() {
        return [
            'readme.html',
            'xmlrpc.php',
            'wp-admin/install.php',
            'wp-content/debug.log',
            '.env',
            'backup.zip',
            'backup.sql',
        ];
    }
}

/**
 * Hace HEAD (fallback a GET si procede) y persiste hallazgos en la opción
 * 'wpvulscan_external_url_issues' como lista de strings.
 */
if ( ! function_exists('wpvulscan_scan_sensitive_urls') ) {
    function wpvulscan_scan_sensitive_urls() {
        $base    = trailingslashit( site_url('/') );
        $paths   = wpvulscan_get_sensitive_external_paths();
        $issues  = [];

        foreach ($paths as $p) {
            $url  = $base . ltrim($p, '/');
            $args = [
                'timeout'     => 6,
                'redirection' => 2,
                'sslverify'   => false,
                'method'      => 'HEAD',
                'headers'     => ['User-Agent' => 'WP-VulScan/1.0 (+external-scan)'],
            ];
            $resp = wp_remote_request($url, $args);
            if (is_wp_error($resp)) {
                continue;
            }

            $code = (int) wp_remote_retrieve_response_code($resp);
            if (in_array($code, [0, 400, 405], true)) {
                $args['method'] = 'GET';
                $resp = wp_remote_request($url, $args);
                if (is_wp_error($resp)) {
                    continue;
                }
                $code = (int) wp_remote_retrieve_response_code($resp);
            }

            if ($code === 200) {
                $issues[] = sprintf('%s — accesible (HTTP %d)', $url, $code);
            }
        }

        update_option('wpvulscan_external_url_issues', $issues, false);
    }
}

/**
 * (Opcional) Pequeño widget para pintar resultados en el panel.
 * Si ya lo sacas en admin-menu.php, puedes omitirlo.
 */
if ( ! function_exists('wpvulscan_render_sensitive_urls_widget') ) {
    function wpvulscan_render_sensitive_urls_widget() {
        echo '<h2>Escaneo de rutas externas sensibles</h2>';
        $external_issues = (array) get_option('wpvulscan_external_url_issues', []);
        if (empty($external_issues)) {
            echo "<p class='ok'>No se han detectado rutas externas expuestas.</p>";
            return;
        }
        echo '<ul>';
        foreach ($external_issues as $issue) {
            echo '<li>' . esc_html($issue) . '</li>';
        }
        echo '</ul>';
    }
}
