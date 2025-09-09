<?php
defined('ABSPATH') or die('Acceso no permitido.');

/**
 * Reset de incidencias externas.
 */
function wpvulscan_reset_external_issues() {
    update_option('wpvulscan_external_url_issues', [], false);
}

/**
 * Añade una incidencia externa (formato string para ser listado en admin-menu.php).
 * Ej: "https://sitio.com — Falta HSTS"
 */
function wpvulscan_add_external_issue($message) {
    $issues = get_option('wpvulscan_external_url_issues', []);
    $issues[] = $message;
    update_option('wpvulscan_external_url_issues', $issues, false);
}

/**
 * Normaliza URL: añade https:// si falta esquema.
 */
function wpvulscan_normalize_url($url) {
    $url = trim($url);
    if ($url === '') return '';
    if (!preg_match('#^https?://#i', $url)) {
        $url = 'https://' . ltrim($url, '/');
    }
    return esc_url_raw($url);
}

/**
 * Solicitud HTTP con HEAD y fallback a GET (para obtener body y cabeceras).
 */
function wpvulscan_request_url($url, $timeout = 10) {
    $args = [
        'timeout'     => $timeout,
        'redirection' => 3,
        'sslverify'   => false,
        'headers'     => ['User-Agent' => 'WP-VulScan/1.0'],
        'method'      => 'HEAD',
    ];
    $resp = wp_remote_request($url, $args);

    if (is_wp_error($resp)) {
        return $resp;
    }

    $code = (int) wp_remote_retrieve_response_code($resp);

    // Fallback a GET si HEAD no es aceptado / útil
    if (in_array($code, [0, 400, 405], true)) {
        $args['method'] = 'GET';
        $resp = wp_remote_request($url, $args);
    }

    return $resp;
}

/**
 * Convierte cabeceras de WP a array lowercase.
 */
function wpvulscan_headers_to_array($headers) {
    if (is_object($headers) && method_exists($headers, 'getAll')) {
        $headers = $headers->getAll();
    }
    if (!is_array($headers)) {
        $headers = [];
    }
    $lower = [];
    foreach ($headers as $k => $v) {
        $lower[strtolower($k)] = is_array($v) ? implode(', ', $v) : $v;
    }
    return $lower;
}

/**
 * Analiza una URL buscando:
 * - uso de HTTPS
 * - cabeceras HSTS, X-Frame-Options, Content-Security-Policy
 * - formularios inseguros (action http:// o página en http)
 * Devuelve array ['url'=>..., 'issues'=>[...]] con mensajes en castellano.
 */
function wpvulscan_analyze_url($raw_url) {
    $url = wpvulscan_normalize_url($raw_url);
    $issues = [];

    if ($url === '') {
        return ['url' => $raw_url, 'issues' => ['URL vacía o inválida']];
    }

    $parts = wp_parse_url($url);
    $is_https = isset($parts['scheme']) && strtolower($parts['scheme']) === 'https';

    if (!$is_https) {
        $issues[] = 'Página servida sobre HTTP (sin HTTPS)';
    }

    $resp = wpvulscan_request_url($url, 10);
    if (is_wp_error($resp)) {
        $issues[] = 'Error de conexión: ' . $resp->get_error_message();
        return ['url' => $url, 'issues' => $issues];
    }

    $code    = (int) wp_remote_retrieve_response_code($resp);
    $headers = wpvulscan_headers_to_array(wp_remote_retrieve_headers($resp));
    $body    = wp_remote_retrieve_body($resp);
    $ctype   = isset($headers['content-type']) ? strtolower($headers['content-type']) : '';

    // Cabeceras de seguridad (solo sentido completo en HTTPS)
    if ($is_https) {
        if (empty($headers['strict-transport-security'])) {
            $issues[] = 'Falta cabecera Strict-Transport-Security (HSTS)';
        }
    }

    if (empty($headers['x-frame-options'])) {
        $issues[] = 'Falta cabecera X-Frame-Options';
    }
    if (empty($headers['content-security-policy'])) {
        $issues[] = 'Falta cabecera Content-Security-Policy';
    }

    // Formularios inseguros: si es HTML, buscar <form> y su action
    if ($code >= 200 && $code < 400 && is_string($body) && stripos($ctype, 'text/html') !== false) {
        if (preg_match_all('/<form\b[^>]*>/i', $body, $forms)) {
            foreach ($forms[0] as $formTag) {
                $action = '';
                if (preg_match('/action\s*=\s*["\']([^"\']+)["\']/i', $formTag, $m)) {
                    $action = trim($m[1]);
                }
                // Si la página es HTTP, cualquier formulario ya es problemático.
                if (!$is_https) {
                    $issues[] = 'Formulario sobre página HTTP (riesgo de intercepción)';
                }
                // Si el action es absoluto http://
                if ($action !== '' && preg_match('#^http://#i', $action)) {
                    $issues[] = 'Formulario con action sobre HTTP (' . $action . ')';
                }
                // Si el action es relativo y la página es HTTPS -> OK (hereda HTTPS)
                // Si no hay action, los navegadores usan la URL actual (ya cubierta arriba).
            }
        }
    }

    // Resumen si no encontramos nada serio
    if (empty($issues)) {
        $issues[] = 'Sin incidencias destacables';
    }

    return ['url' => $url, 'issues' => $issues];
}

/**
 * Formulario para introducir URLs externas (una por línea).
 * - Guarda en wpvulscan_external_urls
 * - Lanza el escaneo inmediatamente y persiste resultados en wpvulscan_external_url_issues
 */
function wp_vulscan_formulario_urls_usuario() {
    // Guardar
    if (isset($_POST['wpvulscan_external_urls']) && check_admin_referer('wpvulscan_external_urls_action')) {
        $raw = wp_unslash($_POST['wpvulscan_external_urls']);
        // Normaliza saltos y limpia espacios
        $raw = str_replace(["\r\n", "\r"], "\n", $raw);
        $lines = array_filter(array_map('trim', explode("\n", $raw)));
        // Guardamos la lista "texto" tal cual para que el textarea la recuerde
        update_option('wpvulscan_external_urls', implode("\n", $lines), false);

        // Ejecuta escaneo
        wpvulscan_scan_sensitive_urls($lines);

        echo '<div class="notice notice-success is-dismissible"><p>URLs guardadas y analizadas correctamente.</p></div>';
    }

    $saved = get_option('wpvulscan_external_urls', '');

    echo '<h2>Escaneo de URLs proporcionadas por el usuario</h2>';
    echo '<p>Introduce una URL por línea. Se evaluará el uso de HTTPS, cabeceras de seguridad y formularios inseguros.</p>';
    echo '<form method="post">';
    wp_nonce_field('wpvulscan_external_urls_action');
    echo '<textarea name="wpvulscan_external_urls" rows="5" cols="80" placeholder="https://ejemplo.com/panel">' . esc_textarea($saved) . '</textarea><br>';
    echo '<button type="submit" class="button button-secondary">Guardar y escanear</button>';
    echo '</form>';
}

/**
 * Ejecuta el escaneo usando la lista guardada en wpvulscan_external_urls,
 * o con el array pasado como parámetro (una vez).
 */
function wpvulscan_scan_sensitive_urls($urls = null) {
    if ($urls === null) {
        $saved = get_option('wpvulscan_external_urls', '');
        $urls = array_filter(array_map('trim', preg_split('/\R+/', (string) $saved)));
    }
    if (empty($urls)) {
        // No URLs -> limpia incidencias
        wpvulscan_reset_external_issues();
        return;
    }

    wpvulscan_reset_external_issues();

    foreach ($urls as $raw) {
        $res = wpvulscan_analyze_url($raw);
        foreach ($res['issues'] as $msg) {
            // Formato simple para tu admin-menu actual:
            wpvulscan_add_external_issue($res['url'] . ' — ' . $msg);
        }
    }
}
