<?php
/**
 * Análisis de formularios remotos (externos)
 * - Módulo para administrar URLs, descargar HTML y auditar <form>:
 *   * Presencia de token CSRF (nonce/csrf/_token/authenticity_token)
 *   * Uso de HTTPS en action (o en la propia URL base si action vacío/relativo)
 *   * Sensibilidad por campos: password / file
 * - Persiste los hallazgos en 'wpvulscan_form_issues'
 */

defined('ABSPATH') or die('Acceso no permitido.');

/** =========================
 *  UTILIDADES
 *  ========================= */

/** Normaliza una URL y asegura esquema (por defecto https://). */
function wpvulscan_norm_url($url) {
    $url = trim((string)$url);
    if ($url === '') return '';
    if (!preg_match('#^https?://#i', $url)) {
        $url = 'https://' . ltrim($url, '/');
    }
    return esc_url_raw($url);
}

/** Resuelve una action relativa contra la URL base (muy básico, suficiente para informes). */
function wpvulscan_resolve_action_url($base, $action) {
    $action = trim((string)$action);
    if ($action === '') return $base; // navegador usa URL actual
    // Absoluta
    if (preg_match('#^https?://#i', $action)) return $action;
    // Protocolo relativo //host/...
    if (strpos($action, '//') === 0) {
        $base_parts = wp_parse_url($base);
        $scheme = isset($base_parts['scheme']) ? $base_parts['scheme'] : 'https';
        return $scheme . ':' . $action;
    }
    // Relativa
    $base_parts = wp_parse_url($base);
    if (!$base_parts || empty($base_parts['scheme']) || empty($base_parts['host'])) {
        return $action;
    }
    $scheme = $base_parts['scheme'];
    $host   = $base_parts['host'];
    $port   = isset($base_parts['port']) ? ':' . $base_parts['port'] : '';
    $path   = isset($base_parts['path']) ? $base_parts['path'] : '/';
    // directorio base
    if (substr($path, -1) !== '/') {
        $path = substr($path, 0, strrpos($path, '/') + 1);
    }
    if (substr($action, 0, 1) === '/') {
        $path = '';
    }
    return $scheme . '://' . $host . $port . $path . ltrim($action, '/');
}

/** Descarga HTML con GET. */
function wpvulscan_fetch_html($url, $timeout = 12) {
    $resp = wp_remote_get($url, [
        'timeout'     => $timeout,
        'redirection' => 3,
        'sslverify'   => false,
        'headers'     => ['User-Agent' => 'WP-VulScan/1.0 (+forms)'],
    ]);
    if (is_wp_error($resp)) return $resp;

    $code = (int) wp_remote_retrieve_response_code($resp);
    $ct   = strtolower((string) wp_remote_retrieve_header($resp, 'content-type'));
    $body = wp_remote_retrieve_body($resp);
    return compact('code','ct','body');
}

/** Heurística de detección de CSRF token en un <form>. */
function wpvulscan_form_has_csrf_token(DOMElement $form) {
    $keys = ['_wpnonce','nonce','csrf','xsrf','_token','authenticity_token'];
    foreach ($form->getElementsByTagName('input') as $input) {
        $type = strtolower($input->getAttribute('type'));
        if ($type !== 'hidden' && $type !== '') continue;
        $name = strtolower((string)$input->getAttribute('name'));
        $id   = strtolower((string)$input->getAttribute('id'));
        foreach ($keys as $k) {
            if ($name !== '' && strpos($name, $k) !== false) return true;
            if ($id   !== '' && strpos($id,   $k) !== false) return true;
        }
    }
    // también se ve a veces en meta
    $metas = $form->getElementsByTagName('meta');
    foreach ($metas as $m) {
        $n = strtolower((string)$m->getAttribute('name'));
        if (in_array($n, ['csrf-token','csrf'], true)) return true;
    }
    return false;
}

/** Señales de sensibilidad: password o upload de ficheros. */
function wpvulscan_form_sensitivity(DOMElement $form) {
    $has_pwd = false;
    $has_file = false;

    foreach ($form->getElementsByTagName('input') as $input) {
        $type = strtolower($input->getAttribute('type'));
        if ($type === 'password') $has_pwd = true;
        if ($type === 'file')     $has_file = true;
    }
    // enctype multipart también indica subida de archivos
    $enctype = strtolower($form->getAttribute('enctype'));
    if (strpos($enctype, 'multipart/form-data') !== false) $has_file = true;

    return [$has_pwd, $has_file];
}

/** Severidad heurística. */
function wpvulscan_severity_label($https_ok, $has_csrf, $has_pwd, $has_file) {
    if (!$https_ok && ($has_pwd || $has_file)) return 'Critical';
    if (!$https_ok)                             return 'High';
    if ($https_ok && !$has_csrf)               return 'Medium';
    return 'Low';
}

/** =========================
 *  UI / HANDLERS
 *  ========================= */

/**
 * Render de la sección en el Admin.
 * Mantiene tu firma pública: wp_vulscan_formulario_urls_usuario()
 */
function wp_vulscan_formulario_urls_usuario() {
    if (!current_user_can('manage_options')) return;

    if (isset($_POST['wp_vulscan_analizar_formularios_remotos'])) {
        wp_vulscan_analizar_formularios_remotos();
        echo '<hr>';
    }
    ?>
    <h2>Análisis de formularios externos</h2>
    <form method="post">
        <?php wp_nonce_field('wpvulscan_forms_action'); ?>
        <label for="wp_vulscan_urls"><strong>Introduce una o varias URLs (una por línea):</strong></label><br>
        <textarea name="wp_vulscan_urls" rows="6" style="width:100%;"><?php
            echo esc_textarea(isset($_POST['wp_vulscan_urls']) ? wp_unslash($_POST['wp_vulscan_urls']) : '');
        ?></textarea><br><br>
        <input type="submit"
               name="wp_vulscan_analizar_formularios_remotos"
               class="button button-primary"
               value="Analizar formularios">
    </form>
    <?php
}

/**
 * Procesa el POST, muestra resultados y persiste en 'wpvulscan_form_issues'
 */
function wp_vulscan_analizar_formularios_remotos() {
    if (!current_user_can('manage_options')) wp_die('Acceso denegado.');
    check_admin_referer('wpvulscan_forms_action');

    // Normalización de URLs
    $urls_raw = isset($_POST['wp_vulscan_urls']) ? (string) wp_unslash($_POST['wp_vulscan_urls']) : '';
    $urls_raw = trim($urls_raw);
    if ($urls_raw === '') {
        echo '<p style="color:red;">No se han proporcionado URLs para analizar.</p>';
        return;
    }
    $lines = preg_split('/\R+/', $urls_raw);
    $urls  = [];
    foreach ($lines as $u) {
        $nu = wpvulscan_norm_url($u);
        if ($nu !== '' && filter_var($nu, FILTER_VALIDATE_URL)) $urls[] = $nu;
    }
    $urls = array_unique($urls);
    if (empty($urls)) {
        echo '<p style="color:red;">Las URLs proporcionadas no son válidas.</p>';
        return;
    }

    $persist = []; // estructura que guardaremos en la opción
    $errores = [];

    foreach ($urls as $url) {
        $resp = wpvulscan_fetch_html($url, 12);
        if (is_wp_error($resp)) {
            $errores[] = ['url' => $url, 'error' => 'Error al acceder: ' . $resp->get_error_message()];
            continue;
        }
        $code = $resp['code'];
        $ct   = $resp['ct'];
        $body = $resp['body'];

        if ($code < 200 || $code >= 400) {
            $errores[] = ['url' => $url, 'error' => 'Código HTTP no exitoso: ' . $code];
            continue;
        }
        if (stripos($ct, 'text/html') === false) {
            $errores[] = ['url' => $url, 'error' => 'Contenido no HTML: ' . $ct];
            continue;
        }

        // Parse HTML con DOMDocument
        libxml_use_internal_errors(true);
        $dom = new DOMDocument();
        $loaded = $dom->loadHTML(mb_convert_encoding($body, 'HTML-ENTITIES', 'UTF-8'));
        if (!$loaded) {
            $errores[] = ['url' => $url, 'error' => 'No se pudo analizar el contenido HTML.'];
            continue;
        }

        $forms = $dom->getElementsByTagName('form');
        if ($forms->length === 0) {
            $errores[] = ['url' => $url, 'error' => 'No se encontraron formularios.'];
            continue;
        }

        echo '<h3>Formulario(s) detectado(s) en: ' . esc_html($url) . '</h3>';
        echo '<table class="widefat fixed striped">';
        echo '<thead><tr>'
            . '<th>Método</th>'
            . '<th>CSRF</th>'
            . '<th>HTTPS</th>'
            . '<th>Sensible</th>'
            . '<th>Severidad</th>'
            . '<th>Action</th>'
            . '</tr></thead><tbody>';

        $persist_url = [
            'url'   => $url,
            'code'  => $code,
            'forms' => [],
        ];

        foreach ($forms as $idx => $form) {
            $method = strtoupper($form->getAttribute('method') ?: 'GET');
            $action_raw = $form->getAttribute('action') ?: '';
            $action_resolved = wpvulscan_resolve_action_url($url, $action_raw);

            $has_csrf = wpvulscan_form_has_csrf_token($form);
            list($has_pwd, $has_file) = wpvulscan_form_sensitivity($form);

            // HTTPS OK si action final es https://
            $https_ok = (stripos($action_resolved, 'https://') === 0);
            if (function_exists('wpvulscan_insert_finding_with_rule')) {
                // Falta CSRF token
                if (!$has_csrf) {
                    wpvulscan_insert_finding_with_rule('rule_csrf_nonce_missing', [
                        'path'      => $url, // página auditada
                        'function_name' => 'FORM#' . $idx,
                        'sample_payload' => $action_resolved,
                        // opcional: 'trace' => ['method'=>$method,'action'=>$action_resolved]
                    ]);
                }
                // Action HTTP o página sin HTTPS
                if (!$https_ok) {
                    wpvulscan_insert_finding_with_rule('rule_form_https_missing', [
                        'path'      => $action_resolved,
                        'function_name' => 'FORM#' . $idx,
                        'sample_payload' => $action_raw ?: '(vacío)'
                    ]);
                }
            }
            $severity = wpvulscan_severity_label($https_ok, $has_csrf, $has_pwd, $has_file);
            $sensible = ($has_pwd || $has_file) ? 'Sí' : 'No';

            // Persistimos por formulario
            $persist_url['forms'][] = [
                'index'          => $idx,
                'method'         => $method,
                'action_raw'     => $action_raw !== '' ? $action_raw : '(vacío)',
                'action_resolved'=> $action_resolved,
                'https'          => $https_ok,
                'csrf'           => $has_csrf,
                'sensitive'      => ['password' => $has_pwd, 'file' => $has_file],
                'severity'       => $severity,
            ];

            // Render
            echo '<tr>';
            echo '<td>' . esc_html($method) . '</td>';
            echo '<td>' . ($has_csrf ? '<span style="color:green;">Sí</span>' : '<span style="color:#d9822b;">No</span>') . '</td>';
            echo '<td>' . ($https_ok ? '<span style="color:green;">Sí</span>' : '<span style="color:red;">No</span>') . '</td>';
            echo '<td>' . ($sensible === 'Sí' ? '<strong>Sí</strong>' : 'No') . '</td>';
            $sev_color = ($severity === 'Critical') ? 'red' : (($severity === 'High') ? '#e86a2f' : (($severity === 'Medium') ? '#d9822b' : 'green'));
            echo '<td><strong style="color:' . esc_attr($sev_color) . ';">' . esc_html($severity) . '</strong></td>';
            echo '<td>' . esc_html($action_raw !== '' ? $action_raw : '(vacío)') . '<br><small>' . esc_html($action_resolved) . '</small></td>';
            echo '</tr>';
        }

        echo '</tbody></table><br>';

        $persist[] = $persist_url;
    }

    if (!empty($errores)) {
        echo '<h3>Errores encontrados:</h3><ul>';
        foreach ($errores as $e) {
            echo '<li><strong>' . esc_html($e['url']) . ':</strong> ' . esc_html($e['error']) . '</li>';
        }
        echo '</ul>';
    }

    // Persiste estructura completa para informes/histórico
    update_option('wpvulscan_form_issues', $persist, false);
}
