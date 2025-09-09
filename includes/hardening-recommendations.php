<?php
defined('ABSPATH') or die('Acceso no permitido.');

/** =========================
 *  Acumulador de incidencias
 *  ========================= */
function wpvulscan_reset_hardening_issues() {
    update_option('wpvulscan_hardening_issues', [], false);
}
function wpvulscan_add_hardening_issue($type, $severity, $message, $recommendation = '', $meta = []) {
    $issues   = get_option('wpvulscan_hardening_issues', []);
    $issues[] = [
        'type'           => $type,         // p.ej. 'headers','config','files'
        'severity'       => $severity,     // 'critical'|'high'|'medium'|'low'|'info'
        'message'        => $message,
        'recommendation' => $recommendation,
        'meta'           => $meta,
        'time'           => current_time('mysql'),
    ];
    update_option('wpvulscan_hardening_issues', $issues, false);
}

/** =========================
 *  Utilidades
 *  ========================= */

/** HEAD con fallback a GET para obtener cabeceras del front. */
function wpvulscan_request_head_or_get($url, $timeout = 8) {
    $args = [
        'timeout'     => $timeout,
        'redirection' => 3,
        'sslverify'   => false,
        'headers'     => ['User-Agent' => 'WP-VulScan/1.0 (+hardening)'],
        'method'      => 'HEAD',
    ];
    $resp = wp_remote_request($url, $args);
    if (is_wp_error($resp)) return $resp;

    $code = (int) wp_remote_retrieve_response_code($resp);
    if (in_array($code, [0, 400, 405], true)) {
        $args['method'] = 'GET';
        $resp = wp_remote_request($url, $args);
    }
    return $resp;
}
function wpvulscan_headers_array($headers) {
    if (is_object($headers) && method_exists($headers, 'getAll')) $headers = $headers->getAll();
    if (!is_array($headers)) $headers = [];
    $out = [];
    foreach ($headers as $k => $v) {
        $out[strtolower($k)] = is_array($v) ? implode(', ', $v) : $v;
    }
    return $out;
}

/** =========================
 *  Chequeos de hardening
 *  ========================= */
function wpvulscan_collect_hardening_findings() {
    wpvulscan_reset_hardening_issues();

    // 1) HTTPS forzado (home y siteurl)
    $home    = get_option('home');
    $siteurl = get_option('siteurl');
    $home_https    = (stripos($home, 'https://') === 0);
    $siteurl_https = (stripos($siteurl, 'https://') === 0);

    if (!$home_https || !$siteurl_https) {
        wpvulscan_add_hardening_issue(
            'config', 'high',
            'El sitio no está configurado para usar HTTPS en home/siteurl.',
            'Actualiza Ajustes > Generales para que la URL del sitio y de WordPress comiencen por https:// y configura redirecciones 301 a HTTPS.'
        );
    }

    // 2) Constantes sensibles: WP_DEBUG y DISALLOW_FILE_EDIT
    if (defined('WP_DEBUG') && WP_DEBUG) {
        wpvulscan_add_hardening_issue(
            'config','medium',
            'WP_DEBUG está habilitado en producción.',
            'Deshabilita WP_DEBUG en entornos productivos para evitar fugas de información.'
        );
    }
    if (!defined('DISALLOW_FILE_EDIT') || !DISALLOW_FILE_EDIT) {
        wpvulscan_add_hardening_issue(
            'config','medium',
            'Edición de archivos desde el panel habilitada.',
            "En wp-config.php define: define('DISALLOW_FILE_EDIT', true);"
        );
    }

    // 3) Claves y sales de autenticación
    $keys = ['AUTH_KEY','SECURE_AUTH_KEY','LOGGED_IN_KEY','NONCE_KEY','AUTH_SALT','SECURE_AUTH_SALT','LOGGED_IN_SALT','NONCE_SALT'];
    foreach ($keys as $k) {
        if (!defined($k)) {
            wpvulscan_add_hardening_issue('config','medium',"Constante $k no definida.", 'Regenera claves y sales en wp-config.php usando https://api.wordpress.org/secret-key/1.1/salt/.');
        } else {
            $val = constant($k);
            if (stripos($val, 'put your unique phrase here') !== false || strlen($val) < 32) {
                wpvulscan_add_hardening_issue('config','high',"Clave/sal $k débil o por defecto.", 'Regenera claves y sales únicas y aleatorias en wp-config.php.');
            }
        }
    }

    // 4) Archivos y presencia de ficheros sensibles
    // xmlrpc.php (presente ≠ activo, pero la presencia + respuesta suele bastar como señal)
    if (file_exists(ABSPATH . 'xmlrpc.php')) {
        wpvulscan_add_hardening_issue(
            'files','low',
            'xmlrpc.php presente en la raíz.',
            'Si no usas apps externas o Jetpack, deshabilita XML-RPC o limita su acceso.'
        );
    }
    if (file_exists(ABSPATH . 'readme.html')) {
        wpvulscan_add_hardening_issue(
            'files','medium',
            'readme.html presente (posible divulgación de versión).',
            'Elimina readme.html o bloquea su acceso desde el servidor web.'
        );
    }
    if (!file_exists(ABSPATH . 'index.php')) {
        wpvulscan_add_hardening_issue(
            'files','medium',
            'Falta index.php en la raíz del sitio.',
            'Asegúrate de que existe para evitar listado de directorios.'
        );
    }
    // .htaccess (esta recomendación aplica sobre todo a Apache)
    $is_apache = isset($_SERVER['SERVER_SOFTWARE']) && stripos($_SERVER['SERVER_SOFTWARE'], 'apache') !== false;
    if ($is_apache && !file_exists(ABSPATH . '.htaccess')) {
        wpvulscan_add_hardening_issue(
            'files','low',
            'Falta .htaccess (entorno Apache).',
            'Configura .htaccess para desactivar directory listing y reforzar reglas de acceso.'
        );
    }

    // 5) Permisos de wp-config.php
    $wp_config = ABSPATH . 'wp-config.php';
    if (file_exists($wp_config)) {
        $perms = substr(sprintf('%o', @fileperms($wp_config)), -3);
        if (!in_array($perms, ['600','640','644'], true)) {
            wpvulscan_add_hardening_issue(
                'files','high',
                "Permisos de wp-config.php no recomendados ($perms).",
                'Ajusta permisos a 640 o 600 según tu hosting para minimizar lecturas no autorizadas.'
            );
        }
    }

    // 6) Cabeceras de seguridad en la página de inicio
    $front_url = trailingslashit(home_url('/'));
    $resp      = wpvulscan_request_head_or_get($front_url, 8);
    if (!is_wp_error($resp)) {
        $headers  = wpvulscan_headers_array(wp_remote_retrieve_headers($resp));
        $is_https = (stripos($front_url, 'https://') === 0);

        $want = [
            'strict-transport-security' => ['when_https' => true,  'sev' => 'high',   'msg' => 'Falta HSTS (Strict-Transport-Security).', 'rec' => "Añade 'Strict-Transport-Security: max-age=31536000; includeSubDomains' en HTTPS."],
            'x-frame-options'           => ['when_https' => false, 'sev' => 'medium', 'msg' => 'Falta X-Frame-Options.',                  'rec' => "Añade 'X-Frame-Options: SAMEORIGIN' para mitigar clickjacking."],
            'content-security-policy'   => ['when_https' => false, 'sev' => 'medium', 'msg' => 'Falta Content-Security-Policy (CSP).',     'rec' => "Define una CSP estricta, p. ej. 'default-src \'self\'' y ajusta según tus recursos."],
            'x-content-type-options'    => ['when_https' => false, 'sev' => 'low',    'msg' => 'Falta X-Content-Type-Options.',           'rec' => "Añade 'X-Content-Type-Options: nosniff'."],
            'referrer-policy'           => ['when_https' => false, 'sev' => 'low',    'msg' => 'Falta Referrer-Policy.',                  'rec' => "Añade 'Referrer-Policy: no-referrer-when-downgrade' (o más restrictiva)."],
            // (opcional) 'permissions-policy' => ['when_https' => false, 'sev' => 'low', 'msg'=>'Falta Permissions-Policy.', 'rec'=>"Limita APIs del navegador (p.ej. 'camera=()')"]
        ];

        $missing = [];
        foreach ($want as $h => $spec) {
            if ($spec['when_https'] && !$is_https) {
                continue; // HSTS solo aplica si sirves en HTTPS
            }
            if (empty($headers[$h])) {
                // registrar recomendación en tabla
                wpvulscan_add_hardening_issue('headers', $spec['sev'], $spec['msg'], $spec['rec']);
                // acumular faltantes para el finding normalizado
                $missing[] = $h;
            }
        }

        if (!empty($missing) && function_exists('wpvulscan_insert_finding_with_rule')) {
            wpvulscan_insert_finding_with_rule('rule_insecure_headers', [
                'path'           => $front_url,
                'sample_payload' => implode(', ', $missing),
                'trace'          => ['missing' => $missing],
            ]);
        }
    } else {
        wpvulscan_add_hardening_issue(
            'headers','info',
            'No se pudo obtener cabeceras del front.',
            'Revisa conectividad del servidor y firewalls si persiste el problema.',
            ['error' => $resp->get_error_message()]
        );
    }

}

/** =========================
 *  Render en el panel
 *  ========================= */
function wp_vulscan_mostrar_recomendaciones_hardening() {
    // Ejecuta/actualiza hallazgos
    wpvulscan_collect_hardening_findings();

    $issues = get_option('wpvulscan_hardening_issues', []);
    echo '<h2>Recomendaciones de Hardening</h2>';

    if (empty($issues)) {
        echo '<p style="color:green;"><strong>Sin recomendaciones pendientes. Configuración robusta detectada.</strong></p>';
        return;
    }

    echo '<table class="widefat fixed striped">';
    echo '<thead><tr>'
        . '<th>Sección</th>'
        . '<th>Severidad</th>'
        . '<th>Hallazgo</th>'
        . '<th>Recomendación</th>'
        . '</tr></thead><tbody>';

    foreach ($issues as $i) {
        $sev = strtolower($i['severity']);
        $color = ($sev === 'critical') ? 'red' : (($sev === 'high') ? '#e86a2f' : (($sev === 'medium') ? '#d9822b' : ($sev === 'low' ? 'green' : '#607d8b')));
        echo '<tr>';
        echo '<td>' . esc_html(ucfirst($i['type'])) . '</td>';
        echo '<td><strong style="color:' . esc_attr($color) . ';">' . esc_html(ucfirst($i['severity'])) . '</strong></td>';
        echo '<td>' . esc_html($i['message']) . '</td>';
        echo '<td>' . esc_html($i['recommendation']) . '</td>';
        echo '</tr>';
    }

    echo '</tbody></table>';
    echo '<p><em>Nota:</em> Los hallazgos se han almacenado en <code>wpvulscan_hardening_issues</code> para su uso en el historial e informes.</p>';
}
