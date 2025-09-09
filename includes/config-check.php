<?php
defined('ABSPATH') or die('Acceso no permitido.');

/**
 * Acumulador de incidencias de configuración
 */
function wpvulscan_reset_config_issues() {
    update_option('wpvulscan_config_issues', [], false);
}
function wpvulscan_add_config_issue($type, $message, $meta = []) {
    $issues = get_option('wpvulscan_config_issues', []);
    $issues[] = [
        'type'    => $type,           // p.ej. 'exposure', 'version_leak', 'backup', 'git', 'xmlrpc'
        'message' => $message,
        'meta'    => $meta,
        'time'    => current_time('mysql'),
    ];
    update_option('wpvulscan_config_issues', $issues, false);
}

/**
 * Lista de rutas sensibles a comprobar desde el sitio base.
 * Puedes añadir más según tu política.
 */
function wp_vulscan_get_sensitive_paths() {
    return [
        'wp-config.php',
        '.env',
        '.git/config',
        'readme.html',
        'xmlrpc.php',
        'wp-admin/install.php',
        'wp-content/debug.log',
        'backup.zip',
        'backup.sql',
    ];
}

/**
 * HEAD con fallback a GET si el servidor no soporta HEAD.
 */
function wpvulscan_head_or_get($url, $timeout = 8) {
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

    $code = wp_remote_retrieve_response_code($resp);

    // Algunos servidores responden 405/400 a HEAD en ficheros; probamos GET
    if (in_array((int)$code, [400, 405], true)) {
        $args['method'] = 'GET';
        $resp = wp_remote_request($url, $args);
    }

    return $resp;
}

/**
 * Devuelve array con rutas inseguras o potencialmente problemáticas.
 * Además, rellena el acumulador wpvulscan_config_issues para el dashboard.
 */
function wp_vulscan_check_sensitive_paths() {
    $site_url = trailingslashit(site_url('/'));
    $paths    = wp_vulscan_get_sensitive_paths();
    $resultados = [];

    foreach ($paths as $path) {
        $url = $site_url . ltrim($path, '/');
        $resp = wpvulscan_head_or_get($url, 8);

        if (is_wp_error($resp)) {
            // Error de conexión: lo ignoramos como "no verificado"
            $resultados[] = [
                'ruta'   => $path,
                'url'    => $url,
                'estado' => 'No verificado',
                'codigo' => '—',
                'nivel'  => 'ok',
            ];
            continue;
        }

        $code = (int) wp_remote_retrieve_response_code($resp);
        $body = wp_remote_retrieve_body($resp);
        $estado = 'No accesible';
        $nivel  = 'ok';

        // Clasificación de riesgo según ruta y código
        switch ($path) {
            case 'wp-config.php':
            case '.env':
            case '.git/config':
            case 'backup.zip':
            case 'backup.sql':
            case 'wp-content/debug.log':
                // 200/206 es crítico (expuesto). 301/302 podría acabar en 200 tras redirección.
                if (in_array($code, [200, 206], true)) {
                    $estado = 'Accesible';
                    $nivel  = 'critico';

                    $type = 'exposure';
                    if ($path === '.git/config')   $type = 'git';
                    if ($path === 'backup.zip' || $path === 'backup.sql') $type = 'backup';

                    wpvulscan_add_config_issue($type, "Recurso sensible expuesto: {$path}", [
                        'url' => $url, 'code' => $code,
                    ]);
                } elseif (in_array($code, [301,302,307,308], true)) {
                    // Redirección: si tuvieras tiempo podrías seguirla y comprobar el destino final.
                    $estado = 'Redirige';
                    $nivel  = 'advertencia';
                } elseif ($code === 403) {
                    $estado = 'Protegido (403)';
                    $nivel  = 'ok';
                } else {
                    $estado = 'No accesible';
                    $nivel  = 'ok';
                }
                break;

            case 'readme.html':
                // Si está 200, probable divulgación de versión WP
                if ($code === 200) {
                    $estado = 'Accesible (divulgación)';
                    $nivel  = 'advertencia';
                    wpvulscan_add_config_issue('version_leak', 'readme.html accesible (posible divulgación de versión)', [
                        'url' => $url, 'code' => $code
                    ]);

                    // (Opcional) heurística para detectar "Version x.y.z" en el body
                    if (is_string($body) && preg_match('/Version\s+\d+\.\d+(\.\d+)?/i', $body, $m)) {
                        wpvulscan_add_config_issue('version_leak', 'Versión detectada en readme.html', [
                            'url' => $url, 'match' => $m[0]
                        ]);
                    }
                    if (function_exists('wpvulscan_insert_finding_with_rule')) {
                        $match = null;
                        if (is_string($body) && preg_match('/Version\s+\d+\.\d+(?:\.\d+)?/i', $body, $m)) {
                            $match = $m[0];
                        }
                        wpvulscan_insert_finding_with_rule('rule_readme_version_leak', [
                            'path' => $url,
                            'sample_payload' => $match ?: 'readme.html accesible'
                        ]);
                    }
                } elseif ($code === 403) {
                    $estado = 'Protegido (403)';
                    $nivel  = 'ok';
                } else {
                    $estado = 'No accesible';
                    $nivel  = 'ok';
                }
                break;

            case 'xmlrpc.php':
                // Muchos hosts devuelven 405 a GET/HEAD; la mera accesibilidad indica que está habilitado.
                if (in_array($code, [200, 401, 403, 405], true)) {
                    $estado = 'Presente';
                    $nivel  = 'advertencia';
                    wpvulscan_add_config_issue('xmlrpc', 'xmlrpc.php habilitado/presente', [
                        'url' => $url, 'code' => $code
                    ]);
                } else {
                    $estado = 'No accesible';
                    $nivel  = 'ok';
                }
                break;

            case 'wp-admin/install.php':
                if ($code === 200) {
                    $estado = 'Accesible';
                    $nivel  = 'advertencia';
                    wpvulscan_add_config_issue('installer', 'Script de instalación accesible', [
                        'url' => $url, 'code' => $code
                    ]);
                } elseif ($code === 403) {
                    $estado = 'Protegido (403)';
                    $nivel  = 'ok';
                } else {
                    $estado = 'No accesible';
                    $nivel  = 'ok';
                }
                break;

            default:
                // Genérico
                if (in_array($code, [200, 206], true)) {
                    $estado = 'Accesible';
                    $nivel  = 'advertencia';
                    wpvulscan_add_config_issue('exposure', "Ruta potencialmente sensible accesible: {$path}", [
                        'url' => $url, 'code' => $code
                    ]);
                } elseif (in_array($code, [301,302,307,308], true)) {
                    $estado = 'Redirige';
                    $nivel  = 'ok';
                } elseif ($code === 403) {
                    $estado = 'Protegido (403)';
                    $nivel  = 'ok';
                } else {
                    $estado = 'No accesible';
                    $nivel  = 'ok';
                }
                break;
        }

        $resultados[] = [
            'ruta'   => $path,
            'url'    => $url,
            'estado' => $estado,
            'codigo' => $code ?: '—',
            'nivel'  => $nivel,
        ];
    }

    return $resultados;
}

/**
 * Renderiza tabla con el resultado del análisis de configuración
 */
function wp_vulscan_mostrar_analisis_configuracion() {
    // Reinicia el acumulador antes de analizar (para el dashboard)
    wpvulscan_reset_config_issues();

    $resultados = wp_vulscan_check_sensitive_paths();

    echo '<h2>Archivos o rutas potencialmente inseguras</h2>';

    if (empty($resultados)) {
        echo '<p style="color:green;"><strong>No se han detectado rutas críticas accesibles.</strong></p>';
        return;
    }

    echo '<table class="widefat fixed striped">';
    echo '<thead><tr>'
        . '<th>Ruta</th>'
        . '<th>URL</th>'
        . '<th>Estado</th>'
        . '<th>Código HTTP</th>'
        . '<th>Nivel</th>'
        . '</tr></thead><tbody>';

    foreach ($resultados as $r) {
        $color = ($r['nivel'] === 'critico') ? 'red' : (($r['nivel'] === 'advertencia') ? '#d9822b' : 'green');
        echo '<tr>';
        echo '<td>' . esc_html($r['ruta']) . '</td>';
        echo '<td><a href="' . esc_url($r['url']) . '" target="_blank" rel="noopener noreferrer">' . esc_html($r['url']) . '</a></td>';
        echo '<td>' . esc_html($r['estado']) . '</td>';
        echo '<td>' . esc_html($r['codigo']) . '</td>';
        echo '<td><strong style="color:' . esc_attr($color) . ';">' . esc_html(ucfirst($r['nivel'])) . '</strong></td>';
        echo '</tr>';
    }

    echo '</tbody></table>';

    // Nota para el informe
    echo '<p><em>Nota:</em> Los resultados se han almacenado en <code>wpvulscan_config_issues</code> para su uso en el
    panel, el histórico y la exportación de informes.</p>';
}
