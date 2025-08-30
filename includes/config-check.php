<?php
defined('ABSPATH') or die('Acceso no permitido.');

/**
 * Lista de rutas inseguras a comprobar desde el sitio base.
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
        'backup.sql'
    ];
}

/**
 * Devuelve array con rutas inseguras accesibles vía HTTP.
 */
function wp_vulscan_check_sensitive_paths() {
    $site_url = site_url('/');
    $paths = wp_vulscan_get_sensitive_paths();
    $resultados = [];

    foreach ($paths as $path) {
        $url = $site_url . $path;

        $response = wp_remote_head($url, ['timeout' => 5]);

        if (!is_wp_error($response)) {
            $status = wp_remote_retrieve_response_code($response);

            if ($status === 200) {
                $resultados[] = [
                    'ruta' => $path,
                    'url' => $url,
                    'estado' => 'Accesible',
                    'codigo' => $status
                ];
            }
        }
    }

    return $resultados;
}

/**
 * Imprime tabla con archivos inseguros detectados
 */
function wp_vulscan_mostrar_analisis_configuracion() {
    $resultados = wp_vulscan_check_sensitive_paths();

    echo '<h2>Archivos o rutas potencialmente inseguras</h2>';

    if (empty($resultados)) {
        echo '<p style="color:green;"><strong>No se han detectado rutas críticas accesibles.</strong></p>';
        return;
    }

    echo '<table class="widefat fixed striped">';
    echo '<thead><tr><th>Ruta</th><th>URL</th><th>Estado</th><th>Código HTTP</th></tr></thead><tbody>';

    foreach ($resultados as $r) {
        echo '<tr>';
        echo '<td>' . esc_html($r['ruta']) . '</td>';
        echo '<td><a href="' . esc_url($r['url']) . '" target="_blank">' . esc_html($r['url']) . '</a></td>';
        echo '<td style="color:red;"><strong>' . esc_html($r['estado']) . '</strong></td>';
        echo '<td>' . esc_html($r['codigo']) . '</td>';
        echo '</tr>';
    }

    echo '</tbody></table>';
}

update_option('wpvulscan_config_issues', $issues); 