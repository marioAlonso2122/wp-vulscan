<?php
defined('ABSPATH') or die('Acceso no permitido.');

require_once plugin_dir_path(__FILE__) . 'security-score.php';
require_once plugin_dir_path(__FILE__) . 'scan-history.php';
require_once plugin_dir_path(__FILE__) . 'plugin-check.php';
require_once plugin_dir_path(__FILE__) . 'external-url-scan.php';

/**
 * Registrar el menú principal del plugin
 */
add_action('admin_menu', 'wp_vulscan_register_menu');
function wp_vulscan_register_menu() {
    add_menu_page(
        'WP-VulScan',
        'WP-VulScan',
        'manage_options',
        'wp-vulscan',
        'wp_vulscan_admin_page',
        'dashicons-shield-alt',
        80
    );
}

/**
 * Página principal del plugin
 */
function wp_vulscan_admin_page() {
    if ( ! current_user_can('manage_options') ) {
        wp_die('Acceso denegado.');
    }

    // Guardar API Key (POST) con nonce
    if ( isset($_POST['wpvulscan_api_key']) ) {
        check_admin_referer('wpvulscan_api_key_action');
        $key = sanitize_text_field( wp_unslash($_POST['wpvulscan_api_key']) );
        update_option('wpvulscan_wpscan_api_key', $key);
        echo '<div class="notice notice-success is-dismissible"><p>API Key guardada correctamente.</p></div>';
    }

    // Obtener la clave almacenada (defínela ANTES de pintar el input)
    $current_key = get_option('wpvulscan_wpscan_api_key', '');

    // Cargar resultados para score
    $results = [
        'Configuración insegura'                   => get_option('wpvulscan_config_issues', []),
        'Formularios inseguros'                    => get_option('wpvulscan_form_issues', []),
        'Hardening'                                => get_option('wpvulscan_hardening_issues', []),
        'Usuarios predecibles / permisos inseguros'=> get_option('wpvulscan_system_issues', []),
        'Rutas externas sensibles'                 => get_option('wpvulscan_external_url_issues', []),
    ];
    $score_data = function_exists('wpvulscan_calculate_score') ? wpvulscan_calculate_score($results) : [
        'score' => 0,
        'riesgo' => ['nivel' => 'N/A', 'color' => '#607d8b']
    ];
    ?>
    <div class="wrap">
        <h1>WP-VulScan</h1>
        <p>Bienvenido al panel de WP-VulScan. Analiza tu sitio WordPress en busca de configuraciones débiles y vulnerabilidades conocidas.</p>

        <h2>Configuración de API</h2>
        <p>Introduce tu clave de API de WPScan para habilitar la detección de vulnerabilidades en plugins:</p>
        <form method="post">
            <?php wp_nonce_field('wpvulscan_api_key_action'); ?>
            <input type="text" name="wpvulscan_api_key" value="<?php echo esc_attr($current_key); ?>" size="60" />
            <button type="submit" class="button button-secondary">Guardar clave</button>
        </form>

        <hr>

        <h2>Evaluación global del sistema</h2>
        <p>
            <strong>Nivel de riesgo:</strong>
            <span style="padding:6px 12px;background-color:<?php echo esc_attr($score_data['riesgo']['color']); ?>;color:#fff;border-radius:6px;">
                <?php echo esc_html($score_data['riesgo']['nivel']); ?> (Puntuación: <?php echo esc_html($score_data['score']); ?>)
            </span>
        </p>

        <hr>

        <h2>Exportar informe</h2>
        <form method="post" action="<?php echo esc_url( admin_url('admin-post.php') ); ?>">
            <input type="hidden" name="action" value="wpvulscan_export_html">
            <button type="submit" class="button button-primary">Descargar informe HTML</button>
        </form>

        <hr>

        <h2>Historial de análisis anteriores</h2>
        <table class="widefat">
            <thead>
                <tr>
                    <th>Fecha</th>
                    <th>Puntuación</th>
                    <th>Nivel</th>
                </tr>
            </thead>
            <tbody>
                <?php
                $history = get_option('wpvulscan_history', []);
                if (empty($history)) {
                    echo "<tr><td colspan='3'>No hay análisis previos.</td></tr>";
                } else {
                    foreach (array_reverse($history) as $entry) {
                        echo '<tr>';
                        echo '<td>' . esc_html($entry['fecha']) . '</td>';
                        echo '<td>' . esc_html($entry['score']) . '</td>';
                        echo '<td>' . esc_html($entry['nivel']) . '</td>';
                        echo '</tr>';
                    }
                }
                ?>
            </tbody>
        </table>

        <hr>

        <h2>Vulnerabilidades en plugins instalados</h2>
        <?php
        if ( function_exists('wpvulscan_check_plugins_vulnerables') ) {
            $vulns = wpvulscan_check_plugins_vulnerables();
            if (empty($vulns)) {
                echo "<p class='ok'>Todos los plugins instalados están libres de vulnerabilidades conocidas (según el catálogo disponible).</p>";
            } else {
                echo '<ul>';
                foreach ($vulns as $item) {
                    echo '<li>' . esc_html($item) . '</li>';
                }
                echo '</ul>';
            }
        } else {
            echo '<p>No está disponible la comprobación de plugins vulnerables.</p>';
        }
        ?>

        <hr>

        <h2>Escaneo de rutas externas sensibles</h2>
        <?php
        $external_issues = get_option('wpvulscan_external_url_issues', []);
        if (empty($external_issues)) {
            echo "<p class='ok'>No se han detectado rutas externas expuestas.</p>";
        } else {
            echo '<ul>';
            foreach ($external_issues as $issue) {
                echo '<li>' . esc_html($issue) . '</li>';
            }
            echo '</ul>';
        }
        ?>

        <h2>Herramientas de análisis</h2>
        <ul>
            <li>Detección de configuración insegura</li>
            <li>Análisis de formularios y URLs vulnerables</li>
            <li>Verificación de usuarios comunes y permisos de archivos</li>
            <li>Revisión de cabeceras de seguridad (hardening)</li>
            <li>Detección de vulnerabilidades en plugins (WPScan)</li>
            <li>Generación de informes HTML</li>
            <li>Historial y puntuación de riesgo</li>
        </ul>
    </div>
    <?php

    // ======= Sección de módulos/análisis en la misma página (renderizados) =======
    if ( function_exists('wp_vulscan_mostrar_analisis_configuracion') ) {
        wp_vulscan_mostrar_analisis_configuracion();
    }

    if ( function_exists('wp_vulscan_formulario_urls_usuario') ) {
        wp_vulscan_formulario_urls_usuario();
        // NO LLAMAMOS aquí a wp_vulscan_analizar_formularios_remotos() para no duplicar ejecución
    }

    if ( function_exists('wp_vulscan_check_wp_version') ) {
        wp_vulscan_check_wp_version();
    }

    if ( function_exists('wp_vulscan_check_usuarios_predecibles') ) {
        wp_vulscan_check_usuarios_predecibles();
    }

    if ( function_exists('wp_vulscan_check_permisos_archivos') ) {
        wp_vulscan_check_permisos_archivos();
    }

    if ( function_exists('wp_vulscan_check_plugins_abandonados') ) {
        wp_vulscan_check_plugins_abandonados();
    }

    if ( function_exists('wp_vulscan_mostrar_recomendaciones_hardening') ) {
        wp_vulscan_mostrar_recomendaciones_hardening();
    }

    if ( function_exists('wpvulscan_scan_sensitive_urls') ) {
        wpvulscan_scan_sensitive_urls();
    }
}
