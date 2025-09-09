<?php
defined('ABSPATH') or die('Acceso no permitido.');

require_once plugin_dir_path(__FILE__) . 'security-score.php';
require_once plugin_dir_path(__FILE__) . 'scan-history.php';
require_once plugin_dir_path(__FILE__) . 'plugin-check.php';
require_once plugin_dir_path(__FILE__) . 'external-url-scan.php';
require_once plugin_dir_path(__FILE__) . 'form-check-remote.php';         // análisis de formularios/URLs
require_once plugin_dir_path(__FILE__) . 'hardening-recommendations.php'; // recomendaciones de cabeceras, etc.
require_once plugin_dir_path(__FILE__) . 'system-check.php';              // versión WP, usuarios, perms, plugins, REST API
require_once plugin_dir_path(__FILE__) . 'export.php';                    // handler admin_post wpvulscan_export_html
require_once plugin_dir_path(__FILE__) . 'rules-loader.php';              // catálogo de reglas (JSON)

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
 * Widget: resumen del catálogo de reglas
 * (solo lectura; recurre a la caché y, si está vacía, fuerza una recarga)
 */
function wpvulscan_render_rules_summary() {
    echo '<h2>Catálogo de reglas</h2>';

    if (!function_exists('wpvulscan_rules_get')) {
        echo '<p>No se pudo cargar el catálogo de reglas.</p>';
        return;
    }

    // Si la caché está vacía, intenta recargar desde /rules
    $cached = get_option('wpvulscan_rules_cache', []);
    if (empty($cached) && function_exists('wpvulscan_rules_load_all')) {
        wpvulscan_rules_load_all();
        $cached = get_option('wpvulscan_rules_cache', []);
    }

    $rules = wpvulscan_rules_get(false); // incluir desactivadas
    $count = is_array($rules) ? count($rules) : 0;

    echo '<p class="description">Reglas cargadas: <strong>' . intval($count) . '</strong></p>';

    if (empty($rules)) {
        echo '<p>No hay reglas cargadas. Asegúrate de que la carpeta <code>/rules</code> contiene JSON válidos y que se cargan en <code>admin_init</code>.</p>';
        return;
    }

    echo '<table class="widefat fixed striped">';
    echo '<thead><tr>'
        . '<th>ID</th>'
        . '<th>Nombre</th>'
        . '<th>Severidad</th>'
        . '<th>OWASP/Categoría</th>'
        . '<th>CWE</th>'
        . '<th>Activo</th>'
        . '</tr></thead><tbody>';

    foreach ($rules as $r) {
        $sev = isset($r['severity_default']) ? ucfirst($r['severity_default']) : '—';
        $enabled = !empty($r['enabled']) ? '<span style="color:green;">Sí</span>' : '<span style="color:#d9822b;">No</span>';
        echo '<tr>';
        echo '<td><code>' . esc_html($r['id']) . '</code></td>';
        echo '<td>' . esc_html($r['name'] ?? '') . '</td>';
        echo '<td>' . esc_html($sev) . '</td>';
        echo '<td>' . esc_html($r['category'] ?? '') . '</td>';
        echo '<td>' . esc_html($r['cwe'] ?? '') . '</td>';
        echo '<td>' . $enabled . '</td>';
        echo '</tr>';
    }

    echo '</tbody></table>';
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

    // Obtener la clave almacenada
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

    // ======= RENDER DE MÓDULOS / ANÁLISIS EN LA MISMA PÁGINA =======

    // ANALÍTICA DE CONFIGURACIÓN/FORMULARIOS/EXTERNAS
    if ( function_exists('wp_vulscan_mostrar_analisis_configuracion') ) {
        wp_vulscan_mostrar_analisis_configuracion();
    }
    if ( function_exists('wp_vulscan_formulario_urls_usuario') ) {
        wp_vulscan_formulario_urls_usuario();
    }

    // --- Chequeos de "Sistema" (system-check.php) ---
    // Limpia incidencias previas y ejecuta los chequeos con salida HTML:
    if ( function_exists('update_option') ) {
        update_option('wpvulscan_system_issues', [], false);
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
    // *** NUEVO: verificación REST API (permission_callback) ***
    if ( function_exists('wp_vulscan_check_rest_api_permissions') ) {
        wp_vulscan_check_rest_api_permissions();
    }

    // HARDENING
    if ( function_exists('wp_vulscan_mostrar_recomendaciones_hardening') ) {
        wp_vulscan_mostrar_recomendaciones_hardening();
    }

    // URLs externas sensibles (ya mostrado arriba, pero si quieres “forzar” análisis aquí):
    if ( function_exists('wpvulscan_scan_sensitive_urls') ) {
        wpvulscan_scan_sensitive_urls();
    }

    // ======= WIDGET: Catálogo de reglas =======
    echo '<hr>';
    if ( function_exists('wpvulscan_render_rules_summary') ) {
        wpvulscan_render_rules_summary();
    }
}
