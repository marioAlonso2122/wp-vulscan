<?php
/**
 * Análisis de formularios remotos (externos)
 * - Muestra un formulario en el panel para introducir URLs (una por línea)
 * - Descarga el HTML de cada URL y busca <form> para comprobar:
 *     * Presencia de nonce (campo cuyo name contenga 'nonce')
 *     * Uso de HTTPS en la action del form (o en la propia URL base)
 * - Persiste los hallazgos en la opción 'wpvulscan_form_issues'
 */

defined('ABSPATH') or die('Acceso no permitido.');

/**
 * Render de la sección en el Admin.
 * Debe ser llamada desde tu página principal del plugin (ej. en admin-menu.php, dentro de wp_vulscan_admin_page()).
 */
function wp_vulscan_formulario_urls_usuario() {
    // Seguridad de capacidades
    if ( ! current_user_can('manage_options') ) {
        return;
    }

    // Si hay POST, procesamos y mostramos resultados justo antes del formulario
    if ( isset($_POST['wp_vulscan_analizar_formularios_remotos']) ) {
        wp_vulscan_analizar_formularios_remotos();
        echo '<hr>';
    }
    ?>
    <h2>Análisis de formularios externos</h2>

    <form method="post">
        <?php wp_nonce_field('wpvulscan_forms_action'); ?>
        <label for="wp_vulscan_urls"><strong>Introduce una o varias URLs (una por línea):</strong></label><br>
        <textarea name="wp_vulscan_urls" rows="6" style="width:100%;"><?php
            // Re-pintamos el contenido enviado (si lo hubiera) de forma segura
            echo esc_textarea( isset($_POST['wp_vulscan_urls']) ? wp_unslash($_POST['wp_vulscan_urls']) : '' );
        ?></textarea><br><br>

        <input type="submit"
               name="wp_vulscan_analizar_formularios_remotos"
               class="button button-primary"
               value="Analizar formularios">
    </form>
    <?php
}

/**
 * Handler que procesa el POST, muestra la tabla de resultados/errores
 * y persiste los hallazgos en 'wpvulscan_form_issues'.
 */
function wp_vulscan_analizar_formularios_remotos() {
    // Seguridad: capacidades + nonce
    if ( ! current_user_can('manage_options') ) {
        wp_die('Acceso denegado.');
    }
    check_admin_referer('wpvulscan_forms_action');

    // Saneado de entrada
    $urls_raw = isset($_POST['wp_vulscan_urls']) ? wp_unslash($_POST['wp_vulscan_urls']) : '';
    $urls_raw = trim($urls_raw);

    if ( $urls_raw === '' ) {
        echo '<p style="color:red;">No se han proporcionado URLs para analizar.</p>';
        return;
    }

    // Normalizamos líneas y validamos URLs
    $lines = array_map('trim', explode("\n", $urls_raw));
    $urls  = array_values(array_filter($lines, function($u){
        return filter_var($u, FILTER_VALIDATE_URL);
    }));

    if ( empty($urls) ) {
        echo '<p style="color:red;">Las URLs proporcionadas no son válidas.</p>';
        return;
    }

    $errores = [];
    $issues  = [];

    foreach ($urls as $url) {
        // Descargamos el HTML
        $respuesta = wp_remote_get($url, ['timeout' => 10, 'redirection' => 3]);
        if ( is_wp_error($respuesta) ) {
            $errores[] = [
                'url'   => esc_url($url),
                'error' => 'Error al acceder: ' . $respuesta->get_error_message()
            ];
            continue;
        }

        $html = wp_remote_retrieve_body($respuesta);

        // Evitar warnings de HTML malformado
        libxml_use_internal_errors(true);
        $dom = new DOMDocument();

        // Convertimos a HTML-ENTITIES para mejorar compatibilidad de encoding
        $loaded = $dom->loadHTML( mb_convert_encoding($html, 'HTML-ENTITIES', 'UTF-8') );
        if ( ! $loaded ) {
            $errores[] = [
                'url'   => esc_url($url),
                'error' => 'No se pudo analizar el contenido HTML.'
            ];
            continue;
        }

        $formularios = $dom->getElementsByTagName('form');
        if ( $formularios->length === 0 ) {
            $errores[] = [
                'url'   => esc_url($url),
                'error' => 'No se encontraron formularios.'
            ];
            continue;
        }

        // Pintamos cabecera de resultados por URL
        echo '<h3>Formulario(s) detectado(s) en: ' . esc_html($url) . '</h3>';
        echo '<table class="widefat fixed striped">';
        echo '<thead><tr><th>Método</th><th>Nonce</th><th>HTTPS</th><th>Action</th></tr></thead><tbody>';

        foreach ($formularios as $form) {
            // Método y action del form
            $method = strtolower($form->getAttribute('method') ?: 'GET');
            $action = $form->getAttribute('action') ?: '';

            // Detección de nonce (campo input cuyo name contenga 'nonce')
            $nonce_detectado = false;
            foreach ($form->getElementsByTagName('input') as $input) {
                $nameAttr = (string)$input->getAttribute('name');
                if ( stripos($nameAttr, 'nonce') !== false ) {
                    $nonce_detectado = true;
                    break;
                }
            }

            // Comprobación de HTTPS: si la action es absoluta y empieza por http:// => insegura
            // Si la action está vacía o es relativa, usamos el esquema de la URL base:
            $https_ok = true;
            if ($action !== '') {
                if ( stripos($action, 'http://') === 0 ) {
                    $https_ok = false;
                } elseif ( stripos($action, 'https://') === 0 ) {
                    $https_ok = true;
                } else {
                    // action relativa: tomamos el esquema de la URL base
                    $https_ok = (stripos($url, 'https://') === 0);
                }
            } else {
                // action vacío => el navegador usa la URL actual
                $https_ok = (stripos($url, 'https://') === 0);
            }

            // Severidad heurística simple
            // - Sin HTTPS => High
            // - Con HTTPS pero sin nonce => Medium
            // - Con HTTPS y nonce => Low
            $severity = 'Low';
            if ( ! $https_ok ) {
                $severity = 'High';
            } elseif ( $https_ok && ! $nonce_detectado ) {
                $severity = 'Medium';
            }

            // Persistimos este hallazgo para informes
            $issues[] = [
                'url'     => esc_url_raw($url),
                'method'  => strtoupper($method),
                'action'  => $action !== '' ? $action : '(vacío)',
                'nonce'   => $nonce_detectado,
                'https'   => $https_ok,
                'severity'=> $severity,
            ];

            // Pintamos fila
            echo '<tr>';
            echo '<td>' . esc_html(strtoupper($method)) . '</td>';
            echo '<td>' . ( $nonce_detectado ? '<span style="color:green;">Sí</span>' : '<span style="color:red;">No</span>' ) . '</td>';
            echo '<td>' . ( $https_ok ? '<span style="color:green;">Sí</span>' : '<span style="color:red;">No</span>' ) . '</td>';
            echo '<td>' . esc_html( $action !== '' ? $action : '(vacío)' ) . '</td>';
            echo '</tr>';
        }

        echo '</tbody></table><br>';
    }

    if ( ! empty($errores) ) {
        echo '<h3>Errores encontrados:</h3><ul>';
        foreach ($errores as $f) {
            echo '<li><strong>' . esc_html($f['url']) . ':</strong> ' . esc_html($f['error']) . '</li>';
        }
        echo '</ul>';
    }

    // Guardamos los hallazgos (corrige la variable no definida del código original)
    update_option('wpvulscan_form_issues', $issues);
}
