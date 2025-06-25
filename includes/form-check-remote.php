<?php
defined('ABSPATH') or die('Acceso no permitido.');

function wp_vulscan_formulario_urls_usuario() {
    ?>
    <h2>Análisis de formularios externos</h2>
    <form method="post">
        <label for="wp_vulscan_urls"><strong>Introduce una o varias URLs (una por línea):</strong></label><br>
        <textarea name="wp_vulscan_urls" rows="6" style="width:100%;"><?php echo esc_textarea($_POST['wp_vulscan_urls'] ?? ''); ?></textarea><br><br>
        <input type="submit" name="wp_vulscan_analizar_formularios_remotos" class="button button-primary" value="Analizar formularios">
    </form>
    <hr>
    <?php
}

function wp_vulscan_analizar_formularios_remotos() {
    if (!isset($_POST['wp_vulscan_analizar_formularios_remotos'])) return;

    $urls_raw = trim($_POST['wp_vulscan_urls'] ?? '');
    if (empty($urls_raw)) {
        echo '<p style="color:red;">No se han proporcionado URLs para analizar.</p>';
        return;
    }

    $urls = array_filter(array_map('trim', explode("\n", $urls_raw)));
    $fallos = [];

    foreach ($urls as $url) {
        $respuesta = wp_remote_get($url, ['timeout' => 8]);
        if (is_wp_error($respuesta)) {
            $fallos[] = [
                'url' => esc_url($url),
                'error' => 'Error al acceder: ' . $respuesta->get_error_message()
            ];
            continue;
        }

        $html = wp_remote_retrieve_body($respuesta);
        libxml_use_internal_errors(true);
        $dom = new DOMDocument();

        if (!$dom->loadHTML($html)) {
            $fallos[] = [
                'url' => esc_url($url),
                'error' => 'No se pudo analizar el contenido HTML.'
            ];
            continue;
        }

        $formularios = $dom->getElementsByTagName('form');
        if ($formularios->length === 0) {
            $fallos[] = [
                'url' => esc_url($url),
                'error' => 'No se encontraron formularios.'
            ];
            continue;
        }

        echo '<h3>Formulario(s) detectado(s) en: ' . esc_url($url) . '</h3>';
        echo '<table class="widefat fixed striped">';
        echo '<thead><tr><th>Método</th><th>Nonce</th><th>Action</th></tr></thead><tbody>';

    foreach ($formularios as $form) {
        $method = strtolower($form->getAttribute('method') ?: 'GET');
        $action = $form->getAttribute('action') ?: '(vacío)';
        $nonce_detectado = false;
        $inseguro_http = false;

        foreach ($form->getElementsByTagName('input') as $input) {
            if (stripos($input->getAttribute('name'), 'nonce') !== false) {
                $nonce_detectado = true;
            }
        }

        if (stripos($action, 'http://') === 0) {
            $inseguro_http = true;
        }

        echo '<tr>';
        echo '<td>' . esc_html(strtoupper($method)) . '</td>';
        echo '<td>' . ($nonce_detectado ? '<span style="color:green;">Sí</span>' : '<span style="color:red;">No</span>') . '</td>';
        echo '<td>' . esc_html($action);
        if ($inseguro_http) {
            echo ' <span style="color:red;">(⚠️ Sin HTTPS)</span>';
        }
        echo '</td>';
        echo '</tr>';
    }


        echo '</tbody></table><br>';
    }

    if (!empty($fallos)) {
        echo '<h3>Errores encontrados:</h3><ul>';
        foreach ($fallos as $f) {
            echo '<li><strong>' . $f['url'] . ':</strong> ' . esc_html($f['error']) . '</li>';
        }
        echo '</ul>';
    }
}
