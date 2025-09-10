<?php
defined('ABSPATH') or die('Acceso no permitido.');

/**
 * Resuelve la ruta absoluta a /rules
 * - Usa WP_VULSCAN_PATH si existe; si no, sube desde /includes
 */
if ( ! function_exists('wpvulscan_rules_dir') ) {
    function wpvulscan_rules_dir() {
        if (defined('WP_VULSCAN_PATH')) {
            $base = rtrim(WP_VULSCAN_PATH, '/\\');
        } else {
            // /wp-vulscan/includes/ -> /wp-vulscan/
            $base = plugin_dir_path(dirname(__FILE__));
        }
        $dir = $base . 'rules';
        // Normaliza y asegura barra final
        $real = realpath($dir);
        return $real ? trailingslashit($real) : trailingslashit($dir);
    }
}

/**
 * Valida y normaliza campos mínimos de una regla
 * Devuelve [true, regla] o [false, "motivo"]
 */
if ( ! function_exists('wpvulscan_validate_rule') ) {
    function wpvulscan_validate_rule(array $r, $fileName) {
        $required = ['id','name','category','severity_default'];
        foreach ($required as $k) {
            if ( ! array_key_exists($k, $r) || $r[$k] === '' ) {
                return [false, "Regla inválida en {$fileName}: falta '{$k}'"];
            }
        }
        $norm = $r;
        $norm['enabled']          = isset($r['enabled']) ? (bool) $r['enabled'] : true;
        $norm['cwe']              = isset($r['cwe']) ? (string) $r['cwe'] : '';
        $norm['owasp']            = isset($r['owasp']) ? (string) $r['owasp'] : '';
        $norm['pattern_json']     = array_key_exists('pattern_json', $r) ? $r['pattern_json'] : new stdClass();
        $norm['severity_default'] = (string) $r['severity_default'];
        $norm['id']               = (string) $r['id'];
        $norm['name']             = (string) $r['name'];
        $norm['category']         = (string) $r['category'];
        return [true, $norm];
    }
}

/**
 * Lee /rules/*.json -> [ 'rules' => [...], 'errors' => [...], 'files' => [...] ]
 */
if ( ! function_exists('wpvulscan_load_rules_from_files') ) {
    function wpvulscan_load_rules_from_files() {
        $dir   = wpvulscan_rules_dir();
        $out   = ['rules' => [], 'errors' => [], 'files' => []];

        if ( ! is_dir($dir) ) {
            $out['errors'][] = "No existe el directorio: {$dir}";
            return $out;
        }

        $files = glob($dir . '*.json');
        if ( ! is_array($files) || empty($files) ) {
            $out['errors'][] = "No se encontraron ficheros .json en {$dir}";
            return $out;
        }
        $out['files'] = array_map('basename', $files);

        foreach ($files as $file) {
            $raw = @file_get_contents($file);
            if ($raw === false || $raw === '') {
                $out['errors'][] = basename($file) . ': no se pudo leer o está vacío';
                continue;
            }
            $json = json_decode($raw, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                $out['errors'][] = basename($file) . ': JSON inválido — ' . json_last_error_msg();
                continue;
            }

            // Permitimos objeto-regla o array de reglas
            $list = (is_array($json) && array_keys($json) === range(0, count($json)-1)) ? $json : [$json];
            foreach ($list as $idx => $rule) {
                if ( ! is_array($rule) ) {
                    $out['errors'][] = basename($file) . " [idx {$idx}]: estructura no válida";
                    continue;
                }
                list($ok, $val) = wpvulscan_validate_rule($rule, basename($file));
                if ($ok) {
                    $out['rules'][$val['id']] = $val;
                } else {
                    $out['errors'][] = $val; // mensaje de error
                }
            }
        }
        return $out;
    }
}

/**
 * Cachea en opciones: catálogo y últimos errores
 */
if ( ! function_exists('wpvulscan_cache_rules') ) {
    function wpvulscan_cache_rules(array $rules, array $errors = [], array $files = []) {
        update_option('wpvulscan_rules_cache',  $rules, false);
        update_option('wpvulscan_rules_errors', $errors, false);
        update_option('wpvulscan_rules_files',  $files, false);
        return $rules;
    }
}

/**
 * Devuelve el catálogo de reglas; si $force_reload, vuelve a leer /rules
 */
if ( ! function_exists('wpvulscan_get_rules') ) {
    function wpvulscan_get_rules($force_reload = false) {
        if ( ! $force_reload ) {
            $cached = get_option('wpvulscan_rules_cache', []);
            if (is_array($cached) && ! empty($cached)) {
                return $cached;
            }
        }
        $res = wpvulscan_load_rules_from_files();
        wpvulscan_cache_rules($res['rules'], $res['errors'], $res['files']);
        return $res['rules'];
    }
}

/**
 * Widget de resumen + aviso de diagnóstico si hay errores
 */
if ( ! function_exists('wpvulscan_render_rules_summary') ) {
    function wpvulscan_render_rules_summary() {
        echo '<h2>Catálogo de reglas</h2>';

        $rules  = wpvulscan_get_rules(); // usa caché si hay
        $errors = get_option('wpvulscan_rules_errors', []);
        $files  = get_option('wpvulscan_rules_files', []);

        if (empty($rules)) {
            echo '<p style="color:#c00;"><strong>No se pudo cargar el catálogo de reglas.</strong></p>';
            $dir = wpvulscan_rules_dir();
            echo '<p>Directorio esperado: <code>' . esc_html($dir) . '</code></p>';

            // Muestra diagnóstico si lo hay
            if ( ! empty($errors) || ! empty($files) ) {
                echo '<details open><summary><strong>Diagnóstico</strong></summary>';
                if ( ! empty($files) ) {
                    echo '<p><em>Ficheros detectados:</em> ' . esc_html(implode(', ', $files)) . '</p>';
                }
                if ( ! empty($errors) ) {
                    echo '<ul>';
                    foreach ($errors as $e) {
                        echo '<li style="color:#c00;">' . esc_html($e) . '</li>';
                    }
                    echo '</ul>';
                }
                echo '</details>';
            } else {
                echo '<p>Sin información adicional. Prueba a forzar recarga.</p>';
            }

            // Botón forzar recarga
            echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
            echo '<input type="hidden" name="action" value="wpvulscan_rules_reload">';
            wp_nonce_field('wpvulscan_rules_reload', '_wpvulscan');
            echo '<button type="submit" class="button">Forzar recarga</button>';
            echo '</form>';
            return;
        }

        // Tabla normal con reglas
        echo '<table class="widefat fixed striped">';
        echo '<thead><tr><th>ID</th><th>Nombre</th><th>Categoría</th><th>OWASP</th><th>CWE</th><th>Severidad</th><th>Enabled</th></tr></thead><tbody>';
        foreach ($rules as $r) {
            echo '<tr>';
            echo '<td>' . esc_html($r['id']) . '</td>';
            echo '<td>' . esc_html($r['name']) . '</td>';
            echo '<td>' . esc_html($r['category']) . '</td>';
            echo '<td>' . esc_html($r['owasp'] ?? '') . '</td>';
            echo '<td>' . esc_html($r['cwe']   ?? '') . '</td>';
            echo '<td>' . esc_html($r['severity_default']) . '</td>';
            echo '<td>' . (!empty($r['enabled']) ? 'Sí' : 'No') . '</td>';
            echo '</tr>';
        }
        echo '</tbody></table>';

        // Si hubo errores al cargar, muéstralos plegados
        if ( ! empty($errors) ) {
            echo '<details style="margin-top:10px;"><summary>Ver advertencias de carga</summary><ul>';
            foreach ($errors as $e) {
                echo '<li>' . esc_html($e) . '</li>';
            }
            echo '</ul></details>';
        }

        // Botón forzar recarga
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="margin-top:8px;">';
        echo '<input type="hidden" name="action" value="wpvulscan_rules_reload">';
        wp_nonce_field('wpvulscan_rules_reload', '_wpvulscan');
        echo '<button type="submit" class="button">Forzar recarga</button>';
        echo '</form>';
    }
}

/**
 * Handler "Forzar recarga"
 */
add_action('admin_post_wpvulscan_rules_reload', function () {
    if (!current_user_can('manage_options')) wp_die('Acceso denegado.');
    check_admin_referer('wpvulscan_rules_reload', '_wpvulscan');
    $res = wpvulscan_load_rules_from_files();
    wpvulscan_cache_rules($res['rules'], $res['errors'], $res['files']);
    wp_safe_redirect(admin_url('admin.php?page=wp-vulscan#rules'));
    exit;
});
