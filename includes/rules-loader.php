<?php
defined('ABSPATH') or die('Acceso no permitido.');

/**
 * Devuelve la ruta absoluta al directorio /rules
 */
if ( ! function_exists('wpvulscan_rules_dir') ) {
    function wpvulscan_rules_dir() {
        $dir = plugin_dir_path(__FILE__) . '../rules/';
        return trailingslashit($dir);
    }
}

/**
 * Valida y normaliza una regla cargada desde JSON.
 * @return array [bool $ok, mixed $dataOrError]
 */
if ( ! function_exists('wpvulscan_validate_rule') ) {
    function wpvulscan_validate_rule(array $r, $fileName) {
        $required = ['id', 'name', 'category', 'severity_default'];

        foreach ($required as $k) {
            if ( ! isset($r[$k]) || $r[$k] === '' ) {
                return [false, "Regla inválida en {$fileName}: falta el campo '{$k}'."];
            }
        }

        // Normalización de campos opcionales
        $norm = $r;
        $norm['enabled']       = isset($r['enabled']) ? (bool) $r['enabled'] : true;
        $norm['cwe']           = isset($r['cwe']) ? (string) $r['cwe'] : '';
        $norm['pattern_json']  = array_key_exists('pattern_json', $r) ? $r['pattern_json'] : new stdClass();

        // Asegurar tipos básicos como string
        $norm['id']            = (string) $norm['id'];
        $norm['name']          = (string) $norm['name'];
        $norm['category']      = (string) $norm['category'];
        $norm['severity_default'] = (string) $norm['severity_default'];

        return [true, $norm];
    }
}

/**
 * Lee /rules/*.json y devuelve un array asociativo [rule_id => regla_normalizada]
 */
if ( ! function_exists('wpvulscan_load_rules_from_files') ) {
    function wpvulscan_load_rules_from_files() {
        $dir = wpvulscan_rules_dir();
        if ( ! is_dir($dir) ) {
            return [];
        }

        $rules = [];
        $files = glob($dir . '*.json');
        if ( ! is_array($files) ) {
            $files = [];
        }

        foreach ($files as $file) {
            $raw = @file_get_contents($file);
            if ($raw === false || $raw === '') {
                continue;
            }

            $json = json_decode($raw, true);
            if (json_last_error() !== JSON_ERROR_NONE) {
                // JSON inválido: lo ignoramos
                continue;
            }

            // Permitimos tanto un objeto-regla como un array de reglas
            $list = (is_array($json) && array_keys($json) === range(0, count($json)-1)) ? $json : [$json];

            foreach ($list as $rule) {
                if ( ! is_array($rule) ) {
                    continue;
                }
                list($ok, $val) = wpvulscan_validate_rule($rule, basename($file));
                if ($ok) {
                    $rules[$val['id']] = $val;
                }
            }
        }

        return $rules;
    }
}

/**
 * Cachea el catálogo de reglas en una opción
 */
if ( ! function_exists('wpvulscan_cache_rules') ) {
    function wpvulscan_cache_rules(array $rules) {
        update_option('wpvulscan_rules_cache', $rules, false);
        return $rules;
    }
}

/**
 * Devuelve el catálogo de reglas (caché si existe; si no, recarga desde /rules)
 */
if ( ! function_exists('wpvulscan_get_rules') ) {
    function wpvulscan_get_rules($force_reload = false) {
        $cached = get_option('wpvulscan_rules_cache', []);
        if ( ! $force_reload && is_array($cached) && ! empty($cached) ) {
            return $cached;
        }
        $rules = wpvulscan_load_rules_from_files();
        return wpvulscan_cache_rules($rules);
    }
}

/**
 * (Opcional) Widget de resumen de reglas para el panel
 */
if ( ! function_exists('wpvulscan_render_rules_summary') ) {
    function wpvulscan_render_rules_summary() {
        $rules = wpvulscan_get_rules();

        echo '<h2>Catálogo de reglas</h2>';
        if ( empty($rules) ) {
            echo '<p>No se encontraron reglas en <code>/rules</code>.</p>';
            return;
        }

        echo '<table class="widefat fixed striped">';
        echo '<thead><tr>';
        echo '<th>ID</th><th>Nombre</th><th>OWASP</th><th>CWE</th><th>Severidad</th><th>Enabled</th>';
        echo '</tr></thead><tbody>';

        foreach ($rules as $r) {
            $owasp = isset($r['category']) ? $r['category'] : '';
            $cwe   = isset($r['cwe']) ? $r['cwe'] : '';
            $sev   = isset($r['severity_default']) ? $r['severity_default'] : '';
            $en    = ! empty($r['enabled']) ? 'Sí' : 'No';

            echo '<tr>';
            echo '<td>' . esc_html($r['id']) . '</td>';
            echo '<td>' . esc_html($r['name']) . '</td>';
            echo '<td>' . esc_html($owasp) . '</td>';
            echo '<td>' . esc_html($cwe) . '</td>';
            echo '<td>' . esc_html($sev) . '</td>';
            echo '<td>' . esc_html($en) . '</td>';
            echo '</tr>';
        }

        echo '</tbody></table>';
    }
}
