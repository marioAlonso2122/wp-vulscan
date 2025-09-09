<?php
defined('ABSPATH') or die('Acceso no permitido.');

function wpvulscan_rules_dir() {
    return trailingslashit(WP_VULSCAN_DIR) . 'rules/';
}

function wpvulscan_rules_load_all() {
    $dir = wpvulscan_rules_dir();
    if (!is_dir($dir)) return [];

    $rules = [];
    foreach (glob($dir . '*.json') as $file) {
        $raw  = file_get_contents($file);
        $json = json_decode($raw, true);
        if (!is_array($json)) continue;

        foreach (['id','name','severity_default','pattern_json'] as $req) {
            if (!array_key_exists($req, $json)) continue 2;
        }
        $json['id']               = trim((string)$json['id']);
        $json['name']             = trim((string)$json['name']);
        $json['category']         = isset($json['category']) ? (string)$json['category'] : '';
        $json['cwe']              = isset($json['cwe']) ? (string)$json['cwe'] : '';
        $json['severity_default'] = strtolower((string)$json['severity_default']);
        $json['pattern_json']     = is_array($json['pattern_json']) ? wp_json_encode($json['pattern_json']) : (string)$json['pattern_json'];
        $json['enabled']          = (int) !!($json['enabled'] ?? true);

        $rules[$json['id']] = $json;
    }

    global $wpdb;
    $table = $wpdb->prefix . 'vulscan_rules';
    $exists = $wpdb->get_var($wpdb->prepare("SHOW TABLES LIKE %s", $table));
    if ($exists === $table) {
        foreach ($rules as $r) {
            $exists_id = $wpdb->get_var($wpdb->prepare("SELECT id FROM {$table} WHERE id = %s LIMIT 1", $r['id']));
            $data = [
                'id'               => $r['id'],
                'name'             => $r['name'],
                'category'         => $r['category'],
                'severity_default' => $r['severity_default'],
                'pattern_json'     => $r['pattern_json'],
                'enabled'          => $r['enabled'],
                'created_at'       => current_time('mysql'),
            ];
            if ($exists_id) {
                $wpdb->update($table, $data, ['id' => $r['id']]);
            } else {
                $wpdb->insert($table, $data);
            }
        }
    }

    update_option('wpvulscan_rules_cache', $rules, false);
    return $rules;
}

function wpvulscan_rules_get($only_enabled = true) {
    $rules = get_option('wpvulscan_rules_cache', []);
    if (empty($rules)) $rules = wpvulscan_rules_load_all();
    if ($only_enabled) {
        $rules = array_filter($rules, fn($r) => !empty($r['enabled']));
    }
    return $rules;
}

function wpvulscan_rule_by_id($rule_id) {
    $all = wpvulscan_rules_get(false);
    return $all[$rule_id] ?? null;
}
