<?php
defined('ABSPATH') or die('Acceso no permitido.');

function wpvulscan_insert_finding_with_rule($rule_id, $args = []) {
    if (!function_exists('wpvulscan_rule_by_id')) return;

    $rule = wpvulscan_rule_by_id($rule_id);
    $severity = strtolower($args['severity'] ?? ($rule['severity_default'] ?? 'medium'));

    $payload = [
        'asset_id'       => $args['asset_id'] ?? null,
        'rule_id'        => $rule_id,
        'cve_id'         => $args['cve_id'] ?? null,
        'cwe'            => $args['cwe'] ?? ($rule['cwe'] ?? null),
        'owasp'          => $args['owasp'] ?? ($rule['category'] ?? null),
        'severity'       => $severity,
        'confidence'     => $args['confidence'] ?? 'high',
        'path'           => $args['path'] ?? null,
        'line'           => $args['line'] ?? null,
        'function_name'  => $args['function_name'] ?? null,
        'hook_name'      => $args['hook_name'] ?? null,
        'trace_json'     => !empty($args['trace']) ? wp_json_encode($args['trace']) : null,
        'sample_payload' => $args['sample_payload'] ?? null,
        'created_at'     => current_time('mysql'),
    ];

    if (function_exists('wpvulscan_insert_finding')) {
        wpvulscan_insert_finding($payload);
    }
}
