<?php
if (!defined('ABSPATH')) exit;

/**
 * WP-VulScan — Scoring global con ponderación por severidad.
 * - Soporta estructuras:
 *   'Configuración insegura'  => array de issues (type/message/meta/time)  [config-check.php]
 *   'Formularios inseguros'   => array de URL blocks {url, code, forms:[{severity, https, csrf, ...}]}
 *   'Hardening'               => array de issues {type,severity,message,recommendation,time}
 *   'Usuarios predecibles / permisos inseguros' => array de issues {type,message,meta,time}
 *   'Vulnerabilidades en plugins' / 'Plugins vulnerables' => array de strings
 *   'Rutas externas sensibles' => array de strings (mensajes simples)
 *
 * Devuelve:
 *   ['score' => int 0..100, 'riesgo' => ['nivel' => 'Bajo|Medio|Alto|Crítico', 'color' => '#RRGGBB'], 'detalle' => [...]]
 */

/** ===== Utilidades de severidad y pesos ===== */
function wpvulscan_sev_weight($sev) {
    $s = strtolower((string)$sev);
    switch ($s) {
        case 'critical': return 8.0;
        case 'high':     return 5.0;
        case 'medium':   return 3.0;
        case 'low':      return 1.0;
        case 'info':     return 0.5;
        default:         return 1.0;
    }
}
function wpvulscan_bucket_from_score($score) {
    // Umbrales razonables para 0..100
    if ($score >= 60) return ['nivel' => 'Crítico', 'color' => '#c62828'];
    if ($score >= 30) return ['nivel' => 'Alto',    'color' => '#ef6c00'];
    if ($score >= 10) return ['nivel' => 'Medio',   'color' => '#f9a825'];
    return ['nivel' => 'Bajo',  'color' => '#2e7d32'];
}

/** ===== Scoring por secciones ===== */

/** 1) Configuración insegura (issues sin severidad explícita) */
function wpvulscan_score_config($items) {
    $score = 0.0; $n = 0;
    foreach ((array)$items as $it) {
        $type = isset($it['type']) ? strtolower($it['type']) : '';
        // Heurística por tipo (ver config-check.php):
        // exposure/git/backup => crítico; version_leak/xmlrpc/installer => medio
        if (in_array($type, ['exposure','git','backup'], true)) {
            $score += wpvulscan_sev_weight('critical');
        } elseif (in_array($type, ['version_leak','xmlrpc','installer'], true)) {
            $score += wpvulscan_sev_weight('medium');
        } else {
            $score += wpvulscan_sev_weight('medium');
        }
        $n++;
    }
    return ['score' => $score, 'count' => $n];
}

/** 2) Formularios inseguros (usa severidad real por formulario) */
function wpvulscan_score_forms($urlBlocks) {
    $score = 0.0; $n = 0;
    foreach ((array)$urlBlocks as $u) {
        $forms = isset($u['forms']) ? (array)$u['forms'] : [];
        foreach ($forms as $f) {
            $sev = isset($f['severity']) ? strtolower($f['severity']) : 'low';
            $score += wpvulscan_sev_weight($sev);
            $n++;
        }
    }
    return ['score' => $score, 'count' => $n];
}

/** 3) Hardening (ya trae 'severity') */
function wpvulscan_score_hardening($items) {
    $score = 0.0; $n = 0;
    foreach ((array)$items as $h) {
        $sev = isset($h['severity']) ? strtolower($h['severity']) : 'info';
        $score += wpvulscan_sev_weight($sev);
        $n++;
    }
    return ['score' => $score, 'count' => $n];
}

/** 4) Sistema (usuarios/permisos/REST/plugins abandonados/core) — sin severidad explícita */
function wpvulscan_score_system($items) {
    $score = 0.0; $n = 0;
    foreach ((array)$items as $s) {
        $type = isset($s['type']) ? strtolower($s['type']) : '';
        // Heurística:
        // rest (sin permission_callback), filesystem (permisos inseguros), core desactualizado => high
        // plugins abandonados, users predecibles => medium
        if (in_array($type, ['rest','filesystem','core'], true)) {
            $score += wpvulscan_sev_weight('high');
        } elseif (in_array($type, ['plugins','users'], true)) {
            $score += wpvulscan_sev_weight('medium');
        } else {
            $score += wpvulscan_sev_weight('medium');
        }
        $n++;
    }
    return ['score' => $score, 'count' => $n];
}

/** 5) Plugins vulnerables (strings; si incluyen CVSS intenta ponderar) */
function wpvulscan_score_plugins($lines) {
    $score = 0.0; $n = 0;
    foreach ((array)$lines as $line) {
        $w = 5.0; // base
        if (is_string($line) && preg_match('/CVSS[:\s]*([0-9]+(?:\.[0-9])?)/i', $line, $m)) {
            $cvss = floatval($m[1]);
            // Escala simple: 0-10 -> 0-8 puntos aprox.
            $w = max(1.0, min(8.0, round(($cvss / 10) * 8, 1)));
        }
        $score += $w; $n++;
    }
    return ['score' => $score, 'count' => $n];
}

/** 6) URLs externas sensibles (strings; heurística por texto) */
function wpvulscan_score_external_urls($lines) {
    $score = 0.0; $n = 0;
    foreach ((array)$lines as $msg) {
        $t = strtolower((string)$msg);
        if (strpos($t, 'sin incidencias destacables') !== false) {
            $w = 0.0;
        } elseif (strpos($t, 'error de conexión') !== false) {
            $w = wpvulscan_sev_weight('info');
        } elseif (preg_match('/https.*falta|falta hsts|x-frame|content-security-policy/i', $t)) {
            $w = wpvulscan_sev_weight('medium');
        } elseif (strpos($t, 'http (sin https)') !== false
            || strpos($t, 'página servida sobre http') !== false
            || strpos($t, 'formulario con action sobre http') !== false) {
            $w = wpvulscan_sev_weight('high');
        } else {
            $w = wpvulscan_sev_weight('low');
        }
        $score += $w; $n++;
    }
    return ['score' => $score, 'count' => $n];
}

/** ===== Función pública ===== */
function wpvulscan_calculate_score($results) {
    $break = [];
    $total = 0.0;

    // Alias aceptados para la sección de plugins
    $plugins_key = null;
    if (isset($results['Plugins vulnerables']))           $plugins_key = 'Plugins vulnerables';
    if (isset($results['Vulnerabilidades en plugins']))   $plugins_key = 'Vulnerabilidades en plugins';

    // 1) Config
    if (isset($results['Configuración insegura'])) {
        $r = wpvulscan_score_config($results['Configuración insegura']);
        $break['config'] = $r; $total += $r['score'];
    }

    // 2) Forms
    if (isset($results['Formularios inseguros'])) {
        $r = wpvulscan_score_forms($results['Formularios inseguros']);
        $break['forms'] = $r; $total += $r['score'];
    }

    // 3) Hardening
    if (isset($results['Hardening'])) {
        $r = wpvulscan_score_hardening($results['Hardening']);
        $break['hardening'] = $r; $total += $r['score'];
    }

    // 4) Sistema
    if (isset($results['Usuarios predecibles / permisos inseguros'])) {
        $r = wpvulscan_score_system($results['Usuarios predecibles / permisos inseguros']);
        $break['system'] = $r; $total += $r['score'];
    }

    // 5) Plugins
    if ($plugins_key && isset($results[$plugins_key])) {
        $r = wpvulscan_score_plugins($results[$plugins_key]);
        $break['plugins'] = $r; $total += $r['score'];
    }

    // 6) URLs externas
    if (isset($results['Rutas externas sensibles'])) {
        $r = wpvulscan_score_external_urls($results['Rutas externas sensibles']);
        $break['external'] = $r; $total += $r['score'];
    }

    // Normalización a 0..100 (cap)
    $normalized = (int) min(100, round($total)); // lineal y acotado; simple y estable

    $risk = wpvulscan_bucket_from_score($normalized);

    return [
        'score'  => $normalized,
        'riesgo' => $risk,
        'detalle'=> $break, // por si quieres usarlo en un tooltip o en el informe
    ];
}
