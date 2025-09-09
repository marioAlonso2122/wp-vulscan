<?php
if (!defined('ABSPATH')) exit;

/**
 * Genera un informe HTML completo con:
 * - Cabecera (fecha, sitio)
 * - Badge de riesgo con color real (hex) desde $score_data
 * - Secciones: Configuración, Formularios, Hardening, Sistema, Plugins, URLs externas
 *
 * $results esperado (según tu admin):
 * [
 *   'Configuración insegura'                    => get_option('wpvulscan_config_issues', []),
 *   'Formularios inseguros'                     => get_option('wpvulscan_form_issues', []),
 *   'Hardening'                                 => get_option('wpvulscan_hardening_issues', []),
 *   'Usuarios predecibles / permisos inseguros' => get_option('wpvulscan_system_issues', []),
 *   // opcional: 'Vulnerabilidades en plugins'  => [... strings ...]
 * ]
 */
function wpvulscan_generate_html_report($results = [], $score_data = []) {
    // Utils de render
    $esc = function($v){ return esc_html((string)$v); };
    $boolChip = function($b){
        $txt = $b ? 'Sí' : 'No';
        $cls = $b ? 'chip ok' : 'chip warn';
        return '<span class="'.$cls.'">'.$txt.'</span>';
    };
    $sevChip = function($sev) {
        $s = strtolower((string)$sev);
        $map = [
            'critical' => 'sev-critical',
            'high'     => 'sev-high',
            'medium'   => 'sev-medium',
            'low'      => 'sev-low',
            'info'     => 'sev-info',
        ];
        $cls = isset($map[$s]) ? $map[$s] : 'sev-info';
        return '<span class="chip '.$cls.'">'.esc_html(ucfirst($s)).'</span>';
    };

    $site = home_url('/');
    $now  = date('Y-m-d H:i:s');

    // Badge de riesgo
    $nivel = isset($score_data['riesgo']['nivel']) ? (string)$score_data['riesgo']['nivel'] : 'N/A';
    $color = isset($score_data['riesgo']['color']) ? (string)$score_data['riesgo']['color'] : '#607d8b';
    $score = isset($score_data['score']) ? (int)$score_data['score'] : 0;

    ob_start();
    ?>
<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<title>Informe de Seguridad - WP-VulScan</title>
<style>
    body { font-family: Arial, sans-serif; margin: 28px; color:#263238; }
    h1 { color:#1e88e5; margin-bottom:6px; }
    h2 { color:#1e88e5; margin:24px 0 10px; }
    h3 { color:#37474f; margin:16px 0 8px; }
    .muted { color:#607d8b; }
    .section { margin-bottom: 28px; }
    .badge { display:inline-block; padding:6px 12px; border-radius:6px; font-weight:700; color:#fff; }
    .chip  { display:inline-block; padding:2px 8px; border-radius:999px; font-size:12px; font-weight:600; }
    .ok    { background:#c8e6c9; color:#2e7d32; }
    .warn  { background:#ffe0b2; color:#ef6c00; }
    .sev-critical { background:#ffcdd2; color:#b71c1c; }
    .sev-high     { background:#ffe0b2; color:#e65100; }
    .sev-medium   { background:#fff3cd; color:#b26a00; }
    .sev-low      { background:#c8e6c9; color:#2e7d32; }
    .sev-info     { background:#cfd8dc; color:#37474f; }

    table { width:100%; border-collapse: collapse; margin:10px 0 18px; }
    th, td { border:1px solid #cfd8dc; padding:8px; text-align:left; vertical-align:top; }
    th { background:#eceff1; }
    small { color:#607d8b; }
    a { color:#1565c0; text-decoration:none; }
    a:hover { text-decoration:underline; }
    .note { font-size:12px; color:#607d8b; }
    .kpi { display:inline-block; margin-right:14px; padding:6px 10px; background:#eceff1; border-radius:6px; }
</style>
</head>
<body>

<h1>Informe de Seguridad - WP-VulScan</h1>
<p class="muted"><strong>Sitio:</strong> <?php echo $esc($site); ?> &nbsp;|&nbsp; <strong>Fecha:</strong> <?php echo $esc($now); ?></p>

<p><strong>Evaluación Global:</strong>
    <span class="badge" style="background: <?php echo $esc($color); ?>;">
        Nivel: <?php echo $esc($nivel); ?> — Puntuación: <?php echo $esc($score); ?>
    </span>
</p>

<div class="section">
    <h2>Resumen ejecutivo</h2>
    <?php
    // KPIs rápidos por sección si existen opciones
    $conf_issues = get_option('wpvulscan_config_issues', []);
    $form_issues = get_option('wpvulscan_form_issues', []);
    $hard_issues = get_option('wpvulscan_hardening_issues', []);
    $sys_issues  = get_option('wpvulscan_system_issues', []);
    $ext_issues  = get_option('wpvulscan_external_url_issues', []);
    ?>
    <span class="kpi"><strong>Config:</strong> <?php echo count($conf_issues); ?> hallazgos</span>
    <span class="kpi"><strong>Forms:</strong> <?php
        // cuenta formularios auditados con severidad != Low
        $cnt = 0;
        foreach ((array)$form_issues as $u) {
            if (!empty($u['forms'])) {
                foreach ($u['forms'] as $f) {
                    $sev = strtolower($f['severity'] ?? '');
                    if ($sev === 'critical' || $sev === 'high' || $sev === 'medium') $cnt++;
                }
            }
        }
        echo (int)$cnt;
    ?> riesgos</span>
    <span class="kpi"><strong>Hardening:</strong> <?php echo count($hard_issues); ?> recomendaciones</span>
    <span class="kpi"><strong>Sistema:</strong> <?php echo count($sys_issues); ?> incidencias</span>
    <span class="kpi"><strong>URLs externas:</strong> <?php echo count($ext_issues); ?> hallazgos</span>
</div>

<?php
/* ----------- 1) CONFIGURACIÓN INSEGURA ----------- */
if (!empty($results['Configuración insegura'])): ?>
<div class="section">
    <h2>Configuración insegura</h2>
    <table>
        <thead><tr>
            <th>Tipo</th><th>Mensaje</th><th>Detalles</th><th>Fecha</th>
        </tr></thead>
        <tbody>
        <?php foreach ((array)$results['Configuración insegura'] as $it): ?>
            <tr>
                <td><?php echo $esc($it['type'] ?? ''); ?></td>
                <td><?php echo $esc($it['message'] ?? ''); ?></td>
                <td>
                    <?php
                    $meta = (array)($it['meta'] ?? []);
                    if (!empty($meta['url'])) {
                        echo '<div><strong>URL:</strong> <a href="'.$esc($meta['url']).'" target="_blank" rel="noopener">'.$esc($meta['url']).'</a></div>';
                    }
                    if (isset($meta['code'])) {
                        echo '<div><strong>Código:</strong> '.$esc($meta['code']).'</div>';
                    }
                    if (!empty($meta['match'])) {
                        echo '<div><strong>Detalle:</strong> '.$esc($meta['match']).'</div>';
                    }
                    ?>
                </td>
                <td><small><?php echo $esc($it['time'] ?? ''); ?></small></td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    <p class="note">Rutas sensibles detectadas (readme, backups, .git, xmlrpc, etc.).</p>
</div>
<?php endif; ?>

<?php
/* ----------- 2) FORMULARIOS INSEGUROS ----------- */
if (!empty($results['Formularios inseguros'])): ?>
<div class="section">
    <h2>Formularios inseguros</h2>
    <?php foreach ((array)$results['Formularios inseguros'] as $urlBlock): ?>
        <h3>URL: <a href="<?php echo $esc($urlBlock['url'] ?? '#'); ?>" target="_blank" rel="noopener">
            <?php echo $esc($urlBlock['url'] ?? ''); ?></a> <small>(HTTP <?php echo $esc($urlBlock['code'] ?? ''); ?>)</small></h3>
        <table>
            <thead><tr>
                <th>#</th><th>Método</th><th>HTTPS</th><th>CSRF</th><th>Sensible</th>
                <th>Severidad</th><th>Action (raw → resuelta)</th>
            </tr></thead>
            <tbody>
            <?php foreach ((array)$urlBlock['forms'] as $f): ?>
                <tr>
                    <td><?php echo (int)($f['index'] ?? 0); ?></td>
                    <td><?php echo $esc($f['method'] ?? ''); ?></td>
                    <td><?php echo $boolChip(!empty($f['https'])); ?></td>
                    <td><?php echo $boolChip(!empty($f['csrf'])); ?></td>
                    <td>
                        <?php
                        $sens = (array)($f['sensitive'] ?? []);
                        echo (!empty($sens['password']) ? '<span class="chip sev-medium">password</span> ' : '');
                        echo (!empty($sens['file'])     ? '<span class="chip sev-medium">file</span>' : '');
                        echo (empty($sens['password']) && empty($sens['file'])) ? '<span class="chip sev-info">—</span>' : '';
                        ?>
                    </td>
                    <td><?php echo $sevChip($f['severity'] ?? 'info'); ?></td>
                    <td>
                        <?php
                        $raw = (string)($f['action_raw'] ?? '(vacío)');
                        $res = (string)($f['action_resolved'] ?? '');
                        echo $esc($raw) . '<br><small>' . $esc($res) . '</small>';
                        ?>
                    </td>
                </tr>
            <?php endforeach; ?>
            </tbody>
        </table>
    <?php endforeach; ?>
    <p class="note">Se evalúa HTTPS efectivo en el destino, presencia de token CSRF y sensibilidad de campos (password/subida de ficheros).</p>
</div>
<?php endif; ?>

<?php
/* ----------- 3) HARDENING ----------- */
if (!empty($results['Hardening'])): ?>
<div class="section">
    <h2>Hardening</h2>
    <table>
        <thead><tr>
            <th>Sección</th><th>Severidad</th><th>Hallazgo</th><th>Recomendación</th><th>Fecha</th>
        </tr></thead>
        <tbody>
        <?php foreach ((array)$results['Hardening'] as $h): ?>
            <tr>
                <td><?php echo $esc(ucfirst($h['type'] ?? '')); ?></td>
                <td><?php echo $sevChip($h['severity'] ?? 'info'); ?></td>
                <td><?php echo $esc($h['message'] ?? ''); ?></td>
                <td><?php echo $esc($h['recommendation'] ?? ''); ?></td>
                <td><small><?php echo $esc($h['time'] ?? ''); ?></small></td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    <p class="note">Comprobaciones de HTTPS, constantes de seguridad, permisos, ficheros sensibles y cabeceras (HSTS, CSP, XFO, etc.).</p>
</div>
<?php endif; ?>

<?php
/* ----------- 4) SISTEMA (usuarios/permisos/REST) ----------- */
if (!empty($results['Usuarios predecibles / permisos inseguros'])): ?>
<div class="section">
    <h2>Chequeos del sistema</h2>
    <table>
        <thead><tr>
            <th>Tipo</th><th>Mensaje</th><th>Detalles</th><th>Fecha</th>
        </tr></thead>
        <tbody>
        <?php foreach ((array)$results['Usuarios predecibles / permisos inseguros'] as $s): ?>
            <tr>
                <td><?php echo $esc($s['type'] ?? ''); ?></td>
                <td><?php echo $esc($s['message'] ?? ''); ?></td>
                <td>
                    <?php
                    $meta = (array)($s['meta'] ?? []);
                    foreach ($meta as $k => $v) {
                        echo '<div><strong>'.$esc($k).':</strong> '.$esc(is_scalar($v) ? $v : wp_json_encode($v)).'</div>';
                    }
                    ?>
                </td>
                <td><small><?php echo $esc($s['time'] ?? ''); ?></small></td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    <p class="note">Incluye usuarios con nombres predecibles, permisos de archivos, plugins abandonados y rutas REST sin `permission_callback`.</p>
</div>
<?php endif; ?>

<?php
/* ----------- 5) VULNERABILIDADES EN PLUGINS (si vienen en $results) ----------- */
if (!empty($results['Vulnerabilidades en plugins'])): ?>
<div class="section">
    <h2>Vulnerabilidades en plugins</h2>
    <ul>
        <?php foreach ((array)$results['Vulnerabilidades en plugins'] as $line): ?>
            <li><?php echo $esc($line); ?></li>
        <?php endforeach; ?>
    </ul>
    <p class="note">Origen: catálogo local / API de WPScan (según configuración).</p>
</div>
<?php endif; ?>

<?php
/* ----------- 6) RUTAS EXTERNAS SENSIBLES ----------- */
$external_issues = get_option('wpvulscan_external_url_issues', []);
?>
<div class="section">
    <h2>Rutas externas sensibles</h2>
    <?php if (!empty($external_issues)): ?>
        <ul>
            <?php foreach ($external_issues as $issue): ?>
                <li><?php echo $esc($issue); ?></li>
            <?php endforeach; ?>
        </ul>
    <?php else: ?>
        <p class="ok"><strong>No se han detectado rutas sensibles accesibles públicamente.</strong></p>
    <?php endif; ?>
</div>

</body>
</html>
<?php
    return ob_get_clean();
}
