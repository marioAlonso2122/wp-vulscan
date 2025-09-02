<?php
if (!defined('ABSPATH')) exit;

/**
 * Calcula una puntuación de seguridad y clasifica el riesgo.
 *
 * @param array $results Resultados del análisis.
 * @return array ['score' => int, 'riesgo' => ['nivel' => string, 'color' => string]]
 */
function wpvulscan_calculate_score($results) {
    $score = 0;

    foreach ($results as $section => $items) {
        $count = is_array($items) ? count($items) : 0;

        switch ($section) {
            case 'Configuración insegura':
                // Configs como acceso al wp-config.php o directorios expuestos
                $score += $count * 3;
                break;

            case 'Formularios inseguros':
                // Falta de CSRF, HTTPS o validaciones
                $score += $count * 2;
                break;

            case 'Usuarios predecibles / permisos inseguros':
                // Admins por defecto, enumeración de usuarios, etc.
                $score += $count * 2;
                break;

            case 'Hardening':
                // Recomendaciones de refuerzo (headers, etc.)
                $score += $count * 1;
                break;

            case 'Plugins vulnerables':
                // Si en el futuro integras esto vía CVEs
                $score += $count * 4;
                break;

            default:
                $score += $count * 1;
        }
    }

    // Clasificación del riesgo
    if ($score <= 4) {
        $risk = ['nivel' => 'Bajo', 'color' => 'green'];
    } elseif ($score <= 10) {
        $risk = ['nivel' => 'Medio', 'color' => 'orange'];
    } else {
        $risk = ['nivel' => 'Alto', 'color' => 'red'];
    }

    return ['score' => $score, 'riesgo' => $risk];
}
