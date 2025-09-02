<?php
if (!defined('ABSPATH')) exit;

function wpvulscan_calculate_score($results) {
    $score = 0;

    foreach ($results as $section => $items) {
        $count = is_array($items) ? count($items) : 0;

        switch ($section) {
            case 'Configuración insegura':
                $score += $count * 3;
                break;

            case 'Formularios inseguros':
                $score += $count * 2;
                break;

            case 'Usuarios predecibles / permisos inseguros':
                $score += $count * 2;
                break;

            case 'Hardening':
                $score += $count * 1;
                break;

            case 'Plugins vulnerables':
                $score += $count * 4;
                break;

            case 'Rutas externas sensibles':
                $score += $count * 3;
                break;

            default:
                $score += $count * 1;
        }
    }

    if ($score <= 4) {
        $risk = ['nivel' => 'Bajo', 'color' => 'green'];
    } elseif ($score <= 10) {
        $risk = ['nivel' => 'Medio', 'color' => 'orange'];
    } else {
        $risk = ['nivel' => 'Alto', 'color' => 'red'];
    }

    return ['score' => $score, 'riesgo' => $risk];
}
