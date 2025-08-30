<?php
defined('ABSPATH') or die('Acceso no permitido.');

function wp_vulscan_mostrar_recomendaciones_hardening() {
    echo '<h2>Recomendaciones de Hardening</h2>';
    echo '<ul>';

    // XML-RPC
    if (file_exists(ABSPATH . 'xmlrpc.php')) {
        echo '<li><strong>Desactiva xmlrpc.php</strong> si no usas apps externas (por ejemplo, la app móvil de WordPress).</li>';
    }

    // readme.html
    if (file_exists(ABSPATH . 'readme.html')) {
        echo '<li><strong>Elimina readme.html</strong>: puede revelar la versión exacta de WordPress.</li>';
    }

    // index.php
    if (!file_exists(ABSPATH . 'index.php')) {
        echo '<li><strong>Falta index.php</strong> en la raíz del sitio. Puede permitir la navegación de directorios.</li>';
    }

    // Directory listing
    if (!file_exists(ABSPATH . '.htaccess')) {
        echo '<li><strong>Falta .htaccess</strong>. Se recomienda bloquear el listado de directorios.</li>';
    }

    // Forzar HTTPS
    if (!is_ssl()) {
        echo '<li><strong>No se está utilizando HTTPS</strong>. Considera redirigir todo el tráfico a HTTPS.</li>';
    } else {
        echo '<li>HTTPS activo.</li>';
    }

    echo '</ul>';
}

update_option('wpvulscan_hardening_issues', $harden_notes);
