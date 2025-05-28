<?php
// Seguridad: evitar el acceso directo
defined('ABSPATH') or die('Acceso no permitido.');

// Hook para registrar el menú en el panel de administración
add_action('admin_menu', 'wp_vulscan_register_menu');

function wp_vulscan_register_menu() {
    add_menu_page(
        'WP-VulScan',                      // Título de la página
        'WP-VulScan',                      // Texto del menú
        'manage_options',                  // Capacidad necesaria
        'wp-vulscan',                      // Slug del menú
        'wp_vulscan_admin_page',           // Función que genera el contenido
        'dashicons-shield-alt',            // Icono (de Dashicons)
        80                                 // Posición en el menú
    );
}

// Contenido de la página de administración
function wp_vulscan_admin_page() {
    ?>
    <div class="wrap">
        <h1>WP-VulScan</h1>
        <p>Bienvenido al panel de WP-VulScan. Aquí podrás analizar tu sitio WordPress en busca de vulnerabilidades comunes.</p>

        <p><strong>Próximas funcionalidades:</strong></p>
        <ul>
            <li>Detección de plugins vulnerables</li>
            <li>Análisis de configuración insegura</li>
            <li>Generación de informes con recomendaciones</li>
        </ul>
    </div>
    <?php
}
