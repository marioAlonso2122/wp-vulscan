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

// Mostrar informe 
wp_vulscan_mostrar_analisis_configuracion(); 

// Introducir URLs con formularios
wp_vulscan_formulario_urls_usuario();

// Analisis URLs introducidas
wp_vulscan_analizar_formularios_remotos();

// Comprobar version de la instalacion
wp_vulscan_check_wp_version();

// Comprobar nombres de usuarios
wp_vulscan_check_usuarios_predecibles();

// Comprobar permisos archivos
wp_vulscan_check_permisos_archivos();

// Comprobacion de plugins abandonados
wp_vulscan_check_plugins_abandonados();

// Recomendaciones de Hardening
wp_vulscan_mostrar_recomendaciones_hardening();
