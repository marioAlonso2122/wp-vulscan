# WP-VulScan

**WP-VulScan** es un plugin de seguridad para WordPress diseñado para detectar vulnerabilidades tanto en los plugins instalados como en la configuración general del sistema. Su objetivo es proporcionar a los administradores una herramienta accesible, automatizada y eficaz para mejorar la seguridad proactiva de sus instalaciones WordPress.

## Características principales

- Detección de versiones de plugins con vulnerabilidades conocidas (CVE).
- Evaluación de criticidad según el sistema CVSS.
- Análisis de archivos expuestos y rutas no protegidas.
- Revisión de formularios sin mecanismos de seguridad (como CSRF o validación de entrada).
- Generación de informes claros y priorizados.
- Integración nativa en el panel de administración de WordPress.

## Instalación

1. Clona este repositorio o descarga el ZIP.
2. Copia la carpeta del plugin en `wp-content/plugins/`.
3. Activa el plugin desde el panel de administración de WordPress.
4. Accede al menú **WP-VulScan** para comenzar el análisis.

## Estructura del plugin

wp-vulscan/
- wp-vulscan.php # Archivo principal del plugin
- includes/ # Lógica del plugin (escaneo, análisis, helpers)
- assets/ # Estilos, scripts, iconos
- templates/ # Vistas HTML/PHP para el panel admin
- docs/ # Documentación técnica adicional
- tests/ # Scripts y datos para pruebas

## Requisitos

- WordPress 5.8 o superior
- PHP 7.4 o superior
- Acceso al backend de WordPress como administrador

## Estado actual

- [x] Estructura inicial del plugin
- [ ] Carga de componentes desde `includes/`
- [ ] Módulo de detección de plugins vulnerables
- [ ] Módulo de análisis de configuración
- [ ] Generador de informes
- [ ] Evaluación final

## Documentación

En desarrollo. La documentación técnica detallada se incluirá en la carpeta `/docs`.

## Licencia

Este plugin se distribuye bajo la licencia [GPL v2 o superior](https://www.gnu.org/licenses/gpl-2.0.html).

---

© 2025 - Mario Alonso Pulgar  
Desarrollado como parte del Trabajo de Fin de Máster en Ciberseguridad - UNIR
