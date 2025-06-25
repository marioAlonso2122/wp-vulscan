# WP-VulScan

**WP-VulScan** es un plugin de seguridad para WordPress diseñado para detectar vulnerabilidades tanto en los plugins instalados como en la configuración general del sistema. Su objetivo es proporcionar a los administradores una herramienta accesible, automatizada y eficaz para mejorar la seguridad proactiva de sus instalaciones WordPress.

## Características principales

- Detección de versiones de plugins con vulnerabilidades conocidas (CVE).
- Evaluación de criticidad según el sistema CVSS.
- Análisis de archivos sensibles expuestos (como `wp-config.php`, `.env`, etc.).
- Detección de rutas potencialmente peligrosas (`install.php`, `debug.log`, etc.).
- Análisis de formularios dentro del tema activo y en URLs externas:
  - Revisión de `method`, `action`, presencia de campos `nonce`.
  - Advertencia si el formulario no usa HTTPS.
- Verificación de la versión actual de WordPress y comparación con la última versión estable.
- Detección de usuarios con nombres predecibles (`admin`, `root`, `editor`...).
- Verificación de permisos inseguros en archivos críticos (`wp-config.php`, `.htaccess`, etc.).
- Detección de plugins abandonados (sin actualización en los últimos 2 años).
- Panel de recomendaciones de hardening (desactivar `xmlrpc`, eliminar `readme.html`, etc.).
- Generación de informes claros desde el panel de administración de WordPress.

## Instalación

1. Clona este repositorio o descarga el ZIP.
2. Copia la carpeta del plugin en `wp-content/plugins/`.
3. Activa el plugin desde el panel de administración de WordPress.
4. Accede al menú **WP-VulScan** para comenzar el análisis.

## Estructura del plugin

wp-vulscan/
- wp-vulscan.php # Archivo principal del plugin
- includes/ # Lógica del plugin (escaneo, análisis, helpers)
    - init.php
    - scan.php
    - config-check.php
    - form-check.php
    - form-check-remote.php
    - system-check.php
    - hardening-recommendations.php
    - report.php
- assets/ # Estilos, scripts, iconos
- templates/ # Vistas HTML/PHP para el panel admin
- docs/ # Documentación técnica adicional
- tests/ # Scripts y datos para pruebas

## Requisitos

- WordPress 5.8 o superior
- PHP 7.4 o superior
- Acceso al backend de WordPress como administrador

## Documentación

En desarrollo. La documentación técnica detallada se incluirá en la carpeta `/docs`.

## Licencia

Este plugin se distribuye bajo la licencia [GPL v2 o superior](https://www.gnu.org/licenses/gpl-2.0.html).

## Funcionalidades Implementadas 25-06

Durante esta jornada se han añadido las siguientes funcionalidades clave:

- Escaneo de configuración: archivos sensibles y rutas expuestas.
- Detección de formularios inseguros en archivos PHP del tema activo.
- Detección de formularios inseguros mediante URL introducida por el usuario.
- Advertencia si los formularios no usan HTTPS.
- Verificación de versión del core de WordPress.
- Detección de usuarios con nombres predecibles.
- Comprobación de permisos de archivos críticos.
- Detección de plugins abandonados.
- Recomendaciones de hardening (eliminar archivos, desactivar funcionalidades, etc.).
---

© 2025 - Mario Alonso Pulgar  
Desarrollado como parte del Trabajo de Fin de Máster en Ciberseguridad - UNIR
