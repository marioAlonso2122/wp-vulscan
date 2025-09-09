# WP-VulScan

**WP-VulScan** es un plugin de seguridad para WordPress que **correla** configuración del sitio, superficies expuestas y el catálogo de vulnerabilidades de terceros (WPScan) para ofrecer un **diagnóstico accionable** con **severidad normalizada**, **puntuación de riesgo** y **exporte de informes**.

> Proyecto desarrollado como parte del TFM (UNIR) de Mario Alonso Pulgar.

---

## Características clave

- **Detección de vulnerabilidades en plugins**
  - Consulta a **WPScan API** (con caché y *fallback* local opcional).
  - Asigna **severidad** a partir de CVSS y registra hallazgos en BD.

- **Análisis de formularios (locales y externos)**
  - Método, *action*, **CSRF/nonce** y **HTTPS efectivo**.
  - Tabla de resultados y persistencia de incidencias.

- **Chequeos de sistema**
  - Versión de WordPress, usuarios con nombres predecibles, permisos de archivos, **plugins abandonados**, y **rutas REST** sin `permission_callback`.

- **Hardening**
  - Recomendaciones sobre **constantes**, ficheros y **cabeceras de seguridad** (HSTS, CSP, XFO, X-Content-Type-Options, Referrer-Policy).
  - Registro normalizado de “cabeceras ausentes” como *finding* ligado a regla.

- **Motor de reglas (DSL)**
  - Catálogo **JSON** en `/rules/` con `id`, `CWE`, `OWASP`, `severity_default` y patrones por tipo.
  - Cargador que sincroniza el catálogo con **BD** y lo expone en un **widget** del panel.

- **Puntuación de riesgo**
  - Cálculo ponderado por severidad (Critical/High/Medium/Low).
  - **Badge** de nivel (color HEX) y **histórico** de escaneos.

- **Informe HTML**
  - Resumen ejecutivo + tablas por categoría (config, forms, hardening, sistema, plugins y URLs externas).

---

## Requisitos

- **WordPress** ≥ 5.8 (recomendado: 6.x)
- **PHP** ≥ 7.4 (recomendado: 8.0+)
- Rol **Administrador** en la instalación
- (Opcional) **API key de WPScan** para enriquecer el catálogo de vulnerabilidades

---

## Instalación y primera ejecución

1. Clona o descarga el ZIP del plugin.
2. Copia la carpeta en `wp-content/plugins/wp-vulscan/`.
3. Activa **WP-VulScan** en *Plugins → Instalados*.
4. Entra a **WP-VulScan** en el menú de administración.
5. (Opcional) En **Configuración de API** pega tu **API key** de WPScan.
6. (Opcional) En “**Análisis de formularios externos**” introduce URLs para auditar.

> El plugin realiza peticiones salientes:
> - A **WPScan** (si configuras API key).
> - **HEAD/GET** al *front* del sitio para leer cabeceras.
> - GET a **URLs externas** que proporciones para analizar formularios.

---

## Estructura del proyecto

wp-vulscan/
├─ wp-vulscan.php # bootstrap del plugin (cabecera WP)
└─ includes/
  ├─ init.php # constantes, hooks de activación, export handler
  ├─ admin-menu.php # UI principal (panel)
  ├─ export.php # admin_post: exporte del informe HTML
  ├─ report-generator.php # render del informe
  ├─ security-score.php # cálculo de score ponderado
  ├─ scan.php # inventario de plugins, WPScan, findings
  ├─ scan-history.php # orquestación de escaneos + histórico/BD
  ├─ config-check.php # rutas/archivos sensibles accesibles
  ├─ form-check-remote.php # análisis de formularios por URL
  ├─ system-check.php # versión, usuarios, permisos, REST, abandonados
  ├─ hardening-recommendations.php # constantes, ficheros, cabeceras
  ├─ external-url-scan.php # escáner de rutas externas (catálogo ampliable)
  ├─ rules-loader.php # carga/validación de /rules/*.json → BD + caché
  └─ findings.php # helper para registrar findings con rule_id
├─ rules/ # catálogo JSON (DSL)
│ ├─ xss.json
│ ├─ csrf_nonce_missing.json
│ ├─ form_https_missing.json
│ ├─ rest_permission_missing.json
│ ├─ insecure_headers.json
│ ├─ open_redirect.json
│ ├─ file_upload_unsafe.json
│ ├─ weak_crypto.json
│ ├─ hardcoded_secrets.json
└─ └─ readme_version_leak.json

## Motor de reglas (DSL)
- Cada fichero **JSON** en `/rules/` define:
  - `id`, `name`, `category` (OWASP), `cwe`, `severity_default`
  - `pattern_json`: bloque de patrón según tipo (`form`, `headers`, `rest_route`, `php_source`, …)
- El **loader** (`rules-loader.php`) sincroniza el catálogo:
  - **Inserta/actualiza** en `wp_vulscan_rules` y guarda una **caché** (`wpvulscan_rules_cache`).
- Los módulos registran hallazgos con `rule_id` mediante `wpvulscan_insert_finding_with_rule()` (incluye metadatos OWASP/CWE y severidad por defecto).

**Widget de reglas (panel):**  
En el dashboard verás “**Catálogo de reglas**” con ID, nombre, severidad, OWASP/CWE y estado (activo).

---

## Modelo de datos

Tablas principales (prefijo `wp_` variable según tu instalación):

- **`wp_vulscan_scans`**: `id, started_at, finished_at, scope, status`
- **`wp_vulscan_assets`**: `id, type, slug, name, version, path, hash, active`
- **`wp_vulscan_findings`**:  
  `id, asset_id, rule_id, cve_id, cwe, owasp, severity, confidence, path, line, function_name, hook_name, trace_json, sample_payload, created_at`
- **`wp_vulscan_rules`**: `id, name, category, severity_default, pattern_json, enabled, created_at`


---

## Puntuación de riesgo (badge)

El **score** se calcula ponderando por severidad y naturaleza del hallazgo:

| Severidad | Peso aprox. |
|---|---:|
| Critical | 8.0 |
| High     | 5.0 |
| Medium   | 3.0 |
| Low      | 1.0 |
| Info     | 0.5 |

**Rangos del badge:**

| Nivel    | Rango | Color |
|---|---|---|
| Bajo     | 0–9   | `#2e7d32` |
| Medio    | 10–29 | `#f9a825` |
| Alto     | 30–59 | `#ef6c00` |
| Crítico  | ≥60   | `#c62828` |

El resultado se muestra en el panel e impacta en el **histórico**.

---

## Flujo de uso

1. **Panel → WP-VulScan**
   - Configura **API key** (opcional).
   - Revisa **badge** de riesgo y **histórico**.
2. **Analítica**
   - **Configuración**: rutas/archivos inseguros.
   - **Formularios externos**: pega URLs para auditar forms (nonce/HTTPS).
   - **Sistema**: versión WP, usuarios, permisos, plugins abandonados, **REST**.
   - **Hardening**: constantes, ficheros y **cabeceras** (con *finding* agregado).
3. **Plugins vulnerables**
   - Lista correlada con WPScan (CVSS/CVE).
4. **Informe HTML**
   - Botón **Exportar informe** para descargar un reporte navegable.


---

## Buenas prácticas del propio plugin

- Control de acceso con `current_user_can('manage_options')`.
- Nonces en formularios del panel.
- Escapado de salida (`esc_html`, `esc_attr`, `esc_url`) en la UI.
- Cabeceras de seguridad recomendadas en vistas del plugin (documentado en hardening).

---

## Limitaciones y notas

- **WPScan**: sujeto a *rate limits* y disponibilidad de la API. El plugin usa **transients** para cachear respuestas.
- **Cabeceras**: la verificación se hace sobre la **home** del sitio; proxies/CDN pueden alterar el resultado.
- **HTTPS**: algunas comprobaciones toleran entornos de laboratorio; en producción usa certificados válidos.
- **Análisis de formularios externos**: descarga el HTML tal cual; formularios generados dinámicamente por JS pueden requerir análisis manual.

---

## Desarrollo y contribución

- Añadir una regla nueva = **crear un JSON** en `/rules/` (sin tocar PHP).
- Para pruebas, puedes añadir un catálogo local `includes/data/wpscan_local.json`.
- Estilo: PHP 7.4+ y funciones *WordPress-friendly* (escapado, nonces, capacidades).

---

## Licencia

Código bajo **GPL v2 o superior**.  
© 2025 — Mario Alonso Pulgar.

---

## Changelog (resumen)

**0.9.0 (TFM)**  
- Motor de reglas JSON + loader a BD/caché y **widget** en el panel.  
- *Findings* normalizados con `rule_id`, OWASP/CWE y severidad por defecto.  
- **Hardening** con verificación de cabeceras y *finding* agregado.  
- **Scoring** ponderado por severidad y badge con color HEX.  
- **Informe HTML** renovado (tablas por categoría + resumen ejecutivo).  
- Módulos: configuración, formularios remotos, sistema (incl. REST), plugins (WPScan), URLs externas.

---

## Agradecimientos

- WPScan (catálogo de vulnerabilidades de plugins de WordPress).
- Comunidad WordPress por sus *hooks* y utilidades.