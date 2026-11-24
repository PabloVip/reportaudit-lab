# Laboratorio 1 — Bitácora de auditoría de la cadena de suministro

- **Autor/a:** Pablo Vicente
- **Repositorio:** https://github.com/PabloVip/reportaudit-lab
- **SonarQube Cloud:** Organization Key `pablovip` · Project Key `PabloVip_reportaudit-lab`
- **Sistema operativo y versión de Python usados:** CachyOS (Linux nativo, sin WSL). Python 3.12 dentro de un entorno virtual creado con `uv`, porque el Python del sistema es más nuevo y el laboratorio está pensado para 3.12.

> Completa cada sección en el momento en que la guía te lo pide, no al final.
> Una bitácora escrita "de memoria" al terminar no sirve como evidencia.

---

## Parte C — Auditoría manual (antes de usar ninguna herramienta)

He leído `app/servicio.py` y `app/reporte_auditoria.py` siguiendo los datos que llegan por la URL (`cliente` y `archivo`) hasta donde se usan. Estas son las cinco cosas que me parecen peligrosas:

| # | Función | Línea | Qué sospechas | Dato de entrada (*source*) | Destino peligroso (*sink*) |
|---|---|---|---|---|---|
| 1 | `buscar_reportes_cliente` | 41–42 | Inyección SQL: la consulta se construye pegando el nombre del cliente al texto SQL, así que lo que escriba el usuario puede cambiar la consulta | Parámetro `cliente` de la URL `/reportes` (`servicio.py`, línea 41) | `cursor.execute(query)` (línea 42) |
| 2 | `convertir_a_pdf` | 50–51 | Inyección de comandos: el nombre del archivo se pega en un comando que ejecuta el sistema operativo. Con un `;` se podría añadir otro comando | Parámetro `archivo` de la URL `/convertir` (`servicio.py`, línea 53) | `os.system(comando)` (línea 51) |
| 3 | `cargar_configuracion` | 33 | Carga del YAML insegura: con `yaml.Loader` el archivo puede crear objetos de Python y no solo leer datos. Lo seguro sería `yaml.safe_load` | Contenido del archivo `app/config.yaml` | `yaml.load(f, Loader=yaml.Loader)` (línea 33) |
| 4 | `hash_password_legacy` | 57 | Hash de contraseñas débil: usa MD5, que es muy rápido de romper, y además sin sal | Parámetro `password` | `hashlib.md5(...)` (línea 57) |
| 5 | Constantes al principio del archivo | 21–22 | Contraseñas y claves escritas directamente en el código (`NOTIFICATION_API_KEY` y `SMTP_PASSWORD`) | No hay: son valores fijos en el código | El propio repositorio de GitHub, que es público. La clave también se imprime en parte en `notificar_cliente` (línea 62) |

**Síntoma observado (paso C.2):** al pedir `/reportes?cliente=o'brien_ltd` el servicio devuelve *Internal Server Error* y en la terminal aparece `sqlite3.OperationalError: near "brien_ltd": syntax error`. El apóstrofo cierra la cadena de la consulta antes de tiempo, y eso confirma la sospecha 1.

**Impacto en el negocio:**

1. **Inyección SQL:** alguien podría ver los reportes de todos los clientes y no solo los suyos (por ejemplo con `cliente=' OR '1'='1`). Son datos de auditoría confidenciales.
2. **Inyección de comandos:** alguien podría ejecutar cualquier comando en el servidor donde corre ReportAudit, y con eso acceder a todo lo que haya en esa máquina.
3. **YAML inseguro:** si alguien consigue modificar `config.yaml`, podría hacer que el servicio ejecute su propio código al arrancar.
4. **MD5:** si se filtraran los hashes, sería fácil sacar las contraseñas originales de los clientes, y mucha gente reutiliza la misma contraseña en otros sitios.
5. **Secretos en el código:** como el repositorio es público, cualquiera puede copiar la clave de la API y la contraseña del correo y enviar mensajes haciéndose pasar por la empresa. No basta con borrar las líneas, porque siguen en el historial de Git: hay que cambiar (rotar) esas credenciales.

---

## Matriz de detección (se completa a lo largo del laboratorio)

Marca ✓ (lo detectó, anota la regla) o ✗ (no lo detectó) en cada columna cuando
llegues a la parte correspondiente.

| Hallazgo | Manual (C) | SonarQube for IDE sin conexión (E) | SonarQube for IDE en Connected Mode (F) | SonarQube Cloud (G) | CodeQL (G) | Semgrep (H) | Trivy (L) |
|---|---|---|---|---|---|---|---|
| H1 Inyección SQL en `buscar_reportes_cliente` | ✓ | ✗ | ✓ Inyección SQL (`pythonsecurity:S3649`) | ✓ Blocker SQL Injection (`reporte_auditoria.py:42`) | ✓ `py/sql-injection` error (`reporte_auditoria.py:42`) | ✗ | n/a |
| H2 Inyección de comandos en `convertir_a_pdf` | ✓ | ✗ | ✓ Inyección de comandos (`pythonsecurity:S2076`) | ✓ Blocker Command Injection (`reporte_auditoria.py:51`) | ✓ `py/command-line-injection` error (`reporte_auditoria.py:51`) | ✗ | n/a |
| H3 Deserialización YAML insegura en `cargar_configuracion` | ✓ | ✗ | ✗ | ✗ | ✗ | ✓ `python.lang.security.deserialization.avoid-pyyaml-load` (línea 33) | n/a |
| H4 Hash MD5 en `hash_password_legacy` | ✓ | ✓ `python:S4790` (línea 57) | ✓ `python:S4790` | ✓ High hashing (`reporte_auditoria.py:57`) | ✓ `py/weak-sensitive-data-hashing` warning (`reporte_auditoria.py:57`) | ✓ `python.lang.security.insecure-hash-algorithms-md5` + `python.lang.security.audit.md5-used-as-password` (línea 57, 2 hallazgos) | n/a |
| H5 Clave de API escrita en el código | ✓ | ✗ | ✗ | ✗ (ningún Issue la nombra) | parcial: `py/clear-text-logging-sensitive-data` error (`reporte_auditoria.py:62`, la clave se registra en el log, no el hardcodeo en `:21`) | ✗ (`p/secrets` no la marca) | ✗ (0 secretos detectados) |
| H6 Contraseña SMTP escrita en el código | ✓ | ✓ `python:S2068` (línea 22) | ✓ `python:S2068` + aviso de secreto SMTP a revocar | ✓ Blocker SMTP revoke + Medium hard-coded password (`reporte_auditoria.py:22`, 2 Issues) | ✗ | ✗ (`p/secrets` no la marca) | ✗ (0 secretos detectados) |

**Nota sobre SonarQube for IDE sin conexión (Parte E):** solo encontró 2 de los 6 problemas: la contraseña SMTP (porque la variable se llama `PASSWORD`) y el uso de MD5. No marcó la clave de la API, seguramente porque el nombre `NOTIFICATION_API_KEY` no le parece una contraseña. Tampoco la inyección SQL ni la de comandos: el dato peligroso llega desde `servicio.py` y, sin conexión, la extensión analiza cada archivo por separado, así que no ve ese recorrido. El YAML inseguro tampoco lo marcó.

**Nota sobre Connected Mode (Parte F.6):** al vincular el editor con el proyecto de SonarQube Cloud aparecieron 5 avisos en vez de 2. Ahora sí detecta la inyección SQL y la de comandos, porque usa las reglas de la nube, que siguen el dato desde `servicio.py` hasta el `execute` y el `os.system`. También añade un aviso de que la contraseña SMTP debe revocarse. Sigue sin marcar el `yaml.load` inseguro ni la clave de la API.

**Nota sobre Semgrep (Parte H.2):** `venv/bin/semgrep --config=p/python --config=p/secrets app/` da 3 hallazgos bloqueantes, todos en `app/reporte_auditoria.py`: YAML inseguro (línea 33) y MD5 dos veces en la misma línea 57 (hash inseguro + MD5 como password). No detecta ni la inyección SQL ni la de comandos ni los dos secretos. Evidencia: salida completa guardada al generar el informe.

**Nota sobre Trivy (Parte L):** `trivy fs --scanners vuln,secret` encuentra las mismas 12 vulnerabilidades de dependencias que Grype (ver tabla) pero 0 secretos en `app/`: las reglas de secretos buscan patrones conocidos (AWS, GitHub, etc.) y los valores de `NOTIFICATION_API_KEY` y `SMTP_PASSWORD` ([REDACTED]) no coinciden con ninguno. Por eso H5 y H6 quedan ✗ también aquí.

**Conclusión de la matriz** (Parte L): ninguna herramienta lo detectó todo. SonarQube Cloud encuentra H1, H2, H4 y H6 pero no H3 (YAML) ni H5 (API key); CodeQL encuentra H1, H2 y H4 (más un parcial de H5 por el log en `:62`) pero no H3 ni H6; Semgrep solo encuentra H3 y H4; Trivy (secretos) no encuentra ni H5 ni H6. Depender de una sola herramienta dejaría vulnerabilidades reales sin detectar: hace falta defensa en profundidad (editor + hook + pipeline + SCA + secretos).

**Ruido:** SonarQube Cloud añade un High en `app/servicio.py:25` (CSRF) que es un falso positivo en este caso: la API solo expone GET de lectura que responden JSON, sin formularios ni sesiones que proteger.

---

## Parte K — SBOM: el iceberg medido

Generado con `./tools/syft scan dir:. --exclude './venv/**' --exclude './tools/**' -o cyclonedx-json=docs/evidencias/sbom.cyclonedx.json` (Syft 1.52.0). Evidencia: `docs/evidencias/sbom.cyclonedx.json`.

| Dato | Valor |
|---|---|
| Dependencias directas (`requirements.in`) | 2: `flask==3.0.0`, `pyyaml==6.0.3` |
| Componentes Python en el SBOM | 9 paquetes `pypi`: blinker 1.7.0, click 8.1.7, colorama 0.4.6, flask 3.0.0, itsdangerous 2.1.2, jinja2 3.1.2, markupsafe 3.0.3, pyyaml 6.0.3, werkzeug 3.0.1 |
| Otros componentes que aparezcan en el SBOM (si los hay) y de dónde salen | 4 acciones GitHub (de `.github/workflows/cadena-suministro.yml`): `actions/checkout@v6`, `SonarSource/sonarqube-scan-action@v7`, `github/codeql-action/init@v4`, `github/codeql-action/analyze@v4` + 2 ficheros (`requirements.txt`, el workflow) |
| Formato y versión de especificación del SBOM (`bomFormat`, `specVersion`) | `CycloneDX`, `1.7` (13 componentes `library` en total) |

---

## Parte K — Triage de vulnerabilidades de dependencias (Grype)

Comando: `./tools/grype sbom:docs/evidencias/sbom.cyclonedx.json | tee docs/evidencias/grype-antes.txt` (Grype 0.119.0). Resultado: 12 vulnerabilidades (werkzeug 6, jinja2 5, flask 1). Trivy (`trivy fs --scanners vuln`) confirma las mismas 12 con identificadores CVE. Tabla resumida por paquete (el detalle completo está en `docs/evidencias/grype-antes.txt` y `docs/evidencias/trivy-antes.json`; `trivy-antes.txt` es el mismo informe en formato tabla, generado con `trivy convert`):

| Paquete | Versión | ¿Directa o transitiva? (usa `# via`) | CVE / GHSA | Severidad | Corregida en | ¿Explotable en ReportAudit? ¿Por qué? | Decisión |
|---|---|---|---|---|---|---|---|
| werkzeug | 3.0.1 | Transitiva (`# via flask`) | CVE-2024-34069 / GHSA-2g68-c3qc-8985 (ejecución de código en máquina del desarrollador vía debugger) | High | 3.0.3 | Difícil en producción (`debug=False` en `servicio.py:64`), pero el riesgo existe si alguien reutiliza el código con debug activado | Actualizar con el PR de Dependabot |
| werkzeug | 3.0.1 | Transitiva (`# via flask`) | CVE-2024-49766 / GHSA-f9vj-2wh5-fj8j, CVE-2024-49767 / GHSA-q34m-jh98-gwm2, CVE-2025-66221, CVE-2026-21860, CVE-2026-27199 | Medium | 3.0.6 → 3.1.6 según CVE | No (las de `safe_join`/Windows no aplican: el servicio corre en Linux y no usa `safe_join`; ver VEX). Las demás se corrigen igual al actualizar | Actualizar + VEX para CVE-2024-49766 |
| jinja2 | 3.1.2 | Transitiva (`# via flask`) | CVE-2024-56326 / GHSA-q2x7-8rv6-6q7h y otras 4 (sandbox breakout, `xmlattr`) | Medium | 3.1.3 → 3.1.6 según CVE | No: afectan al sandbox de plantillas Jinja2 y ReportAudit no renderiza plantillas (responde con `jsonify` en `app/servicio.py:31-47`) | Actualizar con el PR de Dependabot (coste bajo) |
| flask | 3.0.0 | Directa (`# via -r requirements.in`) | CVE-2026-27205 / GHSA-68rp-wp8r-4726 (info disclosure vía caché de sesión) | Low | 3.1.3 | No explotable hoy (no se usan sesiones), pero es dependencia directa y el parche es barato | Actualizar con el PR de Dependabot |

**Comparación con Dependabot** (Parte I): coinciden al 100 %: 12 alertas abiertas con los mismos 3 paquetes y los mismos GHSA/CVE que Grype/Trivy (ej. Werkzeug CVE-2024-34069/GHSA-2g68-c3qc-8985 High, parche 3.0.3). Diferencia: Dependabot abrió 3 PRs separados (#18 flask→3.1.3, #19 werkzeug→3.1.6, #20 jinja2→3.1.6) en vez de 1 agrupado, porque `.github/dependabot.yml` (grupo `parches-de-seguridad`) aún no está en `main` (PR #17 pendiente de revisión). Tras fusionar #17, los siguientes serán agrupados. NO fusionar los PRs #18-20: se integran en M.5.

**Documento VEX:** [`docs/evidencias/reportaudit.openvex.json`](evidencias/reportaudit.openvex.json) — declara `CVE-2024-49766` (`pkg:pypi/werkzeug@3.0.1`) como `not_affected` con justificación `vulnerable_code_not_in_execute_path`. En una frase: el fallo solo afecta a `safe_join()` en Windows y ReportAudit corre en Linux sin llamar jamás a esa función.

---

## Parte M — Corrección del código y de las dependencias

**PR de auditoría (#23, rama `fix/auditoria-seguridad`, cierra #5).** Las cinco correcciones de `app/reporte_auditoria.py`:

| Hallazgo | Antes | Después |
|---|---|---|
| H1 Inyección SQL | Concatenar `nombre_cliente` en el SQL | Consulta parametrizada con `?` |
| H2 Inyección de comandos | `os.system("wkhtmltopdf " + archivo ...)` | `subprocess.run([...])` sin shell + lista blanca del nombre |
| H3 YAML inseguro | `yaml.load(f, Loader=yaml.Loader)` | `yaml.safe_load(f)` |
| H4 Hash débil | `hashlib.md5(...)` sin sal | `hashlib.pbkdf2_hmac("sha256", ...)` con sal aleatoria de 16 bytes y 600.000 iteraciones |
| H5/H6 Secretos | Constantes en el código, y la clave impresa a medias en el log | `os.environ.get(...)`; el log solo dice si la clave está configurada. Credenciales declaradas como comprometidas para rotar |

Al abrir el PR, SonarQube Cloud encontró un problema nuevo en mi propia corrección: `pythonsecurity:S6350` (inyección de argumentos). La lista blanca de la guía se aplicaba a `Path(nombre).name`, así que una ruta como `-x/a.html` pasaba el filtro y llegaba a `wkhtmltopdf` como opción. Lo corregí en un segundo commit validando el argumento completo con `fullmatch` y el siguiente análisis ya no lo marcó.

Comprobaciones antes de confirmar (servicio en el puerto 8087): `acme_corp` → 2 reportes; `o'brien_ltd` → 1 reporte (antes, error 500); `' OR '1'='1` → 0 reportes; `informe.html` → 200; `informe final.html`, `-x/a.html`, `../../etc/a.html` y `--help.html` → 400. `pre-commit run --all-files` → Passed, sin necesidad de `# nosemgrep`.

**M.4.** Al fusionar #23, el pipeline reanalizó `main` y las 4 alertas de CodeQL (`py/sql-injection`, `py/command-line-injection`, `py/weak-sensitive-data-hashing`, `py/clear-text-logging-sensitive-data`) pasaron solas a *Fixed*. En SonarQube Cloud, `main` pasó de 6 vulnerabilidades a 1 y no hay Security Hotspots. La que queda es `python:S4502` en `app/servicio.py:25` (CSRF desactivado), el falso positivo que ya anoté en la matriz: la API solo tiene endpoints GET de lectura que responden JSON, sin formularios, cookies ni sesiones.

**M.5.** Dependabot no abrió un PR agrupado sino tres (#18 flask, #19 werkzeug, #20 jinja2), porque los creó antes de que `dependabot.yml` estuviera en `main`. El #18 no solo subía flask a 3.1.3: también subía werkzeug a 3.1.9, blinker a 1.9.0 e itsdangerous a 2.2.0, que son los mínimos que pide Flask 3.1. Al fusionarlo, el #19 dejó de hacer falta (cerrado sin fusionar) y el #20 quedó en conflicto con `main`. Dependabot no respondió ni a `@dependabot rebase` ni a `@dependabot recreate`, así que resolví el conflicto fusionando `main` en su rama y dejando el lockfile de `main` con `jinja2==3.1.6` como único cambio (comprobado en un entorno limpio con `pip check`: sin dependencias rotas). Con #18 y #20 fusionados, las 12 alertas de Dependabot se cerraron como *fixed* y cerré el Issue #6 con un comentario.

Al actualizar mi `venv` con `pip install -r requirements.txt`, pip avisó de que Semgrep (que tenía instalado en el mismo entorno) pide `click~=8.4.2` y el lockfile fija `click==8.1.7`. El servicio y el hook siguen funcionando (pre-commit usa su propio entorno), pero es justo el motivo por el que las herramientas de desarrollo deberían ir en un `requirements-dev.txt` o en otro entorno.

---

## Parte N — Antes y después

Comandos de la guía sobre `main` actualizada. Evidencias: `sbom-despues.cyclonedx.json`, `grype-despues.txt` y `trivy-despues.txt` en `docs/evidencias/`.

| Medida | Antes | Después |
|---|---|---|
| Hallazgos de Semgrep en `app/` | 3 bloqueantes (YAML 1 + MD5 2 en la misma línea) | 0 (`pre-commit run --all-files` → Passed) |
| Alertas abiertas de CodeQL (Security → Code scanning) | 4 (`py/sql-injection`, `py/command-line-injection`, `py/weak-sensitive-data-hashing`, `py/clear-text-logging-sensitive-data`) | 0: las 4 cerradas como *Fixed* |
| Vulnerabilidades en SonarQube Cloud (rama main) | 6 (Security Rating E) | 1 (Security Rating D): `python:S4502` CSRF en `servicio.py:25`, falso positivo |
| Security Hotspots por revisar en SonarQube Cloud | 0 | 0 |
| Vulnerabilidades de Grype sobre el SBOM | 12 (1 High, 10 Medium, 1 Low) | 0 ("No vulnerabilities found") |
| Vulnerabilidades de Trivy (`vuln`) | 12 (1 High, 10 Medium, 1 Low, mismos paquetes) | 0 |
| Secretos de Trivy (`secret`) | 0 (H5/H6 no detectados) | 0 (ahora ya no están en el código; en el historial los encuentra Gitleaks, Parte O) |
| Alertas abiertas de Dependabot | 12 | 0 (12 *fixed*) |

**SBOM después:** 8 paquetes de Python (blinker 1.9.0, click 8.1.7, flask 3.1.3, itsdangerous 2.2.0, jinja2 3.1.6, markupsafe 3.0.3, pyyaml 6.0.3, werkzeug 3.1.9). Desaparece colorama: el lockfile que generó Dependabot ya no la incluye (solo se instalaba en Windows, vía click). Las acciones de GitHub pasan de 4 a 11 distintas porque ya están en `main` los workflows de publicación, Scorecard y las puertas de pip-audit y Gitleaks.

---

## Bloque final — Publicar y demostrar (Partes O–T)

### O. Secretos en el historial (Gitleaks)

Gitleaks 8.30.1 instalado en `tools/` comprobando a mano su SHA-256 contra `gitleaks_8.30.1_checksums.txt` ("La suma coincide").

| Escaneo | Comando | N.º de hallazgos | Commit(s) donde aparecen |
|---|---|---|---|
| Código actual, reglas por defecto | `gitleaks dir app` | 0 | — |
| Historial, reglas por defecto | `gitleaks git .` | 1 (`generic-api-key` en `NOTIFICATION_API_KEY`, línea 21) | `2e3417f` (importación) |
| Historial, con regla propia | `gitleaks git . -c .gitleaks.toml` | 2 (`reportaudit-hardcoded-credential`, líneas 21 y 22) | `2e3417f` (importación) |
| Historial, tras .gitleaksignore | `gitleaks git . -c .gitleaks.toml` | 0 | — |

¿Por qué el código actual está limpio y el historial no? ¿Qué medida de la Parte M cierra el riesgo y cuál no?

`gitleaks dir app` solo mira los archivos tal como están ahora, y desde la Parte M las credenciales se leen con `os.environ.get(...)`. `gitleaks git .` recorre todos los commits, y el de importación (`2e3417f`) sigue conteniendo los dos valores. Con las reglas por defecto solo saltó la clave de la API (`generic-api-key`, entropía 5,17). La contraseña SMTP no, y lo he comprobado con valores de prueba en una carpeta aparte: la regla genérica no acepta el carácter `!` dentro del valor (`R3pqrt2024!Aqdit` no salta y `R3pqrt2024xAqdit` sí) y además descarta valores que contienen palabras comunes como `report` o `audit` para evitar falsos positivos (`Zq7report9Xk2Lw4` tampoco salta). Por eso hizo falta la regla propia, que se fija en el nombre de la variable y no en el aspecto del valor. Sacar las credenciales del código no cierra el riesgo, porque siguen en el historial público. Lo que lo cierra es la rotación: el valor antiguo deja de servir. La baseline (`.gitleaksignore`) solo registra esos dos hallazgos concretos (commit, archivo, regla y línea); no desactiva la regla, así que cualquier credencial nueva, aunque sea en el mismo archivo, haría fallar el análisis.

### P. Puertas obligatorias en main

| Check | ¿Exigido en main? | Resultado en el PR de prueba (test/puerta-sca) |
|---|---|---|
| SAST - SonarQube Cloud | Sí | Verde |
| SAST - CodeQL | Sí | Verde |
| SCA - pip-audit | Sí | Rojo: `Found 7 known vulnerabilities in 1 package` (werkzeug 3.1.3: PYSEC-2026-2046, PYSEC-2026-2044, PYSEC-2026-2320, PYSEC-2026-4312) |
| Secretos - Gitleaks | Sí | Verde |

Los jobs se añadieron en el PR #28 y se exigieron en la regla de `main` cuando ya se habían ejecutado una vez. Secret scanning y push protection ya estaban activados (repositorio público).

El PR de prueba es el #29 (borrador, cerrado sin fusionar). El primer commit hacía lo que dice la guía, `werkzeug==3.0.1`, y pip-audit salió en rojo pero por otro motivo: `ResolutionImpossible`, porque en `main` ya está flask 3.1.3, que exige Werkzeug 3.1 o superior. Un rojo por un error de instalación no demuestra que la puerta detecte vulnerabilidades, así que en un segundo commit puse `werkzeug==3.1.3`, que es compatible con flask 3.1.3 y tiene avisos conocidos; antes lo comprobé en local con `pip-audit -r requirements.txt --no-deps`. Ahí sí falló por las vulnerabilidades. Además, `gh-action-pip-audit@v1.1.0` avisa de `Unexpected input(s) 'disable-pip'`: esa opción de la guía solo existe en la rama `main` de la acción, todavía no en la versión fijada.

Una alerta de Dependabot avisa y propone un PR, pero no impide fusionar nada; el check `SCA - pip-audit` obligatorio sí: si un PR deja una dependencia vulnerable, no entra en `main`. No se exigió desde la Parte G porque entonces `main` tenía 12 vulnerabilidades conocidas y ningún PR (ni siquiera los de Semgrep o Dependabot) habría podido fusionarse: primero se deja la casa limpia y luego se cierra la puerta (trinquete).

### Q. Divulgación coordinada (simulacro)

- Informe recibido de (usuario de GitHub):
- Identificador del borrador de aviso (GHSA-…):
- Severidad y vector CVSS:
- CWE:
- Versiones afectadas / versión corregida:

### R. Versión 1.0.0 verificable

| Comprobación | Comando | Resultado |
|---|---|---|
| Huellas SHA-256 | `sha256sum -c SHA256SUMS` | OK para `reportaudit-1.0.0.tar.gz` y `reportaudit-sbom.cdx.json` ("La suma coincide") |
| Procedencia (SLSA) | `gh attestation verify reportaudit-1.0.0.tar.gz --repo PabloVip/reportaudit-lab` | Correcta (código de salida 0). `predicateType` `https://slsa.dev/provenance/v1`, firmada por `.github/workflows/publicar-version.yml@refs/tags/v1.0.0`, commit `f1d6306` |
| SBOM atestado | `gh attestation verify reportaudit-1.0.0.tar.gz --repo PabloVip/reportaudit-lab --predicate-type https://cyclonedx.org/bom` | Correcta (código de salida 0), mismo workflow, etiqueta y commit |
| Archivo alterado | `gh attestation verify alterado.tar.gz --repo PabloVip/reportaudit-lab` | Falla: la huella pasa de `3f636415…` a `06c7162c…` y no existe ninguna atestación para ella (HTTP 404, código de salida 1) |

Release: https://github.com/PabloVip/reportaudit-lab/releases/tag/v1.0.0, creada por el workflow `Publicar versión firmada` al subir la etiqueta anotada `v1.0.0` sobre `f1d6306`. Contiene `reportaudit-1.0.0.tar.gz`, `reportaudit-sbom.cdx.json`, `SHA256SUMS`, `reportaudit-provenance.sigstore.json` y `reportaudit-sbom.sigstore.json`. La verificación la hice descargando la Release en `~/verificacion-v1.0.0`, fuera del repositorio.

Qué detecta cada comprobación: las huellas detectan una descarga incompleta o corrupta, pero no un atacante que cambie a la vez el archivo y `SHA256SUMS`. La procedencia detecta cualquier archivo que no haya construido mi workflow desde mi repositorio y esa etiqueta, aunque el atacante también cambie las huellas, porque no puede falsificar la firma de Sigstore. El SBOM atestado demuestra que ese SBOM describe exactamente ese paquete. Lo que ninguna detecta es que el propio código del repositorio sea malicioso o tenga fallos, o que alguien comprometa el workflow: en ese caso la procedencia diría la verdad (qué workflow y qué commit), pero el archivo saldría firmado igual. Por eso los workflows se revisan como el código.

### S. Madurez (OpenSSF Scorecard)

Resultado del análisis del 24/11/2026 sobre `f1d6306` (relanzado a mano después de publicar la v1.0.0): https://scorecard.dev/viewer/?uri=github.com/PabloVip/reportaudit-lab

| Check | Puntuación (0–10) | Qué la explica |
|---|---|---|
| Puntuación global | 6,5 | Media ponderada de los checks que se pudieron calcular (antes de la Release era 6,4) |
| Maintained | 0 | El repositorio se creó hace menos de 90 días; Scorecard no puntúa la actividad hasta entonces |
| Pinned-Dependencies | 0 | Las acciones de los workflows están fijadas por etiqueta (`@v6`, `@v4`…) y no por el hash del commit |
| License | 0 | No hay archivo de licencia en el repositorio |
| Contributors | 0 | Todos los commits son de una sola persona, sin organizaciones o empresas distintas |
| Code-Review | 3 | «Found 4/13 approved changesets»: solo los PRs #14 a #17 tienen una aprobación antes de fusionarse; el commit de importación de la Parte A y el resto de PRs se fusionaron sin revisión aprobada |

Otros datos: Signed-Releases 8 (detecta los `.sigstore.json` de la v1.0.0; según la documentación de Scorecard, el 10 solo se da si la Release incluye la procedencia SLSA como `*.intoto.jsonl`); Branch-Protection sin datos (-1), porque el token del workflow no puede leer la protección clásica de ramas, como avisa la guía; Token-Permissions, Security-Policy, Dependency-Update-Tool, Dangerous-Workflow, Binary-Artifacts y Vulnerabilities a 10; SAST 9 y CI-Tests 9.

El check que me parece más útil para elegir una dependencia es Vulnerabilities, junto con Dependency-Update-Tool y Security-Policy: dicen si el proyecto tiene fallos conocidos abiertos y si hay un proceso para corregirlos y recibir avisos. El más engañoso sin contexto es Maintained: el 0 de ReportAudit no significa abandono ni inseguridad, solo que el repositorio es nuevo. Con Code-Review pasa algo parecido en sentido contrario: mide si hubo una aprobación en GitHub, no si la revisión fue buena.

### T. Expediente de evidencias

Ver `docs/cra/expediente-evidencias.md`.

Compara el expediente con tu respuesta B5 de la Práctica 2: ¿qué evidencia imaginaste que ahora
existe de verdad, y cuál sigue sin existir?

En la B5 propusimos, para cada requisito del Anexo I, una práctica y una evidencia auditable. Ahora existen de verdad:

- **Sin vulnerabilidades explotables conocidas:** pedíamos SAST y SCA en cada PR y en la release, con informes y un VEX. Está: los cuatro checks obligatorios en verde sobre el commit de la v1.0.0, Grype y Trivy «después» con 0 vulnerabilidades y el VEX de CVE-2024-49766.
- **SBOM:** pedíamos Syft en CI por release, en CycloneDX y versionado. Está, y mejor de lo que imaginamos: el SBOM de la v1.0.0 lo genera el workflow de publicación y va atestado con Sigstore junto al paquete.
- **Parche sin demora y actualizaciones firmadas:** Dependabot está activo, las dependencias vulnerables se actualizaron (#18 y #20), la puerta `SCA - pip-audit` impide que vuelvan a entrar y la Release está firmada.
- **CVD y punto de contacto:** `SECURITY.md` publicado con plazos y el canal privado de GitHub activado.

Sigue sin existir: el tiempo de respuesta medido y un SLA de parcheo (no hay datos reales de incidentes), la documentación técnica del Anexo VII, los ADR de diseño que pusimos para «minimizar la superficie de ataque» y un test automático de configuración segura (la revisé en el PR #23, pero no hay un test que falle si alguien vuelve a poner `debug=True` o una credencial en `config.yaml`). Además, en la B5 dábamos por hecho que cada PR tendría su revisión, y en este repositorio la mayoría de PRs se fusionaron sin aprobación (se ve en el Code-Review de Scorecard).

---

## Preguntas de comprobación (Sección 7 de la guía)

1. En mi caso no he usado Windows ni WSL2: trabajo en CachyOS, que ya es Linux. Todo lo que la guía coloca en Ubuntu (la carpeta `~/reportaudit-lab`, el entorno virtual con Python 3.12, Git, pre-commit con Semgrep, Syft, Grype, Trivy, Gitleaks y `reportes.db`) vive directamente en mi equipo, igual que VS Code y el navegador. En GitHub están el repositorio público, los Pull Requests, el pipeline de Actions, el secreto `SONAR_TOKEN`, la protección de `main`, Dependabot y los resultados de CodeQL. En SonarQube Cloud están la organización, el proyecto y el panel de resultados. Se trabaja en Linux porque los runners del pipeline son `ubuntu-latest` y las herramientas están hechas para Linux: lo que funciona en mi terminal se comporta igual en la nube.

2. Una dependencia directa es la que el equipo decide instalar y aparece en `requirements.in`; una transitiva llega arrastrada por otra. En `requirements.txt`, `flask` tiene `# via -r requirements.in` (directa) y `werkzeug 3.0.1` tiene `# via flask` (transitiva). En `sbom.cyclonedx.json` aparecen 9 paquetes de Python cuando solo pedimos 2, y las vulnerabilidades más importantes (werkzeug y jinja2) estaban precisamente en las transitivas.

3. El *source* es el punto por donde entra un dato que controla el usuario y el *sink* el punto donde ese dato puede hacer daño. Ejemplo real: `request.args.get("cliente")` en `servicio.py:41` (source) se pasa a `buscar_reportes_cliente(cliente)` y, dentro de `reporte_auditoria.py`, se pegaba al texto SQL y llegaba a `cursor.execute(query)` en la línea 42 (sink). Lo mismo con `archivo`, que llegaba a `os.system(comando)`.

4. La consulta se construía pegando el nombre dentro de comillas simples. El apóstrofo de `o'brien_ltd` cerraba la cadena antes de tiempo y `brien_ltd'` pasaba a leerse como SQL, por eso salía `near "brien_ltd": syntax error`. Si un apóstrofo inocente cambia la consulta, un texto preparado a propósito (por ejemplo `' OR '1'='1`) también puede hacerlo: el dato y la orden no estaban separados. Con la consulta parametrizada `o'brien_ltd` devuelve su reporte y `' OR '1'='1` devuelve 0 filas.

5. El hook actúa en mi máquina antes de que el commit exista, así que el código inseguro no llega ni al historial ni a GitHub; SonarQube Cloud y CodeQL solo lo ven después del push. Pero solo no basta: solo funciona si se ha hecho `pre-commit install`, se puede saltar con `--no-verify`, y con `p/python` y `p/secrets` no detectó ni la inyección SQL, ni la de comandos, ni las dos credenciales (solo el YAML y el MD5).

6. No es un error de ninguna: cada motor razona de forma distinta. Semgrep busca patrones archivo a archivo y por eso ve el `yaml.load`, pero no el recorrido desde `servicio.py`. SonarQube Cloud y CodeQL hacen análisis de flujo entre archivos y encuentran las dos inyecciones, pero ninguno marcó el YAML. Los detectores de secretos de Trivy buscan formatos de proveedores y no reconocieron ninguna de las dos credenciales. En la matriz, H3 solo lo encontró Semgrep, H6 solo SonarQube y H5 ninguno de forma directa (CodeQL solo marcó la línea donde se imprimía en el log). Además, SonarQube Cloud encontró en mi PR de corrección una inyección de argumentos (`pythonsecurity:S6350`) que yo no había visto: la lista blanca solo comprobaba el nombre final del archivo.

7. Porque son problemas de categorías distintas. Las alertas de CodeQL (SAST) están en mi código: se cerraron cuando el análisis de `main` dejó de encontrarlas tras fusionar el PR de corrección. Las de Dependabot (SCA) dependen de las versiones de `requirements.txt`, que ese PR no tocaba. Y el PR de Dependabot solo cambió versiones, así que el código vulnerable seguía igual y CodeQL lo seguía viendo.

8. Borrar la línea solo quita el secreto de la versión actual: el valor sigue en el commit de importación (`2e3417f`), en cada clon y en cada fork, y el repositorio es público. Corregirlo de verdad es rotar la credencial en el proveedor para que el valor antiguo ya no sirva, y además sacarla del código (ahora se lee de variables de entorno) y añadir controles para que no vuelva a entrar.

9. Ignorar una alerta no deja rastro: nadie sabe después quién lo decidió ni por qué, y la alerta vuelve a aparecer. El VEX deja escrito qué vulnerabilidad, en qué componente exacto (purl), con qué estado, con qué justificación estándar, quién lo firma y cuándo, y se puede revisar. Mi VEX declara `CVE-2024-49766` en `pkg:pypi/werkzeug@3.0.1` como `not_affected` con `vulnerable_code_not_in_execute_path`: el fallo está en `safe_join()` y solo en Windows, y ReportAudit corre en Linux y nunca llama a esa función. Aun así se actualizó werkzeug, porque el parche era barato.

10. Descarga la versión fijada de cada herramienta y el archivo oficial de sumas SHA-256, calcula la huella de lo descargado, la compara con la publicada y solo instala si coinciden. Eso detecta una descarga corrupta o alterada por el camino. Lo que no puede garantizar es que la publicación oficial sea legítima: en el caso de Trivy de marzo de 2026 los atacantes controlaban las etiquetas de la publicación, así que la huella publicada habría sido la del binario malicioso. Fijar versiones ya revisadas reduce ese riesgo, y verificar la firma de la publicación lo reduciría más.

11. `gitleaks dir app` analiza los archivos como están hoy, y desde la Parte M las credenciales se leen del entorno, así que sale limpio. `gitleaks git .` recorre todos los commits y el de importación (`2e3417f`) sigue teniendo los dos valores: el historial no se borra al hacer un commit nuevo, y además está en GitHub, en cada clon y en cada fork. La medida que cierra el riesgo es la rotación de las credenciales; sacarlas del código evita que se sigan usando desde ahí, pero no hace que dejen de estar publicadas.

12. Porque en la Parte G `main` tenía 12 vulnerabilidades conocidas en las dependencias, y con pip-audit obligatorio ningún PR habría podido fusionarse hasta arreglarlas, ni siquiera los de Semgrep o Dependabot. El trinquete es eso: primero llevas el repositorio a un nivel (en mi caso, 0 vulnerabilidades tras fusionar #18 y #20) y solo después prohíbes bajar de ahí. Por eso la regla de `main` empezó con PR y aprobación, en la G se añadieron los dos checks SAST y en la P los de SCA y secretos; ninguna se ha quitado.

13. La alerta de Dependabot es informativa: avisa de que una versión tiene un aviso publicado y propone un PR, pero no bloquea nada. `SCA - pip-audit` es un check obligatorio en `main`: si un PR deja una dependencia vulnerable en el lockfile, ese PR no se puede fusionar. Lo comprobé en el PR #29, que bajaba werkzeug a 3.1.3 y quedó en rojo.

14. Demuestra que `reportaudit-1.0.0.tar.gz` lo construyó el workflow `publicar-version.yml` de `PabloVip/reportaudit-lab` a partir de la etiqueta `v1.0.0` (commit `f1d6306`), y que nadie lo ha modificado después: la firma de Sigstore va ligada a la huella exacta del archivo. No demuestra que el código sea seguro; eso lo dicen los checks de cada PR y el SBOM. `SHA256SUMS` no basta porque se descarga del mismo sitio que el paquete: quien pueda cambiar el archivo en la Release o en un espejo puede cambiar también las huellas, y `sha256sum -c` seguiría diciendo OK. La atestación no la puede rehacer sin la identidad del workflow; con `alterado.tar.gz` la verificación falló.

15. Porque un Issue es público desde el primer momento: publicaría cómo atacar el producto antes de que exista un parche, y cualquiera podría aprovecharlo. El canal privado (Security → Report a vulnerability) solo lo ven el responsable y quien informa, y permite preparar la corrección en un borrador de aviso antes de hacerlo público. `SECURITY.md` es el sitio donde se explica todo eso: qué versiones tienen soporte y hasta cuándo (1.x hasta 2031-10-31), cómo informar, en cuánto tiempo respondemos (3 días hábiles para el acuse, 10 para la evaluación, 90 para la divulgación) y que no habrá acciones legales contra quien informe de buena fe.

16. No es un problema de seguridad. `Maintained` mide si ha habido actividad en los últimos 90 días y Scorecard pone 0 a cualquier repositorio creado hace menos de 90 días, como este. Igual pasa con `License` (no hay archivo de licencia) o `Fuzzing`: dicen qué prácticas no se ven, no que el código sea vulnerable. Una métrica hay que leerla con su motivo al lado; si no, una nota baja puede asustar sin razón y una alta puede dar una falsa sensación de seguridad.

17. En la B5 imaginamos sobre todo informes: «0 blocker + VEX», un SBOM versionado, una política publicada. Ahora casi todo eso existe y, sobre todo, se puede comprobar sin fiarse de mí: cada fila del expediente lleva un enlace y un comando (por ejemplo, `gh attestation verify` sobre la Release). Lo que sigue sin existir es lo que no sale de una herramienta: el SLA de parcheo con tiempos medidos, la documentación técnica del Anexo VII, la evaluación de riesgos, los ADR de diseño y un test que falle si la configuración deja de ser segura. El detalle está en la sección T.

## Backlog del laboratorio (Issues)

| Issue | Título | PR o evidencia de cierre |
|---|---|---|
| #1 | Adopt an international pull request template | PR #14 fusionada |
| #2 | Run SAST (SonarQube Cloud and CodeQL) on every pull request | PR #15 fusionada |
| #3 | Block insecure commits with a Semgrep pre-commit hook | PR #16 fusionada |
| #4 | Enable Dependabot alerts and security updates | PR #17 fusionada, cerrada a mano (12 alertas = Grype; PRs #18-20 en espera de M.5) |
| #5 | Remediate the findings of the security audit | PR #23 fusionado |
| #6 | Upgrade the vulnerable dependencies | PRs de Dependabot #18 y #20 fusionados (#19 cerrado sin fusionar); cerrado a mano con comentario |
| #7 | Publish the audit log and the before/after evidence | PR #30 fusionado |
| #8 | Detect ReportAudit credentials in the whole Git history | PR #24 fusionado |
| #9 | Make SCA and secret scanning required checks on main | PR #28 fusionado + PR de prueba #29 cerrado sin fusionar; cerrado a mano tras P.4 |
| #10 | Publish a security policy and a private vulnerability reporting channel | PR #25 fusionado + canal privado activado; falta el simulacro Q.3 con el compañero |
| #11 | Release v1.0.0 with an SBOM and signed provenance | PR #26 fusionado + Release v1.0.0 verificada; cerrado a mano tras R.3 |
| #12 | Measure supply-chain maturity with OpenSSF Scorecard | PR #27 fusionado |
| #13 | Build the CRA evidence index | PR de la Parte T (expediente y bitácora final) |
