# cleaner-secure

![cleaner-secure logo](assets/logo.png)

`cleaner-secure` es un scanner de procesos, servicios, registry y red para Windows escrito en C17. Combina detección local con reputación opcional de VirusTotal (VT) y respuestas manuales auditadas. La GUI usa un worker thread para que el auto-refresco no bloquee la interfaz.

## Alcance

- **Process scanner** y **service scanner** con umbrales de CPU, RAM, handles e IO.
- **IOC matching** de nombres, rutas, hashes y servicios desde `config/iocs.json`.
- **Signature check** con `WinVerifyTrust`; solo `WinVerifyTrust` success cuenta como válido.
- **Registry scan** y **Event Log scan** con deadline por pasada.
- **Network scan** IPv4 con `GetExtendedTcpTable` / `GetExtendedUdpTable`: IPs maliciosas, puertos sospechosos, exceso de conexiones/IPs/puertos y reputación opcional.
- **Response actions** manuales: kill, suspend, resume, service stop/start, block IP y unblock IP.
- **Audit log** local en `%LOCALAPPDATA%\cleaner-secure\actions.log`.

La detección de red es IPv4. El bloqueo valida IPv4 e IPv6, pero las reglas se crean para direcciones IPv4 remotas.

## Requisitos

- Windows x64.
- LLVM-MinGW portable en `C:\llvm-mingw-20261117-ucrt-x86_64`.
- CMake 3.20+ y MinGW Makefiles. Ninja no es necesario.

## Build

```bash
export PATH="/c/llvm-mingw-20261117-ucrt-x86_64/bin:$PATH"
cmake -S . -B build \
  -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain-llvm-mingw.cmake \
  -DCMAKE_MAKE_PROGRAM="/c/llvm-mingw-20261117-ucrt-x86_64/bin/mingw32-make.exe" \
  -G "MinGW Makefiles"
cmake --build build
```

Outputs:

- `build/cleaner-secure-cli.exe`
- `build/cleaner-secure.exe`
- `build/cleaner-secure-tests.exe`

CMake copia `iocs.json`, `publishers.json` y `thresholds.json` a `build/config/`. La configuración se carga desde el directorio del ejecutable, no del CWD. `config/local.json` nunca se copia ni se versiona.

## Run

CLI:

```bash
./cleaner-secure-cli.exe --once
./cleaner-secure-cli.exe --interval 2
./cleaner-secure-cli.exe --json --once
```

Response actions (se ejecutan antes de cargar la configuración):

```bash
./cleaner-secure-cli.exe --kill <pid>
./cleaner-secure-cli.exe --suspend <pid>
./cleaner-secure-cli.exe --resume <pid>
./cleaner-secure-cli.exe --service-stop <name>
./cleaner-secure-cli.exe --service-start <name>
./cleaner-secure-cli.exe --block-ip <ip>
./cleaner-secure-cli.exe --unblock-ip <ip>
```

GUI:

```bash
./cleaner-secure.exe
```

La GUI muestra alertas ordenadas por score. `Analizar ahora` permite lookup live de VT con cap; el auto-refresco usa solo cache para no saturar el free tier ni bloquear la UI.

## Test

```bash
ctest --test-dir build --output-on-failure
```

O directamente:

```bash
cd build && ./cleaner-secure-tests.exe
```

El test binary no tiene filtros: `tests/test_main.c` registra todas las suites.

## Configuración

Archivos no secretos:

- `config/iocs.json`: `process_names`, `path_substrings`, `hashes_sha256`, `service_names`, `service_path_substrings`, `malicious_ips`, `suspicious_ports`.
- `config/publishers.json`: `trusted_publishers`.
- `config/thresholds.json`: umbrales de recursos, `scan_interval_seconds`, `eventlog_window_minutes`, `scan_timeout_ms`, ajustes de red y VT.

Secreto local:

- `config/local.json`: `vt_api_key` o `api_key`.Tiene prioridad sobre la variable de entorno `VT_API_KEY`.
- El archivo está en `.gitignore`; no commitear ni copiar al directorio de build.

Claves relevantes de red en `thresholds.json`:

| Key | Default | Uso |
| --- | ---: | --- |
| `network_enabled` | `true` | Activa el network scan. |
| `network_max_conns_per_pid` | `500` | Conexiones por PID antes de alertar. |
| `network_max_unique_ips_per_pid` | `100` | IPs remotas únicas por PID. |
| `network_max_listen_ports_per_pid` | `25` | Puertos listen por PID. |
| `network_vt_enabled` | `false` | Habilita lookup de IP en VT. |
| `network_vt_max_lookups` | `8` | Cap de lookups de IP por pasada. |
| `vt_auto_lookup` | `false` | Se mantiene por compatibilidad; el gate real es el modo manual/cache. |

`scan_timeout_ms` acota cada pasada completa (procesos → registry → Event Log → red). El default es `60000`. Valores `<= 1000` se interpretan como segundos y se multiplican por 1000. Valores muy bajos pueden dejar sin tiempo a registry/Event Log porque la verificación de firmas es lenta.

## VirusTotal

- Plan gratuito: 4 requests/minuto, rate limit local con sleep de hasta ~15s por lookup.
- Resultados en memoria; no se persisten reportes de VT.
- La presencia de key habilita VT; `VirusTotal: enabled|disabled` se imprime en stderr con `--json` para no romper stdout.
- Auto-refresco y `--interval`: cache-only.
- `--once` y el botón `Analizar ahora`: lookup live con cap.

## Seguridad y respuesta

- Las acciones revalidan la ruta de imagen del PID y deniegan PID 0/4/self, imágenes core del sistema y servicios críticos.
- `block-ip` / `unblock-ip` requieren elevación y crean/eliminan dos reglas de Windows Firewall (`IN` y `OUT`) con `NET_FW_ACTION_BLOCK`.
- Se deniegan loopback, privadas, multicast y CGNAT para evitar auto-bloqueos.
- Todo intento de respuesta se audita; los rechazos también quedan registrados.

## Estructura

```text
src/core/     lógica compartida, libcleaner_secure_core.a
src/cli/      frontend CLI
src/gui/      frontend Win32 y recursos
tests/        suites C links contra la misma lib
config/       IOC, publishers y thresholds
assets/       logo SVG/PNG/ICO
```

## Notas

- `WinVerifyTrust` success es el único signature check válido; unsigned se suprime en rutas de sistema salvo directorios sospechosos.
- `GetProcessIoCounters` usa totales acumulados: apps longevas pueden generar alertas de IO.
- No hay CI ni targets de lint/typecheck; `ctest` es la única verificación configurada.
