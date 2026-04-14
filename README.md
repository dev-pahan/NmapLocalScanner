# Nmap Local Scanner

Nmap Local Scanner is the local companion service for HCG. It runs Nmap on the user's own machine and securely uploads scan results back to the backend bridge endpoint.

The service listens on `http://127.0.0.1:47633` and is designed for localhost use.

## What This App Does

- Accepts short-lived bridge scan requests from the frontend flow.
- Executes Nmap locally with safe scan constraints.
- Parses and returns open-port/service/OS hints.
- Uploads scan result payloads to `/api/local-scanner/results`.
- Prints scanner + Nmap output to terminal for full transparency.

## Prerequisites

- Node.js 18+
- Nmap installed locally

## Quick Start for End Users

1. Install Nmap if it is not already installed.
2. Download the latest NmapLocalScanner release.
3. Extract the files to a folder of your choice.
4. Run `NmapLocalScanner.exe`.
5. Allow any Windows permission prompts if they appear.
6. Keep the scanner running while you use live scans in HCG.

## Build Windows EXE (Local Machine)

```powershell
cd NmapLocalScanner
npm install
npm run build:win
```

Output binary:

- `dist/NmapLocalScanner.exe`

## Nmap Setup Helper Mode

The app includes a manual helper mode for users who need setup guidance (no automatic system changes):

```powershell
node src/index.js --setup-nmap
```

or

```powershell
NmapLocalScanner.exe --setup-nmap
```

This mode prints:

- current Nmap detection status,
- safe install guidance,
- PATH and `NMAP_PATH` guidance,
- recommended non-admin run mode.

For everyday use, users should launch `NmapLocalScanner.exe` directly after installing Nmap.

## Release Checklist (Manual)

When publishing a new release:

1. Build the EXE on a clean local environment.
2. Run dependency scan:
	- `npm audit --omit=dev`
3. Generate SHA-256 checksum:
	- `Get-FileHash dist/NmapLocalScanner.exe -Algorithm SHA256`
4. (Recommended) Sign EXE with Authenticode certificate.
5. Create GitHub release and attach:
	- `NmapLocalScanner.exe`
	- `NmapLocalScanner.exe.sha256`

GitHub automatically provides source archives (`zip`/`tar.gz`) for each tag/release.

## Security Model

- Binds to localhost by default.
- Rejects disallowed origins and malformed requests.
- Allows only private/local scan targets.
- Validates upload destination path and origin.
- Refuses elevated/admin execution by default on Windows.
- Blocks concurrent overlapping scans.

## Terminal Visibility

Scanner logs include:

- request lifecycle events,
- exact Nmap command arguments,
- raw Nmap stdout (by default),
- upload success/failure details.

To hide raw Nmap stdout lines:

```powershell
$env:LOG_RAW_NMAP_OUTPUT="false"
npm start
```

## Environment Variables

- `PORT`: default `47633`
- `HOST`: default `127.0.0.1`
- `SCANNER_ALLOWED_ORIGINS`: extra allowed CORS origins
- `NMAP_SCAN_TIMEOUT_MS`: scan timeout in ms (default `60000`)
- `LOG_RAW_NMAP_OUTPUT`: `false` disables raw Nmap terminal lines
- `NMAP_PATH`: full path to `nmap.exe` or alternate executable name
- `ALLOW_ELEVATED_RUN`: set to `true` only if admin mode is intentionally required
