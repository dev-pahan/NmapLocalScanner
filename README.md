# Nmap Local Scanner

This companion app runs nmap on the user's own machine and securely uploads scan results back to the HCG backend.

## Quick Start

1. Install Node.js 18+ and nmap.
2. Run `npm install`.
3. Run `npm start`.
4. Keep this app running while using **Assets -> Run Live Scan**.

The app listens on `http://127.0.0.1:47633` and does not expose itself publicly.

## Security Controls

- Binds to localhost only.
- Accepts only short-lived signed bridge tokens issued by the backend.
- Restricts scan targets to private IP ranges or local hostnames.
- Rejects malformed upload URLs.

## Optional Environment Variables

- `PORT`: default `47633`
- `HOST`: default `127.0.0.1`
- `SCANNER_ALLOWED_ORIGINS`: comma-separated origins allowed to call local API.
