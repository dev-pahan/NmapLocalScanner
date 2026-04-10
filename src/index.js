const { execFile } = require('child_process');
const util = require('util');
const express = require('express');
const cors = require('cors');

const execFileAsync = util.promisify(execFile);
const app = express();

const PORT = Number(process.env.PORT) || 47633;
const HOST = process.env.HOST || '127.0.0.1';
const MAX_SCAN_TIMEOUT_MS = Number(process.env.NMAP_SCAN_TIMEOUT_MS) || 60000;

const ALLOWED_HOSTNAMES = new Set(['localhost', '127.0.0.1', '::1']);
const DEFAULT_ALLOWED_ORIGINS = [
    'http://localhost:3000',
    'http://localhost:5173',
    'http://localhost:5500',
    'http://127.0.0.1:3000',
    'http://127.0.0.1:5173',
    'http://127.0.0.1:5500',
    'https://minaga-s.github.io',
];

function normalizeOrigin(value = '') {
    return String(value || '').trim().replace(/\/$/, '').toLowerCase();
}

function parseAllowedOrigins() {
    const configured = String(process.env.SCANNER_ALLOWED_ORIGINS || '')
        .split(',')
        .map((origin) => normalizeOrigin(origin))
        .filter(Boolean);

    return new Set([...DEFAULT_ALLOWED_ORIGINS, ...configured]);
}

const allowedOrigins = parseAllowedOrigins();

app.use(cors({
    origin: (origin, callback) => {
        if (!origin) {
            callback(null, true);
            return;
        }

        const normalized = normalizeOrigin(origin);
        if (allowedOrigins.has(normalized) || /^https:\/\/[a-z0-9-]+\.github\.io$/i.test(normalized)) {
            callback(null, true);
            return;
        }

        callback(new Error('Origin is not allowed'));
    },
}));
app.use(express.json({ limit: '1mb' }));

function parseIpv4Address(value) {
    const octets = String(value || '').trim().split('.').map(Number);
    if (octets.length !== 4 || octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) {
        return null;
    }

    return octets;
}

function isPrivateIpv4Address(value) {
    const octets = parseIpv4Address(value);
    if (!octets) {
        return false;
    }

    const [first, second] = octets;
    if (first === 10 || first === 127) return true;
    if (first === 169 && second === 254) return true;
    if (first === 172 && second >= 16 && second <= 31) return true;
    if (first === 192 && second === 168) return true;
    if (first === 100 && second >= 64 && second <= 127) return true;
    return false;
}

function isAllowedTarget(target) {
    const normalized = String(target || '').trim().toLowerCase();
    if (!normalized) {
        return false;
    }

    if (ALLOWED_HOSTNAMES.has(normalized)) {
        return true;
    }

    if (normalized.endsWith('.local') || normalized.endsWith('.internal') || normalized.endsWith('.lan')) {
        return true;
    }

    return isPrivateIpv4Address(normalized);
}

function normalizePorts(portsInput) {
    const rawPorts = String(portsInput || '').trim();
    if (!rawPorts) {
        return '';
    }

    return rawPorts
        .split(',')
        .map((port) => Number(port.trim()))
        .filter((port) => Number.isInteger(port) && port >= 1 && port <= 65535)
        .join(',');
}

function buildCommandArgs(target, portsInput) {
    const args = ['-Pn', '-sV', '--version-light', '--open'];
    const normalizedPorts = normalizePorts(portsInput);

    if (normalizedPorts) {
        args.push('-p', normalizedPorts);
    }

    args.push('-oG', '-', target);
    return args;
}

function parsePortsLine(output) {
    const portsLineMatch = String(output || '').match(/Ports:\s+([^\n]+)/);
    if (!portsLineMatch) {
        return [];
    }

    return portsLineMatch[1]
        .split(', ')
        .map((entry) => {
            const parts = entry.split('/');
            const port = Number(parts[0]);
            const version = parts.slice(5).join('/').replace(/^\/+|\/+$/g, '').trim();

            return {
                port: Number.isInteger(port) ? port : null,
                state: parts[1] || '',
                protocol: parts[2] || 'tcp',
                service: parts[4] || 'unknown',
                version,
            };
        })
        .filter((entry) => entry.port !== null && entry.state === 'open');
}

function parseOsInfo(output) {
    const normalized = String(output || '');
    const osDetailsMatch = normalized.match(/OS details:\s*([^\n]+)/i);
    if (osDetailsMatch?.[1]) {
        return osDetailsMatch[1].trim();
    }

    const osGuessMatch = normalized.match(/Aggressive OS guesses:\s*([^\n]+)/i);
    if (osGuessMatch?.[1]) {
        return osGuessMatch[1].split(',').map((entry) => entry.trim()).filter(Boolean)[0] || '';
    }

    const runningMatch = normalized.match(/Running:\s*([^\n]+)/i);
    if (runningMatch?.[1]) {
        return runningMatch[1].trim();
    }

    return '';
}

function parseOsCpe(output) {
    const normalized = String(output || '');
    const cpeMatch = normalized.match(/OS CPE:\s*([^\n]+)/i);
    return cpeMatch?.[1] ? cpeMatch[1].trim() : '';
}

function parseHostState(output, target) {
    const hostLineMatch = String(output || '').match(/Host:\s+([^\s]+)\s+\((.*?)\)\s+Status:\s+([^\n]+)/);
    if (!hostLineMatch) {
        return {
            hostAddress: target,
            hostName: '',
            state: 'unknown',
        };
    }

    return {
        hostAddress: hostLineMatch[1] || target,
        hostName: hostLineMatch[2] || '',
        state: hostLineMatch[3] || 'up',
    };
}

function buildOsDetectionArgs(target) {
    return ['-Pn', '-O', '--osscan-guess', '--max-os-tries', '1', target];
}

function isHttpsOrHttpUrl(value) {
    try {
        const parsed = new URL(String(value || ''));
        return parsed.protocol === 'https:' || parsed.protocol === 'http:';
    } catch (error) {
        return false;
    }
}

function isValidUploadPath(uploadUrl) {
    try {
        const parsed = new URL(String(uploadUrl || ''));
        return parsed.pathname === '/api/local-scanner/results';
    } catch (error) {
        return false;
    }
}

async function runNmapScan({ target, ports }) {
    const scanArgs = buildCommandArgs(target, ports);

    const { stdout } = await execFileAsync('nmap', scanArgs, {
        maxBuffer: 5 * 1024 * 1024,
        timeout: MAX_SCAN_TIMEOUT_MS,
    });

    const services = parsePortsLine(stdout || '');
    let osInfo = parseOsInfo(stdout || '');
    let osCpe = parseOsCpe(stdout || '');

    if (!osInfo || !osCpe) {
        try {
            const { stdout: osStdout } = await execFileAsync('nmap', buildOsDetectionArgs(target), {
                maxBuffer: 5 * 1024 * 1024,
                timeout: MAX_SCAN_TIMEOUT_MS,
            });

            osInfo = osInfo || parseOsInfo(osStdout || '');
            osCpe = osCpe || parseOsCpe(osStdout || '');
        } catch (error) {
            osInfo = osInfo || '';
            osCpe = osCpe || '';
        }
    }

    return {
        target,
        requestedPorts: normalizePorts(ports),
        openPorts: services.map((service) => service.port),
        services,
        hostState: parseHostState(stdout || '', target),
        osInfo,
        osCpe,
        rawOutput: String(stdout || ''),
    };
}

app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        service: 'nmap-local-scanner',
        timestamp: new Date().toISOString(),
    });
});

app.post('/scan', async (req, res) => {
    const bridgeToken = String(req.body?.bridgeToken || '').trim();
    const uploadUrl = String(req.body?.uploadUrl || '').trim();
    const target = String(req.body?.target || '').trim();
    const ports = String(req.body?.ports || '').trim();

    if (!bridgeToken) {
        res.status(400).json({ success: false, message: 'bridgeToken is required' });
        return;
    }

    if (!uploadUrl || !isHttpsOrHttpUrl(uploadUrl)) {
        res.status(400).json({ success: false, message: 'A valid uploadUrl is required' });
        return;
    }

    if (!isValidUploadPath(uploadUrl)) {
        res.status(400).json({ success: false, message: 'uploadUrl must target /api/local-scanner/results' });
        return;
    }

    if (!isAllowedTarget(target)) {
        res.status(400).json({ success: false, message: 'Scan target is outside private/local scope' });
        return;
    }

    const startedAt = Date.now();

    try {
        const scanResult = await runNmapScan({ target, ports });
        const uploadResponse = await fetch(uploadUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                bridgeToken,
                scanResult: {
                    ...scanResult,
                    scanDurationMs: Date.now() - startedAt,
                },
            }),
        });

        const uploadPayload = await uploadResponse.json().catch(() => ({}));
        if (!uploadResponse.ok) {
            res.status(uploadResponse.status).json({
                success: false,
                message: uploadPayload?.message || 'Failed to upload local scan result',
            });
            return;
        }

        res.status(200).json(uploadPayload);
    } catch (error) {
        const isMissingNmap = error?.code === 'ENOENT';
        const message = isMissingNmap
            ? 'Nmap is not installed or unavailable in PATH'
            : `Local scan failed: ${error.message}`;

        res.status(500).json({ success: false, message });
    }
});

app.listen(PORT, HOST, () => {
    console.log(`[local-scanner] listening on http://${HOST}:${PORT}`);
});
