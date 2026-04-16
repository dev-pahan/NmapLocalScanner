const { execFile, spawnSync } = require('child_process');
const util = require('util');
const express = require('express');
const cors = require('cors');

const execFileAsync = util.promisify(execFile);
const app = express();

const PORT = Number(process.env.PORT) || 47633;
const HOST = process.env.HOST || '127.0.0.1';
const MAX_SCAN_TIMEOUT_MS = Number(process.env.NMAP_SCAN_TIMEOUT_MS) || 60000;
const SHOULD_LOG_RAW_NMAP_OUTPUT = String(process.env.LOG_RAW_NMAP_OUTPUT || 'true').toLowerCase() !== 'false';
const SHOULD_ALLOW_ELEVATED_RUN = String(process.env.ALLOW_ELEVATED_RUN || 'false').toLowerCase() === 'true';
const NMAP_EXECUTABLE = String(process.env.NMAP_PATH || 'nmap').trim() || 'nmap';
const MAX_BRIDGE_TOKEN_LENGTH = 4096;
const MAX_TARGET_LENGTH = 255;
const MAX_PORT_LIST_LENGTH = 512;
const MAX_PORT_COUNT = 128;
let isScanInProgress = false;
const CLI_ARGS = new Set(process.argv.slice(2).map((value) => String(value || '').trim().toLowerCase()));

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

app.disable('x-powered-by');

app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'no-referrer');
    res.setHeader('Cache-Control', 'no-store');
    next();
});

function isAllowedOrigin(origin) {
    const normalized = normalizeOrigin(origin);
    if (allowedOrigins.has(normalized) || /^https:\/\/[a-z0-9-]+\.github\.io$/i.test(normalized)) {
        return true;
    }

    try {
        const parsed = new URL(normalized);
        const host = String(parsed.hostname || '').toLowerCase();

        if (parsed.protocol === 'http:' && (host === 'localhost' || host === '127.0.0.1' || isPrivateIpv4Address(host))) {
            return true;
        }

        if (parsed.protocol === 'https:' && host.endsWith('.onrender.com')) {
            return true;
        }

        return false;
    } catch (error) {
        return false;
    }
}

app.use((req, res, next) => {
    if (req.headers['access-control-request-private-network'] === 'true') {
        res.setHeader('Access-Control-Allow-Private-Network', 'true');
    }

    next();
});

const corsOptions = {
    origin: (origin, callback) => {
        if (!origin) {
            callback(null, true);
            return;
        }

        if (isAllowedOrigin(origin)) {
            callback(null, true);
            return;
        }

        callback(new Error('Origin is not allowed'));
    },
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));
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

    if (!isSafeTargetFormat(normalized)) {
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

function isSafeTargetFormat(value) {
    if (!value || value.length > MAX_TARGET_LENGTH) {
        return false;
    }

    // Allow local hostnames and IPv4 only; block whitespace, slashes, colons, and option-like prefixes.
    if (value.startsWith('-')) {
        return false;
    }

    return /^[a-z0-9.-]+$/i.test(value);
}

function isValidBridgeToken(token) {
    if (!token || token.length > MAX_BRIDGE_TOKEN_LENGTH) {
        return false;
    }

    // JWT-like shape expected from backend bridge tokens.
    return /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token);
}

function normalizePorts(portsInput) {
    const rawPorts = String(portsInput || '').trim();
    if (!rawPorts) {
        return '';
    }

    if (rawPorts.length > MAX_PORT_LIST_LENGTH) {
        return '';
    }

    const normalizedPorts = rawPorts
        .split(',')
        .map((port) => Number(port.trim()))
        .filter((port) => Number.isInteger(port) && port >= 1 && port <= 65535);

    if (normalizedPorts.length === 0 || normalizedPorts.length > MAX_PORT_COUNT) {
        return '';
    }

    return normalizedPorts.join(',');
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

function logNmapStdout(stdout, phaseLabel) {
    if (!SHOULD_LOG_RAW_NMAP_OUTPUT) {
        return;
    }

    const lines = String(stdout || '')
        .split(/\r?\n/)
        .map((line) => line.trimEnd())
        .filter(Boolean);

    if (lines.length === 0) {
        console.log(`[local-scanner] ${phaseLabel}: no stdout`);
        return;
    }

    console.log(`[local-scanner] ${phaseLabel}: begin nmap output`);
    lines.forEach((line) => {
        console.log(`[nmap] ${line}`);
    });
    console.log(`[local-scanner] ${phaseLabel}: end nmap output`);
}

function isHttpsOrHttpUrl(value) {
    try {
        const parsed = new URL(String(value || ''));
        return parsed.protocol === 'https:' || parsed.protocol === 'http:';
    } catch (error) {
        return false;
    }
}

function normalizeOriginUrl(value) {
    try {
        const parsed = new URL(String(value || '').trim());
        const normalizedPath = parsed.pathname && parsed.pathname !== '/' ? parsed.pathname.replace(/\/$/, '') : '';
        return `${parsed.protocol}//${parsed.host}${normalizedPath}`.toLowerCase();
    } catch (error) {
        return '';
    }
}

function isAllowedUploadDestination(uploadUrl, backendOrigin) {
    try {
        const upload = new URL(String(uploadUrl || '').trim());
        const uploadHost = String(upload.hostname || '').toLowerCase();
        const isLocalUploadHost = uploadHost === 'localhost' || uploadHost === '127.0.0.1' || uploadHost === '::1' || isPrivateIpv4Address(uploadHost);

        if (!(upload.protocol === 'https:' || (upload.protocol === 'http:' && isLocalUploadHost))) {
            return false;
        }

        const normalizedBackendOrigin = normalizeOriginUrl(backendOrigin);
        if (normalizedBackendOrigin) {
            const backend = new URL(normalizedBackendOrigin);
            return upload.origin.toLowerCase() === backend.origin.toLowerCase();
        }

        return isLocalUploadHost || uploadHost.endsWith('.onrender.com');
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

function dedupePreserveOrder(values = []) {
    const seen = new Set();
    const ordered = [];

    values.forEach((value) => {
        const normalized = String(value || '').trim();
        if (!normalized || seen.has(normalized)) {
            return;
        }

        seen.add(normalized);
        ordered.push(normalized);
    });

    return ordered;
}

function buildUploadCandidates(uploadUrl, backendOrigin) {
    const candidates = [String(uploadUrl || '').trim()];

    const normalizedBackendOrigin = normalizeOriginUrl(backendOrigin);
    if (normalizedBackendOrigin) {
        candidates.push(`${normalizedBackendOrigin}/api/local-scanner/results`);
    }

    try {
        const upload = new URL(String(uploadUrl || '').trim());

        if (upload.hostname === 'localhost') {
            const localhostToIp = new URL(upload.toString());
            localhostToIp.hostname = '127.0.0.1';
            candidates.push(localhostToIp.toString());
        }

        if (upload.hostname === '127.0.0.1') {
            const ipToLocalhost = new URL(upload.toString());
            ipToLocalhost.hostname = 'localhost';
            candidates.push(ipToLocalhost.toString());
        }

        const isLikelyLocalHost = upload.protocol === 'http:'
            && (isPrivateIpv4Address(upload.hostname)
                || upload.hostname.endsWith('.local')
                || upload.hostname.endsWith('.internal')
                || upload.hostname.endsWith('.lan'));

        if (isLikelyLocalHost) {
            const localhostFallback = new URL(upload.toString());
            localhostFallback.hostname = 'localhost';
            candidates.push(localhostFallback.toString());

            const loopbackFallback = new URL(upload.toString());
            loopbackFallback.hostname = '127.0.0.1';
            candidates.push(loopbackFallback.toString());
        }
    } catch (error) {
        // Ignore malformed fallback candidates; request validation handles invalid input.
    }

    return dedupePreserveOrder(candidates).filter((candidate) => {
        return isHttpsOrHttpUrl(candidate)
            && isValidUploadPath(candidate)
            && isAllowedUploadDestination(candidate, backendOrigin);
    });
}

async function uploadScanResultWithFallback(candidates, body) {
    let lastNetworkError = null;
    const attemptedUrls = [];

    for (const candidate of candidates) {
        try {
            attemptedUrls.push(candidate);
            console.log(`[local-scanner] upload attempt url=${candidate}`);

            const response = await fetch(candidate, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body,
            });

            const payload = await response.json().catch(() => ({}));
            return {
                response,
                payload,
                url: candidate,
            };
        } catch (error) {
            const reason = error?.cause?.message || error?.message || 'unknown fetch error';
            console.warn(`[local-scanner] upload network failure url=${candidate} reason=${reason}`);
            lastNetworkError = error;
        }
    }

    if (lastNetworkError) {
        const reason = lastNetworkError?.cause?.message || lastNetworkError?.message || 'unknown fetch error';
        throw new Error(`Upload failed for all destinations (${attemptedUrls.join(', ')}): ${reason}`);
    }

    throw new Error('No valid upload destinations available');
}

function isWindowsProcessElevated() {
    if (process.platform !== 'win32') {
        return false;
    }

    try {
        const output = spawnSync('whoami', ['/groups'], { encoding: 'utf8' });
        if (output.status !== 0) {
            return false;
        }

        const groupsText = String(output.stdout || '').toLowerCase();
        return groupsText.includes('high mandatory level') || groupsText.includes('s-1-16-12288');
    } catch (error) {
        return false;
    }
}

function detectNmapVersion(commandValue) {
    try {
        const probe = spawnSync(commandValue, ['--version'], {
            encoding: 'utf8',
            timeout: 10000,
        });

        if (probe.status !== 0) {
            return '';
        }

        return String(probe.stdout || '')
            .split(/\r?\n/)
            .map((line) => line.trim())
            .find((line) => line.toLowerCase().startsWith('nmap version')) || '';
    } catch (error) {
        return '';
    }
}

function printManualNmapSetupGuide() {
    const isWin = process.platform === 'win32';
    const runningElevated = isWindowsProcessElevated();
    const currentProbe = detectNmapVersion(NMAP_EXECUTABLE);

    console.log('');
    console.log('[local-scanner] Nmap setup helper');
    console.log(`[local-scanner] platform: ${process.platform}`);
    console.log(`[local-scanner] configured NMAP_PATH/NMAP_EXECUTABLE: ${NMAP_EXECUTABLE}`);
    if (isWin) {
        console.log(`[local-scanner] elevated shell: ${runningElevated ? 'yes' : 'no'}`);
    }

    if (currentProbe) {
        console.log(`[local-scanner] detected: ${currentProbe}`);
    } else {
        console.log('[local-scanner] nmap not detected with current configuration');
    }

    console.log('');
    console.log('Step 1: Install Nmap from a trusted source');
    if (isWin) {
        console.log('  winget install --id Insecure.Nmap --silent --accept-package-agreements --accept-source-agreements');
    } else {
        console.log('  Use your OS package manager (apt/yum/brew) to install nmap');
    }

    if (isWin) {
        console.log('');
        console.log('Step 2: If PATH is not updated yet, set NMAP_PATH explicitly for this session');
        console.log('  $env:NMAP_PATH = "C:\\Program Files (x86)\\Nmap\\nmap.exe"');
    }

    console.log('');
    console.log('Step 3: Verify nmap');
    console.log('  nmap --version');

    console.log('');
    console.log('Step 4: Start NmapLocalScanner.exe from a standard (non-admin) terminal');
    console.log('  NmapLocalScanner.exe');
    console.log('');
}

async function verifyStartupSecurityAndDependencies() {
    if (isWindowsProcessElevated() && !SHOULD_ALLOW_ELEVATED_RUN) {
        throw new Error('Refusing to start as elevated administrator. Start NmapLocalScanner from a standard user shell, or set ALLOW_ELEVATED_RUN=true if absolutely required.');
    }

    try {
        await execFileAsync(NMAP_EXECUTABLE, ['--version'], {
            timeout: 10000,
            maxBuffer: 512 * 1024,
        });
    } catch (error) {
        throw new Error(`Nmap executable not found or not runnable: ${NMAP_EXECUTABLE}. Install nmap and ensure it is in PATH, or set NMAP_PATH to full nmap.exe path.`);
    }
}

async function runNmapScan({ target, ports }) {
    const scanArgs = buildCommandArgs(target, ports);
    console.log(`[local-scanner] executing ${NMAP_EXECUTABLE} ${scanArgs.join(' ')}`);

    const { stdout } = await execFileAsync(NMAP_EXECUTABLE, scanArgs, {
        maxBuffer: 5 * 1024 * 1024,
        timeout: MAX_SCAN_TIMEOUT_MS,
    });
    logNmapStdout(stdout || '', 'service-discovery');

    const services = parsePortsLine(stdout || '');
    let osInfo = parseOsInfo(stdout || '');
    let osCpe = parseOsCpe(stdout || '');

    if (!osInfo || !osCpe) {
        try {
            const osArgs = buildOsDetectionArgs(target);
            console.log(`[local-scanner] executing ${NMAP_EXECUTABLE} ${osArgs.join(' ')}`);
            const { stdout: osStdout } = await execFileAsync(NMAP_EXECUTABLE, buildOsDetectionArgs(target), {
                maxBuffer: 5 * 1024 * 1024,
                timeout: MAX_SCAN_TIMEOUT_MS,
            });
            logNmapStdout(osStdout || '', 'os-detection');

            osInfo = osInfo || parseOsInfo(osStdout || '');
            osCpe = osCpe || parseOsCpe(osStdout || '');
        } catch (error) {
            console.warn(`[local-scanner] os-detection failed: ${error.message}`);
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
    const backendOrigin = String(req.body?.backendOrigin || '').trim();
    const target = String(req.body?.target || '').trim();
    const ports = String(req.body?.ports || '').trim();

    if (!bridgeToken || !isValidBridgeToken(bridgeToken)) {
        res.status(400).json({ success: false, message: 'A valid bridgeToken is required' });
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

    if (!isAllowedUploadDestination(uploadUrl, backendOrigin)) {
        res.status(400).json({ success: false, message: 'uploadUrl origin is not allowed' });
        return;
    }

    if (!isAllowedTarget(target)) {
        res.status(400).json({ success: false, message: 'Scan target is outside private/local scope' });
        return;
    }

    if (isScanInProgress) {
        res.status(429).json({ success: false, message: 'A scan is already in progress. Please wait for completion.' });
        return;
    }

    const startedAt = Date.now();
    console.log(`[local-scanner] scan request received target=${target} ports=${ports || '<default>'}`);

    isScanInProgress = true;
    try {
        const scanResult = await runNmapScan({ target, ports });
        console.log(`[local-scanner] scan complete target=${target} openPorts=${scanResult.openPorts.length}`);
        const uploadCandidates = buildUploadCandidates(uploadUrl, backendOrigin);
        const requestBody = JSON.stringify({
            bridgeToken,
            scanResult: {
                ...scanResult,
                scanDurationMs: Date.now() - startedAt,
            },
        });

        const {
            response: uploadResponse,
            payload: uploadPayload,
            url: uploadedUrl,
        } = await uploadScanResultWithFallback(uploadCandidates, requestBody);

        if (!uploadResponse.ok) {
            console.error(`[local-scanner] upload failed status=${uploadResponse.status} target=${target} url=${uploadedUrl}`);
            res.status(uploadResponse.status).json({
                success: false,
                message: uploadPayload?.message || 'Failed to upload local scan result',
            });
            return;
        }

        console.log(`[local-scanner] upload complete status=${uploadResponse.status} target=${target} url=${uploadedUrl}`);

        res.status(200).json(uploadPayload);
    } catch (error) {
        const isMissingNmap = error?.code === 'ENOENT';
        const message = isMissingNmap
            ? `Nmap is not installed or unavailable in PATH (NMAP_PATH=${NMAP_EXECUTABLE})`
            : `Local scan failed: ${error.message}`;

        console.error(`[local-scanner] scan failed target=${target} code=${error?.code || 'unknown'} message=${error.message}`);

        res.status(500).json({ success: false, message });
    } finally {
        isScanInProgress = false;
    }
});

async function startServer() {
    try {
        await verifyStartupSecurityAndDependencies();
        app.listen(PORT, HOST, () => {
            console.log(`[local-scanner] listening on http://${HOST}:${PORT}`);
            console.log(`[local-scanner] nmap executable: ${NMAP_EXECUTABLE}`);
        });
    } catch (error) {
        console.error(`[local-scanner] startup failed: ${error.message}`);
        process.exit(1);
    }
}

if (CLI_ARGS.has('--setup-nmap') || CLI_ARGS.has('--doctor')) {
    printManualNmapSetupGuide();
    process.exit(0);
}

startServer();
