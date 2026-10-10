"use strict";
const { cpus, setPriority, constants: osConstants } = require('os');
const dns = require('dns');
const http2 = require('http2');
const tls = require('tls');
const WebSocket = require('ws');
const fs = require('fs');

// 1. MAX THREADPOOL & REALTIME PROCESS PRIORITY
process.env.UV_THREADPOOL_SIZE = String(Math.max(128, cpus().length * 8));
process.setMaxListeners(0);
try {
    if (osConstants && osConstants.priority && osConstants.priority.PRIORITY_HIGHEST !== undefined) {
        setPriority(process.pid, osConstants.priority.PRIORITY_HIGHEST);
    }
} catch (_) {}

// 2. DNS OPTIMIZATION (Force IPv4 first to eliminate dual-stack lookup lag)
if (dns.setDefaultResultOrder) {
    dns.setDefaultResultOrder('ipv4first');
}

// ---------------- CONFIGURATION ----------------
const token = "for";
const guildid = '1555861276696256533';
const SESSION_COUNT = 8;
const TLS_COUNT = 8;
let mfaToken = "";
const vanityCache = new Map();

// If an entitlement delete event arrives WITHOUT a guild_id, fire for every cached vanity.
const FIRE_ALL_ON_UNKNOWN_ENTITLEMENT = false;

const noop = () => {};

// 3. EXACT BROWSER HEADERS & FINGERPRINT
const USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";
const SEC_CH_UA = '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"';
const SUPER_PROPERTIES = "eyJicm93c2VyIjoiQ2hyb21lIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiQ2hyb21lIiwiY2xpZW50X2J1aWxkX251bWJlciI6MjkzMDAwfQ==";

// Gateway payloads
const identifyBuffer = JSON.stringify({
    op: 2,
    d: {
        token,
        intents: 1,
        properties: { os: 'Windows', browser: 'Chrome', device: 'Desktop' },
        guild_subscriptions: false,
        large_threshold: 0
    }
});
const heartbeatBuffer = '{"op":1,"d":null}';

// Timing trackers
const tlsStarts = new Array(TLS_COUNT);
for (let i = 0; i < TLS_COUNT; i++) tlsStarts[i] = process.hrtime();

// CLEAN LOG FORMATTER (Filters out Cloudflare HTML dumps & 5xx spam completely)
function logCleanResponse(protocol, idx, rawStr, ms) {
    if (!rawStr) return;

    // Ignore Cloudflare HTML / JS challenge pages completely
    if (rawStr.includes('<html') || rawStr.includes('<!DOCTYPE') || rawStr.includes('<script') || rawStr.includes('cf-wrapper')) {
        return;
    }

    const start = rawStr.indexOf('{');
    const end = rawStr.lastIndexOf('}');
    if (start !== -1 && end > start) {
        const jsonStr = rawStr.slice(start, end + 1).trim();
        try {
            const parsed = JSON.parse(jsonStr);
            if (parsed.code !== undefined || parsed.message !== undefined || parsed.vanity_url_code !== undefined) {
                console.log(`${protocol}[${idx}]: ${JSON.stringify(parsed)} - ${ms}ms`);
            }
        } catch (_) {}
    }
}

// 4. MFA AUTO-READER WITH INSTANT BUFFER REBUILD
function readMfa() {
    try {
        if (fs.existsSync("mfa.txt")) {
            const data = fs.readFileSync("mfa.txt", "utf8").trim();
            if (data && data !== mfaToken) {
                mfaToken = data;
                console.log(`[${new Date().toLocaleTimeString()}] MFA Token updated -> rebuilding pre-compiled buffers`);
                rebuildAllRequests();
            }
        }
    } catch (_) {}
}
readMfa();
try {
    fs.watch("mfa.txt", (eventType) => {
        if (eventType === "change" || eventType === "rename") readMfa();
    });
} catch (_) {}

// 5. PRE-BUILT REQUEST GENERATOR
function createPrebuiltRequest(vanity) {
    const bodyStr = `{"code":"${vanity}"}`;
    const bodyBuf = Buffer.from(bodyStr, "latin1");
    const len = bodyBuf.length;

    const entry = {
        vanity,
        bodyStr,
        bodyBuf,
        len,
        tlsBuf: null,
        h2Headers: null,
        trigger: null
    };

    function updateBuffers() {
        const mfaLine = mfaToken ? `\r\nx-discord-mfa-authorization: ${mfaToken}` : '';

        const rawHttp =
            `PATCH /api/v9/guilds/${guildid}/vanity-url HTTP/1.1\r\n` +
            `Host: canary.discord.com\r\n` +
            `Connection: keep-alive\r\n` +
            `Content-Length: ${len}\r\n` +
            `sec-ch-ua: ${SEC_CH_UA}\r\n` +
            `sec-ch-ua-mobile: ?0\r\n` +
            `authorization: ${token}\r\n` +
            `content-type: application/json\r\n` +
            `x-super-properties: ${SUPER_PROPERTIES}\r\n` +
            `sec-ch-ua-platform: "Windows"\r\n` +
            `accept: */*\r\n` +
            `user-agent: ${USER_AGENT}\r\n` +
            `sec-fetch-site: same-origin\r\n` +
            `sec-fetch-mode: cors\r\n` +
            `sec-fetch-dest: empty\r\n` +
            `accept-encoding: identity\r\n` +
            `accept-language: en-US,en;q=0.9` +
            `${mfaLine}\r\n\r\n` +
            bodyStr;

        entry.tlsBuf = Buffer.from(rawHttp, "latin1");

        entry.h2Headers = {
            ':method': 'PATCH',
            ':authority': 'canary.discord.com',
            ':scheme': 'https',
            ':path': `/api/v9/guilds/${guildid}/vanity-url`,
            'content-length': len,
            'sec-ch-ua': SEC_CH_UA,
            'sec-ch-ua-mobile': '?0',
            'authorization': token,
            'content-type': 'application/json',
            'x-super-properties': SUPER_PROPERTIES,
            'sec-ch-ua-platform': '"Windows"',
            'accept': '*/*',
            'user-agent': USER_AGENT,
            'sec-fetch-site': 'same-origin',
            'sec-fetch-mode': 'cors',
            'sec-fetch-dest': 'empty',
            'accept-encoding': 'identity',
            'accept-language': 'en-US,en;q=0.9'
        };
        if (mfaToken) {
            entry.h2Headers['x-discord-mfa-authorization'] = mfaToken;
        }
    }

    updateBuffers();
    entry.updateBuffers = updateBuffers;

    // Ultra-fast zero-overhead fire function
    entry.trigger = function() {
        const tBuf = entry.tlsBuf;
        const hHeaders = entry.h2Headers;
        const bBuf = entry.bodyBuf;

        // 1. Parallel write to all raw TLS Keep-Alive sockets
        for (let i = 0; i < TLS_COUNT; i++) {
            const s = tlsSocks[i];
            if (s && !s.destroyed) {
                tlsStarts[i] = process.hrtime();
                try { s.write(tBuf); } catch (_) {}
            }
        }

        // 2. Parallel dispatch to all HTTP/2 Multiplexed Sessions
        for (let i = 0; i < SESSION_COUNT; i++) {
            const conn = h2Conns[i];
            if (conn && !conn.destroyed) {
                try {
                    const t0 = process.hrtime();
                    const req = conn.request(hHeaders);
                    let resp = '';
                    req.on('data', chunk => { resp += chunk; });
                    req.on('end', () => {
                        const diff = process.hrtime(t0);
                        const ms = (diff[0] * 1000 + diff[1] / 1e6).toFixed(2);
                        logCleanResponse('h2', i, resp, ms);
                    });
                    req.on('error', noop);
                    req.end(bBuf);
                } catch (_) {}
            }
        }
    };

    return entry;
}

function rebuildAllRequests() {
    for (const [, entry] of vanityCache) {
        if (entry && entry.updateBuffers) {
            entry.updateBuffers();
        }
    }
}

// 6. HTTP/2 CONNECTIONS POOL
const h2Conns = new Array(SESSION_COUNT);
const createH2Session = (i) => {
    const session = http2.connect('https://canary.discord.com:443', {
        maxVersion: 'TLSv1.3',
        minVersion: 'TLSv1.3',
        ciphers: 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
        sigalgs: 'ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384',
        ecdhCurve: 'X25519:prime256v1:secp384r1',
        ALPNProtocols: ['h2'],
        rejectUnauthorized: false,
        highWaterMark: 128 * 1024,
        peerMaxConcurrentStreams: 1000,
        paddingStrategy: http2.constants.PADDING_STRATEGY_NONE,
        maxConcurrentStreams: 1000,
        enablePush: false,
        initialWindowSize: 6 * 1024 * 1024,
        maxFrameSize: 16384,
        headerTableSize: 65536,
        maxHeaderListSize: 262144
    });
    session.ref();
    session.once('connect', () => {
        try {
            const req = session.request({
                ':method': 'GET',
                ':authority': 'canary.discord.com',
                ':scheme': 'https',
                ':path': '/api/v9/gateway',
                'user-agent': USER_AGENT,
                'accept': '*/*'
            });
            req.on('error', noop);
            req.end();
        } catch (_) {}
    });
    session.on('error', () => { setTimeout(() => { h2Conns[i] = createH2Session(i); }, 50); });
    session.on('close', () => { setTimeout(() => { h2Conns[i] = createH2Session(i); }, 50); });
    return session;
};

// 7. TLS RAW SOCKETS POOL
const tlsSocks = new Array(TLS_COUNT).fill(null);
const tlsBackoff = new Array(TLS_COUNT).fill(500);
let tlsSession = undefined;

function createTLS(i) {
    const s = tls.connect({
        host: "canary.discord.com",
        port: 443,
        servername: "canary.discord.com",
        minVersion: "TLSv1.3",
        maxVersion: "TLSv1.3",
        ciphers: "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256",
        sigalgs: "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384",
        ecdhCurve: "X25519:prime256v1:secp384r1",
        ALPNProtocols: ["http/1.1"],
        rejectUnauthorized: false,
        honorCipherOrder: true,
        session: tlsSession,
        highWaterMark: 1024 * 1024,
        handshakeTimeout: 4000,
        timeout: 0
    });
    s.setNoDelay(true);
    s.setKeepAlive(true, 1000);
    s.on("session", sess => { tlsSession = sess; });
    s.on("secureConnect", () => {
        tlsSocks[i] = s;
        tlsBackoff[i] = 500;
        s.write('\r\n');
    });
    s.on("data", buf => {
        const diff = process.hrtime(tlsStarts[i]);
        const ms = (diff[0] * 1000 + diff[1] / 1e6).toFixed(2);
        const str = buf.toString("latin1");
        logCleanResponse('tls', i, str, ms);
    });
    s.on("timeout", () => { s.destroy(); });
    s.on("error", noop);
    s.on("close", () => {
        tlsSocks[i] = null;
        setTimeout(createTLS, tlsBackoff[i], i);
        tlsBackoff[i] = Math.min(tlsBackoff[i] * 2, 4000);
    });
}

for (let i = 0; i < TLS_COUNT; i++) createTLS(i);
for (let i = 0; i < SESSION_COUNT; i++) h2Conns[i] = createH2Session(i);

// 8. ULTRA-FAST SUBSTRING MATCHER
function extractStr(data, key) {
    const i = data.indexOf(key);
    if (i === -1) return null;
    const start = i + key.length;
    const end = data.indexOf('"', start);
    if (end === -1) return null;
    return data.slice(start, end);
}

// Resolve guild id from a raw dispatch payload (guild_id first, top-level id as fallback)
function extractGuildId(data) {
    return extractStr(data, '"guild_id":"') || extractStr(data, '"id":"');
}

// 9a. ENTITLEMENT DELETE HANDLER (replaces the old premium_subscription_count check)
// Matches ENTITLEMENT_DELETE, GUILD_POWERUP_ENTITLEMENTS_DELETE and any other *ENTITLEMENT*_DELETE dispatch.
function handleEntitlementDelete(eventName, data) {
    try {
        const gid = extractStr(data, '"guild_id":"');

        if (gid) {
            const entry = vanityCache.get(gid);
            if (entry) {
                entry.trigger();
                console.log(`[${new Date().toLocaleTimeString()}] [${eventName}] guild ${gid} -> fired for "${entry.vanity}"`);
            }
            return;
        }

        // No guild_id in payload -> optionally fire for every cached vanity
        if (FIRE_ALL_ON_UNKNOWN_ENTITLEMENT) {
            for (const [, entry] of vanityCache) entry.trigger();
            console.log(`[${new Date().toLocaleTimeString()}] [${eventName}] no guild_id -> fired for all ${vanityCache.size} cached vanities`);
        }
    } catch (_) {}
}

// 9b. GUILD UPDATE HANDLER (vanity change / removal only)
function handleGuildUpdate(data) {
    try {
        const gid = extractGuildId(data);
        if (!gid) return;
        const entry = vanityCache.get(gid);
        if (!entry) return;

        // Vanity code check: if code is cleared or changed
        const vanityKey = '"vanity_url_code":"';
        const vIdx = data.indexOf(vanityKey);
        let newCode = null;
        if (vIdx !== -1) {
            const vStart = vIdx + vanityKey.length;
            const vEnd = data.indexOf('"', vStart);
            if (vEnd !== -1) newCode = data.slice(vStart, vEnd);
        }

        if (!newCode || newCode !== entry.vanity) {
            entry.trigger();
        }
    } catch (_) {}
}

const H2_PING = Buffer.alloc(8);
const PING_GATEWAY = Buffer.from(
    `GET /api/v9/gateway HTTP/1.1\r\n` +
    `Host: canary.discord.com\r\n` +
    `Connection: keep-alive\r\n` +
    `sec-ch-ua: ${SEC_CH_UA}\r\n` +
    `sec-ch-ua-mobile: ?0\r\n` +
    `user-agent: ${USER_AGENT}\r\n` +
    `sec-ch-ua-platform: "Windows"\r\n` +
    `accept: */*\r\n\r\n`,
    "latin1"
);

// 10. KEEP-ALIVE WARMING PINGS
setInterval(() => {
    for (let i = 0; i < SESSION_COUNT; i++) {
        if (h2Conns[i] && !h2Conns[i].destroyed) {
            try { h2Conns[i].ping(H2_PING, noop); } catch (_) {}
        }
    }
}, 4000);

setInterval(() => {
    for (let i = 0; i < TLS_COUNT; i++) {
        const s = tlsSocks[i];
        if (s && !s.destroyed) {
            try { s.write(PING_GATEWAY); } catch (_) {}
        }
    }
}, 3500);

// 11. DUAL DISCORD GATEWAY CONNECTIONS
function connectGateway(url) {
    const sock = new WebSocket(url, {
        perMessageDeflate: false,
        skipUTF8Validation: true,
        followRedirects: false,
        rejectUnauthorized: false,
        maxRedirects: 0,
        handshakeTimeout: 30000,
        headers: { 'User-Agent': USER_AGENT },
    });
    let hbTimer = null;
    let hbAcked = true;
    let pingTimer = null;

    sock.onopen = () => {
        if (sock.readyState === WebSocket.OPEN) {
            sock.send(identifyBuffer);
        }
    };

    sock.onmessage = (msg) => {
        try {
            let data = msg.data;
            if (Buffer.isBuffer(data)) data = data.toString('utf-8');

            // Read the dispatch event name directly ("t":"EVENT_NAME") - no full JSON parse
            const eventName = extractStr(data, '"t":"');

            if (eventName) {
                // Entitlement delete -> fire instantly
                if (eventName.indexOf('ENTITLEMENT') !== -1 && eventName.endsWith('_DELETE')) {
                    handleEntitlementDelete(eventName, data);
                    return;
                }

                if (eventName === 'GUILD_UPDATE') {
                    handleGuildUpdate(data);
                    return;
                }

                if (eventName === 'READY') {
                    const d = JSON.parse(data).d;
                    const guilds = d.guilds;
                    if (guilds) {
                        for (let i = 0; i < guilds.length; i++) {
                            const g = guilds[i];
                            // Never watch our own claim guild (would undo our own claim)
                            if (g.id === guildid) continue;
                            if (g.vanity_url_code) {
                                vanityCache.set(g.id, createPrebuiltRequest(g.vanity_url_code));
                            }
                        }
                    }
                    readMfa();
                    console.log(`[${new Date().toLocaleTimeString()}] Ready on Gateway! Cached ${vanityCache.size} vanities.`);
                    return;
                }

                // Any other dispatch (op 0) -> ignore
                return;
            }

            const p = JSON.parse(data);
            if (p.op === 11) {
                hbAcked = true;
                return;
            }
            if (p.op === 7 || p.op === 9) {
                sock.close();
                return;
            }
            if (p.op === 10) {
                clearInterval(hbTimer);
                hbAcked = true;
                hbTimer = setInterval(() => {
                    if (sock.readyState !== WebSocket.OPEN) return;
                    if (!hbAcked) return sock.terminate();
                    try {
                        hbAcked = false;
                        sock.send(heartbeatBuffer);
                    } catch (_) {}
                }, p.d.heartbeat_interval);
            }
        } catch (_) {}
    };

    sock.onerror = () => sock.close();
    sock.onclose = () => {
        clearInterval(hbTimer);
        clearInterval(pingTimer);
        setTimeout(() => connectGateway(url), 1000);
    };

    pingTimer = setInterval(() => {
        if (sock.readyState !== WebSocket.OPEN) return;
        try { sock.ping(); } catch (_) {}
    }, 25000);
}

connectGateway("wss://gateway.discord.gg/?v=9&encoding=json");
connectGateway("wss://gateway-us-east1-b.discord.gg/?v=9&encoding=json");
console.log(`[${new Date().toLocaleTimeString()}] Fast sniper engine started with ${TLS_COUNT} TLS sockets and ${SESSION_COUNT} HTTP/2 sessions (trigger: ENTITLEMENT_DELETE + vanity change).`);
T} HTTP/2 sessions (trigger: ENTITLEMENT_DELETE + vanity change).`);
