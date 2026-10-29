"use strict";
const { cpus } = require('os');
process.env.UV_THREADPOOL_SIZE = String(cpus().length * 4);

const http2 = require('http2');
const tls = require('tls');
const WebSocket = require('ws');
const fs = require('fs');
const token = "";
const guildid = '';
const SESSION_COUNT = 8; / double
const TLS_COUNT = 8; / double 
let mfaToken = null;
const vanityCache = new Map();

const identifyBuffer = JSON.stringify({op: 2,d: { token, intents: 1, properties: { os: 'linux', browser: 'chrome', device: 'chrome' }, guild_subscriptions: false, large_threshold: 0}});
const heartbeatBuffer = '{"op":1,"d":null}';

const h2Starts = new Array(SESSION_COUNT).fill(process.hrtime());
const h2Resps = new Array(SESSION_COUNT).fill('');
const tlsStarts = new Array(TLS_COUNT).fill(process.hrtime());

function readMfa() {
    try {
        const data = fs.readFileSync("mfa.txt", "utf8").trim();
        if (data && data !== mfaToken) mfaToken = data;
    } catch {}
}
readMfa();
fs.watch("mfa.txt", (eventType) => {if (eventType === "change") readMfa();});

const h2Conns = new Array(SESSION_COUNT);
const tlsSocks = new Array(TLS_COUNT).fill({ write() {}, destroyed: true });
const tlsBackoff = new Array(TLS_COUNT).fill(500);
let tlsSession = undefined;

const createH2Session = (i) => {
    const session = http2.connect('https://canary.discord.com:443', {
        maxVersion: 'TLSv1.3', minVersion: 'TLSv1.3',
        ciphers: 'TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384',
        ecdhCurve: 'X25519', ALPNProtocols: ['h2'], rejectUnauthorized: false,
        highWaterMark: 32 * 1024, peerMaxConcurrentStreams: 1000,
        paddingStrategy: http2.constants.PADDING_STRATEGY_NONE,
        maxConcurrentStreams: 500, enablePush: false, initialWindowSize: 4 * 1024 * 1024,
        maxFrameSize: 4 * 1024 * 1024, headerTableSize: 65536, maxHeaderListSize: 131072
    });
    session.ref();
    session.once('connect', () => {
        try {
            const req = session.request({
                ':method': 'GET', ':path': '/api/v9/gateway', ':scheme': 'https', ':authority': 'canary.discord.com',
            });
            req.on('error', () => {});
            req.end();
        } catch (e) {}
    });
    session.on('error', () => { setTimeout(() => { h2Conns[i] = createH2Session(i); }, 100); });
    session.on('close', () => { setTimeout(() => { h2Conns[i] = createH2Session(i); }, 100); });
    return session;
};

function createTLS(i) {
    const s = tls.connect({
        host: "canary.discord.com", port: 443, servername: "canary.discord.com",
        minVersion: "TLSv1.3", maxVersion: "TLSv1.3",
        ciphers: "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
        sigalgs: "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512",
        ecdhCurve: "X25519:prime256v1:secp384r1", ALPNProtocols: ["http/1.1"],
        rejectUnauthorized: false, honorCipherOrder: true, session: tlsSession,
        highWaterMark: 1024 * 1024, handshakeTimeout: 4000, timeout: 0
    });
    s.setNoDelay(true);
    s.setKeepAlive(true, 1000); // 1 second initial delay to keep polling the socket actively
    s.on("session", sess => { tlsSession = sess; });
    s.on("secureConnect", () => {
        tlsSocks[i] = s;
        tlsBackoff[i] = 500;
        s.write('\r\n');
    });
    s.on("data", buf => {
        const diff = process.hrtime(tlsStarts[i]);
        const ms = (diff[0] * 1000 + diff[1] / 1000000).toFixed(2);
        const str = buf.toString("latin1");
        if (str.includes('"code"')) {
            const parts = str.split("\r\n\r\n");
            if (parts.length > 1 && parts[1].includes('"code"')) {
                console.log(`[${i}]:`, parts[1], `- ${ms}ms`);
            }
        }
    });
    s.on("timeout", () => { s.destroy(); });
    s.on("error", () => {});
    s.on("close", () => {
        tlsSocks[i] = { write() {}, destroyed: true };
        setTimeout(createTLS, tlsBackoff[i], i);
        tlsBackoff[i] = Math.min(tlsBackoff[i] * 2, 5000);
    });
}
for (let i = 0; i < TLS_COUNT; i++) createTLS(i);
for (let i = 0; i < SESSION_COUNT; i++) h2Conns[i] = createH2Session(i);

function buildRequest(vanity) {
    const body = `{"code":"${vanity}"}`;
    const bodyy = Buffer.from(body, "latin1");
    const len = bodyy.length;
    let lastMfa = null;
    let cachedTlsBuf = null;

    return () => {
        if (lastMfa !== mfaToken || !cachedTlsBuf) {
            lastMfa = mfaToken;
            cachedTlsBuf = Buffer.from(
                `PATCH /api/v9/guilds/${guildid}/vanity-url HTTP/1.1\r\nHost: canary.discord.com\r\nAuthorization: ${token}\r\nContent-Type: application/json\r\nAccept-Encoding: identity\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nX-Super-Properties: "eyJicm93c2VyIjoiRmlyZWZveCIsImJyb3dzZXJfdXNlcl9hZ2VudCI6IkZpcmVmb3hfQ29tbWl0dGVkIn0="\r\nX-Discord-Mfa-Authorization: ${lastMfa}\r\nContent-Length: ${len}\r\n\r\n${body}`,
                "latin1"
            );
        }
        for (let i = h2Conns.length - 1; i >= 0; i--) {
            try {
                const conn = h2Conns[i];
                if (!conn || conn.destroyed) continue;
                
                const req = conn.request({
                    ':method': 'PATCH',
                    ':path': `/api/v9/guilds/${guildid}/vanity-url`,
                    ':authority': 'canary.discord.com',
                    'authorization': token,
                    'content-type': 'application/json',
                    "accept-encoding": 'identity',
                    'content-length': len,
                    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                    'x-super-properties': 'eyJicm93c2VyIjoiRmlyZWZveCIsImJyb3dzZXJfdXNlcl9hZ2VudCI6IkZpcmVmb3hfQ29tbWl0dGVkIn0=',
                    'x-discord-mfa-authorization': lastMfa,
                });
                
                h2Starts[i] = process.hrtime();
                h2Resps[i] = '';
                
                req.on('data', chunk => { h2Resps[i] += chunk.toString('latin1'); });
                req.on('end', () => {
                    const diff = process.hrtime(h2Starts[i]);
                    const ms = (diff[0] * 1000 + diff[1] / 1000000).toFixed(2);
                    if (h2Resps[i].includes('code')) console.log(`[${i}]:`, h2Resps[i], `- ${ms}ms`);
                    });
                req.on('error', () => {});
                req.end(bodyy);
            } catch (e) {}
        }
        for (let i = TLS_COUNT - 1; i >= 0; i--) {
            try {
                tlsStarts[i] = process.hrtime();
                tlsSocks[i].write(cachedTlsBuf);
            } catch (e) {}
        }
    };
}

function extractStr(data, key) {
    const i = data.indexOf(key);
    if (i === -1) return null;
    const start = i + key.length;
    const end = data.indexOf('"', start);
    if (end === -1) return null;
    return data.slice(start, end);
}

function handleGuildUpdate(data) {
    try {
        const gid = extractStr(data, '"id":"');
        if (!gid) return;
        const entry = vanityCache.get(gid);
        if (!entry) return;

        const boostKey = '"premium_subscription_count":';
        const bIdx = data.indexOf(boostKey);
        if (bIdx !== -1) {
            const bStart = bIdx + boostKey.length;
            const bEnd = data.indexOf(',', bStart);
            const countStr = data.slice(bStart, bEnd !== -1 ? bEnd : bStart + 5);
            const count = parseInt(countStr);
            if (count < 14) {
                entry[1]();
                return;
            }
        }

        const vanityKey = '"vanity_url_code":"';
        const vIdx = data.indexOf(vanityKey);
        let newCode = null;
        if (vIdx !== -1) {
            const vStart = vIdx + vanityKey.length;
            const vEnd = data.indexOf('"', vStart);
            if (vEnd !== -1) newCode = data.slice(vStart, vEnd);
        }
        
        if (!newCode || newCode === "null" || newCode !== entry[0]) {
            entry[1]();
        }
    } catch (e) {}
}

const H2_PING = Buffer.alloc(8);
const PING_GATEWAY = Buffer.from("GET /api/v9/gateway HTTP/1.1\r\nhost: canary.discord.com\r\nconnection: keep-alive\r\n\r\n", "latin1");
const PING_ROOT = Buffer.from("GET / HTTP/1.1\r\nhost: canary.discord.com\r\nconnection: keep-alive\r\n\r\n", "latin1");

// Keep sockets continuously warm and powerful
setInterval(() => {for (let i = h2Conns.length - 1; i >= 0; i--) {if (h2Conns[i] && !h2Conns[i].destroyed) h2Conns[i].ping(H2_PING, () => {});}}, 5000);
setInterval(() => {for (let i = TLS_COUNT - 1; i >= 0; i--) {if (!tlsSocks[i].destroyed) {try { tlsSocks[i].write(i % 2 === 0 ? PING_GATEWAY : PING_ROOT); } catch(e) {}}}}, 4000);

function connectGateway(url) {
    const sock = new WebSocket(url, {
        perMessageDeflate: false, skipUTF8Validation: true,
        followRedirects: false, rejectUnauthorized: false, maxRedirects: 0,
        handshakeTimeout: 30000,
        headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36' },
    });
    let hbTimer = null;
    let hbAcked = true;
    let pingTimer = null;
    sock.onopen = () => { if (sock.readyState === WebSocket.OPEN) sock.send(identifyBuffer); };
    sock.onmessage = (msg) => {
        try {
            let data = msg.data;
            if (Buffer.isBuffer(data)) data = data.toString('utf-8');
            if (data.indexOf('GUILD_UPDATE') !== -1) {
                handleGuildUpdate(data);
                return;
            }
            if (data.indexOf('READY') !== -1) {
                const d = JSON.parse(data).d;
                const guilds = d.guilds;
                for (let i = 0; i < guilds.length; i++) {
                    const g = guilds[i];
                    if (g.vanity_url_code) vanityCache.set(g.id, [g.vanity_url_code, buildRequest(g.vanity_url_code)]);
                }
                readMfa();
                return;
            }
            if (data.indexOf('"op":0') !== -1) return;
            const p = JSON.parse(data);
            if (p.op === 11) { hbAcked = true; return; }
            if (p.op === 7 || p.op === 9) { sock.close(); return; }
            if (p.op === 10) {
                clearInterval(hbTimer);
                hbAcked = true;
                hbTimer = setInterval(() => {
                    if (sock.readyState !== WebSocket.OPEN) return;
                    if (!hbAcked) return sock.terminate();
                    try { hbAcked = false; sock.send(heartbeatBuffer); } catch(e) {}
                }, p.d.heartbeat_interval);
            }
        } catch (e) {}
    };
    sock.onerror = () => sock.close();
    sock.onclose = () => {
        clearInterval(hbTimer);
        clearInterval(pingTimer);
        setTimeout(() => connectGateway(url), 1000);
    };
    pingTimer = setInterval(() => {
        if (sock.readyState !== WebSocket.OPEN) return;
        try { sock.ping(); } catch {}
    }, 30000);
}
connectGateway("wss://gateway.discord.gg/?v=9&encoding=json");
connectGateway("wss://gateway-us-east1-b.discord.gg/?v=9&encoding=json");

tGateway("wss://gateway-us-east1-b.discord.gg/?v=9&encoding=json");
