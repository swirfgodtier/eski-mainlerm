"use strict";

const http2 = require('http2');
const tls = require('tls');
const net = require('net');
const WebSocket = require('ws');
const fs = require('fs');

const token = "O;
const guildid = '';
const istek = 8;

const vanityCache = new Map();
const fired = new Set();
let mfaToken = null;

const h2Conns = new Array(istek);
const tlsSocks = new Array(istek).fill({ write() { }, destroyed: true });
const tlsStarts = new Array(istek);
const tlsActive = new Array(istek).fill(false);
let tlsSession = undefined;

function readMfa() {
    try {
        const data = fs.readFileSync("mfa.txt", "utf8").trim();
        if (data && data !== mfaToken) mfaToken = data;
    } catch (e) { }
}
readMfa();
fs.watch("mfa.txt", (eventType) => {
    if (eventType === "change") readMfa();
});

const createH2 = (i) => {
    const session = http2.connect('https://canary.discord.com:443', {
        maxVersion: 'TLSv1.3',
        minVersion: 'TLSv1.3',
        ciphers: 'TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384',
        ecdhCurve: 'X25519',
        ALPNProtocols: ['h2'],
        rejectUnauthorized: false
    });
    session.ref();
    session.setTimeout(0);
    session.on('error', () => { setTimeout(() => { h2Conns[i] = createH2(i); }, 100); });
    session.on('close', () => { setTimeout(() => { h2Conns[i] = createH2(i); }, 100); });
    session.on('goaway', () => {
        try { session.destroy(); } catch (e) { }
        setTimeout(() => { h2Conns[i] = createH2(i); }, 100);
    });
    return session;
};

function createTLS(i) {
    const raw = net.connect({
        host: "canary.discord.com",
        port: 443,
        noDelay: true,
        keepAlive: true,
        keepAliveInitialDelay: 0
    });
    raw.setNoDelay(true);
    raw.setKeepAlive(true, 1000);

    const s = tls.connect({
        socket: raw,
        servername: "canary.discord.com",
        minVersion: "TLSv1.3",
        maxVersion: "TLSv1.3",
        ciphers: "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
        ALPNProtocols: ["http/1.1"],
        rejectUnauthorized: false,
        session: tlsSession
    });

    s.setNoDelay(true);
    s.setKeepAlive(true, 1000);

    s.on("session", sess => { tlsSession = sess; });
    s.on("secureConnect", () => {
        tlsSocks[i] = s;
        tlsActive[i] = false;
    });
    s.on("data", buf => {
        if (!tlsActive[i]) return;
        tlsActive[i] = false;
        const ms = (Number(process.hrtime.bigint() - tlsStarts[i]) / 1e6).toFixed(2);
        const str = buf.toString("latin1");
        const idx = str.indexOf("\r\n\r\n");
        const body = (idx !== -1 ? str.slice(idx + 4) : str).trim();
        console.log(`[TLS] ${body} - ${ms}ms`);
    });
    s.on("error", () => { });
    s.on("close", () => {
        tlsSocks[i] = { write() { }, destroyed: true };
        setTimeout(createTLS, 100, i);
    });
}

for (let i = 0; i < istek; i++) createTLS(i);
for (let i = 0; i < istek; i++) h2Conns[i] = createH2(i);

const H2_PING = Buffer.alloc(8);
const PING_PROBE = Buffer.from("HEAD /api/v9/gateway HTTP/1.1\r\nhost: canary.discord.com\r\nconnection: keep-alive\r\n\r\n", "latin1");

let h2Idx = 0;
setInterval(() => {
    const conn = h2Conns[h2Idx % istek];
    if (conn && !conn.destroyed && !conn.closed) {
        try { conn.ping(H2_PING, () => { }); } catch (e) { }
    }
    h2Idx++;
}, 3000);

let tlsIdx = 0;
setInterval(() => {
    const s = tlsSocks[tlsIdx % istek];
    if (s && !s.destroyed) {
        try { s.write(PING_PROBE); } catch (e) { }
    }
    tlsIdx++;
}, 3500);

function claim(vanity) {
    const body = `{"code":"${vanity}"}`;
    const bodyBuf = Buffer.from(body, "latin1");
    const len = bodyBuf.length;

    const mfaHdr = mfaToken ? `\r\nX-Discord-Mfa-Authorization: ${mfaToken}` : "";
    const tlsBuf = Buffer.from(
        `PATCH /api/v9/guilds/${guildid}/vanity-url HTTP/1.1\r\nHost: canary.discord.com\r\nAuthorization: ${token}\r\nContent-Type: application/json\r\nAccept-Encoding: identity\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\nX-Super-Properties: eyJicm93c2VyIjoiQ2hyb21lIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiQ2hyb21lIiwiY2xpZW50X2J1aWxkX251bWJlciI6MzU1NjI0fQ==${mfaHdr}\r\nContent-Length: ${len}\r\n\r\n${body}`,
        "latin1"
    );

    const h2Headers = {
        ':method': 'PATCH',
        ':path': `/api/v9/guilds/${guildid}/vanity-url`,
        ':scheme': 'https',
        ':authority': 'canary.discord.com',
        'authorization': token,
        'content-type': 'application/json',
        'accept-encoding': 'identity',
        'content-length': len,
        'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'x-super-properties': 'eyJicm93c2VyIjoiQ2hyb21lIiwiYnJvd3Nlcl91c2VyX2FnZW50IjoiQ2hyb21lIiwiY2xpZW50X2J1aWxkX251bWJlciI6MzU1NjI0fQ==',
    };
    if (mfaToken) h2Headers['x-discord-mfa-authorization'] = mfaToken;

    for (let i = istek - 1; i >= 0; i--) {
        const s = tlsSocks[i];
        if (s && !s.destroyed) {
            tlsStarts[i] = process.hrtime.bigint();
            tlsActive[i] = true;
            s.write(tlsBuf);
        }
    }

    for (let i = istek - 1; i >= 0; i--) {
        const conn = h2Conns[i];
        if (!conn || conn.destroyed || conn.closed) continue;
        try {
            const req = conn.request(h2Headers);
            const start = process.hrtime.bigint();
            let resp = '';
            req.on('data', chunk => { resp += chunk.toString('latin1'); });
            req.on('end', () => {
                const ms = (Number(process.hrtime.bigint() - start) / 1e6).toFixed(2);
                console.log(`[H2] ${resp} - ${ms}ms`);
            });
            req.on('error', () => { });
            req.end(bodyBuf);
        } catch (e) { }
    }
}

function extractStr(data, key) {
    const i = data.indexOf(key);
    if (i === -1) return null;
    const start = i + key.length;
    const end = data.indexOf('"', start);
    if (end === -1) return null;
    return data.slice(start, end);
}

function isVanityNull(data) {
    const key = '"vanity_url_code":';
    const pos = data.indexOf(key);
    if (pos === -1) return false;
    let i = pos + key.length;
    while (i < data.length && (data[i] === ' ' || data[i] === '\t')) i++;
    return data.startsWith('null', i) || data.startsWith('"null"', i);
}

function connectGateway(url) {
    const ws = new WebSocket(url);
    let hbTimer = null;
    let hbAcked = true;

    ws.on('message', (msg) => {
        try {
            const data = typeof msg === 'string' ? msg : msg.toString('utf-8');

            if (data.indexOf('GUILD_UPDATE') !== -1) {
                const gid = extractStr(data, '"id":"');
                if (gid && vanityCache.has(gid)) {
                    if (isVanityNull(data)) {
                        if (!fired.has(gid)) {
                            fired.add(gid);
                            claim(vanityCache.get(gid));
                        }
                        return;
                    }
                }
                return;
            }

            if (data.indexOf('READY') !== -1) {
                const parsed = JSON.parse(data);
                if (parsed.d && parsed.d.guilds) {
                    for (let i = 0; i < parsed.d.guilds.length; i++) {
                        const g = parsed.d.guilds[i];
                        if (g && g.id && g.vanity_url_code) {
                            vanityCache.set(g.id, g.vanity_url_code);
                        }
                    }
                }
                return;
            }

            if (data.indexOf('GUILD_CREATE') !== -1) {
                try {
                    const p = JSON.parse(data);
                    if (p.d && p.d.id && p.d.vanity_url_code) {
                        vanityCache.set(p.d.id, p.d.vanity_url_code);
                    }
                } catch (e) { }
                return;
            }

            if (data.indexOf('"op":0') !== -1) return;

            const p = JSON.parse(data);
            if (p.op === 11) {
                hbAcked = true;
                return;
            }
            if (p.op === 7 || p.op === 9) {
                ws.close();
                return;
            }
            if (p.op === 10) {
                clearInterval(hbTimer);
                hbAcked = true;
                ws.send(JSON.stringify({
                    op: 2,
                    d: {
                        token,
                        properties: { os: 'Windows', browser: 'Chrome', device: '' }
                    }
                }));
                hbTimer = setInterval(() => {
                    if (ws.readyState !== WebSocket.OPEN) return;
                    if (!hbAcked) return ws.terminate();
                    hbAcked = false;
                    try { ws.send('{"op":1,"d":null}'); } catch (e) { }
                }, p.d.heartbeat_interval);
            }
        } catch (e) { }
    });

    ws.on('close', () => {
        clearInterval(hbTimer);
        setTimeout(() => connectGateway(url), 1000);
    });

    ws.on('error', () => {
        ws.terminate();
    });
}

connectGateway("wss://gateway.discord.gg/?v=9&encoding=json");
connectGateway("wss://gateway-us-east1-b.discord.gg/?v=9&encoding=json");
