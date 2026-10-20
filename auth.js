"use strict";
/*
 * Sign-in for Sightline.
 *
 * With OIDC configured (OIDC_ISSUER, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, PUBLIC_URL, SESSION_SECRET) people sign in with Okta
 * (or any OpenID Connect provider): authorization code flow with PKCE, the ID token's signature checked against the provider's
 * published keys, issuer / audience / expiry / nonce verified, state tied to the browser by a cookie and single-use.
 * Roles come from the provider's groups: owner > admin > user.
 * A signed, HTTP-only session cookie points at a server-side session (kept in DATA_DIR so a redeploy does not sign anyone out;
 * sessions expire after SESSION_HOURS, or after SESSION_IDLE_MINUTES without use).
 * DASHBOARD_PASSWORD keeps working as a "break-glass" owner login (set BREAKGLASS_ENABLED=false to turn it off).
 * Without OIDC the old behaviour is unchanged: the password if one is set, otherwise open.
 * No dependencies: node:crypto and fetch.
 */
const crypto = require("crypto"), fs = require("fs"), path = require("path");

const ROLES = { user: 1, admin: 2, owner: 3 };
const b64u = b => Buffer.from(b).toString("base64url");
const list = v => String(v || "").split(",").map(x => x.trim()).filter(Boolean);
const esc = s => String(s == null ? "" : s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const safeNext = n => (typeof n === "string" && /^\/(?![/\\])[^\r\n]*$/.test(n) && n.length < 500 && !/^\/(login|callback|logout)\b/.test(n)) ? n : "/";

function createAuth({ env, dir, log, audit }) {
  const cfg = {
    issuer: String(env.OIDC_ISSUER || "").trim().replace(/\/+$/, ""), clientId: String(env.OIDC_CLIENT_ID || "").trim(), clientSecret: String(env.OIDC_CLIENT_SECRET || ""),
    publicUrl: String(env.PUBLIC_URL || "").trim().replace(/\/+$/, ""), secret: String(env.SESSION_SECRET || ""),
    scopes: String(env.OIDC_SCOPES || "openid profile email groups").trim(), groupsClaim: String(env.OIDC_GROUPS_CLAIM || "groups").trim(),
    ownerGroups: list(env.OIDC_OWNER_GROUPS).map(x => x.toLowerCase()), adminGroups: list(env.OIDC_ADMIN_GROUPS).map(x => x.toLowerCase()), userGroups: list(env.OIDC_USER_GROUPS).map(x => x.toLowerCase()),
    ownerEmails: list(env.OWNER_EMAILS).map(x => x.toLowerCase()), adminEmails: list(env.ADMIN_EMAILS).map(x => x.toLowerCase()),
    requireGroup: /^(1|true|yes)$/i.test(env.OIDC_REQUIRE_GROUP || ""),
    sessionMs: Math.max(0.05, +env.SESSION_HOURS || 12) * 36e5,
    idleMs: env.SESSION_IDLE_SECONDS ? +env.SESSION_IDLE_SECONDS * 1000 : Math.max(0, env.SESSION_IDLE_MINUTES === undefined || env.SESSION_IDLE_MINUTES === "" ? 60 : +env.SESSION_IDLE_MINUTES) * 60000,
    trustProxy: !/^(0|false|no)$/i.test(env.TRUST_PROXY || ""),
    dashUser: env.DASHBOARD_USER || "admin", dashPass: env.DASHBOARD_PASSWORD || "",
    breakglass: !/^(0|false|no|off)$/i.test(env.BREAKGLASS_ENABLED || "") && !!env.DASHBOARD_PASSWORD
  };
  const wanted = !!(cfg.issuer || cfg.clientId || cfg.clientSecret || cfg.publicUrl);
  const missing = []; if (wanted) { if (!cfg.issuer) missing.push("OIDC_ISSUER"); if (!cfg.clientId) missing.push("OIDC_CLIENT_ID"); if (!cfg.clientSecret) missing.push("OIDC_CLIENT_SECRET"); if (!cfg.publicUrl) missing.push("PUBLIC_URL"); if (cfg.secret.length < 32) missing.push("SESSION_SECRET (at least 32 characters)"); }
  const enabled = wanted && !missing.length, misconfigured = wanted && missing.length > 0;
  const secure = cfg.publicUrl.startsWith("https://"), origin = (() => { try { return new URL(cfg.publicUrl).origin; } catch { return ""; } })();
  if (enabled && !secure && !/^http:\/\/(localhost|127\.0\.0\.1)/.test(cfg.publicUrl)) log("WARNING: PUBLIC_URL is not https, so session cookies cannot be marked Secure.");
  if (misconfigured) log("Sign-in is NOT enabled: missing " + missing.join(", ") + ". Everything except /healthz is refused until this is fixed (the break-glass password still works if set).");

  const sessFile = path.join(dir, "sessions.json"), sessions = new Map(), pending = new Map();
  let saveT = null, persistent = false;
  try { fs.mkdirSync(dir, { recursive: true }); fs.accessSync(dir, fs.constants.W_OK); persistent = true; } catch { /* in memory */ }
  if (enabled && persistent) { try { for (const s of JSON.parse(fs.readFileSync(sessFile, "utf8"))) sessions.set(s.sid, s); log("Sign-in: restored " + sessions.size + " session(s)"); } catch { /* none yet */ } }
  const flush = () => { if (!persistent) return; clearTimeout(saveT); saveT = null; fs.writeFileSync(sessFile + ".tmp", JSON.stringify([...sessions.values()]), { mode: 0o600 }); fs.renameSync(sessFile + ".tmp", sessFile); };
  const saveSoon = () => { if (!persistent || saveT) return; saveT = setTimeout(() => { saveT = null; try { fs.writeFileSync(sessFile + ".tmp", JSON.stringify([...sessions.values()]), { mode: 0o600 }); fs.renameSync(sessFile + ".tmp", sessFile); } catch (e) { log("Sign-in: could not save sessions: " + e.message); } }, 1500); if (saveT.unref) saveT.unref(); };

  const sidHash = sid => crypto.createHash("sha256").update(sid).digest("hex").slice(0, 16);
  const hmac = v => crypto.createHmac("sha256", cfg.secret).update(v).digest("base64url");
  const sign = v => v + "." + hmac(v);
  const unsign = s => { const i = String(s || "").lastIndexOf("."); if (i < 1) return null; const v = s.slice(0, i), m = s.slice(i + 1), want = hmac(v); return m.length === want.length && crypto.timingSafeEqual(Buffer.from(m), Buffer.from(want)) ? v : null; };
  const cookies = req => { const o = {}; for (const p of String(req.headers.cookie || "").split(";")) { const i = p.indexOf("="); if (i > 0) o[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); } return o; };
  const setCookie = (name, value, maxAgeSec) => `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}; Max-Age=${maxAgeSec}`;
  const clientIp = req => { const x = String(req.headers["x-forwarded-for"] || "").split(",").map(s => s.trim()).filter(Boolean); return (cfg.trustProxy && x.length ? x[x.length - 1] : (req.socket && req.socket.remoteAddress) || "").replace(/^::ffff:/, ""); };

  // ---- discovery and keys
  let meta = null, metaAt = 0, jwks = null, jwksAt = 0;
  async function discover() {
    if (meta && Date.now() - metaAt < 36e5) return meta;
    const r = await fetch(cfg.issuer + "/.well-known/openid-configuration", { signal: AbortSignal.timeout(10000) }); if (!r.ok) throw new Error("discovery failed (" + r.status + ")");
    const m = await r.json(); if (String(m.issuer || "").replace(/\/+$/, "") !== cfg.issuer) throw new Error("the provider's issuer does not match OIDC_ISSUER");
    for (const k of ["authorization_endpoint", "token_endpoint", "jwks_uri"]) if (!m[k]) throw new Error("discovery has no " + k);
    meta = m; metaAt = Date.now(); return m;
  }
  async function keyFor(kid) {
    const m = await discover(), find = () => (jwks && jwks.keys || []).find(k => (!kid || k.kid === kid) && (!k.use || k.use === "sig"));
    if (!jwks || (!find() && Date.now() - jwksAt > 60000)) { const r = await fetch(m.jwks_uri, { signal: AbortSignal.timeout(10000) }); if (!r.ok) throw new Error("could not fetch the signing keys"); jwks = await r.json(); jwksAt = Date.now(); }
    const k = find(); if (!k) throw new Error("the token was signed with an unknown key"); return k;
  }
  async function verifyIdToken(token, nonce) {
    const parts = String(token || "").split("."); if (parts.length !== 3) throw new Error("the ID token is malformed");
    const head = JSON.parse(Buffer.from(parts[0], "base64url")), claims = JSON.parse(Buffer.from(parts[1], "base64url")), jwk = await keyFor(head.kid);
    const data = Buffer.from(parts[0] + "." + parts[1]), sig = Buffer.from(parts[2], "base64url"), key = crypto.createPublicKey({ key: jwk, format: "jwk" }); let good = false;
    if (head.alg === "RS256") good = crypto.verify("RSA-SHA256", data, key, sig); else if (head.alg === "ES256") good = crypto.verify("sha256", data, { key, dsaEncoding: "ieee-p1363" }, sig); else throw new Error("unsupported signing algorithm");
    if (!good) throw new Error("the ID token's signature is not valid");
    const m = await discover(), now = Date.now() / 1000;
    if (String(claims.iss || "").replace(/\/+$/, "") !== String(m.issuer).replace(/\/+$/, "")) throw new Error("the ID token is from a different issuer");
    const aud = [].concat(claims.aud || []); if (!aud.includes(cfg.clientId) || (aud.length > 1 && claims.azp !== cfg.clientId)) throw new Error("the ID token is for a different application");
    if (!(claims.exp > now - 60)) throw new Error("the ID token has expired"); if (claims.iat && claims.iat > now + 120) throw new Error("the ID token is from the future");
    if (!nonce || claims.nonce !== nonce) throw new Error("the ID token's nonce does not match this sign-in"); if (!claims.sub) throw new Error("the ID token has no subject");
    return claims;
  }
  function roleFor(email, groups) {
    const g = new Set(groups.map(x => String(x).toLowerCase())), any = l => l.some(x => g.has(x));
    if (cfg.ownerEmails.includes(email) || any(cfg.ownerGroups)) return "owner";
    if (cfg.adminEmails.includes(email) || any(cfg.adminGroups)) return "admin";
    if (cfg.userGroups.length ? any(cfg.userGroups) : !cfg.requireGroup) return "user";
    return null;
  }

  // ---- pages
  const page = (title, body) => `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)} · Sightline</title><link rel="icon" href="/favicon.svg"><style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:#0b0e1a;color:#e6e9f5;font:16px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}.c{max-width:480px;margin:16px;padding:30px;background:#121629;border:1px solid #2b3157;border-radius:16px}img{width:44px;height:44px;border-radius:10px}h1{font-size:20px;margin:14px 0 6px}p{color:#a9b0d0;margin:6px 0}code{background:#1c2140;padding:1px 6px;border-radius:5px}a.b{display:inline-block;margin-top:14px;padding:9px 18px;border-radius:10px;background:#7b8cff;color:#0b0e1a;font-weight:600;text-decoration:none}</style></head><body><div class="c"><img src="/favicon.svg" alt=""><h1>${esc(title)}</h1>${body}</div></body></html>`;
  const html = (res, status, body, extra) => { res.writeHead(status, Object.assign({ "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff", "x-frame-options": "DENY", "referrer-policy": "no-referrer", "content-security-policy": "default-src 'self'; style-src 'unsafe-inline'; img-src 'self'; frame-ancestors 'none'; base-uri 'none'" }, extra || {})); res.end(body); };
  const redirect = (res, to, extra) => { res.writeHead(302, Object.assign({ location: to, "cache-control": "no-store" }, extra || {})); res.end(); };
  const fail = (req, res, status, title, why, detail) => { audit.write({ cat: "auth", action: "auth.login.failed", ok: false, ip: clientIp(req), ua: req.headers["user-agent"], detail: detail || why }); html(res, status, page(title, `<p>${esc(why)}</p><a class="b" href="/login">Try again</a>`), { "set-cookie": setCookie("sl_login", "", 0) }); };

  const hits = new Map(); const rateOk = ip => { const now = Date.now(), a = (hits.get(ip) || []).filter(t => now - t < 60000); a.push(now); hits.set(ip, a); if (hits.size > 5000) hits.clear(); return a.length <= 40; };

  // ---- sessions
  function userOf(s) { return { sid: s.sid, id: s.sub, email: s.email, name: s.name || s.email, role: s.role, via: "oidc", verified: true, created: s.created, last: s.last, expires: Math.min(s.created + cfg.sessionMs, cfg.idleMs ? s.last + cfg.idleMs : Infinity) }; }
  function identify(req) {
    if (enabled) {
      const raw = cookies(req).sl_sid, sid = raw && unsign(raw), s = sid && sessions.get(sid), now = Date.now();
      if (s) {
        const gone = now - s.created > cfg.sessionMs ? "lifetime" : cfg.idleMs && now - s.last > cfg.idleMs ? "idle" : null;
        if (gone) { sessions.delete(sid); saveSoon(); audit.write({ cat: "auth", action: "auth.session.expired", actor: { email: s.email, name: s.name, role: s.role, verified: true, via: "oidc" }, ip: clientIp(req), detail: gone === "idle" ? "no activity" : "maximum session length" }); }
        else { if (now - s.last > 15000) { s.last = now; saveSoon(); } return userOf(s); }
      }
    }
    if (cfg.dashPass && (enabled || misconfigured ? cfg.breakglass : true)) {                       // the password: break-glass when SSO is on, the normal login otherwise
      const h = req.headers.authorization || "";
      if (h.startsWith("Basic ")) {
        const [u, ...p] = Buffer.from(h.slice(6), "base64").toString().split(":"), a = Buffer.from(u + ":" + p.join(":")), b = Buffer.from(cfg.dashUser + ":" + cfg.dashPass);
        const ipk = "bad:" + clientIp(req), failed = (hits.get(ipk) || []).filter(t => Date.now() - t < 60000);
        if (failed.length >= 20) return null;                                                          // too many wrong passwords from here: stop answering for a minute
        if (!(a.length === b.length && crypto.timingSafeEqual(a, b))) { failed.push(Date.now()); hits.set(ipk, failed); }
        else {
          const bg = enabled || misconfigured;
          if (bg) { const k = clientIp(req), now = Date.now(); if (!(hits.get("bg:" + k) > now - 600000)) { hits.set("bg:" + k, now); audit.write({ cat: "auth", action: "auth.breakglass", ip: k, ua: req.headers["user-agent"], actor: { name: "break-glass", role: "owner", via: "break-glass" }, detail: "signed in with the shared password" }); } }
          return { id: "password", email: "", name: bg ? "Break-glass" : "Password sign-in", role: "owner", via: bg ? "break-glass" : "password", verified: false };
        }
      }
    }
    if (!enabled && !misconfigured && !cfg.dashPass) return { id: "open", email: "", name: "Open access", role: "owner", via: "open", verified: false };
    return null;
  }

  async function handle(req, res, url) {
    const p = url.pathname;
    if (p === "/logged-out") { html(res, 200, page("You are signed out", `<p>See you next time.</p>${enabled ? '<a class="b" href="/login">Sign in again</a>' : ""}`)); return true; }
    if (!["/login", "/callback", "/logout", "/breakglass"].includes(p)) return false;
    const ip = clientIp(req);
    if (p === "/breakglass") {                                                                       // where the owner goes when sign-in itself is broken: the browser asks for the shared password
      if (!cfg.breakglass || !(enabled || misconfigured)) { redirect(res, "/"); return true; }
      const u = identify(req); if (u && u.via === "break-glass") { redirect(res, "/"); return true; }
      res.writeHead(401, { "www-authenticate": 'Basic realm="Sightline break-glass"', "cache-control": "no-store" }); res.end("Break-glass sign-in"); return true;
    }
    if (misconfigured) { html(res, 503, page("Sign-in is not set up", `<p>Single sign-on is only partly configured. Missing: <code>${esc(missing.join(", "))}</code>.</p><p>Until that is fixed, access is refused. If a break-glass password is set, it still works.</p>`)); return true; }
    if (!enabled) { redirect(res, "/"); return true; }
    if (p === "/logout") {
      const raw = cookies(req).sl_sid, sid = raw && unsign(raw), s = sid && sessions.get(sid);
      if (s) { sessions.delete(sid); saveSoon(); audit.write({ cat: "auth", action: "auth.logout", actor: { email: s.email, name: s.name, role: s.role, verified: true, via: "oidc" }, ip, ua: req.headers["user-agent"] }); }
      const clear = setCookie("sl_sid", "", 0); let to = "/logged-out";
      try { const m = await discover(); if (m.end_session_endpoint && s && s.idToken) to = m.end_session_endpoint + "?" + new URLSearchParams({ id_token_hint: s.idToken, post_logout_redirect_uri: cfg.publicUrl + "/logged-out" }); } catch { /* local sign-out is enough */ }
      redirect(res, to, { "set-cookie": clear }); return true;
    }
    if (!rateOk(ip)) { html(res, 429, page("Too many attempts", "<p>Wait a minute and try again.</p>")); return true; }
    if (p === "/login") {
      let m; try { m = await discover(); } catch (e) { audit.write({ cat: "auth", action: "auth.login.failed", ok: false, ip, detail: "provider unreachable: " + e.message }); html(res, 502, page("Cannot reach the sign-in provider", `<p>${esc(e.message)}</p><a class="b" href="/login">Try again</a>`)); return true; }
      const state = b64u(crypto.randomBytes(24)), nonce = b64u(crypto.randomBytes(24)), verifier = b64u(crypto.randomBytes(48)), challenge = crypto.createHash("sha256").update(verifier).digest("base64url");
      for (const [k, v] of pending) if (Date.now() - v.at > 600000) pending.delete(k); if (pending.size > 2000) pending.clear();
      pending.set(state, { nonce, verifier, next: safeNext(url.searchParams.get("next")), at: Date.now(), ip });
      const q = new URLSearchParams({ response_type: "code", client_id: cfg.clientId, redirect_uri: cfg.publicUrl + "/callback", scope: cfg.scopes, state, nonce, code_challenge: challenge, code_challenge_method: "S256" });
      redirect(res, m.authorization_endpoint + "?" + q, { "set-cookie": setCookie("sl_login", sign(state), 600) }); return true;
    }
    // /callback
    const state = url.searchParams.get("state") || "", pend = pending.get(state), bound = unsign(cookies(req).sl_login);
    pending.delete(state);                                                                          // a state is good for ONE attempt
    if (url.searchParams.get("error")) { fail(req, res, 400, "Sign-in was not completed", "The sign-in provider did not complete the sign-in (" + String(url.searchParams.get("error_description") || url.searchParams.get("error")).slice(0, 160) + ").", "provider error: " + url.searchParams.get("error")); return true; }
    if (!pend || !bound || bound !== state) { fail(req, res, 400, "That sign-in link is not valid", "The sign-in took too long, was already used, or did not start in this browser.", "state missing, reused, expired or not bound to this browser"); return true; }
    try {
      const m = await discover(), code = url.searchParams.get("code"); if (!code) throw new Error("no authorization code");
      const tr = await fetch(m.token_endpoint, { method: "POST", signal: AbortSignal.timeout(10000), headers: { "content-type": "application/x-www-form-urlencoded", accept: "application/json", authorization: "Basic " + Buffer.from(encodeURIComponent(cfg.clientId) + ":" + encodeURIComponent(cfg.clientSecret)).toString("base64") },
        body: new URLSearchParams({ grant_type: "authorization_code", code, redirect_uri: cfg.publicUrl + "/callback", code_verifier: pend.verifier }) });
      const tok = await tr.json().catch(() => ({})); if (!tr.ok || !tok.id_token) throw new Error("the code could not be exchanged (" + (tok.error || tr.status) + ")");
      const claims = await verifyIdToken(tok.id_token, pend.nonce);
      let groups = claims[cfg.groupsClaim], info = null;
      if (!Array.isArray(groups) && m.userinfo_endpoint && tok.access_token) { const ur = await fetch(m.userinfo_endpoint, { headers: { authorization: "Bearer " + tok.access_token }, signal: AbortSignal.timeout(10000) }).catch(() => null); info = ur && ur.ok ? await ur.json().catch(() => null) : null; if (info && info.sub === claims.sub) groups = info[cfg.groupsClaim]; }
      groups = (Array.isArray(groups) ? groups : groups ? [groups] : []).map(String).slice(0, 200);
      const email = String(claims.email || (info && info.email) || claims.preferred_username || "").trim().toLowerCase(), name = String(claims.name || (info && info.name) || email).slice(0, 120);
      if (!email) throw new Error("the sign-in provider did not return an email address");
      const role = roleFor(email, groups);
      if (!role) { audit.write({ cat: "auth", action: "auth.denied", ok: false, actor: { email, name, verified: true, via: "oidc" }, ip, ua: req.headers["user-agent"], detail: "signed in with Okta but is in none of the groups that may use Sightline" }); html(res, 403, page("You do not have access", `<p>You signed in as <code>${esc(email)}</code>, but your account is not in a group that may use Sightline. Ask an owner to add you.</p><a class="b" href="/logout">Sign out</a>`), { "set-cookie": setCookie("sl_login", "", 0) }); return true; }
      const sid = b64u(crypto.randomBytes(24)), now = Date.now();                                    // a NEW session id at every sign-in
      sessions.set(sid, { sid, sub: String(claims.sub), email, name, role, groups: groups.slice(0, 50), idToken: tok.id_token, created: now, last: now, ip, ua: String(req.headers["user-agent"] || "").slice(0, 160) }); saveSoon();
      audit.write({ cat: "auth", action: "auth.login", actor: { email, name, role, verified: true, via: "oidc" }, ip, ua: req.headers["user-agent"], detail: "role " + role + (groups.length ? " (" + groups.length + " group" + (groups.length === 1 ? "" : "s") + ")" : "") });
      redirect(res, pend.next, { "set-cookie": [setCookie("sl_sid", sign(sid), Math.floor(cfg.sessionMs / 1000)), setCookie("sl_login", "", 0)] });
    } catch (e) { fail(req, res, 403, "Sign-in failed", "We could not verify your sign-in: " + e.message + ".", e.message); }
    return true;
  }

  const roleAtLeast = (u, r) => !!u && (ROLES[u.role] || 0) >= (ROLES[r] || 99);
  return {
    enabled, misconfigured, missing, handle, identify, flush, roleAtLeast, clientIp, origin, cfg, ROLES,
    sessionList() { return [...sessions.values()].map(s => ({ id: sidHash(s.sid), sid: s.sid, email: s.email, name: s.name, role: s.role, created: s.created, last: s.last, ip: s.ip, ua: s.ua })).sort((a, b) => b.last - a.last); },
    revoke(id) { for (const s of sessions.values()) if (sidHash(s.sid) === id) { sessions.delete(s.sid); saveSoon(); return s; } return null; },
    describe() { return { enabled, issuerHost: (() => { try { return new URL(cfg.issuer).host; } catch { return ""; } })(), ownerGroups: cfg.ownerGroups, adminGroups: cfg.adminGroups, userGroups: cfg.userGroups, ownerEmails: cfg.ownerEmails, adminEmails: cfg.adminEmails, requireGroup: cfg.requireGroup, groupsClaim: cfg.groupsClaim, sessionHours: cfg.sessionMs / 36e5, idleMinutes: cfg.idleMs / 60000, breakglass: cfg.breakglass, persistent }; }
  };
}
module.exports = { createAuth, ROLES, safeNext };
