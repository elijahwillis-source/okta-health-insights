"use strict";
/*
 * A fake OpenID Connect provider (like Okta) for tests. Zero dependencies.
 * Env: MOCK_OIDC_PORT (default 4061), MOCK_OIDC_CLIENT_ID / MOCK_OIDC_CLIENT_SECRET, MOCK_OIDC_REDIRECT (comma separated allowed redirect URIs)
 * Test controls: /_user?email=&name=&groups=a,b   who signs in next
 *                /_mode?m=ok|badnonce|badaud|badiss|expired|badsig|nogroups|error|noemail   how the next tokens are broken
 *                /_stats   what the provider saw
 */
const http = require("http"), crypto = require("crypto");
const PORT = +process.env.MOCK_OIDC_PORT || 4061, ISS = `http://localhost:${PORT}`;
const CID = process.env.MOCK_OIDC_CLIENT_ID || "0oaTEST", SECRET = process.env.MOCK_OIDC_CLIENT_SECRET || "s3cret-value";
const REDIRECTS = (process.env.MOCK_OIDC_REDIRECT || "http://localhost:8060/callback").split(",");
const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
const other = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 }).privateKey;
const jwk = Object.assign(publicKey.export({ format: "jwk" }), { kid: "k1", use: "sig", alg: "RS256" });
const b64u = b => Buffer.from(b).toString("base64url");
let user = { email: "owner@x.test", name: "Olivia Owner", groups: ["sightline-owners"] }, mode = "ok";
const codes = new Map(), tokens = new Map(), stats = { authorize: 0, token: 0, codeReused: 0, pkceFailed: 0, badSecret: 0, userinfo: 0, logouts: 0, lastAuthorize: "" };

function idToken(u, nonce) {
  const now = Math.floor(Date.now() / 1000);
  const claims = { iss: mode === "badiss" ? "http://evil.example" : ISS, aud: mode === "badaud" ? "someone-else" : CID, sub: "00u" + crypto.createHash("md5").update(u.email).digest("hex").slice(0, 10), iat: now, exp: mode === "expired" ? now - 3600 : now + 3600,
    nonce: mode === "badnonce" ? "not-the-nonce" : nonce, name: u.name };
  if (mode !== "noemail") claims.email = u.email; if (mode !== "nogroups") claims.groups = u.groups;
  const head = b64u(JSON.stringify({ alg: "RS256", kid: "k1", typ: "JWT" })), body = b64u(JSON.stringify(claims));
  const sig = crypto.sign("RSA-SHA256", Buffer.from(head + "." + body), mode === "badsig" ? other : privateKey);
  return head + "." + body + "." + b64u(sig);
}
const json = (res, status, o) => { res.writeHead(status, { "content-type": "application/json" }); res.end(JSON.stringify(o)); };
const body = req => new Promise(r => { let d = ""; req.on("data", c => d += c); req.on("end", () => r(Object.fromEntries(new URLSearchParams(d)))); });

http.createServer(async (req, res) => {
  const u = new URL(req.url, ISS), q = u.searchParams;
  if (u.pathname === "/.well-known/openid-configuration") return json(res, 200, { issuer: ISS, authorization_endpoint: ISS + "/authorize", token_endpoint: ISS + "/token", jwks_uri: ISS + "/keys", userinfo_endpoint: ISS + "/userinfo", end_session_endpoint: ISS + "/logout", response_types_supported: ["code"], id_token_signing_alg_values_supported: ["RS256"] });
  if (u.pathname === "/keys") return json(res, 200, { keys: [jwk] });
  if (u.pathname === "/_user") { user = { email: q.get("email"), name: q.get("name") || q.get("email"), groups: (q.get("groups") || "").split(",").filter(Boolean) }; return json(res, 200, user); }
  if (u.pathname === "/_mode") { mode = q.get("m") || "ok"; return json(res, 200, { mode }); }
  if (u.pathname === "/_stats") return json(res, 200, stats);
  if (u.pathname === "/authorize") {
    stats.authorize++; stats.lastAuthorize = u.search;
    if (q.get("client_id") !== CID) return json(res, 400, { error: "unauthorized_client" });
    const ru = q.get("redirect_uri"); if (!REDIRECTS.includes(ru)) return json(res, 400, { error: "redirect_uri_mismatch", got: ru });
    if (q.get("response_type") !== "code" || q.get("code_challenge_method") !== "S256" || !q.get("code_challenge") || !q.get("state") || !q.get("nonce")) return json(res, 400, { error: "invalid_request" });
    if (mode === "error") { res.writeHead(302, { location: ru + "?error=access_denied&error_description=" + encodeURIComponent("User is not assigned to the client application.") + "&state=" + q.get("state") }); return res.end(); }
    const code = crypto.randomBytes(16).toString("hex"); codes.set(code, { challenge: q.get("code_challenge"), nonce: q.get("nonce"), redirect: ru, user });
    res.writeHead(302, { location: ru + "?code=" + code + "&state=" + encodeURIComponent(q.get("state")) }); return res.end();
  }
  if (u.pathname === "/token" && req.method === "POST") {
    stats.token++; const f = await body(req), basic = (req.headers.authorization || "").replace(/^Basic /, "");
    if (Buffer.from(basic, "base64").toString() !== encodeURIComponent(CID) + ":" + encodeURIComponent(SECRET)) { stats.badSecret++; return json(res, 401, { error: "invalid_client" }); }
    const c = codes.get(f.code); if (!c) { stats.codeReused++; return json(res, 400, { error: "invalid_grant" }); } codes.delete(f.code);
    if (f.redirect_uri !== c.redirect) return json(res, 400, { error: "invalid_grant", error_description: "redirect_uri" });
    if (crypto.createHash("sha256").update(f.code_verifier || "").digest("base64url") !== c.challenge) { stats.pkceFailed++; return json(res, 400, { error: "invalid_grant", error_description: "PKCE" }); }
    const at = crypto.randomBytes(16).toString("hex"); tokens.set(at, c.user);
    return json(res, 200, { token_type: "Bearer", expires_in: 3600, access_token: at, id_token: idToken(c.user, c.nonce) });
  }
  if (u.pathname === "/userinfo") { stats.userinfo++; const t = tokens.get((req.headers.authorization || "").replace(/^Bearer /, "")); if (!t) return json(res, 401, { error: "invalid_token" }); return json(res, 200, { sub: "00u" + crypto.createHash("md5").update(t.email).digest("hex").slice(0, 10), email: t.email, name: t.name, groups: t.groups }); }
  if (u.pathname === "/logout") { stats.logouts++; res.writeHead(302, { location: q.get("post_logout_redirect_uri") || "/" }); return res.end(); }
  json(res, 404, { error: "not found" });
}).listen(PORT, () => console.log("mock OIDC on :" + PORT));
