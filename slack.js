"use strict";
/*
 * Slack: post Sightline's alerts to a channel.
 *
 * Setup is one pasted JSON file (see MANIFEST below, also served by the app and kept in integrations/slack/app-manifest.json):
 * create a Slack app "from a manifest", install it, then set two settings: SLACK_BOT_TOKEN (the Bot User OAuth Token) and
 * SLACK_CHANNEL (where alerts go by default). The manifest already asks for exactly the permissions needed, and nothing else:
 *   chat:write         post messages as Sightline
 *   chat:write.public  post to public channels without having to be invited first (private channels still need an invite)
 * Sightline only ever POSTS: it cannot read channels, messages or people. Nothing comes back from Slack to Sightline.
 *
 * Safety: everything that came from outside (people's names, app names, cities, reasons) is escaped, so a name like "<!channel>"
 * cannot ping a channel or build a link. Sending is paced (Slack allows about one message a second per channel), a burst is summed up in
 * one message once SLACK_MAX_PER_MINUTE is reached, and a failure never affects the alert itself: it is still raised in the app.
 */
const MANIFEST = {
  _metadata: { major_version: 1, minor_version: 1 },
  display_information: { name: "Sightline", description: "Location and security alerts from Sightline, posted to the channel you choose.", background_color: "#0f172a" },
  features: { bot_user: { display_name: "Sightline", always_online: true } },
  oauth_config: { scopes: { bot: ["chat:write", "chat:write.public"] } },
  settings: { org_deploy_enabled: false, socket_mode_enabled: false, token_rotation_enabled: false }
};

const clip = (v, n) => String(v == null ? "" : v).replace(/[\u0000-\u001f\u007f]/g, " ").replace(/\s+/g, " ").trim().slice(0, n);
const mx = (v, n = 200) => clip(v, n).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");      // Slack's own escaping: it also defuses <!channel> and links
const HINTS = {
  not_in_channel: "Invite the Sightline app to that private channel (type /invite @Sightline there).", channel_not_found: "That channel was not found. Check the name or channel ID.",
  invalid_auth: "The token is not valid. Reinstall the app and copy a fresh Bot User OAuth Token.", token_revoked: "The token was revoked. Reinstall the app and copy a fresh Bot User OAuth Token.",
  account_inactive: "The Slack app or workspace is inactive.", missing_scope: "The app is missing a permission. Recreate it from the Sightline manifest.",
  is_archived: "That channel is archived.", rate_limited: "Slack asked Sightline to slow down.", timeout: "Slack did not answer in time.", network_error: "Slack could not be reached."
};

function createSlack({ env, log, fetchFn }) {
  const token = String(env.SLACK_BOT_TOKEN || "").trim(), channel = String(env.SLACK_CHANNEL || "").trim();
  const base = String(env.SLACK_API_BASE || "https://slack.com/api").replace(/\/+$/, "");
  const cap = Math.max(1, +env.SLACK_MAX_PER_MINUTE || 20), summaryMs = Math.max(1, +env.SLACK_SUMMARY_SECONDS || 60) * 1000;
  const publicUrl = String(env.SLACK_LINK_URL || env.PUBLIC_URL || "").replace(/\/+$/, ""),      // SLACK_LINK_URL so a site without sign-in can have links without PUBLIC_URL (which switches sign-in on)
     showIp = !/^(0|false|no|off)$/i.test(env.SLACK_SHOW_IP || "");
  const configured = !!(token && channel);
  const stats = { sent: 0, failed: 0, summarized: 0, lastOkAt: null, lastError: null, lastErrorAt: null };
  if (token && !channel) log("NOTE: SLACK_BOT_TOKEN is set but SLACK_CHANNEL is not: Slack alerts are off until a default channel is set.");
  if (!token && channel) log("NOTE: SLACK_CHANNEL is set but SLACK_BOT_TOKEN is not: Slack alerts are off until the token is set.");
  if (token && !/^xoxb-/.test(token)) log("NOTE: SLACK_BOT_TOKEN should start with xoxb- (the Bot User OAuth Token). A token starting differently will not work.");
  if (configured) log("Slack alerts are on (default channel " + channel + ")");

  async function call(method, body) {
    const ctl = new AbortController(), t = setTimeout(() => ctl.abort(), 8000);
    try {
      const r = await (fetchFn || fetch)(base + "/" + method, { method: "POST", headers: { "content-type": "application/json; charset=utf-8", authorization: "Bearer " + token }, body: JSON.stringify(body), signal: ctl.signal });
      if (r.status === 429) return { ok: false, error: "rate_limited", retryAfter: Math.min(60, Math.max(1, +r.headers.get("retry-after") || 5)) };
      const j = await r.json().catch(() => ({}));
      return j.ok ? { ok: true, ts: j.ts, channel: j.channel } : { ok: false, error: clip(j.error || ("http_" + r.status), 60) };
    } catch (e) { return { ok: false, error: e && e.name === "AbortError" ? "timeout" : "network_error" }; }
    finally { clearTimeout(t); }
  }
  const note = r => { if (r.ok) { stats.sent++; stats.lastOkAt = new Date().toISOString(); } else { stats.failed++; stats.lastError = r.error; stats.lastErrorAt = new Date().toISOString(); log("Slack: a message was not delivered (" + r.error + ")"); } return r; };

  // one at a time, a little apart, and a rate-limit answer is waited out and retried
  const queue = []; let working = false; const sentAt = []; let suppressed = 0, summaryTimer = null;
  const sleep = ms => new Promise(r => setTimeout(r, ms));
  async function work() {
    if (working) return; working = true;
    while (queue.length) {
      const job = queue.shift(); let r = null;
      for (let tries = 0; tries < 3; tries++) {
        r = await call("chat.postMessage", { channel: job.channel || channel, text: job.text, blocks: job.blocks, unfurl_links: false, unfurl_media: false });
        if (r.error === "rate_limited") { await sleep(r.retryAfter * 1000); continue; }
        if (r.error === "network_error" || r.error === "timeout") { await sleep(1500); continue; }
        break;
      }
      note(r); try { job.done && job.done(r); } catch { /* the caller's problem */ }
      if (queue.length) await sleep(1100);
    }
    working = false;
  }
  function flushSummary() {
    summaryTimer = null; if (!suppressed) return; const n = suppressed; suppressed = 0;
    enqueue({ text: "Sightline raised " + n + " more location alert" + (n === 1 ? "" : "s") + " in the last minute that were not posted one by one.", blocks: [{ type: "section", text: { type: "mrkdwn",
      text: "*" + n + " more location alert" + (n === 1 ? "" : "s") + "* were raised in the last minute and not posted one by one, to keep this channel readable." + (publicUrl ? "\n<" + publicUrl + "/#/alerts|Open Sightline> to see them all." : "") } }] }, true);
  }
  function enqueue(job, skipCap) {
    if (!configured) { try { job.done && job.done({ ok: false, error: "not_configured" }); } catch { /* ignore */ } return; }
    const now = Date.now(); while (sentAt.length && now - sentAt[0] > 60000) sentAt.shift();
    if (!skipCap && sentAt.length >= cap) {                                                              // a flood: sum it up instead of posting every one
      suppressed++; stats.summarized++; if (!summaryTimer) { summaryTimer = setTimeout(flushSummary, summaryMs); if (summaryTimer.unref) summaryTimer.unref(); }
      try { job.done && job.done({ ok: false, summarized: true }); } catch { /* ignore */ } return;
    }
    sentAt.push(now); queue.push(job); work();
  }

  function alertMessage(a) {
    const sev = { bad: "High", warn: "Medium", info: "Low" }[a.severity] || "Medium";
    const place = [a.where.city, a.where.region, a.where.country].filter(Boolean).join(", ") || "unknown location";
    const t = Math.floor(Date.parse(a.ts) / 1000);
    const what = a.kindLabel + (a.threshold > 1 ? " (" + a.matched + " in " + (a.windowMinutes >= 60 && a.windowMinutes % 60 === 0 ? a.windowMinutes / 60 + " h" : a.windowMinutes + " min") + ")" : "");
    const fields = [{ type: "mrkdwn", text: "*Person*\n" + mx(a.person || "unknown") }, { type: "mrkdwn", text: "*Where*\n" + mx(place) }, { type: "mrkdwn", text: "*What*\n" + mx(what) },
      { type: "mrkdwn", text: "*When*\n" + (isFinite(t) ? "<!date^" + t + "^{date_short_pretty} at {time_secs}|" + mx(a.ts, 40) + ">" : mx(a.ts, 40)) }];
    if (showIp && a.ip) fields.push({ type: "mrkdwn", text: "*IP address*\n" + mx(a.ip, 64) });
    if (a.app) fields.push({ type: "mrkdwn", text: "*App*\n" + mx(a.app, 80) });
    const blocks = [{ type: "header", text: { type: "plain_text", text: clip(a.ruleName, 140).replace(/[<>]/g, "") || "Location alert" } }, { type: "section", fields },
      { type: "context", elements: [{ type: "mrkdwn", text: "Severity: *" + sev + "*" + (a.reason ? "  ·  " + mx(a.reason, 120) : "") + (publicUrl ? "  ·  <" + publicUrl + "/#/alerts|Open in Sightline>" : "") }] }];
    return { text: "Sightline: " + mx(a.ruleName, 100) + " (" + mx(a.person || "unknown", 80) + " from " + mx(place, 80) + ")", blocks };      // the notification text is parsed too, so it is escaped like the rest
  }
  function genericMessage(a) {
    const sev = { bad: "High", warn: "Medium", info: "Low" }[a.severity] || "Medium", link = publicUrl ? publicUrl + "/#/" + clip((a.link && a.link.view) || "alerts", 20) : "";
    return { text: "Sightline: " + mx(a.title || a.ruleName, 100) + " (" + mx(a.body, 160) + ")", blocks: [
      { type: "header", text: { type: "plain_text", text: clip(a.title || a.ruleName, 140).replace(/[<>]/g, "") || "Alert" } },
      { type: "section", text: { type: "mrkdwn", text: mx(a.body, 600) || "(no details)" } },
      { type: "context", elements: [{ type: "mrkdwn", text: "Severity: *" + sev + "*" + (link ? "  \u00b7  <" + link + "|Open in Sightline>" : "") }] }] };
  }
  const info = () => ({ configured, channel: configured ? channel : "", tokenSet: !!token, channelSet: !!channel, maxPerMinute: cap, showIp,
    sent: stats.sent, failed: stats.failed, summarized: stats.summarized, lastOkAt: stats.lastOkAt, lastError: stats.lastError, lastErrorAt: stats.lastErrorAt,
    lastErrorHint: stats.lastError ? (HINTS[stats.lastError] || "Slack answered: " + stats.lastError) : null });
  return {
    configured, info, manifest: () => JSON.parse(JSON.stringify(MANIFEST)), hint: code => HINTS[code] || (code ? "Slack answered: " + code : ""),
    alertMessage, enqueue,
    // an alert from the rules; done({ok,error,ts,summarized}) says what happened to it
    sendAlert(a, done) { const m = a.where ? alertMessage(a) : genericMessage(a); enqueue({ channel: a.slack && a.slack.channel || "", text: m.text, blocks: m.blocks, done }); },
    // a message so an admin can check the setup end to end: it waits for the answer
    sendTest(who) {
      return new Promise(resolve => {
        if (!configured) return resolve({ ok: false, error: "not_configured" });
        enqueue({ text: "Sightline test message from " + mx(who, 80) + ". If you can read this, Slack alerts are working.", blocks: [{ type: "section", text: { type: "mrkdwn", text: "*Sightline test message*\nSent by " + mx(who, 80) + ". If you can read this, Slack alerts are working." } }], done: resolve }, true);
      });
    }
  };
}
module.exports = { createSlack, MANIFEST };
