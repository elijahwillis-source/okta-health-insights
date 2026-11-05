"use strict";
/*
 * Sightline's alert logic, shared by the page (which loads this file) and the server (which requires it), so there is ONE copy:
 * event helpers, error categories and filters, the Google scope-risk table, and the checks that decide when an alert fires.
 * It is moved out of the page as it was, not rewritten. Everything here is pure: it works on the data it is given and touches nothing else.
 *
 * The checks (evalRule, evalSilent, evalGoogleRule, runRules) take a context object instead of reading the page's state:
 *   events          the Okta events, oldest first          supOf(e)        the known-error rule that hides an event, or null
 *   catchingUp      true while old history is loading      silentNames()   the names of the apps that are silent now
 *   astate          { fired: {}, silent: null }, kept by the caller (the cooldowns and the silent baseline)
 *   google          { configured, events, approvals }      googleApps()    the Google apps worked out from those events
 */
(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  else { root.SightlineAlerts = api; Object.assign(root, api); }          // in the page, the helpers are plain globals, as they always were
})(typeof self !== "undefined" ? self : this, function () {
const fmtN = n => Number(n).toLocaleString();
const FAIL = new Set(["FAILURE","DENY","ERROR"]);
const ASSIGN_RE = /user_membership|provision|assign|\.push|import|user_management|app\.user|group\.user_membership/i;
const APP_ACTORS=/^(PublicClientApp|OAuth2Client|OAuth2AppInstance|AppInstance)$/;
function appOf(e){
  const t=(e.target||[]).find(x=>x.type==="AppInstance");
  if(t) return String(t.displayName||t.alternateId||t.id||"").trim()||null;
  const a=e.actor; if(a && APP_ACTORS.test(a.type||"")) return String(a.displayName||a.alternateId||"").trim()||null;   // OAuth/OIDC clients show up as the actor
  return null;
}
function userOf(e){
  const tg=e.target||[];
  const t=tg.find(x=>x.type==="User")||tg.find(x=>x.type==="AppUser");   // AppUser = the user's account inside an app (e.g. Active Directory)
  if(t) return t.alternateId||t.displayName;
  if(e.actor && e.actor.type==="User") return e.actor.alternateId||e.actor.displayName;
  return null;
}
function isFail(e){ return FAIL.has(e.outcome && e.outcome.result); }
function isAssign(e){ return ASSIGN_RE.test(e.eventType||""); }
function reasonOf(e){ return (e.outcome && e.outcome.reason) || e.displayMessage || "(no reason given)"; }
function ts(e){ return e._t!==undefined? e._t : (e._t=new Date(e.published).getTime()); }
function normErr(r){
  const t=String(r==null?"":r).replace(/"[0-9a-f]{12,}"/gi,'"<id>"').replace(/\b[0-9a-f]{20,}\b/gi,"<id>").replace(/\b0[0-9a-z]{2}[A-Za-z0-9]{17}\b/g,"<id>");
  const out=[]; for(const p of t.split(/;\s*/)){ const l=out[out.length-1];
    if(l&&(l.t===p||l.u===p)) l.n++;
    else if(l&&l.n===1&&l.t.length>p.length&&l.t.endsWith(p)){ l.n++; l.u=p; }       // the first copy is glued to a prefix
    else out.push({t:p,n:1,u:null}); }
  return out.map(x=>x.n>1? x.t+" (repeated "+x.n+" times)" : x.t).join("; ").slice(0,600);
}
const CATS={signin:"Sign-in & password",provision:"Provisioning & assignment",token:"Token & OAuth",access:"Access denied",other:"Other"};
const CAT_KEYS=["signin","provision","token","access","other"];
function catOf(e){
  if(e._c) return e._c;
  const t=e.eventType||"", r=reasonOf(e); let c;
  if(isAssign(e)) c="provision";
  else if(/^app\.oauth2|token|oauth/i.test(t)||/refresh_token|invalid_grant|login_required|consent_required|interaction_required/i.test(r)) c="token";
  else if((e.outcome&&e.outcome.result==="DENY")||/unauthorized access|not assigned|not authorized|access denied|policy/i.test(r)) c="access";
  else if(/authentication|session|sso|mfa|password|lockout|account\.lock|auth_via/i.test(t)||/password|credential|locked/i.test(r)) c="signin";
  else c="other";
  return (e._c=c);
}
const emptyFilter=()=>({cats:[],results:[],apps:[],include:"",exclude:"",person:""});
const filterActive=f=>!!(f&&(f.cats.length||f.results.length||f.apps.length||(f.include||"").trim()||(f.exclude||"").trim()||(f.person||"").trim()));
function compileFilter(f){
  if(!filterActive(f)) return null;
  const cats=new Set(f.cats), res=new Set(f.results), apps=new Set(f.apps), inc=(f.include||"").trim().toLowerCase(), per=(f.person||"").trim().toLowerCase();
  const exc=(f.exclude||"").split(",").map(x=>x.trim().toLowerCase()).filter(Boolean);
  return e=>{
    if(cats.size&&!cats.has(catOf(e))) return false;
    if(res.size&&!res.has(e.outcome&&e.outcome.result)) return false;
    if(apps.size&&!apps.has(appOf(e))) return false;
    if(inc||exc.length){ const hay=(reasonOf(e)+" "+(e.eventType||"")).toLowerCase(); if(inc&&!hay.includes(inc)) return false; for(const t of exc) if(hay.includes(t)) return false; }
    if(per&&!idRefs(e).some(([a,n])=>a.toLowerCase().includes(per)||String(n||"").toLowerCase().includes(per))) return false;
    return true;
  };
}
function mutePhrase(e){ const r=String(reasonOf(e)).split(/["\s=:][0-9a-f]{12,}/i)[0].trim(); return r.slice(0,60); }
function idRefs(e){
  const out=[]; const a=e.actor;
  if(a&&a.type==="User"&&a.alternateId) out.push([a.alternateId,a.displayName]);
  for(const t of (e.target||[])) if((t.type==="User"||t.type==="AppUser")&&t.alternateId) out.push([t.alternateId,t.displayName]);
  return out;
}
const winText=m=> m<60? m+" minutes" : m===60? "hour" : (m>1440&&m%1440===0)? (m/1440)+" days" : m%60===0? (m/60)+" hours" : m+" minutes";
const lastText=m=> m===60? "the last hour" : "the last "+winText(m);
const RISK_RANK={low:1,medium:2,high:3}, RISK_NAME={1:"low",2:"medium",3:"high"}, RISK_TEXT={low:"Low risk",medium:"Medium risk",high:"High risk"};
// [pattern on the scope, how risky, what it lets the app do]. This list is this dashboard's own judgement, not Google's.
const SCOPE_RULES=[
  [/^openid$/,"low","Confirm who you are (Sign in with Google)"],
  [/(^|\/)userinfo\.email$|^email$/,"low","See your email address"],
  [/(^|\/)userinfo\.profile$|^profile$/,"low","See your name and profile picture"],
  [/^https:\/\/mail\.google\.com\/?$/,"high","Read, send, delete and manage ALL your Gmail"],
  [/gmail\.(modify|full)/,"high","Read, change and delete your Gmail"],
  [/gmail\.readonly/,"high","Read all your Gmail"],
  [/gmail\.(send|compose|insert)/,"high","Send email as you, or create drafts"],
  [/gmail\.settings/,"high","Change Gmail settings such as filters and forwarding"],
  [/gmail\.(labels|metadata)/,"medium","See or manage Gmail labels and message details"],
  [/auth\/drive$/,"high","Read, edit and delete ALL your Google Drive files"],
  [/auth\/drive\.readonly$/,"high","Read all your Google Drive files"],
  [/auth\/drive\.file$/,"low","Only files this app creates or that you open with it"],
  [/auth\/drive\.appdata$/,"low","Its own hidden settings folder in your Drive"],
  [/auth\/drive\.(metadata|activity)/,"medium","See file names, owners and activity in your Drive"],
  [/auth\/calendar(\.events)?$/,"medium","See, edit, share and delete your calendar events"],
  [/auth\/calendar\.(readonly|events\.readonly|calendarlist)/,"medium","See your calendars and events"],
  [/auth\/(contacts|directory)/,"medium","See your contacts or your organisation's directory"],
  [/auth\/(spreadsheets|documents|presentations|forms)/,"medium","Read and edit your Sheets, Docs, Slides or Forms"],
  [/auth\/(admin\.|cloud-identity|apps\.)/,"high","Manage Google Workspace admin data (users, groups, settings)"],
  [/auth\/cloud-platform/,"high","Manage your Google Cloud resources"],
  [/auth\/script\./,"medium","Run Apps Script on your behalf"],
  [/auth\/(chat|meetings|tasks|youtube|photoslibrary|keep)/,"medium","Use your Chat, Meet, Tasks, YouTube, Photos or Keep data"],
  [/auth\/(groups|cloudplatformprojects)/,"medium","See or manage groups and projects"]
];
function scopeInfo(sc){ sc=String(sc||""); for(const [re,risk,label] of SCOPE_RULES) if(re.test(sc)) return {risk,label,known:true}; return {risk:"medium",label:"Not in this dashboard's list: check what it allows before trusting it",known:false}; }
const shortScope=sc=>String(sc||"").replace(/^https:\/\/www\.googleapis\.com\/auth\//,"").replace(/^https:\/\//,"");
const G_NEED={any:1,medium:2,high:3};
function compileRule(r){ const m=Object.assign(emptyFilter(),(r&&r.match)||{}), base=compileFilter(m), et=String((r&&r.match&&r.match.eventType)||"").toLowerCase(); return e=>(!base||base(e))&&(!et||String(e.eventType||"").toLowerCase().includes(et)); }
function recentFails(events,minutes,now,pred,supOf){
  const cut=now-minutes*60000, out=[]; for(const e of events){ const t=ts(e); if(t<cut||t>now+60000) continue; if(isFail(e)&&!(supOf&&supOf(e))&&(!pred||pred(e))) out.push(e); } return out;
}
function evalRule(r,ctx,now){
  const pred=compileFilter(Object.assign(emptyFilter(),r.filter||{}));
  if(r.type==="spike"){
    const ev=recentFails(ctx.events,r.windowMin,now,pred,ctx.supOf), m=new Map();
    for(const e of ev){ let k; if(r.by==="app") k=appOf(e)||"(no app)"; else if(r.by==="person"){ const x=idRefs(e)[0]; k=x? x[0] : "(no person)"; } else k="all"; m.set(k,(m.get(k)||0)+1); }
    return [...m].filter(([,c])=>c>=r.n).sort((a,b)=>b[1]-a[1]).map(([k,c])=>({group:k,count:c,total:ev.length}));
  }
  if(r.type==="new"){
    if(ctx.catchingUp) return [];
    const cut=now-r.windowMin*60000, older=new Set(), recent=new Map();
    for(const e of ctx.events){ if(!isFail(e)||(ctx.supOf&&ctx.supOf(e))||(pred&&!pred(e))) continue; const t=ts(e), n=normErr(reasonOf(e));
      if(t<cut) older.add(n); else if(t<=now+60000){ let o=recent.get(n); if(!o){ o={n,count:0,app:appOf(e),raw:reasonOf(e)}; recent.set(n,o); } o.count++; } }
    if(!older.size) return [];                       // no earlier history to compare with: nothing can be called new
    return [...recent.values()].filter(x=>!older.has(x.n)).map(x=>({group:x.n,count:x.count,app:x.app,raw:x.raw}));
  }
  return [];
}
function evalSilent(r,ctx){
  if(ctx.catchingUp) return {hits:[],cur:null};
  const cur=ctx.silentNames(), base=ctx.astate.silent;
  if(base==null) return {hits:[],cur};                 // first run: remember what is silent now, say nothing
  const known=new Set(base), only=new Set((r.filter&&r.filter.apps)||[]), fresh=cur.filter(n=>!known.has(n)&&(!only.size||only.has(n)));
  return {hits: fresh.length? [{group:"silent",count:fresh.length,names:fresh}] : [], cur};
}
function makeNotif(r,h,now){
  if(r.type&&r.type[0]==="g") return makeGoogleNotif(r,h,now);
  const win=lastText(r.windowMin), f=JSON.parse(JSON.stringify(Object.assign(emptyFilter(),r.filter||{})));
  let body, sev="warn", link={view:"errors",filter:f};
  if(r.type==="spike"){ body=(r.by==="total"? "" : h.group+": ")+fmtN(h.count)+" error"+(h.count===1?"":"s")+" in "+win; sev=h.count>=2*r.n? "bad":"warn";
    if(r.by==="app") f.apps=[h.group]; else if(r.by==="person") f.person=h.group; }
  else if(r.type==="new"){ body="New: "+h.group.slice(0,150)+(h.app?" ("+h.app+")":"")+" · "+h.count+"×"; f.include=mutePhrase({outcome:{reason:h.raw},displayMessage:h.raw,eventType:""}); }
  else { const n=h.names; body=(n.length<=3? n.join(", ") : n.slice(0,3).join(", ")+" and "+(n.length-3)+" more")+(n.length===1?" went silent":" went silent"); sev="info"; link={view:"apps"}; }
  return {id:"n"+now+"-"+Math.random().toString(36).slice(2,7),ruleId:r.id,ruleName:r.name,type:r.type,ts:now,title:r.name,body,sev,link,unread:true};
}
function evalGoogleRule(r,ctx,now){
  const G=ctx.google; if(!G.configured||!G.events.length) return [];
  const cut=now-r.windowMin*60000, need=G_NEED[r.minRisk||"any"]||1, text=String(r.gApp||"").toLowerCase(), out=[], haveOlder=G.events[0].time<cut-864e5;
  for(const a of ctx.googleApps()){
    if(text&&!(a.name+" "+a.clientId).toLowerCase().includes(text)) continue;
    const grants=a.events.filter(e=>e.type==="authorize"&&e.time>=cut&&e.time<=now+60000), who=[...new Set(grants.map(e=>e.actor))], ap=approvalFrom(G.approvals,a);
    if(r.type==="gdrift"){ if(ap.state==="drift") out.push({group:a.key+"|"+ap.extra.slice().sort().join(","),app:a.name,clientId:a.clientId,rank:Math.max(...ap.extra.map(x=>RISK_RANK[scopeInfo(x).risk])),people:a.people.length,extra:ap.extra}); continue; }
    if(r.type==="gflag"){ if(ap.state==="flagged"&&grants.length) out.push({group:a.key,app:a.name,clientId:a.clientId,rank:a.rank,people:who.length}); continue; }
    if(ap.state==="approved") continue;                        // reviewed and approved for this access: no alert (a change in access is caught by the 'approved app asked for new access' rule)
    if(r.type==="gnew"){ if(haveOlder&&a.first>=cut&&a.first<=now+60000&&a.rank>=need) out.push({group:a.key,app:a.name,clientId:a.clientId,rank:a.rank,people:who.length||1}); }
    else if(r.type==="grisk"){ const hit=grants.filter(e=>e.scopes.some(x=>RISK_RANK[scopeInfo(x).risk]>=need)), ppl=[...new Set(hit.map(e=>e.actor))];
      if(ppl.length){ const sc=[...new Set(hit.flatMap(e=>e.scopes).filter(x=>RISK_RANK[scopeInfo(x).risk]>=need))]; out.push({group:a.key,app:a.name,clientId:a.clientId,rank:a.rank,people:ppl.length,scopes:sc}); } }
    else if(r.type==="gspike"){ if(who.length>=r.n&&a.rank>=need) out.push({group:a.key,app:a.name,clientId:a.clientId,rank:a.rank,people:who.length}); }
  }
  return out.sort((x,y)=>y.rank-x.rank||y.people-x.people);
}
function makeGoogleNotif(r,h,now){
  const win=lastText(r.windowMin), who=h.people+" "+(h.people===1?"person":"people"), risk=RISK_NAME[h.rank]; let body;
  if(r.type==="gnew") body=h.app+" was authorized by "+who+" · "+risk+"-risk access";
  else if(r.type==="grisk") body=h.app+" was granted "+h.scopes.slice(0,3).map(shortScope).join(", ")+(h.scopes.length>3?" +"+(h.scopes.length-3):"")+" by "+who;
  else if(r.type==="gdrift") body=h.app+" was approved, but it now also asks for: "+h.extra.slice(0,3).map(shortScope).join(", ")+(h.extra.length>3?" +"+(h.extra.length-3):"")+" ("+(h.people===1?"1 person has":h.people+" people have")+" access)";
  else if(r.type==="gflag") body=h.app+" is marked not allowed, and "+who+" authorized it in "+win;
  else body=h.app+": "+who+" authorized it in "+win;
  return {id:"n"+now+"-"+Math.random().toString(36).slice(2,7),ruleId:r.id,ruleName:r.name,type:r.type,ts:now,title:r.name,body,sev:(r.type==="gflag"||h.rank>=3)?"bad":h.rank===2?"warn":"info",link:{view:"google",app:String(h.group).split("|")[0]},unread:true};
}
function approvalFrom(approvals,a){
  const ap=approvals.find(x=>x.clientId===a.key); if(!ap) return {state:"none"};
  if(ap.status==="flagged") return {state:"flagged",ap};
  const covered=new Set(ap.scopes||[]), extra=[...a.scopes].filter(x=>!covered.has(x));
  if(extra.length) return {state:"drift",ap,extra};
  if(ap.expiresAt&&Date.parse(ap.expiresAt)<Date.now()) return {state:"expired",ap};
  return {state:"approved",ap};
}
function googleAppsFrom(events){
  const m=new Map();
  for(const e of events){ if(!e.clientId&&!e.app) continue; const key=e.clientId||e.app; let a=m.get(key);
    if(!a){ a={key,clientId:e.clientId,name:e.app||e.clientId,scopes:new Set(),state:new Map(),first:Infinity,firstAny:Infinity,last:0,grants:0,revokes:0,denies:0,requests:0,calls:0,events:[]}; m.set(key,a); }
    a.events.push(e); a.last=Math.max(a.last,e.time); a.firstAny=Math.min(a.firstAny,e.time); if(e.app) a.name=e.app; e.scopes.forEach(x=>a.scopes.add(x));
    if(e.type==="authorize"){ a.grants++; a.first=Math.min(a.first,e.time); a.state.set(e.actor,{on:true,time:e.time,scopes:e.scopes}); }
    else if(e.type==="revoke"){ a.revokes+=(e.count||1); const prev=a.state.get(e.actor); a.state.set(e.actor,{on:false,time:e.time,scopes:(prev&&prev.scopes)||e.scopes}); }
    else if(e.type==="deny") a.denies+=(e.count||1); else if(e.type==="request") a.requests+=(e.count||1); else a.calls+=(e.count||1); }
  const apps=[...m.values()].map(a=>{ a.people=[...a.state].filter(([,v])=>v.on).map(([who,v])=>({who,time:v.time,scopes:v.scopes})).sort((x,y)=>y.time-x.time);
    if(!isFinite(a.first)) a.first=a.firstAny; a.rank=Math.max(1,...[...a.scopes].map(x=>RISK_RANK[scopeInfo(x).risk])); a.riskName=RISK_NAME[a.rank]; return a; })
    .sort((a,b)=>b.rank-a.rank||b.people.length-a.people.length||b.last-a.last);
  return apps;
}
function runRules(rules,ctx,now){
  const fired=ctx.astate.fired, out=[]; let silentCur=null;
  const fire=(r,hs)=>{ const list=hs.slice(0,5); list.forEach(h=>{ const key=r.id+"|"+h.group, cool=Math.max(r.cooldownMin||0,r.type==="new"? r.windowMin : 0)*60000;
      if(fired[key]&&now-fired[key]<cool) return; fired[key]=now; const n=makeNotif(r,h,now); if(hs.length>5&&h===list[list.length-1]) n.body+=" (+"+(hs.length-5)+" more)"; out.push(n); }); };
  for(const r of rules){ if(!r.enabled) continue;
    try{ if(r.type==="silent"){ const x=evalSilent(r,ctx); if(x.cur) silentCur=x.cur; fire(r,x.hits); } else if(r.type&&r.type[0]==="g") fire(r,evalGoogleRule(r,ctx,now)); else fire(r,evalRule(r,ctx,now)); }
    catch(err){ if(ctx.onError) ctx.onError(r,err); } }
  if(silentCur) ctx.astate.silent=silentCur;
  for(const k of Object.keys(fired)) if(now-fired[k]>3*864e5) delete fired[k];
  return out;
}
return { FAIL, ASSIGN_RE, APP_ACTORS, appOf, userOf, isFail, isAssign, reasonOf, ts, normErr, CATS, CAT_KEYS, catOf, emptyFilter, filterActive, compileFilter, mutePhrase, idRefs, winText, lastText, RISK_RANK, RISK_NAME, RISK_TEXT, SCOPE_RULES, scopeInfo, shortScope, G_NEED, compileRule, recentFails, evalRule, evalSilent, makeNotif, evalGoogleRule, makeGoogleNotif, approvalFrom, googleAppsFrom, runRules };
});
