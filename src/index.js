// Overlord site API — dashboard for everyone, admin tools for allowlisted admins

// Set ownerOnly to false to let any allowlisted admin do that action
const ACTIONS = {
  maintenance: { ownerOnly: false },
  command: { ownerOnly: false },
  blacklist: { ownerOnly: false },
  broadcast: { ownerOnly: true },
  coins: { ownerOnly: true },
  wipeUser: { ownerOnly: true },
  wipeGuild: { ownerOnly: true },
};

export default {
  async fetch(request, env) {
    try {
      if (request.method === "OPTIONS") return cors(empty(204), env);

      const url = new URL(request.url);
      const path = url.pathname;
      const GET = request.method === "GET";

      if (path === "/" || path === "/health") {
        return cors(json({ ok: true, service: "overlord-admin" }), env);
      }
      if (path === "/auth/login") return startLogin(env);
      if (path === "/auth/callback") return handleCallback(url, env);

      if (path === "/webhooks/topgg" || path === "/webhooks/topgg/") {
        if (request.method === "GET") {
          return json({ ok: true, webhook: true, hint: "POST only for top.gg" });
        }
        if (request.method === "POST") {
          return handleTopggWebhook(request, env);
        }
        return json({ error: "Method not allowed" }, 405);
      }
      
      // ----- Anyone who is logged in -----
      if (path === "/api/me") {
        return withUser(request, env, async (user) =>
          json({
            user: { id: user.id, username: user.username, global_name: user.global_name },
            isOwner: user.id === env.OWNER_ID,
            isAdmin: await isAllowed(env, user.id),
          })
        );
      }
      if (path === "/api/user/stats" && GET) {
        return withUser(request, env, (user) => userStats(env, user));
      }
      if (path === "/api/user/settings" && GET) {
        return withUser(request, env, (user) => userSettings(env, user, url));
      }
      if (path === "/api/user/settings" && request.method === "POST") {
        return withUser(request, env, (user) => saveUserSettings(request, env, user));
      }

      // ----- Admins only -----
      if (path === "/api/state" && GET) {
        return withAdmin(request, env, async () => json(await readState(env)));
      }
      if (path === "/api/logs" && GET) {
        return withAdmin(request, env, () => fetchLogs(env, url));
      }
      if (path === "/api/host-logs" && GET) {
        return withAdmin(request, env, () => fetchHostLogs(env, url));
      }
      if (path === "/api/inbox" && GET) {
        return withAdmin(request, env, () => fetchInbox(env, url));
      }
      if (path === "/api/player" && GET) {
        return withAdmin(request, env, () => fetchPlayer(env, url));
      }
      if (path === "/api/audit" && GET) {
        return withAdmin(request, env, () => listAudit(env));
      }
      if (path === "/api/action" && request.method === "POST") {
        return withAdmin(request, env, (user) => runAction(request, env, user));
      }
      if (path === "/api/admins" && GET) {
        return withAdmin(request, env, async () => json({ admins: await listAdmins(env) }));
      }

      if (path === "/api/admins" && request.method === "POST") {
        return withAdmin(request, env, async (user) => {
          if (user.id !== env.OWNER_ID) return json({ error: "Only the owner can add admins" }, 403);
          const body = await request.json();
          const id = String(body.id || "").trim();
          if (!/^\d{17,20}$/.test(id)) return json({ error: "Need a Discord user ID (numbers only)" }, 400);
          if (id === env.OWNER_ID) return json({ error: "Owner is already allowed" }, 400);
          await env.ADMIN_KV.put(kvKey(id), JSON.stringify({ id, addedAt: Date.now(), addedBy: user.id }));
          await audit(env, user, "admin-add", "Added admin " + id, "done");
          return json({ ok: true, admins: await listAdmins(env) });
        });
      }

      if (path === "/api/admins" && request.method === "DELETE") {
        return withAdmin(request, env, async (user) => {
          if (user.id !== env.OWNER_ID) return json({ error: "Only the owner can remove admins" }, 403);
          const body = await request.json();
          const id = String(body.id || "").trim();
          if (id === env.OWNER_ID) return json({ error: "Cannot remove the owner" }, 400);
          await env.ADMIN_KV.delete(kvKey(id));
          await audit(env, user, "admin-remove", "Removed admin " + id, "done");
          return json({ ok: true, admins: await listAdmins(env) });
        });
      }

      return cors(json({ error: "Not found" }, 404), env);
    } catch (err) {
      return cors(json({ error: String(err.message || err) }, 500), env);
    }
  },
};

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const ID = /^\d{17,20}$/;

function kvKey(id) {
  return "admin:" + id;
}

async function listAdmins(env) {
  const out = [{ id: env.OWNER_ID, role: "owner" }];
  const listed = await env.ADMIN_KV.list({ prefix: "admin:" });
  for (const k of listed.keys) {
    const id = k.name.replace(/^admin:/, "");
    if (id === env.OWNER_ID) continue;
    out.push({ id, role: "admin" });
  }
  return out;
}

async function isAllowed(env, userId) {
  if (String(userId) === String(env.OWNER_ID)) return true;
  const row = await env.ADMIN_KV.get(kvKey(userId));
  return Boolean(row);
}

// A tiny in-memory limiter (per worker instance) so one person can't hammer the settings endpoints
const hits = new Map();
function limited(key, max, windowMs) {
  const now = Date.now();
  const recent = (hits.get(key) || []).filter((t) => now - t < windowMs);
  if (recent.length >= max) {
    hits.set(key, recent);
    return true;
  }
  recent.push(now);
  hits.set(key, recent);
  if (hits.size > 2000) hits.clear();
  return false;
}

// ---------- Audit log (kept 90 days, newest first) ----------

async function audit(env, user, action, summary, status) {
  const at = Date.now();
  const key = "audit:" + String(9999999999999 - at).padStart(13, "0") + ":" + Math.random().toString(36).slice(2, 7);
  const metadata = {
    at,
    by: String(user.id),
    name: String(user.global_name || user.username || "").slice(0, 40),
    action,
    summary: String(summary).slice(0, 200),
    status: status || "done",
  };
  try {
    await env.ADMIN_KV.put(key, "1", { metadata, expirationTtl: 60 * 60 * 24 * 90 });
  } catch {
    /* the audit log must never break an action */
  }
}

async function listAudit(env) {
  const listed = await env.ADMIN_KV.list({ prefix: "audit:", limit: 100 });
  return json({ entries: listed.keys.map((k) => k.metadata).filter(Boolean) });
}

// ---------- Database (the bot's Turso database, over HTTPS) ----------

let tablesReady = false;

function dbArg(v) {
  if (v === null || v === undefined) return { type: "null" };
  if (typeof v === "number") return Number.isInteger(v) ? { type: "integer", value: String(v) } : { type: "float", value: v };
  return { type: "text", value: String(v) };
}

async function pipeline(env, statements) {
  if (!env.TURSO_DATABASE_URL || !env.TURSO_AUTH_TOKEN) {
    throw new Error("TURSO_DATABASE_URL / TURSO_AUTH_TOKEN are not set on the worker");
  }
  const base = String(env.TURSO_DATABASE_URL).replace(/^libsql:/, "https:").replace(/\/$/, "");
  const requests = statements.map((s) => ({
    type: "execute",
    stmt: { sql: s.sql, args: (s.args || []).map(dbArg) },
  }));
  requests.push({ type: "close" });

  const res = await fetch(base + "/v2/pipeline", {
    method: "POST",
    headers: { Authorization: "Bearer " + env.TURSO_AUTH_TOKEN, "content-type": "application/json" },
    body: JSON.stringify({ requests }),
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error("Database: " + (data.error || res.status));

  return statements.map((_, i) => {
    const item = data.results && data.results[i];
    if (!item || item.type === "error") {
      throw new Error("Database: " + ((item && item.error && item.error.message) || "unknown error"));
    }
    const result = item.response.result;
    const cols = result.cols.map((c) => c.name);
    const rows = result.rows.map((r) => {
      const row = {};
      r.forEach((cell, n) => {
        row[cols[n]] =
          cell.type === "null" ? null : cell.type === "integer" || cell.type === "float" ? Number(cell.value) : cell.value;
      });
      return row;
    });
    return { rows, lastId: result.last_insert_rowid ? Number(result.last_insert_rowid) : null };
  });
}

async function sql(env, query, args = []) {
  return (await pipeline(env, [{ sql: query, args }]))[0];
}

async function ensureTables(env) {
  if (tablesReady) return;
  await pipeline(env, [
    { sql: "CREATE TABLE IF NOT EXISTS admin_state (key TEXT PRIMARY KEY, value TEXT NOT NULL, updated INTEGER NOT NULL)" },
    {
      sql: "CREATE TABLE IF NOT EXISTS admin_queue (id INTEGER PRIMARY KEY AUTOINCREMENT, action TEXT NOT NULL, payload TEXT NOT NULL, by_id TEXT, by_name TEXT, created INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending', result TEXT, done_at INTEGER)",
    },
  ]);
  tablesReady = true;
}

async function readState(env) {
  await ensureTables(env);
  const { rows } = await sql(env, "SELECT key, value, updated FROM admin_state WHERE key != 'guilds'");
  const state = {};
  const updated = {};
  for (const r of rows) {
    try {
      state[r.key] = JSON.parse(r.value);
      updated[r.key] = r.updated;
    } catch {
      /* skip a damaged row */
    }
  }
  return { state, updated, now: Date.now() };
}

async function getState(env, key) {
  await ensureTables(env);
  const { rows } = await sql(env, "SELECT value FROM admin_state WHERE key = ?", [key]);
  try {
    return rows[0] ? JSON.parse(rows[0].value) : null;
  } catch {
    return null;
  }
}

// ---------- Discord channel reading (logs + inbox) ----------

function mapMessage(m) {
  const embed = (m.embeds && m.embeds[0]) || null;
  return {
    id: m.id,
    at: m.timestamp,
    content: m.content || "",
    title: embed?.title || null,
    description: embed?.description || null,
    footer: embed?.footer?.text || null,
    color: embed?.color || null,
    author: embed?.author?.name || null,
    fields: ((embed && embed.fields) || []).map((f) => ({ name: f.name, value: f.value })),
  };
}

async function discordGet(env, path) {
  const res = await fetch("https://discord.com/api/v10" + path, {
    headers: { Authorization: "Bot " + env.DISCORD_BOT_TOKEN },
  });
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}

const discordMessages = (env, channelId, query) => discordGet(env, "/channels/" + channelId + "/messages" + query);

async function fetchLogs(env, url) {
  const channelId = env.LOG_CHANNEL_ID;
  if (!channelId) return json({ error: "LOG_CHANNEL_ID not set" }, 500);

  const limit = Math.min(100, Math.max(1, parseInt(url.searchParams.get("limit") || "40", 10) || 40));
  const before = url.searchParams.get("before");
  let query = "?limit=" + limit;
  if (before && ID.test(before)) query += "&before=" + before;

  const res = await discordMessages(env, channelId, query);
  if (!res.ok) return json({ error: "Discord: " + (res.data.message || res.status) }, 502);

  return json({ logs: (res.data || []).map(mapMessage), fetchedAt: new Date().toISOString() });
}

// Raw console from bot-hosting.net — on demand only (no Turso writes).
// Skips lines that are already the bot's structured logging() output so the
// admin panel doesn't show the same event twice. Keeps stacks, TypeErrors, etc.
async function fetchHostLogs(env, url) {
  const key = env.BOTHOSTING_API_KEY;
  const depId = env.BOTHOSTING_DEPLOYMENT_ID;
  if (!key || !depId) {
    return json({
      error: "Host logs not configured. Set BOTHOSTING_API_KEY and BOTHOSTING_DEPLOYMENT_ID on the Worker.",
      lines: [],
      state: null,
    }, 503);
  }

  const size = Math.min(500, Math.max(50, parseInt(url.searchParams.get("size") || "200", 10) || 200));
  const res = await fetch(
    `https://bot-hosting.net/api/v1/deployments/${encodeURIComponent(depId)}/logs?size=${size}`,
    { headers: { Authorization: `Bearer ${key}` } }
  );

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    return json({ error: `bot-hosting ${res.status}: ${text.slice(0, 200)}`, lines: [], state: null }, 502);
  }

  const data = await res.json();
  const raw = Array.isArray(data.lines) ? data.lines : [];

  // Matches: 2026-10-04 12:34:56 | INFO  | Title
  const structured = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} \| (INFO|WARN|ERROR)\s*\|/;
  const boring = /Boss spawned|Admin panel link ready|Admin panel link is off/i;

  const lines = [];
  for (const line of raw) {
    const s = String(line ?? "");
    if (!s.trim()) continue;
    if (structured.test(s)) continue; // already in Discord log channel as embeds
    if (boring.test(s)) continue;
    lines.push(s);
  }

  return json({
    lines,
    rawCount: raw.length,
    state: data.state ?? null,
    settled: data.settled ?? null,
    fetchedAt: new Date().toISOString(),
  });
}

async function fetchInbox(env, url) {
  const kind = url.searchParams.get("kind") === "feedback" ? "feedback" : "report";
  const config = await getState(env, "config");
  const channelId = config && config.inbox ? config.inbox[kind] : null;
  if (!channelId) {
    return json({ error: "No " + kind + " channel is set. Set one in Discord with the bot's inbox command (the bot publishes it a few seconds later)." }, 404);
  }

  const res = await discordMessages(env, channelId, "?limit=50");
  if (!res.ok) return json({ error: "Discord: " + (res.data.message || res.status) }, 502);

  const messages = (res.data || [])
    .filter((m) => m.embeds && m.embeds[0])
    .map((m) => {
      const e = mapMessage(m);
      return {
        id: e.id,
        at: e.at,
        ref: ((e.title || "").match(/·\s*([RF]-[A-Z0-9]+)/) || [])[1] || null,
        title: e.title,
        text: e.description || "",
        fields: e.fields,
      };
    });
  return json({ messages });
}

// ---------- Economy lookup (admin tool) ----------

async function fetchPlayer(env, url) {
  const guild = url.searchParams.get("guild") || "";
  const user = url.searchParams.get("user") || "";
  if (!ID.test(guild) || !ID.test(user)) return json({ error: "Pick a server and enter a user ID" }, 400);

  const { rows } = await sql(env, "SELECT value FROM kv WHERE file = ? AND key = ?", ["economy@" + guild, user]);
  if (!rows.length) return json({ error: "No account for that user in that server (they may not have used the bot there)" }, 404);

  let u;
  try {
    u = JSON.parse(rows[0].value);
  } catch {
    return json({ error: "Could not read that account" }, 500);
  }
  const inventory = Object.entries(u.inventory || {})
    .filter(([, n]) => n > 0)
    .slice(0, 40);
  return json({
    player: {
      coins: u.coins || 0,
      xp: u.xp || 0,
      level: u.level || 0,
      prestige: u.prestige || 0,
      works: u.works || 0,
      streak: u.streak || 0,
      lastDaily: u.lastDaily || null,
      inventory,
    },
  });
}

async function handleTopggWebhook(request, env) {
  const secret = env.TOPGG_WEBHOOK_SECRET;
  if (!secret) {
    return json({ error: "TOPGG_WEBHOOK_SECRET is not set" }, 503);
  }

  const rawBody = await request.text();
  const signatureHeader = request.headers.get("x-topgg-signature") || "";

  const okSig = await verifyTopggSignature(rawBody, signatureHeader, secret);
  if (!okSig) {
    return json(
      {
        error: "Invalid signature",
        hasHeader: Boolean(signatureHeader),
        bodyLen: rawBody.length,
      },
      401
    );
  }

  let body;
  try {
    body = JSON.parse(rawBody || "{}");
  } catch {
    return json({ error: "Bad JSON" }, 400);
  }

  if (body.type === "webhook.test" || body.type === "test") {
    return json({ ok: true, test: true });
  }

  let userId = null;
  let weight = 1;
  let isWeekend = false;

  if (body.type === "vote.create" && body.data) {
    userId = String(body.data.user?.platform_id || body.data.user?.id || "");
    weight = Number(body.data.weight) || 1;
    isWeekend = weight >= 2;
  } else if (body.user) {
    userId = String(body.user || "");
    isWeekend = Boolean(body.isWeekend);
    weight = isWeekend ? 2 : 1;
  } else {
    return json({ ok: true, ignored: String(body.type || "unknown") });
  }

  if (!ID.test(userId)) {
    return json({ error: "No valid Discord user id", userId }, 400);
  }

  try {
    await ensureTables(env);
    await sql(
      env,
      "INSERT INTO admin_queue (action, payload, by_id, by_name, created) VALUES (?, ?, ?, ?, ?)",
      [
        "topggVote",
        JSON.stringify({ userId, weight, isWeekend }),
        "topgg",
        "top.gg",
        Date.now(),
      ]
    );
  } catch (err) {
    return json({ error: String(err.message || err).slice(0, 200) }, 500);
  }

  return json({ ok: true });
}

async function verifyTopggSignature(rawBody, signatureHeader, secret) {
  try {
    const parts = {};
    for (const piece of String(signatureHeader).split(",")) {
      const idx = piece.indexOf("=");
      if (idx === -1) continue;
      const k = piece.slice(0, idx).trim();
      const v = piece.slice(idx + 1).trim();
      parts[k] = v;
    }
    const timestamp = parts.t;
    const received = (parts.v1 || "").toLowerCase();
    if (!timestamp || !received) return false;

    const ts = Number(timestamp);
    const nowSec = Date.now() / 1000;
    const tsSec = ts > 1e12 ? ts / 1000 : ts;
    if (!Number.isFinite(tsSec) || Math.abs(nowSec - tsSec) > 15 * 60) return false;

    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(String(secret).trim()),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const data = new TextEncoder().encode(`${timestamp}.${rawBody}`);
    const sigBuf = await crypto.subtle.sign("HMAC", key, data);
    const expected = [...new Uint8Array(sigBuf)]
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    if (expected.length !== received.length) return false;
    let diff = 0;
    for (let i = 0; i < expected.length; i++) {
      diff |= expected.charCodeAt(i) ^ received.charCodeAt(i);
    }
    return diff === 0;
  } catch {
    return false;
  }
}

    
// ---------- Queue: ask the bot to do something and wait for its answer ----------

async function enqueueAndWait(env, user, action, payload) {
  await ensureTables(env);
  const inserted = await sql(
    env,
    "INSERT INTO admin_queue (action, payload, by_id, by_name, created) VALUES (?, ?, ?, ?, ?)",
    [action, JSON.stringify(payload), user.id, user.global_name || user.username || "", Date.now()]
  );

  // The bot checks the queue every few seconds, so wait a little for its answer
  let status = "pending";
  let result = "";
  for (let i = 0; i < 9; i++) {
    await sleep(i === 0 ? 1000 : 1500);
    const check = await sql(env, "SELECT status, result FROM admin_queue WHERE id = ?", [inserted.lastId]);
    const row = check.rows[0];
    if (row && row.status !== "pending") {
      status = row.status;
      result = row.result || "";
      break;
    }
  }
  if (status === "pending") {
    result = "Sent, but the bot hasn't answered yet. If it's offline, the request expires after 5 minutes.";
  }
  return { status, result };
}

// ---------- Admin actions ----------

function clean(action, p) {
  const text = (v, max) => String(v === undefined || v === null ? "" : v).trim().slice(0, max);
  if (action === "maintenance") {
    return { payload: { on: p.on === true, message: text(p.message, 200) } };
  }
  if (action === "command") {
    const name = text(p.name, 40).replace(/^!!/, "").toLowerCase();
    if (!/^[a-z0-9_-]{1,40}$/.test(name)) return { error: "Bad command name" };
    return { payload: { name, on: p.on === true } };
  }
  if (action === "blacklist") {
    if (!["add", "remove"].includes(p.op) || !["user", "server"].includes(p.kind)) return { error: "Bad blacklist request" };
    const id = text(p.id, 25);
    if (!ID.test(id)) return { error: "Need a Discord ID (17–20 digits)" };
    return { payload: { op: p.op, kind: p.kind, id, reason: text(p.reason, 200) } };
  }
  if (action === "broadcast") {
    const title = text(p.title, 100);
    const body = text(p.text, 2000);
    if (!title || !body) return { error: "Write a title and a message" };
    return { payload: { title, text: body } };
  }
  if (action === "coins") {
    const guildId = text(p.guildId, 25);
    const userId = text(p.userId, 25);
    const amount = Math.floor(Number(p.amount));
    if (!ID.test(guildId) || !ID.test(userId)) return { error: "Bad server or user ID" };
    if (!["add", "remove", "set"].includes(p.mode)) return { error: "Bad mode" };
    if (!Number.isFinite(amount) || amount < 0 || amount > 1000000000000) return { error: "Bad amount" };
    return { payload: { guildId, userId, mode: p.mode, amount } };
  }
  return { error: "Unknown action" };
}

function describe(action, p) {
  if (action === "maintenance") return "Maintenance " + (p.on ? "ON" : "OFF") + (p.message ? ": " + p.message : "");
  if (action === "command") return (p.on ? "Enabled" : "Disabled") + " !!" + p.name + " globally";
  if (action === "blacklist") return (p.op === "add" ? "Blacklisted " : "Un-blacklisted ") + p.kind + " " + p.id + (p.reason ? " (" + p.reason + ")" : "");
  if (action === "broadcast") return "Broadcast: " + p.title;
  if (action === "coins") return p.mode + " " + p.amount + " coins, user " + p.userId + ", server " + p.guildId;
  return action;
}

async function runAction(request, env, user) {
  const body = await request.json().catch(() => ({}));
  const action = String(body.action || "");
  const spec = ACTIONS[action];
  if (!spec) return json({ error: "Unknown action" }, 400);
  if (spec.ownerOnly && user.id !== env.OWNER_ID) return json({ error: "Only the owner can do that" }, 403);

  const checked = clean(action, body.payload && typeof body.payload === "object" ? body.payload : {});
  if (checked.error) return json({ error: checked.error }, 400);

  const { status, result } = await enqueueAndWait(env, user, action, checked.payload);
  await audit(env, user, action, describe(action, checked.payload) + (result ? " → " + result : ""), status);
  return json({ ok: status === "done", status, result });
}

// ---------- Dashboard (every logged-in user) ----------

// The login saves a short list of the user's servers: [id, permissions, isOwner, iconHash]
async function userGuilds(env, user) {
  const raw = await env.ADMIN_KV.get("ug:" + user.id);
  if (!raw) return null;
  try {
    const list = JSON.parse(raw);
    return Array.isArray(list) ? list : [];
  } catch {
    return [];
  }
}

function canManage(entry) {
  if (entry[2]) return true;
  try {
    const p = BigInt(entry[1]);
    return (p & 0x8n) !== 0n || (p & 0x20n) !== 0n; // Administrator or Manage Server
  } catch {
    return false;
  }
}

const iconUrl = (id, hash) => (hash ? "https://cdn.discordapp.com/icons/" + id + "/" + hash + ".png?size=64" : null);

function shapePlayer(u) {
  if (!u || typeof u !== "object") return null;
  const c = u.combat || {};
  return {
    coins: u.coins || 0,
    xp: u.xp || 0,
    level: u.level || 0,
    prestige: u.prestige || 0,
    works: u.works || 0,
    streak: u.streak || 0,
    lastDaily: u.lastDaily || null,
    inventory: Object.entries(u.inventory || {})
      .filter(([, n]) => n > 0)
      .slice(0, 40),
    wins: c.wins || 0,
    best: c.best || 0,
    bossKills: c.bossKills || 0,
    bossDamage: c.bossDamage || 0,
  };
}

async function userStats(env, user) {
  const list = await userGuilds(env, user);
  if (!list) return json({ error: "Log in again to load your server list" }, 409);

  const all = (await getState(env, "guilds")) || [];
  const names = new Map(all.map((g) => [g[0], g[1]]));
  const shared = list.filter((e) => names.has(e[0])).slice(0, 100);

  const players = new Map();
  if (shared.length) {
    const files = shared.map((e) => "economy@" + e[0]);
    const marks = files.map(() => "?").join(",");
    const { rows } = await sql(env, "SELECT file, value FROM kv WHERE key = ? AND file IN (" + marks + ")", [user.id, ...files]);
    for (const r of rows) {
      try {
        players.set(r.file.slice(8), JSON.parse(r.value)); // "economy@".length is 8
      } catch {
        /* skip a damaged row */
      }
    }
  }

  const servers = shared.map((e) => ({
    id: e[0],
    name: names.get(e[0]),
    icon: iconUrl(e[0], e[3]),
    canManage: canManage(e),
    player: shapePlayer(players.get(e[0])),
  }));
  servers.sort((a, b) => (b.player ? b.player.coins : -1) - (a.player ? a.player.coins : -1));
  return json({ servers });
}

// Is this user in the server, with Manage Server there, and is the bot in it too?
async function manageableGuild(env, user, guild) {
  const list = await userGuilds(env, user);
  if (!list) return { error: "Log in again to refresh your server list", status: 409 };
  const entry = list.find((e) => e[0] === guild);
  if (!entry) return { error: "You're not in that server", status: 403 };
  if (!canManage(entry)) return { error: "You need the Manage Server permission there", status: 403 };
  const all = (await getState(env, "guilds")) || [];
  const found = all.find((g) => g[0] === guild);
  if (!found) return { error: "The bot isn't in that server", status: 404 };
  return { name: found[1] };
}

async function userSettings(env, user, url) {
  const guild = url.searchParams.get("guild") || "";
  if (!ID.test(guild)) return json({ error: "Pick a server" }, 400);
  if (limited("get:" + user.id, 30, 60000)) return json({ error: "Slow down a little" }, 429);

  const g = await manageableGuild(env, user, guild);
  if (g.error) return json({ error: g.error }, g.status);

  const [world, announce, rrRow] = await pipeline(env, [
    { sql: "SELECT value FROM kv WHERE file = ? AND key = 'settings'", args: ["world@" + guild] },
    { sql: "SELECT value FROM kv WHERE file = 'announce' AND key = ?", args: [guild] },
    { sql: "SELECT value FROM kv WHERE file = ? AND key = 'reactionRoles'", args: ["world@" + guild] },
  ]);
  let s = {};
  let ann = {};
  let panels = [];
  try {
    if (world.rows[0]) s = JSON.parse(world.rows[0].value) || {};
    if (announce.rows[0]) ann = JSON.parse(announce.rows[0].value) || {};
    if (rrRow.rows[0]) {
      const rawRr = JSON.parse(rrRow.rows[0].value) || {};
      const map = rawRr.panels || {};
      panels = Object.entries(map).map(([messageId, p]) => ({
        messageId,
        channelId: p.channelId,
        mode: p.mode,
        exclusive: Boolean(p.exclusive),
        title: p.title || "Roles",
        roleCount: Array.isArray(p.roles) ? p.roles.length : 0,
      }));
    }
  } catch {
    /* use the defaults */
  }

  const titles = Object.entries(s.customTitles || {}).map(([id, t]) => ({
    id,
    name: t.name,
    emoji: t.emoji || "🏷️",
    price: t.price || 0,
    roleId: t.roleId || null,
    desc: t.desc || "",
  }));

  const res = await discordGet(env, "/guilds/" + guild + "/channels");
  if (!res.ok) return json({ error: "I couldn't read that server's channels (" + (res.data.message || res.status) + ")" }, 502);
  const raw = Array.isArray(res.data) ? res.data : [];
  const cats = new Map(raw.filter((c) => c.type === 4).map((c) => [c.id, c.name]));
  const channels = raw
    .filter((c) => [0, 4, 5].includes(c.type))
    .sort((a, b) => a.position - b.position)
    .map((c) => ({ id: c.id, name: c.name, type: c.type, parent: (c.parent_id && cats.get(c.parent_id)) || null }));

  let roles = [];
  const rolesRes = await discordGet(env, "/guilds/" + guild + "/roles");
  if (rolesRes.ok && Array.isArray(rolesRes.data)) {
    roles = rolesRes.data
      .filter((r) => r.id !== guild && !r.managed)
      .sort((a, b) => b.position - a.position)
      .map((r) => ({ id: r.id, name: r.name, position: r.position, color: r.color || 0 }))
      .slice(0, 200);
  }

  const config = await getState(env, "config");
  return json({
    guild: { id: guild, name: g.name },
    settings: {
      gambling: s.gambling !== false,
      rob: s.rob !== false,
      website: s.website !== false,
      events: ann.channelId || null,
      levels: s.levelChannelId || null,
      board: (s.realmBoard && s.realmBoard.channelId) || null,
      disabledCommands: Object.keys(s.disabledCommands || {}),
      ignored: Object.keys(s.disabledChannels || {}),
      games: Array.isArray(s.gameChannels) ? s.gameChannels : [],
    },
    channels,
    commands: (config && config.commands) || [],
    titles,
    panels,
    roles,
  });
}

function cleanSettings(c) {
  if (!c || typeof c !== "object") return { error: "Nothing to save" };
  const out = {};
  for (const k of ["gambling", "rob", "website"]) if (typeof c[k] === "boolean") out[k] = c[k];
  for (const k of ["events", "levels", "board"]) {
    if (c[k] === null) out[k] = null;
    else if (typeof c[k] === "string") {
      if (!ID.test(c[k])) return { error: "Bad channel" };
      out[k] = c[k];
    }
  }
  if (c.commands && typeof c.commands === "object") {
    const cmds = {};
    for (const [name, on] of Object.entries(c.commands).slice(0, 300)) {
      if (!/^[a-z0-9_-]{1,40}$/.test(name) || typeof on !== "boolean") return { error: "Bad command list" };
      cmds[name] = on;
    }
    if (Object.keys(cmds).length) out.commands = cmds;
  }
    for (const [k, max] of [["ignored", 50], ["games", 10]]) {
    if (Array.isArray(c[k])) {
      if (c[k].length > max || !c[k].every((id) => typeof id === "string" && ID.test(id))) {
        return { error: "Bad " + k + " list (up to " + max + ")" };
      }
      out[k] = c[k];
    }
  }

  if (c.titleUpsert && typeof c.titleUpsert === "object") {
    const t = c.titleUpsert;
    const name = String(t.name || "").trim().slice(0, 64);
    const price = Math.floor(Number(t.price));
    if (!name || !Number.isFinite(price) || price < 0) return { error: "Bad title" };
    const row = {
      name,
      price,
      emoji: String(t.emoji || "🏷️").trim().slice(0, 32) || "🏷️",
      desc: String(t.desc || "").trim().slice(0, 200),
    };
    if (t.id) {
      const id = String(t.id).trim();
      if (!/^title_custom_[a-z0-9_]{1,40}$/.test(id)) return { error: "Bad title id" };
      row.id = id;
    }
    if (t.roleId === null || t.roleId === "") row.roleId = null;
    else if (typeof t.roleId === "string" && ID.test(t.roleId)) row.roleId = t.roleId;
    else if (t.roleId != null) return { error: "Bad title role" };
    out.titleUpsert = row;
  }
  if (typeof c.titleRemove === "string" && c.titleRemove.trim()) {
    out.titleRemove = c.titleRemove.trim().slice(0, 48);
  }

  if (typeof c.rrDelete === "string" && ID.test(c.rrDelete)) out.rrDelete = c.rrDelete;
  if (c.rrPublish && typeof c.rrPublish === "object") {
    const p = c.rrPublish;
    const mode = String(p.mode || "");
    if (!["buttons", "dropdown", "reactions"].includes(mode)) return { error: "Bad panel mode" };
    if (!ID.test(String(p.channelId || ""))) return { error: "Pick a panel channel" };
    const roles = Array.isArray(p.roles) ? p.roles : [];
    if (!roles.length || roles.length > 25) return { error: "Panel needs 1–25 roles" };
    const cleanRoles = [];
    for (const r of roles) {
      if (!ID.test(String(r.roleId || ""))) return { error: "Bad panel role" };
      cleanRoles.push({
        roleId: String(r.roleId),
        emoji: String(r.emoji || "").trim().slice(0, 64),
        description: String(r.description || "").trim().slice(0, 80),
      });
    }
    out.rrPublish = {
      mode,
      channelId: String(p.channelId),
      title: String(p.title || "Pick your roles").trim().slice(0, 100),
      description: String(p.description || "").trim().slice(0, 1000),
      exclusive: Boolean(p.exclusive),
      color: Number.isFinite(Number(p.color)) ? Number(p.color) : 0x5865f2,
      roles: cleanRoles,
    };
  }

  return { value: out };
}

async function saveUserSettings(request, env, user) {
  const body = await request.json().catch(() => ({}));
  const guild = String(body.guild || "");
  if (!ID.test(guild)) return json({ error: "Pick a server" }, 400);
  if (limited("set:" + user.id, 15, 60000)) return json({ error: "Slow down, try again in a minute" }, 429);

  const g = await manageableGuild(env, user, guild);
  if (g.error) return json({ error: g.error }, g.status);

  const checked = cleanSettings(body.changes);
  if (checked.error) return json({ error: checked.error }, 400);
  if (!Object.keys(checked.value).length) return json({ ok: true, status: "done", result: "Nothing to change" });

  // The bot checks Manage Server again before it changes anything
  const { status, result } = await enqueueAndWait(env, user, "guildSettings", { guildId: guild, changes: checked.value });
  await audit(env, user, "server-settings", g.name + ": " + Object.keys(checked.value).join(", ") + (result ? " → " + result : ""), status);
  return json({ ok: status === "done", status, result });
}

// ---------- Login ----------

function startLogin(env) {
  const u = new URL("https://discord.com/api/oauth2/authorize");
  u.searchParams.set("client_id", env.DISCORD_CLIENT_ID);
  u.searchParams.set("response_type", "code");
  u.searchParams.set("scope", "identify guilds");
  u.searchParams.set("redirect_uri", env.OAUTH_REDIRECT_URI);
  return Response.redirect(u.toString(), 302);
}

async function handleCallback(url, env) {
  const front = env.FRONTEND_URL.replace(/\/$/, "");
  const err = url.searchParams.get("error");
  if (err) return Response.redirect(front + "/dashboard.html?error=" + encodeURIComponent(err), 302);

  const code = url.searchParams.get("code");
  if (!code) return Response.redirect(front + "/dashboard.html?error=missing_code", 302);

  const body = new URLSearchParams({
    client_id: env.DISCORD_CLIENT_ID,
    client_secret: env.DISCORD_CLIENT_SECRET,
    grant_type: "authorization_code",
    code,
    redirect_uri: env.OAUTH_REDIRECT_URI,
  });

  const tokenRes = await fetch("https://discord.com/api/oauth2/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
  });
  const tokenData = await tokenRes.json();
  if (!tokenRes.ok) {
    return Response.redirect(
      front + "/dashboard.html?error=" + encodeURIComponent(tokenData.error || "token_failed"),
      302
    );
  }

  const bearer = { Authorization: "Bearer " + tokenData.access_token };
  const meRes = await fetch("https://discord.com/api/v10/users/@me", { headers: bearer });
  const me = await meRes.json();
  if (!meRes.ok) return Response.redirect(front + "/dashboard.html?error=user_failed", 302);

  // Remember which servers they're in and what they can manage (the Discord token itself is not kept)
  let list = [];
  const guildsRes = await fetch("https://discord.com/api/v10/users/@me/guilds?limit=200", { headers: bearer });
  if (guildsRes.ok) {
    const g = await guildsRes.json().catch(() => []);
    if (Array.isArray(g)) list = g.map((x) => [String(x.id), String(x.permissions || "0"), x.owner ? 1 : 0, x.icon || ""]);
  }
  try {
    await env.ADMIN_KV.put("ug:" + me.id, JSON.stringify(list), { expirationTtl: 8 * 24 * 60 * 60 });
  } catch {
    /* the dashboard will ask them to log in again */
  }

  if (await isAllowed(env, me.id)) await audit(env, me, "login", "Signed in", "done");

  const session = await signSession(
    {
      id: me.id,
      username: me.username,
      global_name: me.global_name || me.username,
      exp: Date.now() + 7 * 24 * 60 * 60 * 1000,
    },
    env.SESSION_SECRET
  );

  return Response.redirect(front + "/dashboard.html#token=" + encodeURIComponent(session), 302);
}

async function authUser(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const raw = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  if (!raw) return { res: json({ error: "Not logged in" }, 401) };
  const user = await verifySession(raw, env.SESSION_SECRET);
  if (!user || user.exp < Date.now()) return { res: json({ error: "Session expired" }, 401) };
  return { user };
}

async function withUser(request, env, fn) {
  const a = await authUser(request, env);
  if (a.res) return cors(a.res, env);
  return cors(await fn(a.user), env);
}

async function withAdmin(request, env, fn) {
  const a = await authUser(request, env);
  if (a.res) return cors(a.res, env);
  if (!(await isAllowed(env, a.user.id))) return cors(json({ error: "Not an admin" }, 403), env);
  return cors(await fn(a.user), env);
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

function empty(status) {
  return new Response(null, { status });
}

function cors(res, env) {
  // Browsers send only the origin (no path), so strip FRONTEND_URL down to it
  let origin = "*";
  try {
    origin = new URL(env.FRONTEND_URL).origin;
  } catch {}
  const h = new Headers(res.headers);
  h.set("Access-Control-Allow-Origin", origin);
  h.set("Access-Control-Allow-Headers", "Content-Type, Authorization");
  h.set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  return new Response(res.body, { status: res.status, headers: h });
}

async function signSession(payload, secret) {
  const body = btoa(unescape(encodeURIComponent(JSON.stringify(payload))))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
  const sig = await hmac(secret, body);
  return body + "." + sig;
}

async function verifySession(token, secret) {
  const [body, sig] = String(token).split(".");
  if (!body || !sig) return null;
  if ((await hmac(secret, body)) !== sig) return null;
  try {
    const jsonStr = decodeURIComponent(escape(atob(body.replace(/-/g, "+").replace(/_/g, "/"))));
    return JSON.parse(jsonStr);
  } catch {
    return null;
  }
}

async function hmac(secret, text) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const buf = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(text));
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
                         }
