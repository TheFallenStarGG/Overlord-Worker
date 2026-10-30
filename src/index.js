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

      // ----- Moderation (people with a moderation permission in the server) -----
      if (path === "/api/user/mod/meta" && GET) {
        return withUser(request, env, (user) => modMeta(env, user, url));
      }
      if (path === "/api/user/mod/cases" && GET) {
        return withUser(request, env, (user) => modCases(env, user, url));
      }
      if (path === "/api/user/mod/members" && GET) {
        return withUser(request, env, (user) => modMembers(env, user, url));
      }
      if (path === "/api/user/mod/bans" && GET) {
        return withUser(request, env, (user) => modBans(env, user, url));
      }
      if (path === "/api/user/mod/action" && request.method === "POST") {
        return withUser(request, env, (user) => modAction(request, env, user));
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

// Kick, Ban, Administrator, Manage Channels, Manage Server, Manage Messages, Manage Nicknames, Manage Roles, Moderate Members
const MOD_BITS = 0x2n | 0x4n | 0x8n | 0x10n | 0x20n | 0x2000n | 0x8000000n | 0x10000000n | 0x10000000000n;

function canModerate(entry) {
  if (entry[2]) return true;
  try {
    return (BigInt(entry[1]) & MOD_BITS) !== 0n;
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
    canModerate: canModerate(e),
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

// The server's channels and roles, read with the bot's own token
async function channelsAndRoles(env, guild) {
  const res = await discordGet(env, "/guilds/" + guild + "/channels");
  if (!res.ok) return { error: "I couldn't read that server's channels (" + (res.data.message || res.status) + ")" };
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
  return { channels, roles };
}

const MOD_DEFAULT = { modlogChannelId: null, modRoleIds: [], dmUsers: true, warnActions: {} };
const AUTOMOD_DEFAULT = {
  invites: false, links: false, spam: false, caps: false, mentions: false, words: false,
  punish: "delete", spamMessages: 6, spamSeconds: 8, maxMentions: 5, capsPercent: 70, capsMinLength: 12,
  badWords: [], allowedDomains: [], ignoredChannels: [], ignoredRoles: [],
};
const RAID_DEFAULT = { enabled: true, joinWindowSec: 20, joinThreshold: 8, minAccountAgeHours: 24, action: "kick", lockOnRaid: true, alertChannelId: null };
const WELCOME_DEFAULT = { enabled: false, channelId: null, message: "Welcome {user} to **{server}**!" };

function parseRow(row, fallback) {
  try {
    return row ? JSON.parse(row.value) ?? fallback : fallback;
  } catch {
    return fallback;
  }
}

async function userSettings(env, user, url) {
  const guild = url.searchParams.get("guild") || "";
  if (!ID.test(guild)) return json({ error: "Pick a server" }, 400);
  if (limited("get:" + user.id, 30, 60000)) return json({ error: "Slow down a little" }, 429);

  const g = await manageableGuild(env, user, guild);
  if (g.error) return json({ error: g.error }, g.status);

  const [world, announce, rrRow, modRow, raidRow, welcomeRow] = await pipeline(env, [
    { sql: "SELECT value FROM kv WHERE file = ? AND key = 'settings'", args: ["world@" + guild] },
    { sql: "SELECT value FROM kv WHERE file = 'announce' AND key = ?", args: [guild] },
    { sql: "SELECT value FROM kv WHERE file = ? AND key = 'reactionRoles'", args: ["world@" + guild] },
    { sql: "SELECT value FROM kv WHERE file = ? AND key = 'config'", args: ["moderation@" + guild] },
    { sql: "SELECT value FROM kv WHERE file = ? AND key = 'config'", args: ["antiraid@" + guild] },
    { sql: "SELECT value FROM kv WHERE file = ? AND key = 'welcome'", args: ["antiraid@" + guild] },
  ]);
  const s = parseRow(world.rows[0], {}) || {};
  const ann = parseRow(announce.rows[0], {}) || {};
  let panels = [];
  const rawRr = parseRow(rrRow.rows[0], {}) || {};
  panels = Object.entries(rawRr.panels || {}).map(([messageId, p]) => ({
    messageId,
    channelId: p.channelId,
    mode: p.mode,
    exclusive: Boolean(p.exclusive),
    title: p.title || "Roles",
    roleCount: Array.isArray(p.roles) ? p.roles.length : 0,
  }));

  const modCfg = parseRow(modRow.rows[0], {}) || {};
  const raid = parseRow(raidRow.rows[0], {}) || {};
  const welcome = parseRow(welcomeRow.rows[0], {}) || {};

  const titles = Object.entries(s.customTitles || {}).map(([id, t]) => ({
    id,
    name: t.name,
    emoji: t.emoji || "🏷️",
    price: t.price || 0,
    roleId: t.roleId || null,
    desc: t.desc || "",
  }));

  const cr = await channelsAndRoles(env, guild);
  if (cr.error) return json({ error: cr.error }, 502);

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
    mod: {
      prefix: s.prefix || "!!",
      modlog: modCfg.modlogChannelId || null,
      modRoles: Array.isArray(modCfg.modRoleIds) ? modCfg.modRoleIds : MOD_DEFAULT.modRoleIds,
      dmUsers: modCfg.dmUsers !== false,
      warnActions: modCfg.warnActions && typeof modCfg.warnActions === "object" ? modCfg.warnActions : {},
      automod: { ...AUTOMOD_DEFAULT, ...(modCfg.automod || {}) },
      antiraid: { ...RAID_DEFAULT, ...raid },
      welcome: { ...WELCOME_DEFAULT, ...welcome },
    },
    channels: cr.channels,
    commands: (config && config.commands) || [],
    titles,
    panels,
    roles: cr.roles,
  });
}

// Checks the moderation part of a settings save (the bot checks it all again)
function cleanMod(m) {
  if (!m || typeof m !== "object" || Array.isArray(m)) return { error: "Bad moderation settings" };
  const out = {};
  const isBool = (v) => typeof v === "boolean";
  const isInt = (v, lo, hi) => Number.isInteger(v) && v >= lo && v <= hi;
  const isId = (v) => typeof v === "string" && ID.test(v);
  const idList = (v, max) => Array.isArray(v) && v.length <= max && v.every(isId);
  const chan = (v) => v === null || isId(v);
  const strList = (v, max, len) => Array.isArray(v) && v.length <= max && v.every((x) => typeof x === "string" && x.length <= len);

  if ("modlog" in m) {
    if (!chan(m.modlog)) return { error: "Bad mod log channel" };
    out.modlog = m.modlog;
  }
  if ("modRoles" in m) {
    if (!idList(m.modRoles, 10)) return { error: "Pick up to 10 moderator roles" };
    out.modRoles = m.modRoles;
  }
  if ("dmUsers" in m) {
    if (!isBool(m.dmUsers)) return { error: "Bad DM setting" };
    out.dmUsers = m.dmUsers;
  }
  if ("prefix" in m) {
    const p = String(m.prefix ?? "").trim();
    if (p.length > 5 || /\s/.test(p)) return { error: "Bad prefix" };
    out.prefix = p;
  }
  if ("warnActions" in m) {
    const w = m.warnActions;
    if (!w || typeof w !== "object" || Array.isArray(w) || Object.keys(w).length > 20) return { error: "Bad automatic actions" };
    const rules = {};
    for (const [count, r] of Object.entries(w)) {
      if (!isInt(Number(count), 1, 20) || !r || typeof r !== "object") return { error: "Bad automatic action" };
      if (r.action === "mute") {
        if (!isInt(r.duration, 60000, 28 * 86400000)) return { error: "Mute length must be 1 minute to 28 days" };
        rules[count] = { action: "mute", duration: r.duration };
      } else if (r.action === "kick" || r.action === "ban") {
        rules[count] = { action: r.action };
      } else return { error: "Automatic action must be mute, kick or ban" };
    }
    out.warnActions = rules;
  }

  const a = m.automod;
  if (a !== undefined) {
    if (!a || typeof a !== "object") return { error: "Bad automod settings" };
    const o = {};
    for (const k of ["invites", "links", "spam", "caps", "mentions", "words"]) {
      if (k in a) {
        if (!isBool(a[k])) return { error: "Bad automod switch" };
        o[k] = a[k];
      }
    }
    if ("punish" in a) {
      if (!["delete", "warn"].includes(a.punish)) return { error: "Automod punishment must be delete or warn" };
      o.punish = a.punish;
    }
    for (const [k, lo, hi] of [["spamMessages", 3, 20], ["spamSeconds", 2, 60], ["maxMentions", 2, 50], ["capsPercent", 40, 100]]) {
      if (k in a) {
        if (!isInt(a[k], lo, hi)) return { error: "Bad automod number (" + k + ")" };
        o[k] = a[k];
      }
    }
    if ("badWords" in a) {
      if (!strList(a.badWords, 100, 40)) return { error: "Blocked words: up to 100, 40 characters each" };
      o.badWords = a.badWords;
    }
    if ("allowedDomains" in a) {
      if (!strList(a.allowedDomains, 50, 100)) return { error: "Allowed domains: up to 50" };
      o.allowedDomains = a.allowedDomains;
    }
    if ("ignoredChannels" in a) {
      if (!idList(a.ignoredChannels, 50)) return { error: "Bad ignored channels" };
      o.ignoredChannels = a.ignoredChannels;
    }
    if ("ignoredRoles" in a) {
      if (!idList(a.ignoredRoles, 50)) return { error: "Bad ignored roles" };
      o.ignoredRoles = a.ignoredRoles;
    }
    if (Object.keys(o).length) out.automod = o;
  }

  const r = m.antiraid;
  if (r !== undefined) {
    if (!r || typeof r !== "object") return { error: "Bad anti-raid settings" };
    const o = {};
    if ("enabled" in r) {
      if (!isBool(r.enabled)) return { error: "Bad anti-raid switch" };
      o.enabled = r.enabled;
    }
    if ("lockOnRaid" in r) {
      if (!isBool(r.lockOnRaid)) return { error: "Bad soft-lock switch" };
      o.lockOnRaid = r.lockOnRaid;
    }
    for (const [k, lo, hi] of [["joinThreshold", 3, 50], ["joinWindowSec", 5, 120], ["minAccountAgeHours", 0, 720]]) {
      if (k in r) {
        if (!isInt(r[k], lo, hi)) return { error: "Bad anti-raid number (" + k + ")" };
        o[k] = r[k];
      }
    }
    if ("action" in r) {
      if (!["kick", "ban", "timeout"].includes(r.action)) return { error: "Anti-raid action must be kick, ban or timeout" };
      o.action = r.action;
    }
    if ("alertChannelId" in r) {
      if (!chan(r.alertChannelId)) return { error: "Bad alert channel" };
      o.alertChannelId = r.alertChannelId;
    }
    if (Object.keys(o).length) out.antiraid = o;
  }

  const w = m.welcome;
  if (w !== undefined) {
    if (!w || typeof w !== "object") return { error: "Bad welcome settings" };
    const o = {};
    if ("enabled" in w) {
      if (!isBool(w.enabled)) return { error: "Bad welcome switch" };
      o.enabled = w.enabled;
    }
    if ("channelId" in w) {
      if (!chan(w.channelId)) return { error: "Bad welcome channel" };
      o.channelId = w.channelId;
    }
    if ("message" in w) {
      const text = String(w.message || "").trim();
      if (!text || text.length > 1800) return { error: "The welcome message must be 1–1800 characters" };
      o.message = text;
    }
    if (Object.keys(o).length) out.welcome = o;
  }

  return { value: out };
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

  if (c.mod !== undefined) {
    const r = cleanMod(c.mod);
    if (r.error) return r;
    if (Object.keys(r.value).length) out.mod = r.value;
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

// ---------- Moderation (dashboard) ----------

// In the server, bot present, and some moderation permission (or one of the bot's moderator roles)
async function modGuild(env, user, guild) {
  const list = await userGuilds(env, user);
  if (!list) return { error: "Log in again to refresh your server list", status: 409 };
  const entry = list.find((e) => e[0] === guild);
  if (!entry) return { error: "You're not in that server", status: 403 };
  const all = (await getState(env, "guilds")) || [];
  const found = all.find((g) => g[0] === guild);
  if (!found) return { error: "The bot isn't in that server", status: 404 };

  const manage = canManage(entry);
  if (!manage && !canModerate(entry)) {
    // They may still hold a moderator role that was set up with the bot
    const { rows } = await sql(env, "SELECT value FROM kv WHERE file = ? AND key = 'config'", ["moderation@" + guild]);
    const cfg = parseRow(rows[0], {}) || {};
    const roleIds = Array.isArray(cfg.modRoleIds) ? cfg.modRoleIds : [];
    const res = roleIds.length ? await discordGet(env, "/guilds/" + guild + "/members/" + user.id) : null;
    const mine = res && res.ok && Array.isArray(res.data.roles) ? res.data.roles : [];
    if (!mine.some((r) => roleIds.includes(r))) {
      return { error: "You don't have a moderation permission in that server", status: 403 };
    }
  }
  return { name: found[1], manage };
}

async function modMeta(env, user, url) {
  const guild = url.searchParams.get("guild") || "";
  if (!ID.test(guild)) return json({ error: "Pick a server" }, 400);
  if (limited("modget:" + user.id, 60, 60000)) return json({ error: "Slow down a little" }, 429);
  const g = await modGuild(env, user, guild);
  if (g.error) return json({ error: g.error }, g.status);
  const cr = await channelsAndRoles(env, guild);
  if (cr.error) return json({ error: cr.error }, 502);
  return json({ guild: { id: guild, name: g.name }, manage: g.manage, channels: cr.channels, roles: cr.roles });
}

const nameCache = new Map();
async function resolveNames(env, ids) {
  const out = {};
  let budget = 12;
  for (const id of ids) {
    if (nameCache.has(id)) {
      out[id] = nameCache.get(id);
      continue;
    }
    if (budget <= 0) continue;
    budget--;
    const res = await discordGet(env, "/users/" + id);
    const name = res.ok ? res.data.global_name || res.data.username : null;
    if (nameCache.size > 3000) nameCache.clear();
    nameCache.set(id, name);
    out[id] = name;
  }
  return out;
}

const CASE_TYPES = ["warn", "mute", "unmute", "kick", "ban", "tempban", "softban", "unban", "note"];

async function modCases(env, user, url) {
  const guild = url.searchParams.get("guild") || "";
  if (!ID.test(guild)) return json({ error: "Pick a server" }, 400);
  if (limited("modget:" + user.id, 60, 60000)) return json({ error: "Slow down a little" }, 429);
  const g = await modGuild(env, user, guild);
  if (g.error) return json({ error: g.error }, g.status);

  const uid = url.searchParams.get("user") || "";
  const type = url.searchParams.get("type") || "";
  const before = Math.floor(Number(url.searchParams.get("before"))) || 0;
  if (uid && !ID.test(uid)) return json({ error: "Bad user" }, 400);
  if (type && !CASE_TYPES.includes(type)) return json({ error: "Bad case type" }, 400);

  const file = "moderation@" + guild;
  let where = "file = ? AND key LIKE 'case_%'";
  const args = [file];
  if (uid) {
    where += " AND json_extract(value, '$.userId') = ?";
    args.push(uid);
  }
  if (type) {
    where += " AND json_extract(value, '$.type') = ?";
    args.push(type);
  }
  if (before > 0) {
    where += " AND CAST(SUBSTR(key, 6) AS INTEGER) < ?";
    args.push(before);
  }

  const statements = [
    { sql: "SELECT key, value FROM kv WHERE " + where + " ORDER BY CAST(SUBSTR(key, 6) AS INTEGER) DESC LIMIT 61", args },
  ];
  if (!uid && !type && !before) {
    statements.push({
      sql: "SELECT json_extract(value, '$.type') AS type, COUNT(*) AS n FROM kv WHERE file = ? AND key LIKE 'case_%' AND json_extract(value, '$.removed') = 0 GROUP BY type",
      args: [file],
    });
  }
  if (uid) {
    statements.push({
      sql: "SELECT COUNT(*) AS n FROM kv WHERE file = ? AND key LIKE 'case_%' AND json_extract(value, '$.userId') = ? AND json_extract(value, '$.type') = 'warn' AND json_extract(value, '$.removed') = 0",
      args: [file, uid],
    });
  }
  const results = await pipeline(env, statements);

  const rows = results[0].rows;
  const cases = [];
  for (const r of rows.slice(0, 60)) {
    try {
      const c = JSON.parse(r.value);
      cases.push({
        id: c.id,
        type: c.type,
        userId: c.userId || null,
        modId: c.modId || null,
        reason: String(c.reason || ""),
        at: c.at || 0,
        until: c.until || null,
        removed: Boolean(c.removed),
      });
    } catch {
      /* skip a damaged row */
    }
  }

  const ids = [...new Set(cases.flatMap((c) => [c.userId, c.modId]).filter(Boolean))];
  const names = await resolveNames(env, ids);

  const out = { cases, more: rows.length > 60, names };
  if (!uid && !type && !before) {
    out.counts = {};
    for (const r of results[1].rows) if (r.type) out.counts[r.type] = r.n;
  }
  if (uid) out.activeWarnings = results[1].rows[0] ? results[1].rows[0].n : 0;
  return json(out);
}

const avatarOf = (u) => {
  if (u.avatar) return "https://cdn.discordapp.com/avatars/" + u.id + "/" + u.avatar + ".png?size=64";
  let n = 0;
  try {
    n = Number((BigInt(u.id) >> 22n) % 6n);
  } catch {
    /* default avatar 0 */
  }
  return "https://cdn.discordapp.com/embed/avatars/" + n + ".png";
};

function shapeMember(m, inServer) {
  const u = m.user || m;
  return {
    id: u.id,
    name: u.global_name || u.username,
    username: u.username,
    nick: m.nick || null,
    avatar: avatarOf(u),
    bot: Boolean(u.bot),
    inServer,
    roles: inServer ? m.roles || [] : [],
    joinedAt: inServer ? m.joined_at || null : null,
    mutedUntil: inServer ? m.communication_disabled_until || null : null,
  };
}

async function modMembers(env, user, url) {
  const guild = url.searchParams.get("guild") || "";
  if (!ID.test(guild)) return json({ error: "Pick a server" }, 400);
  if (limited("modget:" + user.id, 60, 60000)) return json({ error: "Slow down a little" }, 429);
  const g = await modGuild(env, user, guild);
  if (g.error) return json({ error: g.error }, g.status);

  const q = (url.searchParams.get("q") || "").trim().slice(0, 32);
  if (!q) return json({ members: [] });

  // A pasted ID: works even for people who already left
  if (ID.test(q)) {
    const m = await discordGet(env, "/guilds/" + guild + "/members/" + q);
    if (m.ok && m.data.user) return json({ members: [shapeMember(m.data, true)] });
    const u = await discordGet(env, "/users/" + q);
    if (u.ok) return json({ members: [shapeMember({ user: u.data }, false)] });
    return json({ members: [] });
  }

  const res = await discordGet(env, "/guilds/" + guild + "/members/search?limit=12&query=" + encodeURIComponent(q));
  if (!res.ok) return json({ error: "Discord: " + (res.data.message || res.status) }, 502);
  return json({ members: (Array.isArray(res.data) ? res.data : []).filter((m) => m.user).map((m) => shapeMember(m, true)) });
}

async function modBans(env, user, url) {
  const guild = url.searchParams.get("guild") || "";
  if (!ID.test(guild)) return json({ error: "Pick a server" }, 400);
  if (limited("modget:" + user.id, 60, 60000)) return json({ error: "Slow down a little" }, 429);
  const g = await modGuild(env, user, guild);
  if (g.error) return json({ error: g.error }, g.status);

  const res = await discordGet(env, "/guilds/" + guild + "/bans?limit=200");
  if (!res.ok) return json({ error: "I couldn't read the ban list (" + (res.data.message || res.status) + "). I need the Ban Members permission." }, 502);
  const bans = (Array.isArray(res.data) ? res.data : []).map((b) => ({
    id: b.user.id,
    name: b.user.global_name || b.user.username,
    username: b.user.username,
    avatar: avatarOf(b.user),
    reason: b.reason || "",
  }));
  return json({ bans });
}

// Only known fields get through, each checked
function cleanModAction(action, p) {
  if (!p || typeof p !== "object") return { error: "Bad request" };
  const text = (v, max) => String(v === undefined || v === null ? "" : v).trim().slice(0, max);
  const DAY = 86400000;
  const uid = text(p.userId, 25);
  const reason = text(p.reason, 400);
  const needUser = () => (ID.test(uid) ? null : "Pick a member first");
  const dur = (min, max) => {
    const n = Math.floor(Number(p.durationMs));
    return Number.isFinite(n) && n >= min && n <= max ? n : null;
  };

  switch (action) {
    case "warn":
    case "note":
      if (needUser()) return { error: needUser() };
      if (!reason) return { error: "Write a reason" };
      return { payload: { userId: uid, reason } };
    case "mute": {
      if (needUser()) return { error: needUser() };
      const ms = p.durationMs === undefined ? 3600000 : dur(60000, 28 * DAY);
      if (!ms) return { error: "Mute length must be 1 minute to 28 days" };
      return { payload: { userId: uid, reason, durationMs: ms } };
    }
    case "unmute":
    case "kick":
    case "softban":
    case "unban":
      if (needUser()) return { error: needUser() };
      return { payload: { userId: uid, reason } };
    case "ban": {
      if (needUser()) return { error: needUser() };
      const days = p.deleteDays === undefined ? 0 : Math.floor(Number(p.deleteDays));
      if (!Number.isInteger(days) || days < 0 || days > 7) return { error: "Delete 0–7 days of messages" };
      return { payload: { userId: uid, reason, deleteDays: days } };
    }
    case "tempban": {
      if (needUser()) return { error: needUser() };
      const ms = dur(60000, 365 * DAY);
      if (!ms) return { error: "Ban length must be 1 minute to 365 days" };
      return { payload: { userId: uid, reason, durationMs: ms } };
    }
    case "nick":
      if (needUser()) return { error: needUser() };
      return { payload: { userId: uid, nick: text(p.nick, 32) } };
    case "role": {
      if (needUser()) return { error: needUser() };
      const roleId = text(p.roleId, 25);
      if (!ID.test(roleId)) return { error: "Pick a role" };
      if (!["add", "remove"].includes(p.mode)) return { error: "Bad role mode" };
      return { payload: { userId: uid, roleId, mode: p.mode } };
    }
    case "clearwarns":
      if (needUser()) return { error: needUser() };
      return { payload: { userId: uid } };
    case "delwarn":
    case "reason": {
      const caseId = Math.floor(Number(p.caseId));
      if (!Number.isInteger(caseId) || caseId < 1) return { error: "Bad case number" };
      if (action === "reason" && !reason) return { error: "Write a reason" };
      return { payload: action === "reason" ? { caseId, reason } : { caseId } };
    }
    case "slowmode": {
      const channelId = text(p.channelId, 25);
      const seconds = Math.floor(Number(p.seconds));
      if (!ID.test(channelId)) return { error: "Pick a channel" };
      if (!Number.isInteger(seconds) || seconds < 0 || seconds > 21600) return { error: "Slowmode is 0–21600 seconds" };
      return { payload: { channelId, seconds } };
    }
    case "lock":
    case "unlock": {
      const channelId = text(p.channelId, 25);
      if (!ID.test(channelId)) return { error: "Pick a channel" };
      return { payload: { channelId, reason } };
    }
    case "purge": {
      const channelId = text(p.channelId, 25);
      const count = Math.floor(Number(p.count));
      if (!ID.test(channelId)) return { error: "Pick a channel" };
      if (!Number.isInteger(count) || count < 1 || count > 100) return { error: "Delete 1–100 messages" };
      const filterUserId = text(p.filterUserId, 25);
      if (filterUserId && !ID.test(filterUserId)) return { error: "Bad user filter" };
      return { payload: { channelId, count, filterUserId: filterUserId || null, bots: p.bots === true } };
    }
    case "welcomeTest":
      return { payload: {} };
    default:
      return { error: "Unknown action" };
  }
}

async function modAction(request, env, user) {
  const body = await request.json().catch(() => ({}));
  const guild = String(body.guild || "");
  if (!ID.test(guild)) return json({ error: "Pick a server" }, 400);
  if (limited("modact:" + user.id, 20, 60000)) return json({ error: "Slow down, try again in a minute" }, 429);

  const g = await modGuild(env, user, guild);
  if (g.error) return json({ error: g.error }, g.status);

  const action = String(body.action || "");
  const checked = cleanModAction(action, body.payload);
  if (checked.error) return json({ error: checked.error }, 400);

  // The bot checks the person's permissions and role order again before doing anything
  const { status, result } = await enqueueAndWait(env, user, "modAction", { guildId: guild, action, ...checked.payload });
  await audit(env, user, "mod-" + action, g.name + ": " + (result || ""), status);
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
