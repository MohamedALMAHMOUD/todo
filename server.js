// توزيع المهام — serveur Node.js (Express + PostgreSQL) pour Railway
"use strict";
const express = require("express");
const crypto = require("crypto");
const path = require("path");
const { Pool } = require("pg");

const PORT = process.env.PORT || 3000;
const JOIN_CODE = process.env.JOIN_CODE || "";
let SECRET = process.env.SESSION_SECRET;
if (!SECRET) {
  SECRET = crypto.randomBytes(32).toString("hex");
  console.warn("⚠️  SESSION_SECRET absent : les sessions seront perdues à chaque redémarrage.");
}
if (!process.env.DATABASE_URL) {
  console.error("❌ DATABASE_URL manquant. Ajoute une base PostgreSQL au projet Railway.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSL === "true" ? { rejectUnauthorized: false } : false,
});

/* ---------- schéma ---------- */
async function migrate() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT NOT NULL UNIQUE,
      display_name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      is_admin BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS tasks (
      id SERIAL PRIMARY KEY,
      title TEXT NOT NULL,
      descr TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL CHECK (status IN ('proposed','open','taken','done')),
      proposed_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      assignee INTEGER REFERENCES users(id) ON DELETE SET NULL,
      progress INTEGER NOT NULL DEFAULT 0 CHECK (progress BETWEEN 0 AND 100),
      notes TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      taken_at TIMESTAMPTZ,
      done_at TIMESTAMPTZ,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    -- sous-tâches : une tâche « mère » (is_group) peut avoir des sous-tâches partagées dans la pioche
    ALTER TABLE tasks ADD COLUMN IF NOT EXISTS parent_id INTEGER REFERENCES tasks(id) ON DELETE CASCADE;
    ALTER TABLE tasks ADD COLUMN IF NOT EXISTS is_group BOOLEAN NOT NULL DEFAULT FALSE;
    CREATE INDEX IF NOT EXISTS tasks_parent_idx ON tasks(parent_id);
    -- étapes : petite checklist gardée par la personne qui a la tâche
    CREATE TABLE IF NOT EXISTS steps (
      id SERIAL PRIMARY KEY,
      task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
      title TEXT NOT NULL,
      done BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS steps_task_idx ON steps(task_id);
    ALTER TABLE steps ADD COLUMN IF NOT EXISTS notes TEXT NOT NULL DEFAULT '';
    -- réglages partagés (ex. informations sur le projet affichées en haut)
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL DEFAULT '',
      updated_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    -- sondages : chacun peut en créer, ajouter des choix et voter (une voix par sondage)
    CREATE TABLE IF NOT EXISTS polls (
      id SERIAL PRIMARY KEY,
      question TEXT NOT NULL,
      created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      closed BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS poll_options (
      id SERIAL PRIMARY KEY,
      poll_id INTEGER NOT NULL REFERENCES polls(id) ON DELETE CASCADE,
      label TEXT NOT NULL,
      added_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE UNIQUE INDEX IF NOT EXISTS poll_options_unique ON poll_options(poll_id, lower(label));
    CREATE TABLE IF NOT EXISTS poll_votes (
      poll_id INTEGER NOT NULL REFERENCES polls(id) ON DELETE CASCADE,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      option_id INTEGER NOT NULL REFERENCES poll_options(id) ON DELETE CASCADE,
      PRIMARY KEY (poll_id, user_id)
    );
    -- une seule tâche en cours par personne, garanti par la base
    -- (une tâche mère qu'on coordonne ne compte pas : on peut piocher une tâche en plus)
    DROP INDEX IF EXISTS one_taken_task_per_user;
    CREATE UNIQUE INDEX IF NOT EXISTS one_current_task_per_user ON tasks(assignee) WHERE status = 'taken' AND NOT is_group;
  `);
  const u = process.env.ADMIN_USERNAME, p = process.env.ADMIN_PASSWORD;
  if (u && p) {
    const { rowCount } = await pool.query("SELECT 1 FROM users WHERE username = $1", [u.toLowerCase()]);
    if (!rowCount) {
      await pool.query("INSERT INTO users (username, display_name, password_hash, is_admin) VALUES ($1,$2,$3,TRUE)",
        [u.toLowerCase(), process.env.ADMIN_NAME || u, await hashPassword(p)]);
      console.log(`👑 Compte admin « ${u} » créé.`);
    } else {
      await pool.query("UPDATE users SET is_admin = TRUE WHERE username = $1", [u.toLowerCase()]);
    }
  }
}

/* ---------- mots de passe & sessions ---------- */
function hashPassword(pw) {
  return new Promise((res, rej) => {
    const salt = crypto.randomBytes(16);
    crypto.scrypt(pw, salt, 64, (e, key) => e ? rej(e) : res(`scrypt$${salt.toString("hex")}$${key.toString("hex")}`));
  });
}
function checkPassword(pw, stored) {
  return new Promise(res => {
    const [, saltHex, keyHex] = String(stored).split("$");
    if (!saltHex || !keyHex) return res(false);
    crypto.scrypt(pw, Buffer.from(saltHex, "hex"), 64, (e, key) => {
      if (e) return res(false);
      const ref = Buffer.from(keyHex, "hex");
      res(ref.length === key.length && crypto.timingSafeEqual(ref, key));
    });
  });
}
const SESSION_DAYS = 30;
function sign(v) { return crypto.createHmac("sha256", SECRET).update(v).digest("base64url"); }
function makeToken(userId) {
  const body = `${userId}.${Date.now() + SESSION_DAYS * 86400e3}`;
  return `${body}.${sign(body)}`;
}
function readToken(tok) {
  if (!tok) return null;
  const parts = tok.split(".");
  if (parts.length !== 3) return null;
  const body = `${parts[0]}.${parts[1]}`;
  const sig = Buffer.from(parts[2]), good = Buffer.from(sign(body));
  if (sig.length !== good.length || !crypto.timingSafeEqual(sig, good)) return null;
  if (+parts[1] < Date.now()) return null;
  return +parts[0];
}
function getCookie(req, name) {
  const m = (req.headers.cookie || "").split(/;\s*/).find(c => c.startsWith(name + "="));
  return m ? decodeURIComponent(m.slice(name.length + 1)) : null;
}
function setSession(req, res, userId) {
  const secure = req.secure ? "; Secure" : "";
  res.setHeader("Set-Cookie", `sid=${makeToken(userId)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_DAYS * 86400}${secure}`);
}

/* ---------- temps réel (Server-Sent Events) ---------- */
const clients = new Set();
function broadcast() {
  for (const res of clients) res.write(`event: changed\ndata: ${Date.now()}\n\n`);
}
setInterval(() => { for (const res of clients) res.write(": ping\n\n"); }, 25000);

/* ---------- app ---------- */
const app = express();
app.set("trust proxy", 1);
app.use(express.json({ limit: "100kb" }));
app.use((req, res, next) => {
  // Les requêtes qui modifient doivent être en JSON (protection CSRF avec SameSite=Lax)
  const hasBody = +(req.headers["content-length"] || 0) > 0 || !!req.headers["transfer-encoding"];
  if (req.method !== "GET" && req.method !== "HEAD" && hasBody && !req.is("application/json")) return res.status(415).json({ error: "json_required" });
  next();
});

const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
async function loadUser(req) {
  const id = readToken(getCookie(req, "sid"));
  if (!id) return null;
  const { rows } = await pool.query("SELECT id, username, display_name, is_admin FROM users WHERE id = $1", [id]);
  return rows[0] || null;
}
const auth = wrap(async (req, res, next) => {
  const u = await loadUser(req);
  if (!u) return res.status(401).json({ error: "not_logged_in" });
  req.user = u; next();
});
const adminOnly = (req, res, next) => req.user.is_admin ? next() : res.status(403).json({ error: "admin_only" });
const str = (v, max) => String(v == null ? "" : v).trim().slice(0, max);

app.get("/health", (req, res) => res.send("ok"));

app.post("/api/register", wrap(async (req, res) => {
  if (!JOIN_CODE) return res.status(403).json({ error: "registration_closed" });
  const username = str(req.body.username, 40).toLowerCase();
  const displayName = str(req.body.displayName, 60);
  const password = String(req.body.password || "");
  if (str(req.body.joinCode, 100) !== JOIN_CODE) return res.status(403).json({ error: "bad_join_code" });
  if (!/^[a-z0-9._-]{3,40}$/.test(username)) return res.status(400).json({ error: "bad_username" });
  if (!displayName) return res.status(400).json({ error: "bad_name" });
  if (password.length < 6) return res.status(400).json({ error: "short_password" });
  try {
    const { rows } = await pool.query("INSERT INTO users (username, display_name, password_hash) VALUES ($1,$2,$3) RETURNING id",
      [username, displayName, await hashPassword(password)]);
    setSession(req, res, rows[0].id);
    broadcast();
    res.json({ ok: true });
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "username_taken" });
    throw e;
  }
}));

app.post("/api/login", wrap(async (req, res) => {
  const username = str(req.body.username, 40).toLowerCase();
  const { rows } = await pool.query("SELECT id, password_hash FROM users WHERE username = $1", [username]);
  if (!rows[0] || !(await checkPassword(String(req.body.password || ""), rows[0].password_hash)))
    return res.status(401).json({ error: "bad_credentials" });
  setSession(req, res, rows[0].id);
  res.json({ ok: true });
}));

app.post("/api/logout", (req, res) => {
  res.setHeader("Set-Cookie", "sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0");
  res.json({ ok: true });
});

app.get("/api/state", auth, wrap(async (req, res) => {
  const [users, tasks, steps, info, polls, options, votes] = await Promise.all([
    pool.query("SELECT id, display_name, is_admin FROM users ORDER BY display_name"),
    pool.query(`SELECT id, title, descr, status, proposed_by, assignee, progress, notes, parent_id, is_group,
      (extract(epoch from created_at)*1000)::bigint AS created_at,
      (extract(epoch from taken_at)*1000)::bigint AS taken_at,
      (extract(epoch from done_at)*1000)::bigint AS done_at
      FROM tasks ORDER BY id`),
    pool.query("SELECT id, task_id, title, done, notes FROM steps ORDER BY id"),
    pool.query(`SELECT s.value, s.updated_by, (extract(epoch from s.updated_at)*1000)::bigint AS updated_at
      FROM settings s WHERE s.key='project_info'`),
    pool.query("SELECT id, question, created_by, closed, (extract(epoch from created_at)*1000)::bigint AS created_at FROM polls ORDER BY id DESC"),
    pool.query("SELECT id, poll_id, label, added_by FROM poll_options ORDER BY id"),
    pool.query("SELECT poll_id, user_id, option_id FROM poll_votes"),
  ]);
  const pi = info.rows[0];
  res.json({
    me: { id: req.user.id, displayName: req.user.display_name, username: req.user.username, isAdmin: req.user.is_admin },
    joinCode: req.user.is_admin ? JOIN_CODE : undefined,
    users: users.rows,
    tasks: tasks.rows.map(t => ({ ...t, created_at: +t.created_at || null, taken_at: +t.taken_at || null, done_at: +t.done_at || null })),
    steps: steps.rows,
    projectInfo: pi ? { text: pi.value, updatedBy: pi.updated_by, updatedAt: +pi.updated_at || null } : { text: "" },
    polls: polls.rows.map(p => ({ ...p, created_at: +p.created_at || null })),
    pollOptions: options.rows,
    pollVotes: votes.rows,
  });
}));

/* ---------- sondages ---------- */
const MAX_OPTIONS = 20;
async function getPoll(id) {
  const { rows } = await pool.query("SELECT * FROM polls WHERE id=$1", [+id || 0]);
  return rows[0] || null;
}
const canManagePoll = (p, u) => p && (u.is_admin || p.created_by === u.id);

app.post("/api/polls", auth, wrap(async (req, res) => {
  const question = str(req.body.question, 200);
  if (!question) return res.status(400).json({ error: "question_required" });
  const seen = new Set();
  const opts = (Array.isArray(req.body.options) ? req.body.options : [])
    .map(o => str(o, 100)).filter(o => o && !seen.has(o.toLowerCase()) && seen.add(o.toLowerCase())).slice(0, MAX_OPTIONS);
  await tx(async c => {
    const { rows } = await c.query("INSERT INTO polls (question, created_by) VALUES ($1,$2) RETURNING id", [question, req.user.id]);
    for (const o of opts) await c.query("INSERT INTO poll_options (poll_id, label, added_by) VALUES ($1,$2,$3)", [rows[0].id, o, req.user.id]);
  });
  broadcast(); res.json({ ok: true });
}));

// ajouter un choix : tout le monde, tant que le sondage est ouvert
app.post("/api/polls/:id/options", auth, wrap(async (req, res) => {
  const label = str(req.body.label, 100);
  if (!label) return res.status(400).json({ error: "option_required" });
  const p = await getPoll(req.params.id);
  if (!p || p.closed) return res.status(409).json({ error: "poll_closed" });
  const { rows } = await pool.query("SELECT count(*)::int AS n FROM poll_options WHERE poll_id=$1", [p.id]);
  if (rows[0].n >= MAX_OPTIONS) return res.status(409).json({ error: "too_many_options" });
  try {
    await pool.query("INSERT INTO poll_options (poll_id, label, added_by) VALUES ($1,$2,$3)", [p.id, label, req.user.id]);
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "option_exists" });
    throw e;
  }
  broadcast(); res.json({ ok: true });
}));

// voter (une voix par personne, modifiable) ; optionId null = retirer sa voix
app.post("/api/polls/:id/vote", auth, wrap(async (req, res) => {
  const p = await getPoll(req.params.id);
  if (!p || p.closed) return res.status(409).json({ error: "poll_closed" });
  const optionId = req.body.optionId == null ? null : +req.body.optionId || 0;
  if (optionId === null) {
    await pool.query("DELETE FROM poll_votes WHERE poll_id=$1 AND user_id=$2", [p.id, req.user.id]);
  } else {
    const r = await pool.query(`INSERT INTO poll_votes (poll_id, user_id, option_id)
      SELECT $1, $2, id FROM poll_options WHERE id=$3 AND poll_id=$1
      ON CONFLICT (poll_id, user_id) DO UPDATE SET option_id=EXCLUDED.option_id`, [p.id, req.user.id, optionId]);
    if (!r.rowCount) return res.status(409).json({ error: "not_allowed" });
  }
  broadcast(); res.json({ ok: true });
}));

// fermer / rouvrir, supprimer : l'auteur du sondage ou l'admin
app.post("/api/polls/:id/close", auth, wrap(async (req, res) => {
  const p = await getPoll(req.params.id);
  if (!canManagePoll(p, req.user)) return res.status(403).json({ error: "not_allowed" });
  await pool.query("UPDATE polls SET closed=$1 WHERE id=$2", [!!req.body.closed, p.id]);
  broadcast(); res.json({ ok: true });
}));
app.delete("/api/polls/:id", auth, wrap(async (req, res) => {
  const p = await getPoll(req.params.id);
  if (!canManagePoll(p, req.user)) return res.status(403).json({ error: "not_allowed" });
  await pool.query("DELETE FROM polls WHERE id=$1", [p.id]);
  broadcast(); res.json({ ok: true });
}));
// retirer un choix : la personne qui l'a ajouté (tant que le sondage est ouvert), l'auteur du sondage ou l'admin
app.delete("/api/poll-options/:id", auth, wrap(async (req, res) => {
  const r = await pool.query(`DELETE FROM poll_options o USING polls p WHERE o.id=$1 AND p.id=o.poll_id
    AND ($2 OR p.created_by=$3 OR (o.added_by=$3 AND NOT p.closed))`, [+req.params.id || 0, req.user.is_admin, req.user.id]);
  done(res, r.rowCount);
}));

// informations sur le projet (encadré en haut) : modifiables par l'admin, visibles par tous
app.post("/api/project-info", auth, adminOnly, wrap(async (req, res) => {
  await pool.query(`INSERT INTO settings (key, value, updated_by, updated_at) VALUES ('project_info', $1, $2, now())
    ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value, updated_by=EXCLUDED.updated_by, updated_at=now()`,
    [String(req.body.text || "").slice(0, 10000), req.user.id]);
  broadcast(); res.json({ ok: true });
}));

app.get("/api/events", auth, (req, res) => {
  res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-cache, no-transform", Connection: "keep-alive", "X-Accel-Buffering": "no" });
  res.write("retry: 3000\n\n");
  clients.add(res);
  req.on("close", () => clients.delete(res));
});

function done(res, rowCount, err = "not_allowed") {
  if (!rowCount) return res.status(409).json({ error: err });
  broadcast(); res.json({ ok: true });
}

// créer : admin → directement dans la pioche ; membre → proposition
app.post("/api/tasks", auth, wrap(async (req, res) => {
  const title = str(req.body.title, 140);
  if (!title) return res.status(400).json({ error: "title_required" });
  const status = req.user.is_admin ? "open" : "proposed";
  await pool.query("INSERT INTO tasks (title, descr, status, proposed_by) VALUES ($1,$2,$3,$4)",
    [title, str(req.body.desc, 2000), status, req.user.id]);
  broadcast(); res.json({ ok: true, status });
}));

// modifier titre/description : admin, ou auteur d'une proposition
app.patch("/api/tasks/:id", auth, wrap(async (req, res) => {
  const title = str(req.body.title, 140);
  if (!title) return res.status(400).json({ error: "title_required" });
  const r = await pool.query(`UPDATE tasks SET title=$1, descr=$2, updated_at=now()
    WHERE id=$3 AND ($4 OR (status='proposed' AND proposed_by=$5))`,
    [title, str(req.body.desc, 2000), +req.params.id || 0, req.user.is_admin, req.user.id]);
  done(res, r.rowCount);
}));

// piocher (atomique : la tâche doit être libre, et l'index unique empêche 2 tâches en cours)
app.post("/api/tasks/:id/take", auth, wrap(async (req, res) => {
  try {
    const r = await pool.query(`UPDATE tasks SET status='taken', assignee=$1, taken_at=now(), updated_at=now()
      WHERE id=$2 AND status='open'`, [req.user.id, +req.params.id || 0]);
    done(res, r.rowCount, "already_taken");
  } catch (e) {
    if (e.code === "23505") return res.status(409).json({ error: "has_current_task" });
    throw e;
  }
}));

app.post("/api/tasks/:id/progress", auth, wrap(async (req, res) => {
  const p = Math.max(0, Math.min(100, Math.round(+req.body.progress || 0)));
  const r = await pool.query("UPDATE tasks SET progress=$1, updated_at=now() WHERE id=$2 AND status='taken' AND assignee=$3",
    [p, +req.params.id || 0, req.user.id]);
  done(res, r.rowCount);
}));

// « sa partie » : seule la personne qui a la tâche (en cours ou terminée) écrit
app.post("/api/tasks/:id/notes", auth, wrap(async (req, res) => {
  const r = await pool.query("UPDATE tasks SET notes=$1, updated_at=now() WHERE id=$2 AND assignee=$3 AND status IN ('taken','done')",
    [String(req.body.notes || "").slice(0, 8000), +req.params.id || 0, req.user.id]);
  done(res, r.rowCount);
}));

// terminer : seulement quand toutes les sous-tâches partagées sont terminées
app.post("/api/tasks/:id/finish", auth, wrap(async (req, res) => {
  const id = +req.params.id || 0;
  const r = await pool.query(`UPDATE tasks SET status='done', progress=100, done_at=now(), updated_at=now()
    WHERE id=$1 AND status='taken' AND assignee=$2
    AND NOT EXISTS (SELECT 1 FROM tasks c WHERE c.parent_id=$1 AND c.status<>'done')`, [id, req.user.id]);
  if (!r.rowCount) {
    const { rowCount } = await pool.query("SELECT 1 FROM tasks WHERE parent_id=$1 AND status<>'done'", [id]);
    return res.status(409).json({ error: rowCount ? "subtasks_pending" : "not_allowed" });
  }
  await pool.query("UPDATE steps SET done=TRUE WHERE task_id=$1", [id]);
  broadcast(); res.json({ ok: true });
}));

// remettre dans la pioche : la personne elle-même ou l'admin (avancement et notes conservés)
app.post("/api/tasks/:id/release", auth, wrap(async (req, res) => {
  const r = await pool.query("UPDATE tasks SET status='open', assignee=NULL, updated_at=now() WHERE id=$1 AND status='taken' AND (assignee=$2 OR $3)",
    [+req.params.id || 0, req.user.id, req.user.is_admin]);
  done(res, r.rowCount);
}));

app.post("/api/tasks/:id/approve", auth, adminOnly, wrap(async (req, res) => {
  const r = await pool.query("UPDATE tasks SET status='open', updated_at=now() WHERE id=$1 AND status='proposed'", [+req.params.id || 0]);
  done(res, r.rowCount);
}));

app.post("/api/tasks/:id/reopen", auth, adminOnly, wrap(async (req, res) => {
  const id = +req.params.id || 0;
  const r = await pool.query("UPDATE tasks SET status='open', assignee=NULL, progress=0, done_at=NULL, updated_at=now() WHERE id=$1 AND status='done'", [id]);
  if (r.rowCount) await pool.query("UPDATE steps SET done=FALSE WHERE task_id=$1", [id]);
  done(res, r.rowCount);
}));

// supprimer : admin, auteur qui retire sa proposition,
// ou responsable de la tâche mère qui retire une sous-tâche encore dans la pioche
app.delete("/api/tasks/:id", auth, wrap(async (req, res) => {
  const r = await pool.query(`DELETE FROM tasks WHERE id=$1 AND ($2
    OR (status='proposed' AND proposed_by=$3)
    OR (status='open' AND parent_id IN (SELECT id FROM tasks WHERE status='taken' AND assignee=$3)))`,
    [+req.params.id || 0, req.user.is_admin, req.user.id]);
  done(res, r.rowCount);
}));

/* ---------- découpage : étapes (pour soi) et sous-tâches (pour l'équipe) ---------- */
async function tx(fn) {
  const c = await pool.connect();
  try { await c.query("BEGIN"); const out = await fn(c); await c.query("COMMIT"); return out; }
  catch (e) { await c.query("ROLLBACK").catch(() => {}); throw e; }
  finally { c.release(); }
}
// peut découper : la personne qui a la tâche en cours, ou l'admin (tâche libre ou en cours)
const canSplit = (t, u) => t && ((t.status === "taken" && t.assignee === u.id) || (u.is_admin && (t.status === "open" || t.status === "taken")));
async function shareChild(c, parent, title, userId, descr) {
  await c.query("INSERT INTO tasks (title, descr, status, proposed_by, parent_id) VALUES ($1,$2,'open',$3,$4)", [title, descr || "", userId, parent.id]);
  await c.query("UPDATE tasks SET is_group=TRUE, updated_at=now() WHERE id=$1", [parent.id]);
}

app.post("/api/tasks/:id/subtasks", auth, wrap(async (req, res) => {
  const title = str(req.body.title, 140);
  if (!title) return res.status(400).json({ error: "title_required" });
  const share = req.body.mode === "share";
  const err = await tx(async c => {
    const { rows } = await c.query("SELECT * FROM tasks WHERE id=$1 FOR UPDATE", [+req.params.id || 0]);
    const t = rows[0];
    if (!canSplit(t, req.user)) return "not_allowed";
    if (share) {
      if (t.parent_id) return "no_nested";
      await shareChild(c, t, title, req.user.id);
    } else {
      await c.query("INSERT INTO steps (task_id, title) VALUES ($1,$2)", [t.id, title]);
    }
    await c.query("UPDATE tasks SET updated_at=now() WHERE id=$1", [t.id]);
    return null;
  });
  if (err) return res.status(err === "no_nested" ? 400 : 409).json({ error: err });
  broadcast(); res.json({ ok: true });
}));

// cocher / décocher une étape : seulement la personne qui a la tâche en cours
app.post("/api/steps/:id/toggle", auth, wrap(async (req, res) => {
  const r = await pool.query(`UPDATE steps s SET done=$1 FROM tasks t
    WHERE s.id=$2 AND t.id=s.task_id AND t.status='taken' AND t.assignee=$3`,
    [!!req.body.done, +req.params.id || 0, req.user.id]);
  done(res, r.rowCount);
}));

// texte d'une étape : la personne qui a (ou a eu) la tâche, ou l'admin
app.post("/api/steps/:id/notes", auth, wrap(async (req, res) => {
  const r = await pool.query(`UPDATE steps s SET notes=$1 FROM tasks t
    WHERE s.id=$2 AND t.id=s.task_id AND ((t.assignee=$3 AND t.status IN ('taken','done')) OR ($4 AND t.status<>'proposed'))`,
    [String(req.body.notes || "").slice(0, 8000), +req.params.id || 0, req.user.id, req.user.is_admin]);
  done(res, r.rowCount);
}));

// consignes d'une sous-tâche partagée : le responsable de la tâche mère, ou l'admin
app.post("/api/tasks/:id/descr", auth, wrap(async (req, res) => {
  const r = await pool.query(`UPDATE tasks SET descr=$1, updated_at=now()
    WHERE id=$2 AND parent_id IS NOT NULL AND ($3 OR parent_id IN (SELECT id FROM tasks WHERE status='taken' AND assignee=$4))`,
    [str(req.body.desc, 8000), +req.params.id || 0, req.user.is_admin, req.user.id]);
  done(res, r.rowCount);
}));

app.delete("/api/steps/:id", auth, wrap(async (req, res) => {
  const r = await pool.query(`DELETE FROM steps s USING tasks t
    WHERE s.id=$1 AND t.id=s.task_id AND ((t.status='taken' AND t.assignee=$2) OR ($3 AND t.status IN ('open','taken')))`,
    [+req.params.id || 0, req.user.id, req.user.is_admin]);
  done(res, r.rowCount);
}));

// transformer une étape en sous-tâche partagée dans la pioche
app.post("/api/steps/:id/share", auth, wrap(async (req, res) => {
  const err = await tx(async c => {
    const { rows } = await c.query("SELECT s.id AS step_id, s.title AS step_title, s.notes AS step_notes, t.* FROM steps s JOIN tasks t ON t.id=s.task_id WHERE s.id=$1 FOR UPDATE OF t", [+req.params.id || 0]);
    const t = rows[0];
    if (!canSplit(t, req.user)) return "not_allowed";
    if (t.parent_id) return "no_nested";
    // le texte de l'étape devient les consignes de la sous-tâche
    await shareChild(c, t, t.step_title, req.user.id, t.step_notes);
    await c.query("DELETE FROM steps WHERE id=$1", [t.step_id]);
    return null;
  });
  if (err) return res.status(err === "no_nested" ? 400 : 409).json({ error: err });
  broadcast(); res.json({ ok: true });
}));

/* ---------- gestion de l'équipe (admin) ---------- */
app.post("/api/users/:id/admin", auth, adminOnly, wrap(async (req, res) => {
  const id = +req.params.id || 0;
  if (id === req.user.id) return res.status(400).json({ error: "cannot_change_self" });
  const r = await pool.query("UPDATE users SET is_admin=$1 WHERE id=$2", [!!req.body.isAdmin, id]);
  done(res, r.rowCount);
}));
app.post("/api/users/:id/password", auth, adminOnly, wrap(async (req, res) => {
  const pw = String(req.body.password || "");
  if (pw.length < 6) return res.status(400).json({ error: "short_password" });
  const r = await pool.query("UPDATE users SET password_hash=$1 WHERE id=$2", [await hashPassword(pw), +req.params.id || 0]);
  done(res, r.rowCount);
}));
app.delete("/api/users/:id", auth, adminOnly, wrap(async (req, res) => {
  const id = +req.params.id || 0;
  if (id === req.user.id) return res.status(400).json({ error: "cannot_delete_self" });
  // ses tâches en cours retournent dans la pioche
  await pool.query("UPDATE tasks SET status='open', assignee=NULL, updated_at=now() WHERE assignee=$1 AND status='taken'", [id]);
  const r = await pool.query("DELETE FROM users WHERE id=$1", [id]);
  done(res, r.rowCount);
}));
app.post("/api/me/password", auth, wrap(async (req, res) => {
  const { rows } = await pool.query("SELECT password_hash FROM users WHERE id=$1", [req.user.id]);
  if (!(await checkPassword(String(req.body.current || ""), rows[0].password_hash))) return res.status(403).json({ error: "bad_credentials" });
  const pw = String(req.body.password || "");
  if (pw.length < 6) return res.status(400).json({ error: "short_password" });
  await pool.query("UPDATE users SET password_hash=$1 WHERE id=$2", [await hashPassword(pw), req.user.id]);
  res.json({ ok: true });
}));

app.use(express.static(path.join(__dirname, "public"), { index: "index.html", maxAge: "5m" }));

app.use((err, req, res, next) => {
  if (err && err.type === "entity.parse.failed") return res.status(400).json({ error: "bad_json" });
  if (err && err.type === "entity.too.large") return res.status(413).json({ error: "too_large" });
  console.error(err);
  res.status(500).json({ error: "server_error" });
});

migrate()
  .then(() => app.listen(PORT, () => console.log(`✅ توزيع المهام en ligne sur le port ${PORT}`)))
  .catch(e => { console.error("❌ Échec de la migration :", e); process.exit(1); });
