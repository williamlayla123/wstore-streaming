"use strict";
// WStore: servidor sem dependências externas (Node 22.13+). Banco SQLite embutido.
const http = require("node:http"), fs = require("node:fs"), path = require("node:path"), crypto = require("node:crypto");
const { DatabaseSync } = require("node:sqlite");
const PORT = +process.env.PORT || 3000;
const DBF = process.env.DB_PATH || path.join(__dirname, "data", "wstore.db");
const SIGMA = process.env.SIGMA_API_BASE || "https://next.panelbr.site/api/reseller-api/v1";
fs.mkdirSync(path.dirname(DBF), { recursive: true });
const db = new DatabaseSync(DBF);
db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS usuarios(id INTEGER PRIMARY KEY, usuario TEXT UNIQUE NOT NULL, senha TEXT NOT NULL,
  papel TEXT NOT NULL DEFAULT 'revendedor', creditos INTEGER NOT NULL DEFAULT 0, ativo INTEGER NOT NULL DEFAULT 1, criado_em TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS sessoes(token TEXT PRIMARY KEY, usuario_id INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE, expira INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS clientes(id INTEGER PRIMARY KEY, nome TEXT NOT NULL, whatsapp TEXT DEFAULT '', usuario_servico TEXT DEFAULT '',
  obs TEXT DEFAULT '', vencimento TEXT NOT NULL, revendedor_id INTEGER NOT NULL REFERENCES usuarios(id), criado_em TEXT DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE IF NOT EXISTS movimentos(id INTEGER PRIMARY KEY, usuario_id INTEGER NOT NULL REFERENCES usuarios(id), valor INTEGER NOT NULL,
  descricao TEXT NOT NULL, criado_em TEXT DEFAULT CURRENT_TIMESTAMP);`);

const sha = s => crypto.createHash("sha256").update(s).digest("hex");
const hashPw = p => { const s = crypto.randomBytes(16).toString("hex"); return s + ":" + crypto.scryptSync(p, s, 64).toString("hex"); };
const okPw = (p, h) => { const [s, k] = h.split(":"), a = Buffer.from(k, "hex"), b = crypto.scryptSync(p, s, 64); return a.length === b.length && crypto.timingSafeEqual(a, b); };
const hoje = () => new Date(Date.now() - 3 * 3600e3).toISOString().slice(0, 10); // horário de Brasília
const addMeses = (d, n) => { const x = new Date(d + "T12:00:00Z"), dia = x.getUTCDate(); x.setUTCDate(1); x.setUTCMonth(x.getUTCMonth() + n);
  x.setUTCDate(Math.min(dia, new Date(Date.UTC(x.getUTCFullYear(), x.getUTCMonth() + 1, 0)).getUTCDate())); return x.toISOString().slice(0, 10); };
const err = (status, msg) => Object.assign(new Error(msg), { status });
const txt = (v, max, nome, obrig) => { v = String(v ?? "").trim(); if (obrig && !v) throw err(400, `Preencha ${nome}`); if (v.length > max) throw err(400, `${nome} muito longo`); return v; };
const MESES = [1, 3, 6, 12];
const meses = v => { v = +v; if (!MESES.includes(v)) throw err(400, "Plano inválido"); return v; };
const tx = fn => { db.exec("BEGIN IMMEDIATE"); try { const r = fn(); db.exec("COMMIT"); return r; } catch (e) { db.exec("ROLLBACK"); throw e; } };
const pub = u => ({ id: u.id, usuario: u.usuario, papel: u.papel, creditos: u.creditos });

if (!db.prepare("SELECT 1 FROM usuarios WHERE papel='admin'").get()) {
  const user = process.env.ADMIN_USER || "admin", pw = process.env.ADMIN_PASS || crypto.randomBytes(9).toString("base64url");
  db.prepare("INSERT INTO usuarios(usuario,senha,papel) VALUES(?,?,'admin')").run(user, hashPw(pw));
  console.log(`\n>>> Admin criado. Usuário: ${user}  Senha: ${pw}\n>>> Guarde esta senha e troque no painel.\n`);
}

const falhas = new Map();
const bloqueado = ip => { const f = falhas.get(ip); return f && f.n >= 8 && Date.now() - f.t < 15 * 60e3; };
const falhou = ip => { const f = falhas.get(ip); falhas.set(ip, { n: f && Date.now() - f.t < 15 * 60e3 ? f.n + 1 : 1, t: Date.now() }); };
const cookie = (c, val, max) => c.res.setHeader("Set-Cookie", `sid=${val}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${max}${c.https ? "; Secure" : ""}`);
const admin = c => { if (c.u.papel !== "admin") throw err(403, "Apenas o administrador pode fazer isto"); };
const dono = (c, id) => { const cl = db.prepare("SELECT * FROM clientes WHERE id=?").get(id);
  if (!cl || (c.u.papel !== "admin" && cl.revendedor_id !== c.u.id)) throw err(404, "Cliente não encontrado"); return cl; };
function cobrar(u, n, desc) {
  if (u.papel === "admin") return;
  const r = db.prepare("UPDATE usuarios SET creditos=creditos-? WHERE id=? AND creditos>=?").run(n, u.id, n);
  if (!r.changes) throw err(402, `Créditos insuficientes (precisa de ${n})`);
  db.prepare("INSERT INTO movimentos(usuario_id,valor,descricao) VALUES(?,?,?)").run(u.id, -n, desc);
}
const dadosCliente = b => ({ nome: txt(b.nome, 80, "o nome", true), whatsapp: txt(b.whatsapp, 20, "o WhatsApp"),
  usuario_servico: txt(b.usuario_servico, 60, "o usuário do serviço"), obs: txt(b.obs, 300, "a observação") });

const routes = [], R = (m, p, pub_, fn) => routes.push({ m, re: new RegExp("^" + p.replace(/:id/g, "(\\d+)") + "$"), pub: pub_, fn });
R("POST", "/api/login", true, c => {
  if (bloqueado(c.ip)) throw err(429, "Muitas tentativas. Aguarde 15 minutos.");
  const u = db.prepare("SELECT * FROM usuarios WHERE usuario=? AND ativo=1").get(String(c.b.usuario || "").trim());
  if (!u || !okPw(String(c.b.senha || ""), u.senha)) { falhou(c.ip); throw err(401, "Usuário ou senha incorretos"); }
  falhas.delete(c.ip); db.prepare("DELETE FROM sessoes WHERE expira<?").run(Date.now());
  const t = crypto.randomBytes(32).toString("base64url");
  db.prepare("INSERT INTO sessoes VALUES(?,?,?)").run(sha(t), u.id, Date.now() + 7 * 864e5); cookie(c, t, 7 * 86400); return pub(u);
});
R("POST", "/api/logout", false, c => { db.prepare("DELETE FROM sessoes WHERE token=?").run(c.tok); cookie(c, "", 0); return { ok: true }; });
R("GET", "/api/me", false, c => pub(c.u));
R("POST", "/api/senha", false, c => {
  if (!okPw(String(c.b.atual || ""), c.u.senha)) throw err(400, "Senha atual incorreta");
  const n = String(c.b.nova || ""); if (n.length < 8) throw err(400, "A nova senha precisa de 8 caracteres ou mais");
  db.prepare("UPDATE usuarios SET senha=? WHERE id=?").run(hashPw(n), c.u.id); return { ok: true };
});
R("GET", "/api/resumo", false, c => {
  const w = c.u.papel === "admin" ? "" : "WHERE revendedor_id=" + c.u.id, h = hoje();
  const em7 = new Date(new Date(h).getTime() + 7 * 864e5).toISOString().slice(0, 10);
  const cnt = (cond, ...a) => db.prepare(`SELECT COUNT(*) n FROM clientes ${w} ${w ? "AND" : "WHERE"} ${cond}`).get(...a).n;
  const r = { clientes: db.prepare(`SELECT COUNT(*) n FROM clientes ${w}`).get().n, ativos: cnt("vencimento>=?", h), vencidos: cnt("vencimento<?", h), vencem7: cnt("vencimento>=? AND vencimento<=?", h, em7), creditos: c.u.creditos };
  if (c.u.papel === "admin") { r.revendedores = db.prepare("SELECT COUNT(*) n FROM usuarios WHERE papel='revendedor'").get().n; r.creditos = db.prepare("SELECT COALESCE(SUM(creditos),0) n FROM usuarios WHERE papel='revendedor'").get().n; }
  return r;
});
R("GET", "/api/clientes", false, c => db.prepare(`SELECT c.*, u.usuario revendedor FROM clientes c JOIN usuarios u ON u.id=c.revendedor_id
  ${c.u.papel === "admin" ? "" : "WHERE c.revendedor_id=" + c.u.id} ORDER BY c.vencimento`).all());
R("POST", "/api/clientes", false, c => {
  const d = dadosCliente(c.b), m = meses(c.b.meses);
  return tx(() => { cobrar(c.u, m, `Novo cliente: ${d.nome} (${m} mês/meses)`);
    const r = db.prepare("INSERT INTO clientes(nome,whatsapp,usuario_servico,obs,vencimento,revendedor_id) VALUES(?,?,?,?,?,?)")
      .run(d.nome, d.whatsapp, d.usuario_servico, d.obs, addMeses(hoje(), m), c.u.id); return { id: Number(r.lastInsertRowid) }; });
});
R("PUT", "/api/clientes/:id", false, c => { dono(c, c.p[0]); const d = dadosCliente(c.b);
  db.prepare("UPDATE clientes SET nome=?,whatsapp=?,usuario_servico=?,obs=? WHERE id=?").run(d.nome, d.whatsapp, d.usuario_servico, d.obs, c.p[0]); return { ok: true }; });
R("DELETE", "/api/clientes/:id", false, c => { dono(c, c.p[0]); db.prepare("DELETE FROM clientes WHERE id=?").run(c.p[0]); return { ok: true }; });
R("POST", "/api/clientes/:id/renovar", false, c => { const cl = dono(c, c.p[0]), m = meses(c.b.meses);
  return tx(() => { cobrar(c.u, m, `Renovação: ${cl.nome} (${m} mês/meses)`);
    const base = cl.vencimento > hoje() ? cl.vencimento : hoje(), v = addMeses(base, m);
    db.prepare("UPDATE clientes SET vencimento=? WHERE id=?").run(v, cl.id); return { vencimento: v }; }); });
R("GET", "/api/revendedores", false, c => { admin(c); return db.prepare(`SELECT id,usuario,creditos,ativo,criado_em,
  (SELECT COUNT(*) FROM clientes WHERE revendedor_id=usuarios.id) clientes FROM usuarios WHERE papel='revendedor' ORDER BY usuario`).all(); });
R("POST", "/api/revendedores", false, c => { admin(c);
  const u = txt(c.b.usuario, 30, "o usuário", true).toLowerCase(), s = String(c.b.senha || "");
  if (!/^[a-z0-9._-]{3,30}$/.test(u)) throw err(400, "Usuário: 3 a 30 letras, números, ponto, hífen ou _");
  if (s.length < 8) throw err(400, "A senha precisa de 8 caracteres ou mais");
  try { return { id: Number(db.prepare("INSERT INTO usuarios(usuario,senha) VALUES(?,?)").run(u, hashPw(s)).lastInsertRowid) }; }
  catch { throw err(409, "Este usuário já existe"); } });
R("POST", "/api/revendedores/:id/creditos", false, c => { admin(c); const v = Math.trunc(+c.b.valor);
  if (!v || Math.abs(v) > 100000) throw err(400, "Informe uma quantidade válida");
  return tx(() => { const r = db.prepare("UPDATE usuarios SET creditos=creditos+? WHERE id=? AND papel='revendedor' AND creditos+?>=0").run(v, c.p[0], v);
    if (!r.changes) throw err(400, "Revendedor não encontrado ou saldo ficaria negativo");
    db.prepare("INSERT INTO movimentos(usuario_id,valor,descricao) VALUES(?,?,?)").run(c.p[0], v, v > 0 ? "Créditos adicionados pelo admin" : "Créditos removidos pelo admin"); return { ok: true }; }); });
R("PUT", "/api/revendedores/:id", false, c => { admin(c);
  if (c.b.senha) { if (String(c.b.senha).length < 8) throw err(400, "A senha precisa de 8 caracteres ou mais"); db.prepare("UPDATE usuarios SET senha=? WHERE id=? AND papel='revendedor'").run(hashPw(String(c.b.senha)), c.p[0]); }
  if (c.b.ativo !== undefined) { db.prepare("UPDATE usuarios SET ativo=? WHERE id=? AND papel='revendedor'").run(c.b.ativo ? 1 : 0, c.p[0]); if (!c.b.ativo) db.prepare("DELETE FROM sessoes WHERE usuario_id=?").run(c.p[0]); }
  return { ok: true }; });
R("GET", "/api/movimentos", false, c => db.prepare(`SELECT m.*, u.usuario FROM movimentos m JOIN usuarios u ON u.id=m.usuario_id
  ${c.u.papel === "admin" ? "" : "WHERE m.usuario_id=" + c.u.id} ORDER BY m.id DESC LIMIT 200`).all());
R("GET", "/api/sigma/status", false, async c => { admin(c);
  if (!process.env.SIGMA_API_TOKEN) throw err(503, "Defina SIGMA_API_TOKEN no servidor para ativar a integração");
  try { const r = await fetch(`${SIGMA}/me`, { headers: { Authorization: `Bearer ${process.env.SIGMA_API_TOKEN}`, Accept: "application/json" }, signal: AbortSignal.timeout(10000) });
    if (!r.ok) throw err(502, `A API recusou a solicitação (código ${r.status})`); return { conectado: true, conta: await r.json() };
  } catch (e) { throw e.status ? e : err(502, "Não foi possível conectar à API"); } });

const INDEX = fs.readFileSync(path.join(__dirname, "public", "index.html"));
const server = http.createServer(async (req, res) => {
  res.setHeader("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  res.setHeader("X-Content-Type-Options", "nosniff"); res.setHeader("Referrer-Policy", "no-referrer"); res.setHeader("Cache-Control", "no-store");
  const send = (s, o) => { res.writeHead(s, { "Content-Type": "application/json; charset=utf-8" }); res.end(JSON.stringify(o)); };
  try {
    const url = new URL(req.url, "http://x");
    if (req.method === "GET" && url.pathname === "/") { res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" }); return res.end(INDEX); }
    if (url.pathname === "/health") return send(200, { status: "online" });
    const rt = routes.find(r => r.m === req.method && r.re.test(url.pathname));
    if (!rt) return send(404, { erro: "Não encontrado" });
    const c = { req, res, p: url.pathname.match(rt.re).slice(1), b: {}, ip: String(req.headers["x-forwarded-for"] || req.socket.remoteAddress).split(",")[0].trim(), https: req.headers["x-forwarded-proto"] === "https" };
    if (req.method !== "GET") {
      if (!String(req.headers["content-type"] || "").startsWith("application/json")) throw err(415, "Formato inválido");
      let raw = ""; for await (const ch of req) { raw += ch; if (raw.length > 65536) throw err(413, "Pedido muito grande"); }
      try { c.b = raw ? JSON.parse(raw) : {}; } catch { throw err(400, "JSON inválido"); }
    }
    if (!rt.pub) {
      c.tok = sha((/(?:^|;\s*)sid=([^;]+)/.exec(req.headers.cookie || "") || [])[1] || "");
      c.u = db.prepare("SELECT u.* FROM sessoes s JOIN usuarios u ON u.id=s.usuario_id WHERE s.token=? AND s.expira>? AND u.ativo=1").get(c.tok, Date.now());
      if (!c.u) throw err(401, "Sessão expirada. Entre novamente.");
    }
    send(200, await rt.fn(c));
  } catch (e) { if (!e.status) console.error(e); send(e.status || 500, { erro: e.status ? e.message : "Erro interno do servidor" }); }
});
server.listen(PORT, () => console.log(`WStore online na porta ${PORT}`));
module.exports = server;
