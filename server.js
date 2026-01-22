/**
 * IMS ULTRA PRO — server.js (COMPLETO)
 * Stack: Node + Express + SQLite + JWT + Multer
 * Features:
 * - Login + roles (admin/soporte/usuario)
 * - Empresas (admin crea)
 * - Usuarios (admin crea y asigna empresa por PATCH)
 * - Tickets (ITIL): create/list/detail/update/assign/take
 * - SLA (1ra respuesta + resolución) + ETA (contador) + retraso automático
 * - Chat (conversación por ticket)
 * - Adjuntos (uploads/)
 * - Auditoría
 * - Notificaciones
 * - Dashboard métricas
 *
 * Run:
 *   npm i
 *   node server.js
 */

const path = require("path");
const fs = require("fs");
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const sqlite3 = require("sqlite3").verbose();

const app = express();
app.use(cors());
app.use(express.json({ limit: "2mb" }));

// ---------------- Config
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "ims_ultra_pro_secret_change_me";
const DB_FILE = process.env.DB_FILE || path.join(__dirname, "ims.sqlite");
const UPLOAD_DIR = path.join(__dirname, "uploads");

if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// serve public + uploads
app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(UPLOAD_DIR));

// ---------------- SQLite helpers
const db = new sqlite3.Database(DB_FILE);

function dbRun(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.run(sql, params, function (err) {
      if (err) return reject(err);
      resolve({ lastID: this.lastID, changes: this.changes });
    });
  });
}
function dbGet(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.get(sql, params, function (err, row) {
      if (err) return reject(err);
      resolve(row);
    });
  });
}
function dbAll(sql, params = []) {
  return new Promise((resolve, reject) => {
    db.all(sql, params, function (err, rows) {
      if (err) return reject(err);
      resolve(rows);
    });
  });
}

async function runMigrations() {
  // base tables
await dbRun(`
    CREATE TABLE IF NOT EXISTS companies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        ruc TEXT UNIQUE,
        address TEXT,
        contact_name TEXT,
        contact_phone TEXT,
        contact_email TEXT,
        notes TEXT,
        is_active INTEGER NOT NULL DEFAULT 1
    )
`);

    async function addCol(table, colDef){
    try { await dbRun(`ALTER TABLE ${table} ADD COLUMN ${colDef}`); }
    catch(e){
        // ignora si ya existe
        if(!String(e.message).includes("duplicate column name")) throw e;
    }
    }

    await addCol("companies", "ruc TEXT");
    await addCol("companies", "address TEXT");
    await addCol("companies", "contact_name TEXT");
    await addCol("companies", "contact_phone TEXT");
    await addCol("companies", "contact_email TEXT");
    await addCol("companies", "notes TEXT");
    await addCol("companies", "is_active INTEGER NOT NULL DEFAULT 1");

  await dbRun(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin','soporte','usuario')),
      company_id INTEGER,
      is_active INTEGER NOT NULL DEFAULT 1,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY(company_id) REFERENCES companies(id)
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS brands (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL UNIQUE
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS categories (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      brand_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      UNIQUE(brand_id, name),
      FOREIGN KEY(brand_id) REFERENCES brands(id)
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS subcategories (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      category_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      UNIQUE(category_id, name),
      FOREIGN KEY(category_id) REFERENCES categories(id)
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS subcategory_field_defs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      subcategory_id INTEGER NOT NULL,
      field_key TEXT NOT NULL,
      label TEXT NOT NULL,
      field_type TEXT NOT NULL CHECK(field_type IN ('text','number','select')),
      required INTEGER NOT NULL DEFAULT 0,
      options_json TEXT,
      sort_order INTEGER NOT NULL DEFAULT 0,
      UNIQUE(subcategory_id, field_key),
      FOREIGN KEY(subcategory_id) REFERENCES subcategories(id)
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS tickets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      company_id INTEGER NOT NULL,
      requester_id INTEGER NOT NULL,
      assigned_to INTEGER,
      brand_id INTEGER NOT NULL,
      category_id INTEGER NOT NULL,
      subcategory_id INTEGER NOT NULL,
      contact_phone TEXT NOT NULL,
      priority TEXT NOT NULL CHECK(priority IN ('Alta','Media','Baja')),
      status TEXT NOT NULL DEFAULT 'Nuevo',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),

      -- SLA times
      first_response_due_at TEXT,
      first_response_at TEXT,
      resolution_due_at TEXT,
      resolved_at TEXT,

      -- ETA
      eta_due_at TEXT,

      FOREIGN KEY(company_id) REFERENCES companies(id),
      FOREIGN KEY(requester_id) REFERENCES users(id),
      FOREIGN KEY(assigned_to) REFERENCES users(id),
      FOREIGN KEY(brand_id) REFERENCES brands(id),
      FOREIGN KEY(category_id) REFERENCES categories(id),
      FOREIGN KEY(subcategory_id) REFERENCES subcategories(id)
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS ticket_custom_fields (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ticket_id INTEGER NOT NULL,
      field_key TEXT NOT NULL,
      field_value TEXT,
      UNIQUE(ticket_id, field_key),
      FOREIGN KEY(ticket_id) REFERENCES tickets(id)
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS ticket_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ticket_id INTEGER NOT NULL,
      author_id INTEGER NOT NULL,
      message TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY(ticket_id) REFERENCES tickets(id),
      FOREIGN KEY(author_id) REFERENCES users(id)
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS attachments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ticket_id INTEGER NOT NULL,
      uploader_id INTEGER NOT NULL,
      original_name TEXT NOT NULL,
      stored_name TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      size INTEGER NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY(ticket_id) REFERENCES tickets(id),
      FOREIGN KEY(uploader_id) REFERENCES users(id)
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ticket_id INTEGER NOT NULL,
      actor_id INTEGER NOT NULL,
      action TEXT NOT NULL,
      field TEXT,
      from_value TEXT,
      to_value TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY(ticket_id) REFERENCES tickets(id)
    )
  `);

  await dbRun(`
    CREATE TABLE IF NOT EXISTS notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      title TEXT NOT NULL,
      body TEXT,
      is_read INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);
}

// ---------------- SLA rules
function minutesFromNow(min) {
  // SQLite friendly datetime string: datetime('now', '+X minutes')
  return `datetime('now','+${min} minutes')`;
}
function slaMinutes(priority) {
  // first response / resolution in minutes
  // Alta: 1h / 8h, Media: 4h / 24h, Baja: 8h / 72h
  if (priority === "Alta") return { fr: 60, rs: 8 * 60 };
  if (priority === "Media") return { fr: 4 * 60, rs: 24 * 60 };
  return { fr: 8 * 60, rs: 72 * 60 };
}

async function audit(ticket_id, actor_id, action, field = null, from_value = null, to_value = null) {
  await dbRun(
    `INSERT INTO audit_log(ticket_id, actor_id, action, field, from_value, to_value)
     VALUES(?,?,?,?,?,?)`,
    [ticket_id, actor_id, action, field, from_value, to_value]
  );
}

async function notify(user_id, title, body) {
  await dbRun(
    `INSERT INTO notifications(user_id,title,body) VALUES(?,?,?)`,
    [user_id, title, body || ""]
  );
}

// ---------------- Auth middleware
function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: "No autorizado" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: "Token inválido" });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (req.user?.role !== role) return res.status(403).json({ error: "No autorizado" });
    next();
  };
}

function requireAnyRole(roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user?.role)) return res.status(403).json({ error: "No autorizado" });
    next();
  };
}

// ---------------- Overdue enforcement
async function enforceOverdue() {
  // Mark tickets as Retraso when ETA due is passed and not closed/resolved
  await dbRun(`
    UPDATE tickets
    SET status='Retraso', updated_at=datetime('now')
    WHERE eta_due_at IS NOT NULL
      AND datetime('now') >= eta_due_at
      AND status NOT IN ('Resuelto','Cerrado')
  `);

  // also mark as Retraso if resolution SLA passed and not closed/resolved
  await dbRun(`
    UPDATE tickets
    SET status='Retraso', updated_at=datetime('now')
    WHERE resolution_due_at IS NOT NULL
      AND datetime('now') >= resolution_due_at
      AND status NOT IN ('Resuelto','Cerrado')
  `);
}

// ---------------- Multer
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const safe = Date.now() + "_" + Math.random().toString(16).slice(2);
    cb(null, safe + path.extname(file.originalname || ""));
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB
});

// ---------------- Seed demo data
async function seedDemo() {
  const company = await dbGet("SELECT * FROM companies WHERE name=?", ["DemoCorp"]);
  let companyId;
  if (!company) {
    const r = await dbRun("INSERT INTO companies(name) VALUES(?)", ["DemoCorp"]);
    companyId = r.lastID;
  } else {
    companyId = company.id;
  }

  const ensureUser = async (username, pass, role, company_id = null) => {
    const u = await dbGet("SELECT id FROM users WHERE username=?", [username]);
    if (u) return;
    const hash = await bcrypt.hash(pass, 10);
    await dbRun(
      "INSERT INTO users(username,password_hash,role,company_id) VALUES(?,?,?,?)",
      [username, hash, role, company_id]
    );
  };

  await ensureUser("admin", "admin123", "admin", companyId);
  await ensureUser("soporte", "soporte123", "soporte", null);
  await ensureUser("soporte2", "soporte123", "soporte", null);
  await ensureUser("user", "user123", "usuario", companyId);

  // seed brands/categories/subcategories/fields
  const ensureBrand = async (name) => {
    let b = await dbGet("SELECT * FROM brands WHERE name=?", [name]);
    if (!b) {
      const r = await dbRun("INSERT INTO brands(name) VALUES(?)", [name]);
      b = { id: r.lastID, name };
    }
    return b.id;
  };
  const ensureCategory = async (brand_id, name) => {
    let c = await dbGet("SELECT * FROM categories WHERE brand_id=? AND name=?", [brand_id, name]);
    if (!c) {
      const r = await dbRun("INSERT INTO categories(brand_id,name) VALUES(?,?)", [brand_id, name]);
      c = { id: r.lastID };
    }
    return c.id;
  };
  const ensureSubcategory = async (category_id, name) => {
    let s = await dbGet("SELECT * FROM subcategories WHERE category_id=? AND name=?", [category_id, name]);
    if (!s) {
      const r = await dbRun("INSERT INTO subcategories(category_id,name) VALUES(?,?)", [category_id, name]);
      s = { id: r.lastID };
    }
    return s.id;
  };
  const ensureField = async (subcategory_id, field_key, label, field_type, required, options_json, sort_order) => {
    const f = await dbGet(
      "SELECT id FROM subcategory_field_defs WHERE subcategory_id=? AND field_key=?",
      [subcategory_id, field_key]
    );
    if (f) return;
    await dbRun(
      `INSERT INTO subcategory_field_defs(subcategory_id,field_key,label,field_type,required,options_json,sort_order)
       VALUES(?,?,?,?,?,?,?)`,
      [subcategory_id, field_key, label, field_type, required ? 1 : 0, options_json || null, sort_order || 0]
    );
  };

  const hp = await ensureBrand("HP");
  const ms = await ensureBrand("Microsoft");

  const hw = await ensureCategory(hp, "Hardware");
  const sw = await ensureCategory(hp, "Software");
  const lic = await ensureCategory(ms, "Licencias");

  const impresora = await ensureSubcategory(hw, "Impresora");
  const laptop = await ensureSubcategory(hw, "Laptop");
  const office = await ensureSubcategory(lic, "Licencias");
  const soft = await ensureSubcategory(sw, "Aplicación");

  await ensureField(impresora, "modelo", "Modelo", "text", true, null, 1);
  await ensureField(impresora, "tipo_falla", "Tipo de falla", "select", true, JSON.stringify(["Atasco", "No imprime", "Mancha"]), 2);

  await ensureField(laptop, "modelo", "Modelo", "text", true, null, 1);
  await ensureField(laptop, "problema", "Problema", "select", true, JSON.stringify(["No enciende", "Lento", "Pantalla"]), 2);

  await ensureField(office, "producto", "Producto", "text", true, null, 1);
  await ensureField(office, "cantidad", "Cantidad", "number", true, null, 2);

  await ensureField(soft, "modulo", "Módulo", "text", false, null, 1);
  await ensureField(soft, "error", "Código de error", "text", false, null, 2);

  console.log("✅ Seed: DemoCorp + meta + templates + users (admin/soporte/soporte2/user)");
}

// ---------------- Helpers: ticket visibility
async function canAccessTicket(user, ticketId) {
  const t = await dbGet("SELECT * FROM tickets WHERE id=?", [ticketId]);
  if (!t) return { ok: false, ticket: null };

  if (user.role === "admin") return { ok: true, ticket: t };
  if (user.role === "usuario") return { ok: t.requester_id === user.id, ticket: t };
  if (user.role === "soporte") {
    // support can access if assigned OR unassigned (cola)
    return { ok: (t.assigned_to === user.id || t.assigned_to == null), ticket: t };
  }
  return { ok: false, ticket: t };
}

async function ticketDetailRow(ticketId) {
  return dbGet(
    `
    SELECT t.*,
      u.username AS requester_name,
      a.username AS assigned_name,
      co.name AS company_name,
      b.name AS brand_name,
      ca.name AS category_name,
      sc.name AS subcategory_name
    FROM tickets t
    JOIN users u ON u.id=t.requester_id
    LEFT JOIN users a ON a.id=t.assigned_to
    JOIN companies co ON co.id=t.company_id
    JOIN brands b ON b.id=t.brand_id
    JOIN categories ca ON ca.id=t.category_id
    JOIN subcategories sc ON sc.id=t.subcategory_id
    WHERE t.id=?
    `,
    [ticketId]
  );
}

// ---------------- Auth routes
app.post("/api/auth/login", async (req, res) => {
  try {
    const { username, password } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: "Credenciales requeridas" });

    const u = await dbGet(
      `SELECT u.*, c.name AS company_name
       FROM users u
       LEFT JOIN companies c ON c.id=u.company_id
       WHERE u.username=? AND u.is_active=1`,
      [username]
    );
    if (!u) return res.status(401).json({ error: "Usuario o contraseña inválida" });

    const ok = await bcrypt.compare(password, u.password_hash);
    if (!ok) return res.status(401).json({ error: "Usuario o contraseña inválida" });

    const token = jwt.sign(
      { id: u.id, username: u.username, role: u.role, company_id: u.company_id || null },
      JWT_SECRET,
      { expiresIn: "12h" }
    );
    res.json({ token });
  } catch (e) {
    console.error("POST /api/auth/login", e);
    res.status(500).json({ error: "Error" });
  }
});

app.get("/api/me", auth, async (req, res) => {
  const u = await dbGet(
    `SELECT u.id,u.username,u.role,u.company_id,c.name AS company_name
     FROM users u
     LEFT JOIN companies c ON c.id=u.company_id
     WHERE u.id=?`,
    [req.user.id]
  );
  res.json({ user: u });
});

// ---------------- META
app.get("/api/meta/companies", auth, async (req, res) => {
  if (req.user.role === "usuario") {
    return res.json(await dbAll(
      "SELECT id,name,ruc,address,contact_name,contact_phone,contact_email,is_active FROM companies WHERE id=? AND is_active=1",
      [req.user.company_id]
    ));
  }
  res.json(await dbAll(
    "SELECT id,name,ruc,address,contact_name,contact_phone,contact_email,notes,is_active FROM companies ORDER BY name ASC",
    []
  ));
});


app.get("/api/meta/brands", auth, async (req, res) => {
  res.json(await dbAll("SELECT id,name FROM brands ORDER BY name ASC"));
});

app.get("/api/meta/categories", auth, async (req, res) => {
  const brand_id = Number(req.query.brand_id);
  if (!brand_id) return res.status(400).json({ error: "brand_id requerido" });
  res.json(await dbAll("SELECT id,name FROM categories WHERE brand_id=? ORDER BY name ASC", [brand_id]));
});

app.get("/api/meta/subcategories", auth, async (req, res) => {
  const category_id = Number(req.query.category_id);
  if (!category_id) return res.status(400).json({ error: "category_id requerido" });
  res.json(await dbAll("SELECT id,name FROM subcategories WHERE category_id=? ORDER BY name ASC", [category_id]));
});

app.get("/api/meta/subcategory-fields", auth, async (req, res) => {
  const subcategory_id = Number(req.query.subcategory_id);
  if (!subcategory_id) return res.status(400).json({ error: "subcategory_id requerido" });
  res.json(
    await dbAll(
      `SELECT field_key,label,field_type,required,options_json,sort_order
       FROM subcategory_field_defs
       WHERE subcategory_id=?
       ORDER BY sort_order ASC`,
      [subcategory_id]
    )
  );
});

app.post("/api/companies", auth, requireRole("admin"), async (req, res) => {
  try{
    const { name, ruc, address, contact_name, contact_phone, contact_email, notes } = req.body || {};
    if(!name || !name.trim()) return res.status(400).json({ error:"name requerido" });

    const nm = name.trim();
    const rc = (ruc || "").trim();
    if(!/^\d{11}$/.test(rc)) return res.status(400).json({ error:"RUC inválido (11 dígitos)" });

    const exName = await dbGet("SELECT id FROM companies WHERE LOWER(name)=LOWER(?)", [nm]);
    if(exName) return res.status(400).json({ error:"Empresa ya existe" });

    const exRuc = await dbGet("SELECT id FROM companies WHERE ruc=?", [rc]);
    if(exRuc) return res.status(400).json({ error:"RUC ya registrado" });

    const r = await dbRun(
      `INSERT INTO companies(name,ruc,address,contact_name,contact_phone,contact_email,notes,is_active)
       VALUES(?,?,?,?,?,?,?,1)`,
      [
        nm, rc,
        (address||"").trim() || null,
        (contact_name||"").trim() || null,
        (contact_phone||"").trim() || null,
        (contact_email||"").trim() || null,
        (notes||"").trim() || null
      ]
    );

    res.json({ ok:true, id:r.lastID });
  }catch(e){
    console.error(e);
    res.status(500).json({ error:"Error creando empresa" });
  }
});

app.post("/api/companies/:id/toggle", auth, requireRole("admin"), async (req, res) => {
  try{
    const id = Number(req.params.id);
    const c = await dbGet("SELECT id,is_active FROM companies WHERE id=?", [id]);
    if(!c) return res.status(404).json({ error:"Empresa no existe" });

    const next = c.is_active ? 0 : 1;
    await dbRun("UPDATE companies SET is_active=? WHERE id=?", [next, id]);
    res.json({ ok:true, is_active: next });
  }catch(e){
    console.error(e);
    res.status(500).json({ error:"Error cambiando estado" });
  }
});

app.get("/api/companies/:id/users", auth, requireRole("admin"), async (req, res) => {
  const id = Number(req.params.id);
  const rows = await dbAll(
    "SELECT id,username,role,company_id FROM users WHERE company_id=? ORDER BY role, username",
    [id]
  );
  res.json(rows);
});

// ---------------- Users (Admin)
app.get("/api/users", auth, requireRole("admin"), async (req, res) => {
  const role = req.query.role;
  const base = `
    SELECT u.id,u.username,u.role,u.company_id,c.name AS company_name
    FROM users u
    LEFT JOIN companies c ON c.id=u.company_id
  `;
  if (role) {
    return res.json(await dbAll(base + " WHERE u.role=? ORDER BY u.username", [role]));
  }
  res.json(await dbAll(base + " ORDER BY u.username"));
});

app.post("/api/users", auth, requireRole("admin"), async (req, res) => {
  try {
    const { username, password, role, company_id } = req.body || {};

    if (!username || !password || !role) {
      return res.status(400).json({ error: "username, password y role son requeridos" });
    }
    if (!["admin", "soporte", "usuario"].includes(role)) {
      return res.status(400).json({ error: "role inválido" });
    }

    if (role === "usuario" && !company_id) {
      return res.status(400).json({ error: "company_id requerido para rol usuario" });
    }

    if (company_id) {
      const c = await dbGet("SELECT id FROM companies WHERE id=?", [company_id]);
      if (!c) return res.status(400).json({ error: "company_id no existe" });
    }

    const exists = await dbGet("SELECT id FROM users WHERE username=?", [username]);
    if (exists) return res.status(400).json({ error: "username ya existe" });

    const hash = await bcrypt.hash(password, 10);

    const r = await dbRun(
      "INSERT INTO users(username,password_hash,role,company_id) VALUES(?,?,?,?)",
      [username.trim(), hash, role, company_id || null]
    );

    res.json({ ok: true, id: r.lastID });
  } catch (e) {
    console.error("POST /api/users", e);
    res.status(500).json({ error: "Error creando usuario" });
  }
});

// Update company/role/password (Admin)
app.patch("/api/users/:id", auth, requireRole("admin"), async (req, res) => {
  try {
    const id = Number(req.params.id);
    const { company_id, role, password } = req.body || {};

    const u = await dbGet("SELECT id, role FROM users WHERE id=?", [id]);
    if (!u) return res.status(404).json({ error: "Usuario no existe" });

    if (role && !["admin", "soporte", "usuario"].includes(role)) {
      return res.status(400).json({ error: "role inválido" });
    }

    if (company_id !== undefined && company_id !== null) {
      const c = await dbGet("SELECT id FROM companies WHERE id=?", [company_id]);
      if (!c) return res.status(400).json({ error: "company_id no existe" });
    }

    if (password) {
      const hash = await bcrypt.hash(password, 10);
      await dbRun("UPDATE users SET password_hash=? WHERE id=?", [hash, id]);
    }

    if (role !== undefined || company_id !== undefined) {
      await dbRun(
        "UPDATE users SET role=COALESCE(?, role), company_id=? WHERE id=?",
        [role || null, company_id ?? null, id]
      );
    }

    res.json({ ok: true });
  } catch (e) {
    console.error("PATCH /api/users/:id", e);
    res.status(500).json({ error: "Error actualizando usuario" });
  }
});

// ---------------- Dashboard
app.get("/api/dashboard/metrics", auth, async (req, res) => {
  await enforceOverdue();

  // role-based scope
  let where = "";
  const params = [];

  if (req.user.role === "usuario") {
    where = "WHERE requester_id=?";
    params.push(req.user.id);
  } else if (req.user.role === "soporte") {
    where = "WHERE (assigned_to=? OR assigned_to IS NULL)";
    params.push(req.user.id);
  } // admin => all

  const total = await dbGet(`SELECT COUNT(*) AS n FROM tickets ${where}`, params);
  const abiertos = await dbGet(
    `SELECT COUNT(*) AS n FROM tickets ${where ? where + " AND" : "WHERE"} status NOT IN ('Resuelto','Cerrado')`,
    params
  );
  const retraso = await dbGet(
    `SELECT COUNT(*) AS n FROM tickets ${where ? where + " AND" : "WHERE"} status='Retraso'`,
    params
  );
  const resueltos = await dbGet(
    `SELECT COUNT(*) AS n FROM tickets ${where ? where + " AND" : "WHERE"} status IN ('Resuelto','Cerrado')`,
    params
  );

  const porPrio = await dbAll(
    `SELECT priority, COUNT(*) AS n FROM tickets ${where} GROUP BY priority`,
    params
  );

  res.json({
    tickets: {
      total: total.n,
      abiertos: abiertos.n,
      retraso: retraso.n,
      resueltos: resueltos.n,
      por_prioridad: porPrio
    }
  });
});

// ---------------- Tickets list
app.get("/api/tickets", auth, async (req, res) => {
  await enforceOverdue();

  const role = req.user.role;
  const uid = req.user.id;

  let sql = `
    SELECT t.*,
      u.username AS requester_name,
      a.username AS assigned_name,
      co.name AS company_name,
      b.name AS brand_name,
      ca.name AS category_name,
      sc.name AS subcategory_name
    FROM tickets t
    JOIN users u ON u.id=t.requester_id
    LEFT JOIN users a ON a.id=t.assigned_to
    JOIN companies co ON co.id=t.company_id
    JOIN brands b ON b.id=t.brand_id
    JOIN categories ca ON ca.id=t.category_id
    JOIN subcategories sc ON sc.id=t.subcategory_id
  `;
  const params = [];

  if (role === "usuario") {
    sql += " WHERE t.requester_id=?";
    params.push(uid);
  } else if (role === "soporte") {
    sql += " WHERE (t.assigned_to=? OR t.assigned_to IS NULL)";
    params.push(uid);
  }

  sql += " ORDER BY t.id DESC";
  res.json(await dbAll(sql, params));
});

// ---------------- Create ticket
app.post("/api/tickets", auth, requireAnyRole(["admin", "usuario", "soporte"]), async (req, res) => {
  try {
    await enforceOverdue();

    const {
      title,
      description,
      company_id,
      brand_id,
      category_id,
      subcategory_id,
      contact_phone,
      priority,
      custom_fields
    } = req.body || {};

    if (!title || !description || !company_id || !brand_id || !category_id || !subcategory_id || !contact_phone || !priority) {
      return res.status(400).json({ error: "Campos requeridos incompletos" });
    }

    // users only in their company
    if (req.user.role === "usuario" && Number(company_id) !== Number(req.user.company_id)) {
      return res.status(403).json({ error: "Empresa inválida" });
    }

    // Validate meta ids exist
    const comp = await dbGet("SELECT id FROM companies WHERE id=?", [company_id]);
    if (!comp) return res.status(400).json({ error: "Empresa no existe" });

    const sub = await dbGet(
      `SELECT sc.id, sc.category_id, c.brand_id
       FROM subcategories sc
       JOIN categories c ON c.id=sc.category_id
       WHERE sc.id=?`,
      [subcategory_id]
    );
    if (!sub) return res.status(400).json({ error: "Subcategoría inválida" });

    if (Number(sub.category_id) !== Number(category_id)) return res.status(400).json({ error: "category_id no corresponde a subcategoría" });
    if (Number(sub.brand_id) !== Number(brand_id)) return res.status(400).json({ error: "brand_id no corresponde a categoría" });

    // Validate required custom fields
    const defs = await dbAll(
      `SELECT field_key,label,required
       FROM subcategory_field_defs
       WHERE subcategory_id=?`,
      [subcategory_id]
    );

    const cf = custom_fields || {};
    const missing = defs.filter(d => d.required && !String(cf[d.field_key] || "").trim());
    if (missing.length) {
      return res.status(400).json({ error: "Faltan campos requeridos: " + missing.map(m => m.label).join(", ") });
    }

    const { fr, rs } = slaMinutes(priority);

    const r = await dbRun(
      `
      INSERT INTO tickets(
        title, description, company_id, requester_id, brand_id, category_id, subcategory_id,
        contact_phone, priority, status,
        first_response_due_at, resolution_due_at,
        created_at, updated_at
      )
      VALUES(?,?,?,?,?,?,?,?,?,'Nuevo', ${minutesFromNow(fr)}, ${minutesFromNow(rs)}, datetime('now'), datetime('now'))
      `,
      [
        String(title).trim(),
        String(description).trim(),
        Number(company_id),
        req.user.id,
        Number(brand_id),
        Number(category_id),
        Number(subcategory_id),
        String(contact_phone).trim(),
        priority
      ]
    );

    const ticketId = r.lastID;

    // Save custom fields
    for (const k of Object.keys(cf)) {
      await dbRun(
        "INSERT OR REPLACE INTO ticket_custom_fields(ticket_id,field_key,field_value) VALUES(?,?,?)",
        [ticketId, k, String(cf[k] ?? "")]
      );
    }

    await audit(ticketId, req.user.id, "Creación", null, null, null);

    // notify admin + supports (simple: notify all supports)
    const supports = await dbAll("SELECT id FROM users WHERE role='soporte' AND is_active=1");
    for (const s of supports) {
      await notify(s.id, `Nuevo ticket #${ticketId}`, `Se creó un ticket: ${title}`);
    }

    res.json({ ok: true, id: ticketId });
  } catch (e) {
    console.error("POST /api/tickets", e);
    res.status(500).json({ error: "Error creando ticket" });
  }
});

// ---------------- Ticket detail
app.get("/api/tickets/:id", auth, async (req, res) => {
  await enforceOverdue();
  const id = Number(req.params.id);

  const access = await canAccessTicket(req.user, id);
  if (!access.ticket) return res.status(404).json({ error: "No existe" });
  if (!access.ok) return res.status(403).json({ error: "No autorizado" });

  const ticket = await ticketDetailRow(id);

  const custom_fields = await dbAll(
    "SELECT field_key, field_value FROM ticket_custom_fields WHERE ticket_id=? ORDER BY field_key",
    [id]
  );

  const auditRows = await dbAll(
    `SELECT a.*, u.username AS actor_name
     FROM audit_log a
     LEFT JOIN users u ON u.id=a.actor_id
     WHERE a.ticket_id=?
     ORDER BY a.id DESC
     LIMIT 50`,
    [id]
  );

  res.json({ ticket, custom_fields, audit: auditRows });
});

// ---------------- Update ticket (status / eta / etc)
app.patch("/api/tickets/:id", auth, async (req, res) => {
  try {
    await enforceOverdue();
    const id = Number(req.params.id);
    const access = await canAccessTicket(req.user, id);
    if (!access.ticket) return res.status(404).json({ error: "No existe" });
    if (!access.ok) return res.status(403).json({ error: "No autorizado" });

    const t = access.ticket;
    const { status, estimate_minutes } = req.body || {};

    // Status updates: support/admin only
    if (status !== undefined) {
      if (req.user.role === "usuario") return res.status(403).json({ error: "No autorizado" });

      const allowed = ["Nuevo", "Asignado", "En progreso", "Pendiente usuario", "Pendiente proveedor", "Resuelto", "Cerrado", "Retraso"];
      if (!allowed.includes(status)) return res.status(400).json({ error: "Estado inválido" });

      // mark resolved_at if resolves/closes
      if (status === "Resuelto" || status === "Cerrado") {
        await dbRun(
          "UPDATE tickets SET status=?, resolved_at=COALESCE(resolved_at, datetime('now')), updated_at=datetime('now') WHERE id=?",
          [status, id]
        );
        await audit(id, req.user.id, "Cambio estado", "status", t.status, status);
      } else {
        await dbRun("UPDATE tickets SET status=?, updated_at=datetime('now') WHERE id=?", [status, id]);
        await audit(id, req.user.id, "Cambio estado", "status", t.status, status);
      }

      // notify requester
      await notify(t.requester_id, `Ticket #${id} actualizado`, `Estado: ${status}`);
    }

    // ETA updates: support only
    if (estimate_minutes !== undefined) {
      if (req.user.role !== "soporte" && req.user.role !== "admin") return res.status(403).json({ error: "No autorizado" });
      const mins = Number(estimate_minutes);
      if (!mins || mins <= 0 || mins > 10080) return res.status(400).json({ error: "ETA inválido" });

      await dbRun(
        `UPDATE tickets
         SET eta_due_at = datetime('now', '+' || ? || ' minutes'),
             updated_at=datetime('now')
         WHERE id=?`,
        [mins, id]
      );
      await audit(id, req.user.id, "Set ETA", "eta_due_at", t.eta_due_at || null, `+${mins} min`);
      await notify(t.requester_id, `ETA definido para ticket #${id}`, `ETA: ${mins} min`);
    }

    res.json({ ok: true });
  } catch (e) {
    console.error("PATCH /api/tickets/:id", e);
    res.status(500).json({ error: "Error actualizando ticket" });
  }
});

// ---------------- Assign (admin)
app.post("/api/tickets/:id/assign", auth, requireRole("admin"), async (req, res) => {
  try {
    await enforceOverdue();
    const id = Number(req.params.id);
    const { assigned_to } = req.body || {};
    if (!assigned_to) return res.status(400).json({ error: "assigned_to requerido" });

    const t = await dbGet("SELECT * FROM tickets WHERE id=?", [id]);
    if (!t) return res.status(404).json({ error: "No existe" });

    const u = await dbGet("SELECT id, role FROM users WHERE id=? AND is_active=1", [assigned_to]);
    if (!u || u.role !== "soporte") return res.status(400).json({ error: "Usuario soporte inválido" });

    await dbRun("UPDATE tickets SET assigned_to=?, status='Asignado', updated_at=datetime('now') WHERE id=?", [assigned_to, id]);
    await audit(id, req.user.id, "Asignación", "assigned_to", t.assigned_to || null, String(assigned_to));

    await notify(assigned_to, `Ticket #${id} asignado`, `Te asignaron el ticket #${id}`);
    await notify(t.requester_id, `Ticket #${id} asignado`, `Soporte asignado al ticket`);

    res.json({ ok: true });
  } catch (e) {
    console.error("POST /api/tickets/:id/assign", e);
    res.status(500).json({ error: "Error asignando" });
  }
});

// ---------------- Take (support)
app.post("/api/tickets/:id/take", auth, requireRole("soporte"), async (req, res) => {
  try {
    await enforceOverdue();
    const id = Number(req.params.id);

    const t = await dbGet("SELECT * FROM tickets WHERE id=?", [id]);
    if (!t) return res.status(404).json({ error: "No existe" });

    if (t.assigned_to && t.assigned_to !== req.user.id) {
      return res.status(403).json({ error: "Ya asignado a otro soporte" });
    }

    await dbRun(
      "UPDATE tickets SET assigned_to=?, status='Asignado', updated_at=datetime('now') WHERE id=?",
      [req.user.id, id]
    );
    await audit(id, req.user.id, "Tomar ticket", "assigned_to", t.assigned_to || null, String(req.user.id));
    await notify(t.requester_id, `Ticket #${id} tomado`, `Un soporte tomó tu ticket`);

    res.json({ ok: true });
  } catch (e) {
    console.error("POST /api/tickets/:id/take", e);
    res.status(500).json({ error: "Error" });
  }
});

// ---------------- Messages (conversation)
app.get("/api/tickets/:id/messages", auth, async (req, res) => {
  await enforceOverdue();
  const id = Number(req.params.id);

  const access = await canAccessTicket(req.user, id);
  if (!access.ticket) return res.status(404).json({ error: "No existe" });
  if (!access.ok) return res.status(403).json({ error: "No autorizado" });

  const msgs = await dbAll(
    `
    SELECT m.id,m.ticket_id,m.author_id,m.message,m.created_at,
           u.username,u.role AS author_role
    FROM ticket_messages m
    JOIN users u ON u.id=m.author_id
    WHERE m.ticket_id=?
    ORDER BY m.id ASC
    `,
    [id]
  );

  res.json(msgs);
});

app.post("/api/tickets/:id/messages", auth, async (req, res) => {
  try {
    await enforceOverdue();
    const id = Number(req.params.id);
    const { message } = req.body || {};
    if (!message || !String(message).trim()) return res.status(400).json({ error: "message requerido" });

    const access = await canAccessTicket(req.user, id);
    if (!access.ticket) return res.status(404).json({ error: "No existe" });
    if (!access.ok) return res.status(403).json({ error: "No autorizado" });

    const t = access.ticket;

    await dbRun(
      "INSERT INTO ticket_messages(ticket_id,author_id,message) VALUES(?,?,?)",
      [id, req.user.id, String(message)]
    );

    // set first_response_at if first time non-requester responds (simple rule)
    // We'll mark first_response_at when ANYONE posts and first_response_at is null.
    const cur = await dbGet("SELECT first_response_at FROM tickets WHERE id=?", [id]);
    if (!cur.first_response_at) {
      await dbRun("UPDATE tickets SET first_response_at=datetime('now'), updated_at=datetime('now') WHERE id=?", [id]);
      await audit(id, req.user.id, "Primera respuesta", "first_response_at", null, "now");
    } else {
      await dbRun("UPDATE tickets SET updated_at=datetime('now') WHERE id=?", [id]);
    }

    await audit(id, req.user.id, "Mensaje", null, null, null);

    // notify other side(s)
    const recipients = new Set();
    if (t.requester_id) recipients.add(t.requester_id);
    if (t.assigned_to) recipients.add(t.assigned_to);
    // admins: notify all admins? (optional) - keep simple: only requester & assigned
    recipients.delete(req.user.id);

    for (const uid of recipients) {
      await notify(uid, `Nuevo mensaje en ticket #${id}`, String(message).slice(0, 80));
    }

    res.json({ ok: true });
  } catch (e) {
    console.error("POST /api/tickets/:id/messages", e);
    res.status(500).json({ error: "Error enviando mensaje" });
  }
});

// ---------------- Attachments
app.get("/api/tickets/:id/attachments", auth, async (req, res) => {
  await enforceOverdue();
  const id = Number(req.params.id);
  const access = await canAccessTicket(req.user, id);
  if (!access.ticket) return res.status(404).json({ error: "No existe" });
  if (!access.ok) return res.status(403).json({ error: "No autorizado" });

  const files = await dbAll(
    `SELECT id,ticket_id,uploader_id,original_name,stored_name,mime_type,size,created_at
     FROM attachments
     WHERE ticket_id=?
     ORDER BY id DESC`,
    [id]
  );
  res.json(files);
});

app.post("/api/tickets/:id/attachments", auth, upload.single("file"), async (req, res) => {
  try {
    await enforceOverdue();
    const id = Number(req.params.id);
    const access = await canAccessTicket(req.user, id);
    if (!access.ticket) return res.status(404).json({ error: "No existe" });
    if (!access.ok) return res.status(403).json({ error: "No autorizado" });

    if (!req.file) return res.status(400).json({ error: "Archivo requerido" });

    await dbRun(
      `INSERT INTO attachments(ticket_id,uploader_id,original_name,stored_name,mime_type,size)
       VALUES(?,?,?,?,?,?)`,
      [
        id,
        req.user.id,
        req.file.originalname,
        req.file.filename,
        req.file.mimetype || "application/octet-stream",
        req.file.size
      ]
    );

    await audit(id, req.user.id, "Adjunto", "attachment", null, req.file.originalname);

    // notify other side
    const t = access.ticket;
    const recipients = new Set([t.requester_id, t.assigned_to].filter(Boolean));
    recipients.delete(req.user.id);
    for (const uid of recipients) {
      await notify(uid, `Archivo en ticket #${id}`, req.file.originalname);
    }

    res.json({ ok: true });
  } catch (e) {
    console.error("POST /api/tickets/:id/attachments", e);
    res.status(500).json({ error: "Error subiendo archivo" });
  }
});

// ---------------- Notifications
app.get("/api/notifications", auth, async (req, res) => {
  const unreadRow = await dbGet(
    "SELECT COUNT(*) AS n FROM notifications WHERE user_id=? AND is_read=0",
    [req.user.id]
  );
  const items = await dbAll(
    "SELECT * FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 20",
    [req.user.id]
  );
  res.json({ unread: unreadRow.n, items });
});

app.post("/api/notifications/:id/read", auth, async (req, res) => {
  const id = Number(req.params.id);
  await dbRun("UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?", [id, req.user.id]);
  res.json({ ok: true });
});

app.post("/api/notifications/read-all", auth, async (req, res) => {
  await dbRun("UPDATE notifications SET is_read=1 WHERE user_id=?", [req.user.id]);
  res.json({ ok: true });
});

// ---------------- Start
(async () => {
  try {
    await runMigrations();
    await seedDemo();

    app.listen(PORT, () => {
      console.log(`✅ IMS ULTRA PRO corriendo en http://localhost:${PORT}`);
    });
  } catch (e) {
    console.error("❌ Error inicializando server:", e);
    process.exit(1);
  }
})();
