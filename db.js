// db.js
const sqlite3 = require("sqlite3").verbose();
const path = require("path");

const db = new sqlite3.Database(path.join(__dirname, "ims.db"));

    await addColumnIfMissing("companies", "ruc", "ruc TEXT");
    await addColumnIfMissing("companies", "address", "address TEXT");
    await addColumnIfMissing("companies", "contact_name", "contact_name TEXT");
    await addColumnIfMissing("companies", "contact_phone", "contact_phone TEXT");
    await addColumnIfMissing("companies", "contact_email", "contact_email TEXT");
    await addColumnIfMissing("companies", "notes", "notes TEXT");
    await addColumnIfMissing("companies", "is_active", "is_active INTEGER NOT NULL DEFAULT 1");
    await addColumnIfMissing("companies", "created_at", "created_at TEXT NOT NULL DEFAULT (datetime('now'))");

    await addIndex(`CREATE UNIQUE INDEX IF NOT EXISTS ux_companies_ruc ON companies(ruc)`);
    await addIndex(`CREATE INDEX IF NOT EXISTS ix_companies_active ON companies(is_active)`);


db.serialize(() => {
  db.run(`PRAGMA foreign_keys = ON`);

  db.run(`
    CREATE TABLE IF NOT EXISTS companies (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    )
  `);


  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin','soporte','usuario')),
      company_id INTEGER,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY(company_id) REFERENCES companies(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS brands (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE NOT NULL
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS categories (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      brand_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      UNIQUE(brand_id, name),
      FOREIGN KEY(brand_id) REFERENCES brands(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS subcategories (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      category_id INTEGER NOT NULL,
      name TEXT NOT NULL,
      UNIQUE(category_id, name),
      FOREIGN KEY(category_id) REFERENCES categories(id)
    )
  `);

  db.run(`
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

  db.run(`
    CREATE TABLE IF NOT EXISTS tickets (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      description TEXT NOT NULL,
      company_id INTEGER NOT NULL,
      brand_id INTEGER NOT NULL,
      category_id INTEGER NOT NULL,
      subcategory_id INTEGER NOT NULL,
      contact_phone TEXT NOT NULL,
      priority TEXT NOT NULL CHECK(priority IN ('Alta','Media','Baja')),
      status TEXT NOT NULL CHECK(status IN (
        'Nuevo','Asignado','En progreso','Pendiente usuario','Pendiente proveedor','Resuelto','Cerrado','Retraso'
      )) DEFAULT 'Nuevo',
      requester_id INTEGER NOT NULL,
      assigned_to INTEGER,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      first_response_due_at TEXT,
      first_response_at TEXT,
      resolution_due_at TEXT,
      resolved_at TEXT,
      estimate_minutes INTEGER,
      eta_set_at TEXT,
      eta_due_at TEXT,
      FOREIGN KEY(company_id) REFERENCES companies(id),
      FOREIGN KEY(brand_id) REFERENCES brands(id),
      FOREIGN KEY(category_id) REFERENCES categories(id),
      FOREIGN KEY(subcategory_id) REFERENCES subcategories(id),
      FOREIGN KEY(requester_id) REFERENCES users(id),
      FOREIGN KEY(assigned_to) REFERENCES users(id)
    )
  `);

  // ✅ AQUÍ ESTÁ EL FIX CLAVE: UNIQUE(ticket_id, field_key)
  db.run(`
    CREATE TABLE IF NOT EXISTS ticket_custom_fields (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ticket_id INTEGER NOT NULL,
      field_key TEXT NOT NULL,
      field_value TEXT,
      UNIQUE(ticket_id, field_key),
      FOREIGN KEY(ticket_id) REFERENCES tickets(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS ticket_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ticket_id INTEGER NOT NULL,
      author_id INTEGER NOT NULL,
      author_role TEXT NOT NULL CHECK(author_role IN ('admin','soporte','usuario')),
      message TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY(ticket_id) REFERENCES tickets(id),
      FOREIGN KEY(author_id) REFERENCES users(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS ticket_attachments (
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

  db.run(`
    CREATE TABLE IF NOT EXISTS ticket_audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ticket_id INTEGER NOT NULL,
      actor_id INTEGER NOT NULL,
      actor_role TEXT NOT NULL,
      action TEXT NOT NULL,
      field TEXT,
      from_value TEXT,
      to_value TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY(ticket_id) REFERENCES tickets(id),
      FOREIGN KEY(actor_id) REFERENCES users(id)
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS notifications (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      type TEXT NOT NULL,
      title TEXT NOT NULL,
      body TEXT,
      payload_json TEXT,
      is_read INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);
});

module.exports = db;

async function addColumnIfMissing(table, column, ddl) {
  const cols = await dbAll(`PRAGMA table_info(${table})`);
  const exists = cols.some(c => c.name === column);
  if (!exists) await dbRun(`ALTER TABLE ${table} ADD COLUMN ${ddl}`);
}

async function addIndex(sql) {
  await dbRun(sql);
}
