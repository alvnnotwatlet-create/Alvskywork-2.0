const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const pgSession = require("connect-pg-simple")(session);

const app = express();
const PORT = process.env.PORT || 3000;

const required = [
  "DATABASE_URL",
  "SESSION_SECRET",
  "ADMIN_USERNAME",
  "ADMIN_PASSWORD"
];

for (const key of required) {
  if (!process.env[key]) {
    throw new Error("Environment variable belum diatur: " + key);
  }
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes("localhost")
    ? false
    : { rejectUnauthorized: false }
});

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true }));

app.use(session({
  store: new pgSession({
    pool,
    createTableIfMissing: true
  }),
  name: "alvsky.sid",
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: "auto",
    sameSite: "lax",
    maxAge: 86400000
  }
}));

async function setupDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS records (
      id SERIAL PRIMARY KEY,
      type TEXT NOT NULL,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      content JSONB NOT NULL DEFAULT '{}',
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);
}

function requireUser(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({ message: "Silakan login." });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.isAdmin) {
    return res.status(401).json({ message: "Akses admin ditolak." });
  }
  next();
}

app.get("/api/status", (req, res) => {
  res.json({ online: true, name: "Alvskywok 2.0" });
});

app.post("/api/register", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    if (username.length < 3 || username.length > 30 || password.length < 8) {
      return res.status(400).json({
        message: "Username minimal 3 karakter dan password minimal 8 karakter."
      });
    }

    const hash = await bcrypt.hash(password, 12);
    const result = await pool.query(
      "INSERT INTO users(username,password) VALUES($1,$2) RETURNING id,username",
      [username, hash]
    );

    res.status(201).json({ user: result.rows[0] });
  } catch (error) {
    res.status(400).json({
      message: "Registrasi gagal atau username sudah digunakan."
    });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    const result = await pool.query(
      "SELECT * FROM users WHERE username=$1",
      [username]
    );

    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(401).json({
        message: "Username atau password salah."
      });
    }

    req.session.regenerate(error => {
      if (error) {
        return res.status(500).json({ message: "Sesi gagal dibuat." });
      }

      req.session.userId = user.id;
      req.session.save(error => {
        if (error) {
          return res.status(500).json({ message: "Sesi gagal disimpan." });
        }

        res.json({
          user: { id: user.id, username: user.username }
        });
      });
    });
  } catch (error) {
    res.status(500).json({ message: "Login gagal." });
  }
});

app.get("/api/me", requireUser, async (req, res) => {
  const result = await pool.query(
    "SELECT id,username,created_at FROM users WHERE id=$1",
    [req.session.userId]
  );
  res.json({ user: result.rows[0] || null });
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(error => {
    if (error) {
      return res.status(500).json({ message: "Logout gagal." });
    }
    res.clearCookie("alvsky.sid");
    res.json({ message: "Berhasil logout." });
  });
});

app.post("/api/admin/login", (req, res) => {
  const username = String(req.body.username || "");
  const password = String(req.body.password || "");

  if (
    username !== process.env.ADMIN_USERNAME ||
    password !== process.env.ADMIN_PASSWORD
  ) {
    return res.status(401).json({ message: "Login admin salah." });
  }

  req.session.regenerate(error => {
    if (error) {
      return res.status(500).json({ message: "Sesi gagal dibuat." });
    }

    req.session.isAdmin = true;
    req.session.save(error => {
      if (error) {
        return res.status(500).json({ message: "Sesi gagal disimpan." });
      }
      res.json({ message: "Login admin berhasil." });
    });
  });
});

app.get("/api/admin/data", requireAdmin, async (req, res) => {
  const users = await pool.query(
    "SELECT id,username,created_at FROM users ORDER BY id DESC"
  );
  const records = await pool.query(
    "SELECT * FROM records ORDER BY id DESC LIMIT 200"
  );
  res.json({ users: users.rows, records: records.rows });
});

app.post("/api/admin/backup", requireAdmin, async (req, res) => {
  const users = await pool.query("SELECT id,username,created_at FROM users");
  const records = await pool.query("SELECT * FROM records");

  res.json({
    message: "Backup berhasil disiapkan.",
    backup: { users: users.rows, records: records.rows }
  });
});

app.get("/api/admin/settings", requireAdmin, (req, res) => {
  res.json({ message: "Pengaturan Alvskywok 2.0" });
});

app.post("/api/admin/settings", requireAdmin, (req, res) => {
  res.json({ message: "Endpoint pengaturan tersedia." });
});

app.post("/api/admin/notify", requireAdmin, (req, res) => {
  res.json({ message: "Endpoint notifikasi tersedia." });
});

app.post("/api/chat", requireUser, async (req, res) => {
  const result = await pool.query(
    "INSERT INTO records(type,user_id,content) VALUES($1,$2,$3) RETURNING *",
    ["chat", req.session.userId, req.body]
  );
  res.status(201).json({ record: result.rows[0] });
});

app.get("/api/comments", async (req, res) => {
  const result = await pool.query(
    "SELECT * FROM records WHERE type='comment' ORDER BY id DESC"
  );
  res.json({ comments: result.rows });
});

app.post("/api/comments", requireUser, async (req, res) => {
  const result = await pool.query(
    "INSERT INTO records(type,user_id,content) VALUES($1,$2,$3) RETURNING *",
    ["comment", req.session.userId, req.body]
  );
  res.status(201).json({ comment: result.rows[0] });
});

app.post("/api/reports", requireUser, async (req, res) => {
  const result = await pool.query(
    "INSERT INTO records(type,user_id,content) VALUES($1,$2,$3) RETURNING *",
    ["report", req.session.userId, req.body]
  );
  res.status(201).json({ report: result.rows[0] });
});

app.get("/api/health", (req, res) => {
  res.json({ status: "ok" });
});

app.use((req, res) => {
  res.status(404).json({ message: "Endpoint tidak ditemukan." });
});

setupDatabase()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log("Alvskywok 2.0 berjalan pada port " + PORT);
    });
  })
  .catch(error => {
    console.error("Gagal menjalankan server:", error);
    process.exit(1);
  });
