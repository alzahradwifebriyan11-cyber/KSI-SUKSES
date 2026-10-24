import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";
import express from "express";
import session from "express-session";
import helmet from "helmet";
import multer from "multer";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const dataDir = process.env.DATA_DIR || path.join(__dirname, "data");
const uploadDir = process.env.UPLOAD_DIR || path.join(__dirname, "uploads");
fs.mkdirSync(dataDir, { recursive: true });
fs.mkdirSync(uploadDir, { recursive: true });

const db = new DatabaseSync(path.join(dataDir, "campus.sqlite"));
db.exec("PRAGMA foreign_keys = ON");
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK (role IN ('student', 'lecturer', 'admin')),
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS grades (
    id INTEGER PRIMARY KEY,
    student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    lecturer_id INTEGER NOT NULL REFERENCES users(id),
    course TEXT NOT NULL,
    score REAL NOT NULL CHECK (score >= 0 AND score <= 100),
    note TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS assignments (
    id INTEGER PRIMARY KEY,
    student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL,
    original_name TEXT NOT NULL,
    stored_name TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS forum_posts (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

function passwordHash(password, salt = crypto.randomBytes(16).toString("hex")) {
  const digest = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${digest}`;
}

function passwordMatches(password, stored) {
  const [salt, expectedHex] = stored.split(":");
  const actual = crypto.scryptSync(password, salt, 64);
  const expected = Buffer.from(expectedHex, "hex");
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

const seedUsers = [
  ["Alya Putri", "alya@fikti.test", "student", "MhsFikti2026!"],
  ["Bima Santoso", "bima@fikti.test", "student", "MhsFikti2026!"],
  ["Dina Pratama", "dina@fikti.test", "lecturer", "DosenFikti2026!"],
  ["Raka Wijaya", "raka@fikti.test", "admin", "AdminFikti2026!"]
];
const userCount = db.prepare("SELECT COUNT(*) AS count FROM users").get().count;
if (userCount === 0) {
  const insertUser = db.prepare(
    "INSERT INTO users (name, email, role, password_hash) VALUES (?, ?, ?, ?)"
  );
  const insertSeed = () => {
    for (const [name, email, role, password] of seedUsers) {
      insertUser.run(name, email, role, passwordHash(password));
    }
  };
  db.exec("BEGIN");
  try {
    insertSeed();
    db.exec("COMMIT");
  } catch (error) {
    db.exec("ROLLBACK");
    throw error;
  }
  const studentId = db.prepare("SELECT id FROM users WHERE email = ?").get("alya@fikti.test").id;
  const lecturerId = db.prepare("SELECT id FROM users WHERE email = ?").get("dina@fikti.test").id;
  db.prepare(
    "INSERT INTO grades (student_id, lecturer_id, course, score, note) VALUES (?, ?, ?, ?, ?)"
  ).run(studentId, lecturerId, "Pemrograman Web", 88, "Bagus, teruskan usaha.");
}

const app = express();
const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
if (process.env.NODE_ENV === "production" && !process.env.SESSION_SECRET) {
  throw new Error("SESSION_SECRET mesti ditetapkan dalam persekitaran production.");
}
app.disable("x-powered-by");
if (process.env.NODE_ENV === "production") app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: "32kb" }));
app.use(session({
  name: "fikti.sid",
  secret: sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
    maxAge: 1000 * 60 * 60 * 4
  }
}));
app.use(express.static(path.join(__dirname, "public")));

const loginAttempts = new Map();
function requireCsrf(req, res, next) {
  const expected = req.session.csrfToken;
  const received = req.get("x-csrf-token");
  const expectedBuffer = Buffer.from(expected || "");
  const receivedBuffer = Buffer.from(received || "");
  if (!expected || !received || expectedBuffer.length !== receivedBuffer.length ||
    !crypto.timingSafeEqual(expectedBuffer, receivedBuffer)) {
    return res.status(403).json({ error: "Token keselamatan tidak sah. Muat semula halaman." });
  }
  next();
}
app.use("/api", (req, res, next) => {
  if (["POST", "PUT", "DELETE"].includes(req.method)) return requireCsrf(req, res, next);
  next();
});

function requireUser(req, res, next) {
  const user = req.session.user;
  if (!user) return res.status(401).json({ error: "Sila log masuk dahulu." });
  req.user = user;
  next();
}

function requireRole(...roles) {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) return res.status(403).json({ error: "Akses tidak dibenarkan." });
    next();
  };
}

function cleanText(value, maxLength) {
  return typeof value === "string" ? value.trim().slice(0, maxLength) : "";
}

function publicUser(user) {
  return { id: user.id, name: user.name, email: user.email, role: user.role };
}

app.get("/api/csrf", (req, res) => {
  req.session.csrfToken ??= crypto.randomBytes(32).toString("hex");
  res.json({ csrfToken: req.session.csrfToken });
});

app.post("/api/login", (req, res, next) => {
  const ip = req.ip;
  const attempt = loginAttempts.get(ip);
  if (attempt && attempt.count >= 8 && Date.now() - attempt.startedAt < 10 * 60 * 1000) {
    return res.status(429).json({ error: "Terlalu banyak percubaan. Cuba lagi dalam 10 minit." });
  }
  const email = cleanText(req.body.email, 254).toLowerCase();
  const password = typeof req.body.password === "string" ? req.body.password : "";
  const user = db.prepare("SELECT id, name, email, role, password_hash FROM users WHERE email = ?").get(email);
  if (!user || !passwordMatches(password, user.password_hash)) {
    const current = loginAttempts.get(ip);
    loginAttempts.set(ip, current && Date.now() - current.startedAt < 10 * 60 * 1000
      ? { ...current, count: current.count + 1 }
      : { startedAt: Date.now(), count: 1 });
    return res.status(401).json({ error: "E-mel atau kata laluan tidak tepat." });
  }
  loginAttempts.delete(ip);
  req.session.regenerate((error) => {
    if (error) return next(error);
    req.session.user = publicUser(user);
    req.session.csrfToken = crypto.randomBytes(32).toString("hex");
    res.json({ user: req.session.user, csrfToken: req.session.csrfToken });
  });
});

app.post("/api/logout", requireUser, (req, res, next) => {
  req.session.destroy((error) => {
    if (error) return next(error);
    res.clearCookie("fikti.sid", { httpOnly: true, sameSite: "strict" });
    res.json({ ok: true });
  });
});

app.get("/api/me", requireUser, (req, res) => res.json({ user: req.user }));

app.get("/api/grades", requireUser, (req, res) => {
  let rows;
  if (req.user.role === "student") {
    rows = db.prepare(
      "SELECT g.id, g.course, g.score, g.note, g.created_at, u.name AS lecturer FROM grades g JOIN users u ON u.id = g.lecturer_id WHERE g.student_id = ? ORDER BY g.created_at DESC"
    ).all(req.user.id);
  } else {
    rows = db.prepare(
      "SELECT g.id, g.course, g.score, g.note, g.created_at, s.name AS student FROM grades g JOIN users s ON s.id = g.student_id ORDER BY g.created_at DESC"
    ).all();
  }
  res.json({ grades: rows });
});

app.post("/api/grades", requireUser, requireRole("lecturer"), (req, res) => {
  const email = cleanText(req.body.email, 254).toLowerCase();
  const course = cleanText(req.body.course, 100);
  const note = cleanText(req.body.note, 500);
  const score = Number(req.body.score);
  const student = db.prepare("SELECT id FROM users WHERE email = ? AND role = 'student'").get(email);
  if (!student || !course || !Number.isFinite(score) || score < 0 || score > 100) {
    return res.status(400).json({ error: "Semak e-mel mahasiswa, kursus dan nilai (0–100)." });
  }
  const result = db.prepare(
    "INSERT INTO grades (student_id, lecturer_id, course, score, note) VALUES (?, ?, ?, ?, ?)"
  ).run(student.id, req.user.id, course, score, note);
  res.status(201).json({ id: result.lastInsertRowid });
});

app.get("/api/assignments", requireUser, (req, res) => {
  const rows = req.user.role === "student"
    ? db.prepare("SELECT a.id, a.title, a.original_name, a.created_at, u.name AS student FROM assignments a JOIN users u ON u.id = a.student_id WHERE a.student_id = ? ORDER BY a.created_at DESC").all(req.user.id)
    : db.prepare("SELECT a.id, a.title, a.original_name, a.created_at, u.name AS student FROM assignments a JOIN users u ON u.id = a.student_id ORDER BY a.created_at DESC").all();
  res.json({ assignments: rows });
});

const allowedFiles = new Map([
  [".pdf", "application/pdf"],
  [".docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"],
  [".txt", "text/plain"]
]);
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024, files: 1 },
  fileFilter: (req, file, callback) => {
    const extension = path.extname(file.originalname).toLowerCase();
    if (!allowedFiles.has(extension) || allowedFiles.get(extension) !== file.mimetype) {
      return callback(new Error("Jenis fail tidak dibenarkan. Gunakan PDF, DOCX atau TXT."));
    }
    callback(null, true);
  }
});

function validFileSignature(file) {
  const extension = path.extname(file.originalname).toLowerCase();
  if (extension === ".pdf") return file.buffer.subarray(0, 5).toString() === "%PDF-";
  if (extension === ".docx") return file.buffer.subarray(0, 2).toString() === "PK";
  return !file.buffer.includes(0);
}

app.post("/api/assignments", requireUser, requireRole("student"), (req, res, next) => {
  upload.single("file")(req, res, (error) => {
    if (error) return res.status(400).json({ error: error.message });
    next();
  });
}, (req, res) => {
  const title = cleanText(req.body.title, 120);
  if (!req.file || !title) return res.status(400).json({ error: "Tajuk dan fail tugasan diperlukan." });
  if (!validFileSignature(req.file)) return res.status(400).json({ error: "Kandungan fail tidak sepadan dengan jenis fail." });

  const extension = path.extname(req.file.originalname).toLowerCase();
  const storedName = `${crypto.randomUUID()}${extension}`;
  fs.writeFileSync(path.join(uploadDir, storedName), req.file.buffer, { flag: "wx" });
  try {
    const result = db.prepare(
      "INSERT INTO assignments (student_id, title, original_name, stored_name) VALUES (?, ?, ?, ?)"
    ).run(req.user.id, title, path.basename(req.file.originalname).slice(0, 255), storedName);
    res.status(201).json({ id: result.lastInsertRowid });
  } catch (error) {
    fs.unlinkSync(path.join(uploadDir, storedName));
    throw error;
  }
});

app.get("/api/assignments/:id/download", requireUser, (req, res) => {
  const assignment = db.prepare("SELECT * FROM assignments WHERE id = ?").get(Number(req.params.id));
  if (!assignment) return res.status(404).json({ error: "Fail tidak ditemui." });
  if (req.user.role === "student" && assignment.student_id !== req.user.id) {
    return res.status(403).json({ error: "Akses tidak dibenarkan." });
  }
  const filePath = path.join(uploadDir, assignment.stored_name);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: "Fail tidak ditemui pada pelayan." });
  res.download(filePath, assignment.original_name);
});

app.get("/api/forum", requireUser, (req, res) => {
  const posts = db.prepare(
    "SELECT p.id, p.message, p.created_at, u.name, u.role FROM forum_posts p JOIN users u ON u.id = p.user_id ORDER BY p.created_at DESC LIMIT 100"
  ).all();
  res.json({ posts });
});

app.post("/api/forum", requireUser, (req, res) => {
  const message = cleanText(req.body.message, 1000);
  if (!message) return res.status(400).json({ error: "Mesej tidak boleh kosong." });
  const result = db.prepare("INSERT INTO forum_posts (user_id, message) VALUES (?, ?)").run(req.user.id, message);
  res.status(201).json({ id: result.lastInsertRowid });
});

app.get("/api/users", requireUser, requireRole("admin"), (req, res) => {
  const users = db.prepare("SELECT id, name, email, role, created_at FROM users ORDER BY id").all();
  res.json({ users });
});

app.post("/api/users", requireUser, requireRole("admin"), (req, res) => {
  const name = cleanText(req.body.name, 100);
  const email = cleanText(req.body.email, 254).toLowerCase();
  const role = req.body.role;
  const password = typeof req.body.password === "string" ? req.body.password : "";
  if (!name || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !["student", "lecturer", "admin"].includes(role) || password.length < 12) {
    return res.status(400).json({ error: "Isi nama, e-mel, peranan yang sah dan kata laluan sekurang-kurangnya 12 aksara." });
  }
  try {
    const result = db.prepare("INSERT INTO users (name, email, role, password_hash) VALUES (?, ?, ?, ?)")
      .run(name, email, role, passwordHash(password));
    res.status(201).json({ id: result.lastInsertRowid });
  } catch (error) {
    if (error.message.includes("UNIQUE constraint failed: users.email")) return res.status(409).json({ error: "E-mel sudah digunakan." });
    throw error;
  }
});

app.put("/api/users/:id", requireUser, requireRole("admin"), (req, res) => {
  const id = Number(req.params.id);
  const existing = db.prepare("SELECT id, role FROM users WHERE id = ?").get(id);
  if (!existing) return res.status(404).json({ error: "Pengguna tidak ditemui." });
  const name = cleanText(req.body.name, 100);
  const email = cleanText(req.body.email, 254).toLowerCase();
  const role = req.body.role;
  const password = typeof req.body.password === "string" ? req.body.password : "";
  if (!name || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || !["student", "lecturer", "admin"].includes(role) || (password && password.length < 12)) {
    return res.status(400).json({ error: "Semak nama, e-mel, peranan dan panjang kata laluan." });
  }
  if (id === req.user.id && role !== "admin") return res.status(400).json({ error: "Anda tidak boleh menurunkan peranan akaun sendiri." });
  try {
    if (password) {
      db.prepare("UPDATE users SET name = ?, email = ?, role = ?, password_hash = ? WHERE id = ?")
        .run(name, email, role, passwordHash(password), id);
    } else {
      db.prepare("UPDATE users SET name = ?, email = ?, role = ? WHERE id = ?").run(name, email, role, id);
    }
    res.json({ ok: true });
  } catch (error) {
    if (error.message.includes("UNIQUE constraint failed: users.email")) return res.status(409).json({ error: "E-mel sudah digunakan." });
    throw error;
  }
});

app.delete("/api/users/:id", requireUser, requireRole("admin"), (req, res) => {
  const id = Number(req.params.id);
  if (id === req.user.id) return res.status(400).json({ error: "Anda tidak boleh memadam akaun sendiri." });
  const target = db.prepare("SELECT id, role FROM users WHERE id = ?").get(id);
  if (!target) return res.status(404).json({ error: "Pengguna tidak ditemui." });
  if (target.role === "admin" && db.prepare("SELECT COUNT(*) AS count FROM users WHERE role = 'admin'").get().count <= 1) {
    return res.status(400).json({ error: "Sekurang-kurangnya seorang admin mesti kekal." });
  }
  const files = db.prepare("SELECT stored_name FROM assignments WHERE student_id = ?").all(id);
  if (target.role === "lecturer") {
    db.prepare("DELETE FROM grades WHERE lecturer_id = ?").run(id);
  }
  db.prepare("DELETE FROM users WHERE id = ?").run(id);
  for (const file of files) {
    const filePath = path.join(uploadDir, file.stored_name);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
  }
  res.json({ ok: true });
});

app.use((error, req, res, next) => {
  console.error(error);
  if (res.headersSent) return next(error);
  res.status(500).json({ error: "Ralat pelayan. Sila cuba lagi." });
});

const port = Number(process.env.PORT) || 3000;
app.listen(port, () => console.log(`Portal FIKTI tersedia di http://localhost:${port}`));
