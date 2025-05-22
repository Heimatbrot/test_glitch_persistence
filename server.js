// A basic user authentication web app for Glitch with persistent storage
// Backend: Node.js + Express
// Database: SQLite (stored in .data folder for persistence on Glitch)
require("dotenv").config(); // Load variables from .env

const fs = require("fs");
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const sqlite3 = require("sqlite3").verbose();
const SQLiteStore = require("connect-sqlite3")(session);
const path = require("path");
const app = express();

// Ensure the .data directory exists
const dataDir = path.join(__dirname, ".data");
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir);
}

const dbPath = path.join(dataDir, "users.db");
const db = new sqlite3.Database(dbPath);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(
  session({
    store: new SQLiteStore({ db: "sessions.db", dir: ".data" }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
  })
);

app.use(express.static("public"));

// Initialize the database
const initDb = () => {
  db.run(
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT
    )`
  );
};

initDb();

const isAuthenticated = (req, res, next) => {
  if (req.session.userId) return next();
  res.redirect("/login");
};

app.get("/", (req, res) => {
  if (req.session.userId) {
    res.redirect("/lobby");
  } else {
    res.sendFile(path.join(__dirname, "public/index.html"));
  }
});

app.get("/register", (req, res) => {
  res.sendFile(path.join(__dirname, "public/register.html"));
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hash = await bcrypt.hash(password, 10);
  db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, hash], function (err) {
    if (err) {
      return res.send("Username already taken. <a href='/register'>Try again</a>");
    }
    req.session.userId = this.lastID;
    res.redirect("/lobby");
  });
});

app.get("/login", (req, res) => {
  res.sendFile(path.join(__dirname, "public/login.html"));
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {
    if (user && await bcrypt.compare(password, user.password)) {
      req.session.userId = user.id;
      res.redirect("/lobby");
    } else {
      res.send("Invalid login. <a href='/login'>Try again</a>");
    }
  });
});

app.get("/lobby", isAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, "public/lobby.html"));
});

app.get("/api/users", isAuthenticated, (req, res) => {
  db.all("SELECT id, username FROM users", (err, users) => {
    const current = users.find(u => u.id === req.session.userId);
    const others = users.filter(u => u.id !== req.session.userId);
    res.json({ current, others });
  });
});

app.post("/delete", isAuthenticated, (req, res) => {
  db.run("DELETE FROM users WHERE id = ?", [req.session.userId], (err) => {
    req.session.destroy(() => {
      res.redirect("/");
    });
  });
});

app.get("/logout", (req, res) => {
  req.session.destroy(() => {
    res.redirect("/");
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));