/**
 * VulnShop — base de donnees (SQLite via sql.js, pur JS/WASM, en memoire).
 *
 * CIBLE D'ENTRAINEMENT VOLONTAIREMENT VULNERABLE pour PENTAGON.
 * Toutes les donnees sont FACTICES (faux utilisateurs, numeros de carte de
 * TEST valides Luhn mais non rattaches a un vrai compte). Base recreee et
 * re-semee a chaque demarrage : rien de reel n'est stocke.
 *
 * On utilise sql.js (SQLite compile en WebAssembly) : AUCUNE compilation
 * native requise → s'installe partout (Windows, Render, Kali). Le moteur SQL
 * est reel → les injections SQL sont de VRAIES injections (non simulees).
 *
 * Vulnerabilites semees ici, a dessein :
 *  - Mots de passe haches en MD5 (crypto faible, A02) + mots de passe triviaux
 *  - Compte admin par defaut (admin / admin123, A07)
 *  - "Numeros de carte" en clair dans la table users (A02)
 *  - Emails/donnees liees a l'utilisateur dans users/orders (support de l'IDOR, A01)
 */

const crypto = require("crypto");
const initSqlJs = require("sql.js");

function md5(s) {
  return crypto.createHash("md5").update(String(s)).digest("hex");
}

async function createDb() {
  const SQL = await initSqlJs();
  const db = new SQL.Database();

  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY,
      username TEXT,
      email TEXT,
      password TEXT,      -- hache MD5 (faible, a dessein)
      creditCard TEXT,    -- "numero de carte" de TEST (donnee factice)
      role TEXT
    );
    CREATE TABLE products (
      id INTEGER PRIMARY KEY,
      name TEXT,
      price REAL,
      description TEXT
    );
    CREATE TABLE orders (
      id INTEGER PRIMARY KEY,
      userId INTEGER,
      customerEmail TEXT,
      total REAL,
      items TEXT
    );
    CREATE TABLE comments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      productId INTEGER,
      author TEXT,
      content TEXT,
      createdAt TEXT
    );
  `);

  // --- Utilisateurs (donnees factices ; mots de passe triviaux haches MD5) ---
  const users = [
    [1, "admin", "admin@vulnshop.test", md5("admin123"), "4111111111111111", "ADMIN"],
    [2, "alice", "alice@vulnshop.test", md5("password"), "5555555555554444", "USER"],
    [3, "bob", "bob@vulnshop.test", md5("123456"), "4012888888881881", "USER"],
    [4, "carol", "carol@vulnshop.test", md5("qwerty"), "5105105105105100", "USER"],
  ];
  for (const u of users) {
    db.run(
      "INSERT INTO users (id, username, email, password, creditCard, role) VALUES (?,?,?,?,?,?)",
      u
    );
  }

  // --- Catalogue produits (public, NORMAL — sert d'anti-faux-positif IDOR) ---
  const products = [
    [1, "Clavier mecanique", 79.9, "Clavier retroeclaire, switches bruns."],
    [2, "Souris ergonomique", 39.5, "Souris sans fil, 6 boutons."],
    [3, "Ecran 27 pouces", 229.0, "Dalle IPS 2560x1440, 75 Hz."],
    [4, "Casque USB", 59.0, "Casque micro antibruit."],
  ];
  for (const p of products) {
    db.run("INSERT INTO products (id, name, price, description) VALUES (?,?,?,?)", p);
  }

  // --- Commandes (liees a des utilisateurs → support de l'IDOR/BOLA, A01) ---
  const orders = [
    [1, 1, "admin@vulnshop.test", 79.9, "Clavier mecanique x1"],
    [2, 2, "alice@vulnshop.test", 39.5, "Souris ergonomique x1"],
    [3, 3, "bob@vulnshop.test", 288.0, "Ecran 27 pouces x1, Casque USB x1"],
    [4, 4, "carol@vulnshop.test", 59.0, "Casque USB x1"],
  ];
  for (const o of orders) {
    db.run(
      "INSERT INTO orders (id, userId, customerEmail, total, items) VALUES (?,?,?,?,?)",
      o
    );
  }

  // --- Commentaires initiaux (rendus SANS echappement cote client → XSS stocke) ---
  const now = new Date().toISOString();
  db.run(
    "INSERT INTO comments (productId, author, content, createdAt) VALUES (?,?,?,?)",
    [1, "alice", "Super clavier, tres reactif !", now]
  );
  db.run(
    "INSERT INTO comments (productId, author, content, createdAt) VALUES (?,?,?,?)",
    [1, "bob", "Bon rapport qualite/prix.", now]
  );

  // ------ Petite couche d'acces (all/get/run) au-dessus de sql.js ------

  function all(sql, params = []) {
    const stmt = db.prepare(sql); // leve une erreur si le SQL est invalide
    try {
      stmt.bind(params);
      const rows = [];
      while (stmt.step()) rows.push(stmt.getAsObject());
      return rows;
    } finally {
      stmt.free();
    }
  }

  function get(sql, params = []) {
    const rows = all(sql, params);
    return rows.length ? rows[0] : null;
  }

  function run(sql, params = []) {
    db.run(sql, params);
    const r = db.exec("SELECT last_insert_rowid() AS id");
    return r.length ? r[0].values[0][0] : null;
  }

  return { all, get, run, md5 };
}

module.exports = { createDb, md5 };
