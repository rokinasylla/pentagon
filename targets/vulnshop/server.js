/**
 * VulnShop — serveur (Express + sql.js).
 *
 * CIBLE D'ENTRAINEMENT VOLONTAIREMENT VULNERABLE pour le systeme PENTAGON.
 * A n'utiliser QUE pour tester son propre outil. Donnees 100% factices.
 *
 * Architecture : service unique (API + front SPA sur la meme origine), pensee
 * pour etre DECOUVRABLE par les heuristiques generiques de PENTAGON :
 *   - le bundle /assets/app.js expose les chemins d'API et les routes (js_analyzer)
 *   - /api/auth/login : login concatene en SQL → contournement d'auth (A03) + JWT (A07)
 *   - /api/products/search?q= : parametre concatene → SQLi basee erreurs (A03)
 *   - /api/orders/:id, /api/users/:id : objets d'autrui accessibles → IDOR/BOLA (A01)
 *   - /users, /orders : dump JSON sans auth → controle d'acces casse (A01) + donnees (A02)
 *   - /api/comments : contenu stocke puis rendu sans echappement → XSS stocke (A03)
 *   - JWT HS256 signe avec un secret FAIBLE ("secret") → forgeable (A02/A07)
 *
 * Correspondance OWASP visee : 7/7 comme TechShop.
 */

const path = require("path");
const crypto = require("crypto");
const express = require("express");
const { createDb } = require("./db");

// Secret JWT FAIBLE a dessein (present dans les dictionnaires) → token forgeable.
const JWT_SECRET = process.env.JWT_SECRET || "secret";

// ----------------------------- Helpers JWT (HS256) --------------------------

function b64url(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/=/g, "")
    .replace(/\+/g, "-")
    .replace(/\//g, "_");
}

function signJwt(payload) {
  const header = { alg: "HS256", typ: "JWT" };
  const h = b64url(JSON.stringify(header));
  // NB (vuln a dessein) : role expose en clair, claim "debug" (fuite d'info),
  // et AUCUN champ "exp" (pas d'expiration).
  const body = { ...payload, iat: Math.floor(Date.now() / 1000), debug: true };
  const p = b64url(JSON.stringify(body));
  const data = `${h}.${p}`;
  const sig = crypto.createHmac("sha256", JWT_SECRET).update(data).digest();
  return `${data}.${b64url(sig)}`;
}

// Lit le payload du token Bearer SANS verifier la signature (l'app est laxiste
// a dessein) — suffit pour rattacher une commande a l'utilisateur courant.
function decodeBearer(req) {
  const h = req.headers.authorization || "";
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return null;
  try {
    return JSON.parse(Buffer.from(m[1].split(".")[1], "base64").toString());
  } catch (e) {
    return null;
  }
}

// ------------------------------ Application ---------------------------------

async function main() {
  const store = await createDb();
  const { md5 } = store;

  const app = express();
  app.use(express.json());

  // A03 + A07 : login construit par CONCATENATION SQL (injection + creds faibles).
  app.post("/api/auth/login", (req, res) => {
    const { username, password } = req.body || {};
    const hashed = md5(password == null ? "" : password);
    // VULNERABLE A DESSEIN : concatenation directe de l'entree utilisateur.
    const sql = `SELECT * FROM users WHERE username = '${username}' AND password = '${hashed}'`;
    try {
      const row = store.get(sql);
      if (row) {
        const token = signJwt({ sub: row.id, username: row.username, role: row.role });
        return res.json({
          token,
          user: { id: row.id, username: row.username, role: row.role },
        });
      }
      return res.status(401).json({ error: "invalid credentials" });
    } catch (e) {
      // Message d'erreur VERBEUX a dessein (fuite de requete SQL).
      return res
        .status(500)
        .json({ error: `SQL error executing query: ${sql} :: ${e.message}` });
    }
  });

  // A07 (bonus) : inscription — cree un compte (mot de passe hache MD5, faible).
  app.post("/api/auth/register", (req, res) => {
    const { username, email, password } = req.body || {};
    if (!username || !password) {
      return res.status(400).json({ error: "username et password requis" });
    }
    const exists = store.get("SELECT id FROM users WHERE username = ?", [username]);
    if (exists) {
      return res.status(409).json({ error: "utilisateur deja existant" });
    }
    const id = store.run(
      "INSERT INTO users (username, email, password, creditCard, role) VALUES (?,?,?,?,?)",
      [username, email == null ? "" : String(email), md5(password), "", "USER"]
    );
    const token = signJwt({ sub: id, username, role: "USER" });
    return res.status(201).json({ token, user: { id, username, role: "USER" } });
  });

  // Catalogue public (NORMAL — ne doit PAS etre signale comme faille).
  app.get("/api/products", (_req, res) => {
    res.json(store.all("SELECT id, name, price, description, image FROM products"));
  });

  // A03 : recherche par CONCATENATION sur le parametre q (+ reflexion de q).
  app.get("/api/products/search", (req, res) => {
    const q = req.query.q == null ? "" : String(req.query.q);
    const sql = `SELECT id, name, price, description, image FROM products WHERE name LIKE '%${q}%'`;
    try {
      const results = store.all(sql);
      return res.json({ query: q, results }); // q reflete brut (XSS reflechi/DOM)
    } catch (e) {
      return res
        .status(500)
        .json({ error: `SQL error executing query: ${sql} :: ${e.message}` });
    }
  });

  // A03 (bonus) : id de chemin concatene → SQLi sur le parametre de chemin.
  app.get("/api/products/:id", (req, res) => {
    const sql = `SELECT id, name, price, description, image FROM products WHERE id = ${req.params.id}`;
    try {
      const row = store.get(sql);
      if (!row) return res.status(404).json({ error: "not found" });
      return res.json(row);
    } catch (e) {
      return res
        .status(500)
        .json({ error: `SQL error executing query: ${sql} :: ${e.message}` });
    }
  });

  // Passer commande : cree une commande rattachee a l'utilisateur du token.
  app.post("/api/orders", (req, res) => {
    const user = decodeBearer(req);
    if (!user) return res.status(401).json({ error: "authentification requise" });
    const { items, total } = req.body || {};
    const email =
      user.email || `${user.username || "client"}@vulnshop.test`;
    const id = store.run(
      "INSERT INTO orders (userId, customerEmail, total, items) VALUES (?,?,?,?)",
      [user.sub || 0, email, total || 0, items == null ? "" : String(items)]
    );
    res.status(201).json({ id, userId: user.sub || 0, total: total || 0, items });
  });

  // A01 : commandes d'AUTRUI accessibles par simple enumeration d'id (IDOR/BOLA).
  app.get("/api/orders", (_req, res) => {
    res.json(store.all("SELECT * FROM orders"));
  });
  app.get("/api/orders/:id", (req, res) => {
    const row = store.get("SELECT * FROM orders WHERE id = ?", [req.params.id]);
    if (!row) return res.status(404).json({ error: "not found" });
    res.json(row); // aucun controle : on renvoie la commande quel que soit le token
  });

  // A01 : utilisateurs d'AUTRUI accessibles par enumeration d'id (IDOR/BOLA).
  app.get("/api/users/:id", (req, res) => {
    const row = store.get(
      "SELECT id, username, email, role FROM users WHERE id = ?",
      [req.params.id]
    );
    if (!row) return res.status(404).json({ error: "not found" });
    res.json(row);
  });

  // A03 : commentaires — stockage puis relecture SANS assainissement (XSS stocke).
  app.get("/api/comments", (req, res) => {
    const pid = req.query.productId;
    const rows =
      pid != null
        ? store.all("SELECT * FROM comments WHERE productId = ?", [pid])
        : store.all("SELECT * FROM comments");
    res.json(rows);
  });
  app.post("/api/comments", (req, res) => {
    const { productId, content, author } = req.body || {};
    const id = store.run(
      "INSERT INTO comments (productId, author, content, createdAt) VALUES (?,?,?,?)",
      [
        productId == null ? 1 : productId,
        author == null ? "anon" : String(author),
        content == null ? "" : String(content), // stocke BRUT (pas d'echappement)
        new Date().toISOString(),
      ]
    );
    res.status(201).json({
      id,
      productId: productId == null ? 1 : productId,
      author: author == null ? "anon" : String(author),
      content: content == null ? "" : String(content),
    });
  });

  // A01 + A02 : "dumps" JSON sans authentification (controle d'acces casse).
  // Exposent mots de passe MD5 + "numeros de carte" → alimentent l'analyse de
  // donnees de PENTAGON (hash faibles, mots de passe cassables, cartes Luhn).
  app.get("/users", (_req, res) => {
    res.json(store.all("SELECT * FROM users"));
  });
  app.get("/orders", (_req, res) => {
    res.json(store.all("SELECT * FROM orders"));
  });

  // ------------------------------- Front (SPA) ------------------------------

  app.use(express.static(path.join(__dirname, "public")));
  // Repli SPA : toute autre route sert l'index (routage cote client par hash).
  app.get("*", (_req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
  });

  const PORT = process.env.PORT || 3000;
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`VulnShop (cible d'entrainement) en ecoute sur le port ${PORT}`);
    console.log(
      "⚠️  Application VOLONTAIREMENT vulnerable — donnees factices, usage pedagogique."
    );
  });
}

main().catch((e) => {
  console.error("Echec du demarrage de VulnShop :", e);
  process.exit(1);
});
