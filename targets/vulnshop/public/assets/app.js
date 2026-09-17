/*
 * VulnShop — bundle SPA (client VOLONTAIREMENT vulnerable).
 *
 * Les chemins d'API et les routes ci-dessous sont declares en clair : c'est ce
 * que l'analyseur de bundle de PENTAGON (js_analyzer) lit pour cartographier la
 * surface d'attaque, exactement comme sur une vraie SPA React/Vue.
 */

// Endpoints d'API (decouverts par js_analyzer via ces litteraux).
const API = {
  register: "/api/auth/register",
  login: "/api/auth/login",
  products: "/api/products",
  productSearch: "/api/products/search",
  comments: "/api/comments",
  orders: "/api/orders",
  users: "/api/users",
};

// Routes de l'application (SPA).
const ROUTES = [
  "/login",
  "/register",
  "/products",
  "/product",
  "/search",
  "/cart",
  "/admin",
  "/users",
  "/orders",
  "/account",
];

function token() {
  return localStorage.getItem("token");
}
function authHeaders() {
  const t = token();
  return t ? { Authorization: "Bearer " + t } : {};
}
function app() {
  return document.getElementById("app");
}
function updateStatus() {
  const el = document.getElementById("user-status");
  if (!el) return;
  const u = localStorage.getItem("username");
  el.textContent = token() ? "● " + (u || "connecte") : "";
}

function productCard(p) {
  return `
    <article class="card">
      <a class="product-link" id="product-${p.id}" href="#/product/${p.id}">
        <img class="thumb" src="/assets/img/${p.image || "logo.svg"}" alt="${p.name}" loading="lazy" />
        <h3>${p.name}</h3>
      </a>
      <p class="price">${p.price} €</p>
      <a class="btn" href="#/product/${p.id}">Voir le produit</a>
    </article>`;
}

async function renderHome() {
  let products = [];
  try {
    products = await (await fetch(API.products)).json();
  } catch (e) {
    /* ignore */
  }
  app().innerHTML = `
    <section class="hero">
      <div>
        <h1>Le meilleur du high-tech</h1>
        <p>Claviers, écrans, audio et accessoires — livraison offerte dès 50 €.</p>
        <a class="btn btn-lg" href="#/product/1">Découvrir</a>
      </div>
    </section>
    <h2 class="section-title">Nos produits</h2>
    <div class="grid">${products.map(productCard).join("")}</div>`;
}

function renderLogin() {
  app().innerHTML = `
    <div class="auth-card">
      <h2>Connexion</h2>
      <form id="login-form" autocomplete="off">
        <label>Utilisateur<input id="username" name="username" type="text"></label>
        <label>Mot de passe<input id="password" name="password" type="password"></label>
        <button id="login-btn" type="submit">Se connecter</button>
      </form>
      <p class="muted">Pas de compte ? <a href="#/register">Inscrivez-vous</a></p>
      <p id="login-msg" class="msg"></p>
    </div>`;
  document.getElementById("login-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
    let data = {};
    try {
      const res = await fetch(API.login, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      data = await res.json();
      if (res.ok && data.token) {
        localStorage.setItem("token", data.token);
        localStorage.setItem("username", (data.user && data.user.username) || username);
        updateStatus();
        location.hash = "#/";
        return;
      }
    } catch (e) {
      /* ignore */
    }
    document.getElementById("login-msg").textContent =
      "Echec : " + (data.error || "identifiants invalides");
  });
}

function renderRegister() {
  app().innerHTML = `
    <div class="auth-card">
      <h2>Créer un compte</h2>
      <form id="register-form" autocomplete="off">
        <label>Utilisateur<input id="reg-username" name="username" type="text"></label>
        <label>Email<input id="reg-email" name="email" type="email"></label>
        <label>Mot de passe<input id="reg-password" name="password" type="password"></label>
        <button id="register-btn" type="submit">S'inscrire</button>
      </form>
      <p class="muted">Déjà inscrit ? <a href="#/login">Connexion</a></p>
      <p id="register-msg" class="msg"></p>
    </div>`;
  document.getElementById("register-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const username = document.getElementById("reg-username").value;
    const email = document.getElementById("reg-email").value;
    const password = document.getElementById("reg-password").value;
    let data = {};
    try {
      const res = await fetch(API.register, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, email, password }),
      });
      data = await res.json();
      if (res.ok && data.token) {
        localStorage.setItem("token", data.token);
        localStorage.setItem("username", (data.user && data.user.username) || username);
        updateStatus();
        location.hash = "#/";
        return;
      }
    } catch (e) {
      /* ignore */
    }
    document.getElementById("register-msg").textContent =
      "Echec : " + (data.error || "inscription impossible");
  });
}

async function renderSearch(q) {
  let payload = { query: q, results: [] };
  try {
    payload = await (await fetch(API.productSearch + "?q=" + encodeURIComponent(q))).json();
  } catch (e) {
    /* ignore */
  }
  const results = payload.results || [];
  app().innerHTML = `
    <h2 class="section-title">Résultats pour « ${payload.query} »</h2>
    <div class="grid">${results.map(productCard).join("")}</div>
    ${results.length ? "" : '<p class="muted">Aucun produit trouvé.</p>'}`;
}

async function renderProduct(id) {
  let product = { name: "?", price: "?", description: "", image: "logo.svg" };
  let comments = [];
  try {
    const pres = await fetch(API.products + "/" + id);
    if (pres.ok) product = await pres.json();
    const cres = await fetch(API.comments + "?productId=" + id);
    if (cres.ok) comments = await cres.json();
  } catch (e) {
    /* ignore */
  }
  app().innerHTML = `
    <p><a class="muted" href="#/">← Retour au catalogue</a></p>
    <div class="product">
      <img class="product-img" src="/assets/img/${product.image || "logo.svg"}" alt="${product.name}" />
      <div class="product-info">
        <h2>${product.name}</h2>
        <p class="price price-lg">${product.price} €</p>
        <p>${product.description || ""}</p>
        <button class="btn btn-lg">Ajouter au panier</button>
      </div>
    </div>
    <h3 class="section-title">Avis clients</h3>
    <div id="comments"></div>
    <form id="comment-form" class="comment-form">
      <textarea id="comment-input" placeholder="Votre avis..."></textarea>
      <button id="comment-btn" type="submit">Publier</button>
    </form>`;
  // VULNERABILITE A DESSEIN : le contenu des commentaires est injecte via
  // innerHTML SANS echappement → un commentaire piege s'execute (XSS stocke).
  document.getElementById("comments").innerHTML = comments
    .map((c) => `<div class="comment"><b>${c.author}</b> : ${c.content}</div>`)
    .join("");

  document.getElementById("comment-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const content = document.getElementById("comment-input").value;
    try {
      await fetch(API.comments, {
        method: "POST",
        headers: Object.assign({ "Content-Type": "application/json" }, authHeaders()),
        body: JSON.stringify({ productId: Number(id), content, author: localStorage.getItem("username") || "client" }),
      });
    } catch (e) {
      /* ignore */
    }
    renderProduct(id);
  });
}

function router() {
  updateStatus();
  const hash = location.hash.replace(/^#/, "") || "/";
  if (hash === "/" || hash === "") return renderHome();
  if (hash === "/login") return renderLogin();
  if (hash === "/register") return renderRegister();
  const s = hash.match(/^\/search\?q=(.*)$/);
  if (s) return renderSearch(decodeURIComponent(s[1]));
  const m = hash.match(/^\/product\/(\d+)/);
  if (m) return renderProduct(m[1]);
  return renderHome();
}

document.addEventListener("submit", (e) => {
  if (e.target && e.target.id === "search-form") {
    e.preventDefault();
    const q = document.getElementById("search-input").value;
    location.hash = "#/search?q=" + encodeURIComponent(q);
  }
});

window.addEventListener("hashchange", router);
window.addEventListener("DOMContentLoaded", router);
