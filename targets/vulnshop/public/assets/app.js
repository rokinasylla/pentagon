/*
 * VulnShop — bundle SPA (client VOLONTAIREMENT vulnerable).
 *
 * Les chemins d'API et les routes ci-dessous sont declares en clair : c'est ce
 * que l'analyseur de bundle de PENTAGON (js_analyzer) lit pour cartographier la
 * surface d'attaque, exactement comme sur une vraie SPA React/Vue.
 */

// Endpoints d'API (decouverts par js_analyzer via ces litteraux).
const API = {
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
  "/products",
  "/product",
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
  if (el) el.textContent = token() ? "● connecte" : "";
}

async function renderHome() {
  let products = [];
  try {
    products = await (await fetch(API.products)).json();
  } catch (e) {
    /* ignore */
  }
  app().innerHTML =
    "<h2>Nos produits</h2><ul id=\"products\">" +
    products
      .map(
        (p) =>
          `<li><a class="product-link" id="product-${p.id}" href="#/product/${p.id}">${p.name}</a> — ${p.price} €</li>`
      )
      .join("") +
    "</ul>";
}

function renderLogin() {
  app().innerHTML = `
    <h2>Connexion</h2>
    <form id="login-form" autocomplete="off">
      <p><label>Utilisateur<br><input id="username" name="username" type="text"></label></p>
      <p><label>Mot de passe<br><input id="password" name="password" type="password"></label></p>
      <button id="login-btn" type="submit">Se connecter</button>
    </form>
    <p id="login-msg"></p>`;
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

async function renderProduct(id) {
  let product = { name: "?", price: "?", description: "" };
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
    <p><a href="#/">← Retour</a></p>
    <h2>${product.name} — ${product.price} €</h2>
    <p>${product.description || ""}</p>
    <h3>Avis clients</h3>
    <div id="comments"></div>
    <form id="comment-form">
      <p><textarea id="comment-input" placeholder="Votre avis..."></textarea></p>
      <button id="comment-btn" type="submit">Publier</button>
    </form>`;
  // VULNERABILITE A DESSEIN : le contenu des commentaires est injecte via
  // innerHTML SANS echappement → un commentaire piege s'execute (XSS stocke).
  document.getElementById("comments").innerHTML = comments
    .map((c) => `<div class="comment"><b>${c.author}</b> : ${c.content}</div>`)
    .join("");

  document
    .getElementById("comment-form")
    .addEventListener("submit", async (e) => {
      e.preventDefault();
      const content = document.getElementById("comment-input").value;
      try {
        await fetch(API.comments, {
          method: "POST",
          headers: Object.assign(
            { "Content-Type": "application/json" },
            authHeaders()
          ),
          body: JSON.stringify({ productId: Number(id), content, author: "client" }),
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
  const m = hash.match(/^\/product\/(\d+)/);
  if (m) return renderProduct(m[1]);
  return renderHome();
}

window.addEventListener("hashchange", router);
window.addEventListener("DOMContentLoaded", router);
