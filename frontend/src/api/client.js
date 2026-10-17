// Client de l'API PENTAGON. Toutes les requêtes passent en même origine
// (dev : proxy Vite /api → Flask ; prod : servi par Flask), donc le cookie de
// session est transmis automatiquement avec credentials: "same-origin".

async function request(path, { method = "GET", body } = {}) {
  const opts = { method, credentials: "same-origin", headers: {} };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  let data = null;
  try {
    data = await res.json();
  } catch {
    data = null;
  }
  if (!res.ok) {
    const message = (data && (data.error || data.reason)) || `HTTP ${res.status}`;
    const err = new Error(message);
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

// ─── Authentification ───
export const me = () => request("/api/v1/me");
export const login = (username, password) =>
  request("/api/v1/login", { method: "POST", body: { username, password } });
export const logout = () => request("/api/v1/logout", { method: "POST" });

// ─── Sessions / campagnes ───
// /api/jobs est l'inventaire existant des campagnes (récentes + persistées).
export const listSessions = () => request("/api/jobs");
// Vue d'ensemble multi-cas (pages d'index Audits/Rapports).
export const getIndex = () => request("/api/v1/index");
export const getFindings = (sessionId) =>
  request(`/api/v1/sessions/${encodeURIComponent(sessionId)}/findings`);
export const getAudit = (sessionId) =>
  request(`/api/v1/sessions/${encodeURIComponent(sessionId)}/audit`);
export const getReport = (sessionId) =>
  request(`/api/v1/sessions/${encodeURIComponent(sessionId)}/report`);
export const createShare = (sessionId) =>
  request(`/api/v1/sessions/${encodeURIComponent(sessionId)}/share`, { method: "POST" });
// Génération du PDF (endpoint historique). Le téléchargement se fait par lien <a>.
export const generatePdf = (sessionId) =>
  request(`/api/report/${encodeURIComponent(sessionId)}`, { method: "POST" });
export const downloadUrl = (sessionId, kind) =>
  `/api/download/${encodeURIComponent(sessionId)}/${kind}`;

// ─── Nouvelle mission (lancer un pentest) ───
export const getCatalog = () => request("/api/v1/catalog");
export const startCampaign = (payload) =>
  request("/api/start", { method: "POST", body: payload });
// Flux de progression en direct (SSE). L'appelant gère l'EventSource.
export const streamUrl = (jobId) => `/api/stream/${encodeURIComponent(jobId)}`;

// ─── Administration (Lot UI-5) — admin only ───
export const adminListUsers = () => request("/api/v1/admin/users");
export const adminSetUserSites = (username, sites) =>
  request(`/api/v1/admin/users/${encodeURIComponent(username)}/sites`, {
    method: "PUT",
    body: { sites },
  });
// Gestion des comptes (endpoint historique /api/admin/users).
export const adminCreateUser = (username, password, role) =>
  request("/api/admin/users", { method: "POST", body: { username, password, role } });
export const adminSetUserRole = (username, role) =>
  request("/api/admin/users", { method: "PATCH", body: { username, role } });
export const adminDeleteUser = (username) =>
  request("/api/admin/users", { method: "DELETE", body: { username } });

// ─── Lot UI-2 (préparé, câblé plus tard dans l'UI) ───
export const sendCommand = (sessionId, command) =>
  request(`/api/v1/sessions/${encodeURIComponent(sessionId)}/command`, {
    method: "POST",
    body: { command },
  });
export const exploitFinding = (sessionId, findingId, mode) =>
  request(
    `/api/v1/sessions/${encodeURIComponent(sessionId)}/findings/${encodeURIComponent(
      findingId
    )}/exploit`,
    { method: "POST", body: { mode } }
  );
export const retestFinding = (sessionId, findingId) =>
  request(
    `/api/v1/sessions/${encodeURIComponent(sessionId)}/findings/${encodeURIComponent(
      findingId
    )}/retest`,
    { method: "POST" }
  );
