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
export const getFindings = (sessionId) =>
  request(`/api/v1/sessions/${encodeURIComponent(sessionId)}/findings`);
export const getAudit = (sessionId) =>
  request(`/api/v1/sessions/${encodeURIComponent(sessionId)}/audit`);

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
