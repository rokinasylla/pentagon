// Explications vulgarisées par catégorie, pour un propriétaire de site non
// expert. Affichées dans le drawer de détail à côté de la preuve technique.
export const CATEGORY_EXPLAIN = {
  ssti: "Le serveur exécute du texte fourni par l'utilisateur comme du code : un attaquant peut lui faire exécuter des commandes.",
  ssrf: "Le serveur peut être poussé à envoyer des requêtes vers des adresses internes qu'il ne devrait pas joindre.",
  csrf: "Une action sensible peut être déclenchée depuis un autre site, à l'insu de l'utilisateur connecté.",
  lfi: "Un attaquant peut faire lire au serveur des fichiers internes (configuration, mots de passe système).",
  open_redirect: "Le site redirige vers n'importe quelle adresse : utile pour des pièges d'hameçonnage crédibles.",
  sqli: "Des entrées non filtrées atteignent la base de données : lecture ou contournement d'authentification possibles.",
  xss: "Du script fourni par un tiers s'exécute dans le navigateur des visiteurs : vol de session, défiguration.",
  jwt: "Le jeton d'authentification est falsifiable : un attaquant peut se faire passer pour un autre compte, voire l'admin.",
  idor: "On peut accéder aux données d'autres utilisateurs en changeant un identifiant dans l'URL.",
  auth: "L'authentification est contournable (identifiants faibles/par défaut) : accès à des comptes non autorisés.",
};

export const CATEGORY_LABEL = {
  ssti: "Injection de template (SSTI)",
  ssrf: "Falsification de requête serveur (SSRF)",
  csrf: "Falsification inter-site (CSRF)",
  lfi: "Traversée / lecture de fichier (LFI)",
  open_redirect: "Redirection ouverte",
  sqli: "Injection SQL",
  xss: "Cross-site scripting (XSS)",
  jwt: "Jeton JWT falsifiable",
  idor: "Accès horizontal (IDOR)",
  auth: "Authentification faible",
};
