// Jeu d'icônes SVG — trait 2px cohérent, fidèle à l'artboard « Identité ».
// Remplace les glyphes (◆ ❯ ▣ …) par un système homogène piloté par la
// couleur courante. Décoratif par défaut ; passez `label` pour l'exposer.
const PATHS = {
  missions: (
    <>
      <path d="M4 7l8-4 8 4-8 4-8-4z" />
      <path d="M4 12l8 4 8-4M4 17l8 4 8-4" />
    </>
  ),
  sessions: (
    <>
      <path d="M8 10h8M8 14h5" />
      <path d="M4 5h16v11H9l-5 4V5z" />
    </>
  ),
  audits: (
    <>
      <path d="M12 3l7 3v5c0 4.2-2.8 7.6-7 9-4.2-1.4-7-4.8-7-9V6l7-3z" />
      <path d="M9 12l2 2 4-4" />
    </>
  ),
  rapports: (
    <>
      <path d="M7 3h7l5 5v13H7z" />
      <path d="M14 3v5h5M10 13h6M10 16h6" />
    </>
  ),
  reglages: (
    <>
      <circle cx="12" cy="12" r="3.2" />
      <path d="M12 3v3M12 18v3M3 12h3M18 12h3M6 6l2 2M16 16l2 2M18 6l-2 2M8 16l-2 2" />
    </>
  ),
  scan: (
    <>
      <circle cx="11" cy="11" r="7" />
      <path d="M16 16l4 4" />
    </>
  ),
  exploit: <path d="M13 3L4 14h7l-1 7 9-11h-7l1-7z" />,
  shield: <path d="M12 3l7 3v5c0 4.2-2.8 7.6-7 9-4.2-1.4-7-4.8-7-9V6l7-3z" />,
  shieldCheck: (
    <>
      <path d="M12 3l7 3v5c0 4.2-2.8 7.6-7 9-4.2-1.4-7-4.8-7-9V6l7-3z" />
      <path d="M9 12l2 2 4-4" />
    </>
  ),
  globe: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18" />
    </>
  ),
  stop: <rect x="6" y="6" width="12" height="12" rx="2" />,
  lock: (
    <>
      <rect x="5" y="11" width="14" height="9" rx="2" />
      <path d="M8 11V8a4 4 0 018 0v3" />
    </>
  ),
  share: (
    <>
      <circle cx="7" cy="12" r="2.4" />
      <circle cx="17" cy="6" r="2.4" />
      <circle cx="17" cy="18" r="2.4" />
      <path d="M9 11l6-4M9 13l6 4" />
    </>
  ),
  check: <path d="M5 13l4 4L19 7" />,
  arrow: <path d="M5 12h13M12 5l7 7-7 7" />,
  chevron: <path d="M6 9l6 6 6-6" />,
  external: <path d="M4 20L20 4M9 4h11v11" />,
  user: (
    <>
      <circle cx="12" cy="8" r="3.4" />
      <path d="M5 20c1.2-3.6 4-5 7-5s5.8 1.4 7 5" />
    </>
  ),
  help: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M9.6 9.2a2.4 2.4 0 1 1 4 1.8c-1 .7-1.6 1.2-1.6 2.3" />
      <circle cx="12" cy="16.6" r="1" />
    </>
  ),
  plus: <path d="M12 5v14M5 12h14" />,
};

export default function Icon({ name, size = 18, sw = 1.8, label, className }) {
  const inner = PATHS[name];
  if (!inner) return null;
  return (
    <svg
      className={className}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={sw}
      strokeLinecap="round"
      strokeLinejoin="round"
      role={label ? "img" : undefined}
      aria-label={label || undefined}
      aria-hidden={label ? undefined : "true"}
    >
      {inner}
    </svg>
  );
}
