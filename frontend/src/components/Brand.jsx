// Logo PENTAGON : un pentagone refermé par une coche de preuve — le symbole de
// la charte (« Détecté → Prouvé → Confirmé »). Monochrome, piloté par la
// couleur courante (indigo‑ardoise via la classe .mark).
export function Logo({ size = 28, title = "PENTAGON" }) {
  return (
    <svg
      className="logo-mark"
      width={size}
      height={size}
      viewBox="0 0 100 100"
      role="img"
      aria-label={title}
    >
      <polygon
        points="50,8 90,38 74.5,86 25.5,86 10,38"
        fill="none"
        stroke="currentColor"
        strokeWidth="7"
        strokeLinejoin="round"
      />
      <path
        d="M31 50 L44 63 L70 35"
        fill="none"
        stroke="currentColor"
        strokeWidth="7.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

export default function Brand({ showSub = true }) {
  return (
    <div className="brand">
      <span className="mark" aria-hidden="true">
        <Logo size={20} />
      </span>
      <span>
        PENTAGON
        {showSub && <span className="sub"> · console</span>}
      </span>
    </div>
  );
}
