// Marque provisoire (logo texte). À remplacer par le logo de la charte :
// seul ce composant change, pas les écrans.
export default function Brand({ showSub = true }) {
  return (
    <div className="brand">
      <span className="mark" aria-hidden="true">
        P
      </span>
      <span>
        PENTAGON
        {showSub && <span className="sub"> · console</span>}
      </span>
    </div>
  );
}
