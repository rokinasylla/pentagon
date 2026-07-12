"""
Agent Reporting de PENTAGON (PTES phase 7 — Reporting).

Transforme le JSON consolidé d'une campagne en un rapport PDF professionnel :
page de garde, synthèse exécutive, tableau de bord des sévérités, couverture
OWASP, findings détaillés (prouvés puis détectés), reconnaissance, et une
annexe de gouvernance/audit (agents exécutés, journal, erreurs).

Architecture (comme la CLI) : la logique d'assemblage est PURE et testable
hors-ligne (pentagon/tools/report_builder.py). Ici, seul le RENDU dépend de
reportlab, dont l'import est DIFFÉRÉ — l'agent peut donc être importé sans
reportlab, et n'exige la librairie qu'au moment de générer réellement le PDF.

Installation (sur Kali) : pip install reportlab
"""

import json
import os
from datetime import datetime, timezone
from typing import Any

from pentagon.tools.report_builder import (
    build_report, ReportModel, Finding, SEVERITY_LABELS,
)


# Couleurs par sévérité (hex), réutilisées dans le rendu.
SEVERITY_COLORS = {
    "critical": "#b00020",
    "high": "#e65100",
    "medium": "#f9a825",
    "low": "#2e7d32",
    "info": "#546e7a",
}


class ReportingAgent:
    """
    Agent de génération de rapport.

    N'émet AUCUN trafic vers la cible : il ne fait que consolider et mettre en
    forme les résultats déjà collectés. C'est une action purement locale.
    """

    name = "Reporting_Agent"

    def run(
        self,
        campaign: dict[str, Any] | str,
        output_path: str | None = None,
        operator: str = "",
    ) -> str:
        """
        Génère le rapport PDF d'une campagne.

        Args:
            campaign: soit le dict de campagne (PentagonState.to_dict()),
                soit le CHEMIN d'un fichier JSON de campagne à charger.
            output_path: chemin du PDF à produire. Si None, dérivé de la cible
                et de l'horodatage, dans le dossier 'reports/'.
            operator: nom de l'opérateur (traçabilité dans le rapport).

        Returns:
            Le chemin du PDF généré.
        """
        if isinstance(campaign, str):
            with open(campaign, "r", encoding="utf-8") as f:
                campaign = json.load(f)

        model = build_report(campaign, operator=operator)

        if output_path is None:
            output_path = self._default_output_path(model)

        print(f"[{self.name}] Assemblage du rapport "
              f"({len(model.findings)} finding(s), risque global : {model.overall_risk})")
        self._render_pdf(model, output_path)
        print(f"[{self.name}] Rapport PDF généré : {output_path}")
        return output_path

    @staticmethod
    def _default_output_path(model: ReportModel) -> str:
        os.makedirs("reports", exist_ok=True)
        safe = "".join(c if c.isalnum() or c in ".-" else "_" for c in model.target)
        safe = safe.strip("_") or "cible"
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        return os.path.join("reports", f"rapport_{safe}_{ts}.pdf")

    # ─────────────────────────────── Rendu PDF ──────────────────────────────

    def _render_pdf(self, model: ReportModel, output_path: str) -> None:
        """Rend le ReportModel en PDF. Import de reportlab DIFFÉRÉ ici."""
        try:
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import cm
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
                PageBreak,
            )
            from reportlab.lib.enums import TA_CENTER, TA_LEFT
        except ImportError as e:
            raise RuntimeError(
                "reportlab est requis pour générer le PDF. "
                "Installez-le : pip install reportlab"
            ) from e

        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(
            "PgTitle", parent=styles["Title"], fontSize=26, leading=30))
        styles.add(ParagraphStyle(
            "PgH2", parent=styles["Heading2"], textColor=colors.HexColor("#1a237e"),
            spaceBefore=14, spaceAfter=6))
        styles.add(ParagraphStyle(
            "PgH3", parent=styles["Heading3"], spaceBefore=8, spaceAfter=4))
        styles.add(ParagraphStyle(
            "PgBody", parent=styles["BodyText"], fontSize=9.5, leading=13))
        styles.add(ParagraphStyle(
            "PgSmall", parent=styles["BodyText"], fontSize=8, leading=10,
            textColor=colors.HexColor("#555555")))
        styles.add(ParagraphStyle(
            "PgCenter", parent=styles["BodyText"], alignment=TA_CENTER))

        def P(text, style="PgBody"):
            return Paragraph(_esc(text), styles[style])

        story: list = []

        # ---- Page de garde ----
        story.append(Spacer(1, 3 * cm))
        story.append(Paragraph("PENTAGON", styles["PgTitle"]))
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph(
            "Rapport de test d'intrusion automatisé", styles["PgCenter"]))
        story.append(Spacer(1, 1.5 * cm))
        meta_rows = [
            ["Cible", model.target or "—"],
            ["Campagne", model.campaign_id or "—"],
            ["Opérateur", model.operator or "—"],
            ["Début", _fmt_dt(model.started_at)],
            ["Fin", _fmt_dt(model.ended_at)],
            ["Risque global", model.overall_risk.upper()],
            ["Généré le", _fmt_dt(model.generated_at)],
        ]
        meta_tbl = Table(meta_rows, colWidths=[4 * cm, 11 * cm])
        meta_tbl.setStyle(TableStyle([
            ("FONTSIZE", (0, 0), (-1, -1), 10),
            ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#1a237e")),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LINEBELOW", (0, 0), (-1, -1), 0.3, colors.HexColor("#dddddd")),
        ]))
        story.append(meta_tbl)
        story.append(Spacer(1, 1 * cm))
        story.append(Paragraph(
            "Document confidentiel — usage réservé au périmètre autorisé (RoE). "
            "Les preuves ont été bornées : détecter en prouvant, jamais ravager.",
            styles["PgSmall"]))
        story.append(PageBreak())

        # ---- Synthèse exécutive ----
        story.append(Paragraph("1. Synthèse exécutive", styles["PgH2"]))
        story.append(P(
            f"La campagne a exécuté {len(model.agents_executed)} agent(s) "
            f"({', '.join(model.agents_executed) or '—'}). "
            f"{model.proven_count} vulnérabilité(s) prouvée(s) par exploitation "
            f"et {model.detected_count} détectée(s) par analyse. "
            f"Risque global évalué : {model.overall_risk.upper()}."))
        story.append(Spacer(1, 0.3 * cm))

        # Tableau de bord des sévérités
        story.append(Paragraph("Répartition par sévérité", styles["PgH3"]))
        sev_header = ["Sévérité"] + [s.capitalize() for s in SEVERITY_LABELS]
        sev_values = ["Nombre"] + [str(model.severity_counts.get(s, 0))
                                   for s in SEVERITY_LABELS]
        sev_tbl = Table([sev_header, sev_values], colWidths=[3 * cm] + [2.4 * cm] * 5)
        sev_style = [
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("ALIGN", (1, 0), (-1, -1), "CENTER"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f0f0f0")),
        ]
        for i, s in enumerate(SEVERITY_LABELS, start=1):
            sev_style.append(
                ("TEXTCOLOR", (i, 0), (i, 0), colors.HexColor(SEVERITY_COLORS[s])))
        sev_tbl.setStyle(TableStyle(sev_style))
        story.append(sev_tbl)
        story.append(Spacer(1, 0.3 * cm))

        # Couverture OWASP
        if model.owasp_coverage:
            story.append(Paragraph("Couverture OWASP Top 10", styles["PgH3"]))
            for cat in model.owasp_coverage:
                story.append(P(f"• {cat}"))
            story.append(Spacer(1, 0.2 * cm))

        # Résumés exécutifs par phase
        for label, summary in model.exec_summaries.items():
            story.append(Paragraph(f"Résumé — {label}", styles["PgH3"]))
            story.append(P(summary))

        story.append(PageBreak())

        # ---- Findings détaillés ----
        story.append(Paragraph("2. Vulnérabilités détaillées", styles["PgH2"]))
        if not model.findings:
            story.append(P("Aucune vulnérabilité retenue."))
        for i, f in enumerate(model.findings, start=1):
            self._append_finding(story, styles, i, f, colors, Table, TableStyle, cm)

        # Attaques tentées sans succès (preuve d'absence)
        if model.attempted_not_confirmed:
            story.append(Paragraph(
                "Attaques tentées sans confirmation (preuve d'absence)", styles["PgH3"]))
            for item in model.attempted_not_confirmed:
                story.append(P(f"• {item}"))

        story.append(PageBreak())

        # ---- Reconnaissance ----
        story.append(Paragraph("3. Reconnaissance", styles["PgH2"]))
        if model.recon_osint_summary:
            story.append(Paragraph("OSINT", styles["PgH3"]))
            story.append(P(model.recon_osint_summary))
        if model.recon_scanning_findings:
            story.append(Paragraph("Scanning — findings clés", styles["PgH3"]))
            for kf in model.recon_scanning_findings:
                if isinstance(kf, dict):
                    txt = kf.get("finding") or kf.get("description") or json.dumps(
                        kf, ensure_ascii=False)
                else:
                    txt = str(kf)
                story.append(P(f"• {txt}"))

        story.append(PageBreak())

        # ---- Annexe gouvernance / audit ----
        story.append(Paragraph("4. Gouvernance & audit (RoE)", styles["PgH2"]))
        story.append(P(
            "PENTAGON applique le principe deny-by-default : chaque agent n'a "
            "agi qu'après autorisation explicite du RoE Enforcer. Le journal "
            "ci-dessous documente le déroulé de la campagne."))
        story.append(Paragraph(
            f"Erreurs enregistrées : {len(model.errors)}", styles["PgH3"]))
        for err in model.errors:
            story.append(P(
                f"• [{err.get('agent', '?')}] {err.get('error', '')}", "PgSmall"))
        story.append(Paragraph("Journal d'exécution", styles["PgH3"]))
        for ev in model.execution_log:
            story.append(P(
                f"{_fmt_dt(ev.get('timestamp',''))} — [{ev.get('agent','?')}] "
                f"{ev.get('event','')} {ev.get('details','')}", "PgSmall"))

        doc = SimpleDocTemplate(
            output_path, pagesize=A4,
            leftMargin=2 * cm, rightMargin=2 * cm,
            topMargin=2 * cm, bottomMargin=2 * cm,
            title=f"Rapport PENTAGON — {model.target}",
            author="PENTAGON",
        )
        doc.build(story)

    def _append_finding(self, story, styles, index, f: Finding,
                         colors, Table, TableStyle, cm) -> None:
        """Ajoute un bloc de finding détaillé au récit."""
        from reportlab.platypus import Paragraph, Spacer

        tag = "PROUVÉE" if f.proven else "détectée"
        color = SEVERITY_COLORS.get(f.severity, "#546e7a")
        title = (f"{index}. {_esc(f.title)} "
                 f"<font color='{color}'>[{f.severity.upper()}]</font> "
                 f"<font size=7 color='#888888'>({tag})</font>")
        story.append(Paragraph(title, styles["PgH3"]))

        rows = []
        if f.owasp:
            rows.append(["OWASP", f.owasp])
        if f.cwe:
            rows.append(["CWE", f.cwe])
        if f.mitre:
            rows.append(["MITRE ATT&CK", f.mitre])
        if f.endpoint:
            rows.append(["Endpoint", f.endpoint])
        if f.confidence:
            rows.append(["Confiance", f"{f.confidence:.0%}"])
        if rows:
            tbl = Table([[k, Paragraph(_esc(v), styles["PgSmall"])] for k, v in rows],
                        colWidths=[3 * cm, 13 * cm])
            tbl.setStyle(TableStyle([
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ]))
            story.append(tbl)

        if f.description:
            story.append(Paragraph(
                f"<b>{'Impact' if f.proven else 'Description'} :</b> "
                f"{_esc(f.description)}", styles["PgBody"]))
        if f.evidence:
            story.append(Paragraph(
                f"<b>{'Preuve' if f.proven else 'Élément observé'} :</b> "
                f"{_esc(f.evidence)}", styles["PgBody"]))
        if f.remediation:
            story.append(Paragraph(
                f"<b>Remédiation :</b> {_esc(f.remediation)}", styles["PgBody"]))
        story.append(Spacer(1, 0.35 * cm))


# ─────────────────────────────── Utilitaires ───────────────────────────────

def _esc(text: Any) -> str:
    """Échappe le texte pour les Paragraph reportlab (mini-markup XML)."""
    s = str(text if text is not None else "")
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _fmt_dt(iso: str) -> str:
    """Formate un ISO-8601 en 'YYYY-MM-DD HH:MM UTC' (best effort)."""
    if not iso:
        return "—"
    try:
        dt = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, TypeError):
        return str(iso)
