"""Rapport executif PDF de la posture de securite.

Genere un document synthetique (une page) destine a un comite ou a un
responsable : indicateurs clefs, conformite SLA, distribution du risque et
principales vulnerabilites a traiter. Construit avec ReportLab (pur Python,
aucune dependance systeme), en memoire.
"""

import io
from datetime import datetime, timezone

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from sqlalchemy.orm import Session

from app.risk import CRITICALITY_LABEL
from app.web_posture import posture_stats
from app.web_stats import dashboard_stats, extra_totals

# Palette alignee sur l'UI.
C_CRIT = colors.HexColor("#f43f5e")
C_HIGH = colors.HexColor("#fb923c")
C_MED = colors.HexColor("#fbbf24")
C_LOW = colors.HexColor("#34d399")
C_INK = colors.HexColor("#14171f")
C_MUTED = colors.HexColor("#5b6472")
C_LINE = colors.HexColor("#d7dbe2")
C_HEAD = colors.HexColor("#1a1e28")

SEV_FR = {"critical": "Critique", "high": "Élevée", "medium": "Moyenne",
          "low": "Faible", "info": "Info"}
BAND_COLOR = {"critical": C_CRIT, "high": C_HIGH, "medium": C_MED, "low": C_LOW}


def build_report_pdf(db: Session) -> bytes:
    """Construit le rapport et renvoie les octets du PDF."""
    stats = dashboard_stats(db)
    extras = extra_totals(db)
    posture = posture_stats(db)

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=A4, leftMargin=1.6 * cm, rightMargin=1.6 * cm,
        topMargin=1.5 * cm, bottomMargin=1.4 * cm,
        title="VulnTrack — Rapport de posture",
    )
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("h1", parent=styles["Title"], fontSize=20, textColor=C_INK,
                        spaceAfter=2, alignment=0)
    sub = ParagraphStyle("sub", parent=styles["Normal"], fontSize=9.5,
                         textColor=C_MUTED, spaceAfter=14)
    h2 = ParagraphStyle("h2", parent=styles["Heading2"], fontSize=12,
                        textColor=C_INK, spaceBefore=10, spaceAfter=6)
    cell = ParagraphStyle("cell", parent=styles["Normal"], fontSize=8.5, textColor=C_INK)

    now = datetime.now(timezone.utc)
    story = []
    story.append(Paragraph("Rapport de posture de sécurité", h1))
    story.append(Paragraph(
        f"VulnTrack — Gestion des vulnérabilités basée sur le risque · "
        f"généré le {now.strftime('%Y-%m-%d %H:%M UTC')}", sub))

    # --- Indicateurs clefs (grille de tuiles) ------------------------------
    t = posture["totals"]
    kpis = [
        ("Assets suivis", str(stats["total_assets"]), C_INK),
        ("Findings ouverts", str(stats["total_open"]), C_INK),
        ("Critiques ouverts", str(stats["critical_open"]), C_CRIT),
        ("KEV (activement exploitées)", str(extras["kev_open"]), C_CRIT),
        ("SLA dépassé", str(t["overdue"]), C_HIGH),
        ("MTTR (jours)", "—" if t["mttr"] is None else str(t["mttr"]), C_INK),
        ("Conformité SLA", "—" if t["sla_compliance"] is None else f"{t['sla_compliance']} %", C_LOW),
        ("Corrigés", str(extras["fixed"]), C_LOW),
    ]
    tiles = []
    row = []
    for label, value, col in kpis:
        hexc = "#" + col.hexval()[2:]
        para = [Paragraph(f'<font size=15 color="{hexc}"><b>{value}</b></font>', cell),
                Spacer(1, 4),
                Paragraph(f'<font color="#5b6472">{label}</font>', cell)]
        row.append(para)
        if len(row) == 4:
            tiles.append(row)
            row = []
    if row:
        while len(row) < 4:
            row.append("")
        tiles.append(row)
    kpi_table = Table(tiles, colWidths=[4.35 * cm] * 4)
    kpi_table.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.5, C_LINE),
        ("INNERGRID", (0, 0), (-1, -1), 0.5, C_LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(kpi_table)

    # --- Distribution du risque -------------------------------------------
    story.append(Paragraph("Distribution du risque (findings ouverts)", h2))
    bands = posture["risk"]["bands"]
    band_rows = [["Bande", "Nombre"]]
    band_names = {"critical": "Critique", "high": "Élevé", "medium": "Moyen", "low": "Faible"}
    for b in ["critical", "high", "medium", "low"]:
        band_rows.append([band_names[b], str(bands.get(b, 0))])
    band_table = Table(band_rows, colWidths=[4 * cm, 3 * cm])
    band_style = [
        ("BACKGROUND", (0, 0), (-1, 0), C_HEAD),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.4, C_LINE),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    for i, b in enumerate(["critical", "high", "medium", "low"], start=1):
        band_style.append(("TEXTCOLOR", (0, i), (0, i), BAND_COLOR[b]))
        band_style.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))
    band_table.setStyle(TableStyle(band_style))
    story.append(band_table)

    # --- Top risques -------------------------------------------------------
    story.append(Paragraph("Principales vulnérabilités à traiter", h2))
    head = ["Risque", "Sév.", "KEV", "Vulnérabilité", "Asset", "Criticité", "CVE", "EPSS"]
    data = [head]
    for f in posture["risk"]["top"][:12]:
        data.append([
            str(f["risk"]),
            SEV_FR.get(f["severity"], f["severity"]),
            "Oui" if f["kev"] else "—",
            Paragraph(f["title"], cell),
            f["asset_name"],
            CRITICALITY_LABEL.get(f["criticality"], f["criticality"]),
            f["cve"] or "—",
            "—" if f["epss_score"] is None else f"{f['epss_score']:.2f}",
        ])
    top_table = Table(data, colWidths=[1.4 * cm, 1.7 * cm, 1.1 * cm, 4.9 * cm,
                                       2.6 * cm, 1.8 * cm, 2.3 * cm, 1.2 * cm], repeatRows=1)
    ts = [
        ("BACKGROUND", (0, 0), (-1, 0), C_HEAD),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("GRID", (0, 0), (-1, -1), 0.3, C_LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("FONTNAME", (0, 1), (0, -1), "Helvetica-Bold"),
    ]
    for i, f in enumerate(posture["risk"]["top"][:12], start=1):
        ts.append(("TEXTCOLOR", (0, i), (0, i), BAND_COLOR.get(f["risk_band"], C_INK)))
        if f["kev"]:
            ts.append(("TEXTCOLOR", (2, i), (2, i), C_CRIT))
            ts.append(("FONTNAME", (2, i), (2, i), "Helvetica-Bold"))
    top_table.setStyle(TableStyle(ts))
    story.append(top_table)

    story.append(Spacer(1, 0.5 * cm))
    story.append(Paragraph(
        "<font size=7.5 color='#8b93a5'>Score de risque = sévérité × EPSS (probabilité "
        "d'exploitation) × KEV (exploitation active confirmée, CISA) × criticité métier de "
        "l'asset. SLA de remédiation : critique 7 j · élevé 30 j · moyen 90 j · faible 180 j.</font>",
        cell))

    doc.build(story)
    return buf.getvalue()
