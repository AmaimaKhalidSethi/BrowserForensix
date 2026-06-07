"""
BrowserForensix — pdf_routes.py
Generates a professional PDF forensic report from analysis.json.

Register in serve.py (identical pattern to ctf_routes / ai_routes):

    try:
        from pdf_routes import register_pdf_routes
        _PDF_AVAILABLE = True
    except ImportError:
        _PDF_AVAILABLE = False

    # inside startup():
    if _PDF_AVAILABLE:
        register_pdf_routes(app, load_analysis)

Requires: pip install reportlab
Degrades silently if reportlab is not installed.
"""

import io
from datetime import datetime, timezone
from flask import Blueprint, jsonify, request, Response

pdf_bp = Blueprint("pdf", __name__, url_prefix="/api/pdf")


def _err(msg, code=500):
    return jsonify({"error": msg}), code


def register_pdf_routes(app, load_analysis_fn):

    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import cm, mm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable, KeepTogether
        )
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    except ImportError:
        @app.route("/api/pdf/report")
        def pdf_unavailable():
            return jsonify({
                "error": "reportlab not installed",
                "install": "pip install reportlab"
            }), 503
        print("[PDF] reportlab not found — PDF export disabled. Run: pip install reportlab")
        return

    # ── Colour palette (matches the dark theme accent colours) ────────────────
    C_PURPLE  = colors.HexColor("#8B45F5")
    C_PURPLE2 = colors.HexColor("#5B21B6")
    C_RED     = colors.HexColor("#EF4444")
    C_AMBER   = colors.HexColor("#F59E0B")
    C_GREEN   = colors.HexColor("#34D399")
    C_DARK    = colors.HexColor("#1A1530")
    C_MID     = colors.HexColor("#2A2048")
    C_TEXT    = colors.HexColor("#EDE8FF")
    C_SUB     = colors.HexColor("#9D8FD4")
    C_WHITE   = colors.white
    C_OFFWHITE= colors.HexColor("#F5F3FF")

    def _styles():
        base = getSampleStyleSheet()

        def ps(name, parent="Normal", **kw):
            return ParagraphStyle(name, parent=base[parent], **kw)

        return {
            "title":    ps("BfxTitle",    fontSize=22, textColor=C_TEXT,
                           spaceAfter=4, fontName="Helvetica-Bold",
                           backColor=C_DARK, leading=28),
            "subtitle": ps("BfxSub",      fontSize=11, textColor=C_SUB,
                           spaceAfter=2, fontName="Helvetica"),
            "h1":       ps("BfxH1",       fontSize=13, textColor=C_PURPLE,
                           spaceBefore=14, spaceAfter=4, fontName="Helvetica-Bold",
                           borderPad=2),
            "h2":       ps("BfxH2",       fontSize=11, textColor=C_PURPLE2,
                           spaceBefore=8, spaceAfter=3, fontName="Helvetica-Bold"),
            "body":     ps("BfxBody",     fontSize=9,  textColor=C_DARK,
                           spaceAfter=3, fontName="Helvetica", leading=13),
            "mono":     ps("BfxMono",     fontSize=8,  textColor=C_DARK,
                           fontName="Courier", leading=11, spaceAfter=2),
            "label":    ps("BfxLabel",    fontSize=8,  textColor=C_SUB,
                           fontName="Helvetica", spaceAfter=1),
            "flag":     ps("BfxFlag",     fontSize=9,  textColor=C_RED,
                           fontName="Helvetica-Bold", spaceAfter=2),
            "warn":     ps("BfxWarn",     fontSize=9,  textColor=C_AMBER,
                           fontName="Helvetica-Bold", spaceAfter=2),
            "ok":       ps("BfxOk",       fontSize=9,  textColor=colors.HexColor("#059669"),
                           fontName="Helvetica-Bold", spaceAfter=2),
        }

    def _table_style_base():
        return TableStyle([
            ("BACKGROUND",   (0, 0), (-1, 0),  C_DARK),
            ("TEXTCOLOR",    (0, 0), (-1, 0),  C_PURPLE),
            ("FONTNAME",     (0, 0), (-1, 0),  "Helvetica-Bold"),
            ("FONTSIZE",     (0, 0), (-1, 0),  8),
            ("BOTTOMPADDING",(0, 0), (-1, 0),  5),
            ("TOPPADDING",   (0, 0), (-1, 0),  5),
            ("FONTNAME",     (0, 1), (-1, -1), "Helvetica"),
            ("FONTSIZE",     (0, 1), (-1, -1), 8),
            ("TOPPADDING",   (0, 1), (-1, -1), 3),
            ("BOTTOMPADDING",(0, 1), (-1, -1), 3),
            ("ROWBACKGROUNDS",(0, 1), (-1, -1), [C_OFFWHITE, C_WHITE]),
            ("GRID",         (0, 0), (-1, -1), 0.3, C_SUB),
            ("LEFTPADDING",  (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("VALIGN",       (0, 0), (-1, -1), "TOP"),
        ])

    # ── Main PDF route ─────────────────────────────────────────────────────────

    @pdf_bp.route("/report")
    def pdf_report():
        """
        Generate and stream a PDF forensic report.
        Query params: case, examiner, date, notes
        """
        case_num  = request.args.get("case",     "").strip()
        examiner  = request.args.get("examiner", "").strip()
        rpt_date  = request.args.get("date",     datetime.now(timezone.utc).strftime("%Y-%m-%d"))
        notes     = request.args.get("notes",    "").strip()

        try:
            data = load_analysis_fn()
        except Exception as e:
            return _err(f"Could not load analysis: {e}")

        summary   = data.get("summary",   {})
        meta      = data.get("meta",      {})
        anomalies = data.get("anomalies", [])
        history   = data.get("history",   [])
        cookies   = data.get("cookies",   [])
        downloads = data.get("downloads", [])
        hashes    = data.get("hashes",    {})

        flagged_h  = [h for h in history   if h.get("risk_score", 0) >= 61]
        flagged_c  = [c for c in cookies   if c.get("risk_score", 0) >= 61]
        flagged_d  = [d for d in downloads if d.get("risk_score", 0) >= 61]
        moderate_h = [h for h in history   if 31 <= h.get("risk_score", 0) < 61]

        S  = _styles()
        buf = io.BytesIO()

        doc = SimpleDocTemplate(
            buf,
            pagesize=A4,
            leftMargin=2*cm, rightMargin=2*cm,
            topMargin=2*cm,  bottomMargin=2*cm,
            title=f"BrowserForensix Report — {case_num or 'No Case Number'}",
            author=examiner or "BrowserForensix",
        )

        W = A4[0] - 4*cm   # usable width

        def HR(): return HRFlowable(width="100%", thickness=0.5,
                                     color=C_MID, spaceAfter=6, spaceBefore=6)

        story = []

        # ── Cover block ───────────────────────────────────────────────────────
        story.append(Spacer(1, 0.4*cm))
        story.append(Paragraph("BrowserForensix", S["title"]))
        story.append(Paragraph("Browser Forensic Analysis Report", S["subtitle"]))
        story.append(Spacer(1, 0.3*cm))

        meta_rows = [
            ["Case Number",      case_num  or "—"],
            ["Examiner",         examiner  or "—"],
            ["Report Date",      rpt_date],
            ["Browser",          (meta.get("browser") or "Chrome").title()],
            ["Extraction Time",  (meta.get("extraction_time") or "—")[:19].replace("T", " ")],
            ["Profiles",         str(len(meta.get("profiles_extracted") or []))],
            ["Total Artifacts",  f"{summary.get('total_artifacts', 0):,}"],
        ]
        meta_t = Table(
            [[Paragraph(r[0], S["label"]), Paragraph(r[1], S["body"])] for r in meta_rows],
            colWidths=[3.5*cm, W - 3.5*cm],
        )
        meta_t.setStyle(TableStyle([
            ("FONTNAME",    (0, 0), (-1, -1), "Helvetica"),
            ("FONTSIZE",    (0, 0), (-1, -1), 9),
            ("TOPPADDING",  (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING",(0,0), (-1, -1), 3),
            ("TEXTCOLOR",   (0, 0), (0, -1),  C_SUB),
            ("FONTNAME",    (1, 0), (1, -1),  "Helvetica-Bold"),
            ("LINEBELOW",   (0, 0), (-1, -1), 0.3, C_MID),
        ]))
        story.append(meta_t)

        if notes:
            story.append(Spacer(1, 0.3*cm))
            story.append(Paragraph("Examiner Notes", S["h2"]))
            story.append(Paragraph(notes, S["body"]))

        story.append(HR())

        # ── Executive Summary ─────────────────────────────────────────────────
        story.append(Paragraph("Executive Summary", S["h1"]))

        sev_color = C_RED if summary.get("flagged_count", 0) > 0 else C_AMBER
        summary_rows = [
            ["Metric", "Value", "Band"],
            ["Total Artifacts",  f"{summary.get('total_artifacts',0):,}",  "—"],
            ["Flagged Items",    f"{summary.get('flagged_count',0):,}",    "Risk ≥ 61"],
            ["Moderate Items",   f"{summary.get('moderate_count',0):,}",   "Risk 31–60"],
            ["Average Risk Score",f"{summary.get('average_risk_score',0)}", "0–100"],
            ["Anomalies Detected",f"{summary.get('anomaly_count',0)}",     "Patterns"],
        ]
        sum_t = Table(
            summary_rows,
            colWidths=[5*cm, 3*cm, W - 8*cm],
        )
        sum_t.setStyle(_table_style_base())
        story.append(sum_t)
        story.append(Spacer(1, 0.3*cm))

        story.append(HR())

        # ── Anomalies ─────────────────────────────────────────────────────────
        story.append(Paragraph("Detected Anomalies", S["h1"]))

        if not anomalies:
            story.append(Paragraph("No anomalies detected.", S["body"]))
        else:
            sev_order = {"critical": 0, "moderate": 1, "low": 2}
            for a in sorted(anomalies, key=lambda x: sev_order.get(x.get("severity","low"), 9)):
                sev   = a.get("severity", "low")
                color = C_RED if sev == "critical" else C_AMBER if sev == "moderate" else C_GREEN
                title = a.get("title") or a.get("type", "").replace("_", " ").title()
                story.append(KeepTogether([
                    Paragraph(f"[{sev.upper()}] {title}", S["flag"] if sev == "critical" else S["warn"] if sev == "moderate" else S["ok"]),
                    Paragraph(a.get("description", ""), S["body"]),
                    Spacer(1, 0.15*cm),
                ]))

        story.append(HR())

        # ── Flagged History ───────────────────────────────────────────────────
        story.append(Paragraph(f"Flagged History ({len(flagged_h)} items)", S["h1"]))

        if flagged_h:
            rows = [["Risk", "URL", "Title", "Last Visit", "Visits"]]
            for h in sorted(flagged_h, key=lambda x: -x.get("risk_score", 0))[:50]:
                url   = (h.get("url") or "")[:60]
                title = (h.get("title") or "")[:40]
                ts    = (h.get("last_visit") or "")[:16].replace("T", " ")
                rows.append([
                    Paragraph(str(h.get("risk_score", 0)), S["flag"]),
                    Paragraph(url,   S["mono"]),
                    Paragraph(title, S["body"]),
                    Paragraph(ts,    S["mono"]),
                    Paragraph(str(h.get("visit_count", 1)), S["body"]),
                ])
            t = Table(rows, colWidths=[1*cm, 6.5*cm, 4*cm, 3.2*cm, 1.3*cm])
            t.setStyle(_table_style_base())
            story.append(t)
            if len(flagged_h) > 50:
                story.append(Paragraph(f"… {len(flagged_h)-50} more flagged items not shown.", S["label"]))
        else:
            story.append(Paragraph("No flagged history items.", S["body"]))

        story.append(Spacer(1, 0.3*cm))

        # ── Moderate History ──────────────────────────────────────────────────
        if moderate_h:
            story.append(Paragraph(f"Moderate History ({len(moderate_h)} items)", S["h2"]))
            rows = [["Risk", "URL", "Last Visit"]]
            for h in sorted(moderate_h, key=lambda x: -x.get("risk_score", 0))[:30]:
                rows.append([
                    Paragraph(str(h.get("risk_score", 0)), S["warn"]),
                    Paragraph((h.get("url") or "")[:75], S["mono"]),
                    Paragraph((h.get("last_visit") or "")[:16].replace("T", " "), S["mono"]),
                ])
            t = Table(rows, colWidths=[1*cm, W - 4.5*cm, 3.5*cm])
            t.setStyle(_table_style_base())
            story.append(t)
            story.append(Spacer(1, 0.2*cm))

        story.append(HR())

        # ── Flagged Downloads ─────────────────────────────────────────────────
        story.append(Paragraph(f"Flagged Downloads ({len(flagged_d)} items)", S["h1"]))

        if flagged_d:
            rows = [["Risk", "Filename", "Source", "On Disk?", "Date"]]
            for d in sorted(flagged_d, key=lambda x: -x.get("risk_score", 0)):
                rows.append([
                    Paragraph(str(d.get("risk_score", 0)), S["flag"]),
                    Paragraph((d.get("filename") or "")[:35],    S["mono"]),
                    Paragraph((d.get("source_url") or "")[:40],  S["mono"]),
                    Paragraph("Yes" if d.get("file_exists") else "NO", S["body"]),
                    Paragraph((d.get("start_time") or "")[:10],  S["mono"]),
                ])
            t = Table(rows, colWidths=[1*cm, 3.8*cm, W - 9*cm, 1.5*cm, 2.5*cm])
            t.setStyle(_table_style_base())
            story.append(t)
        else:
            story.append(Paragraph("No flagged downloads.", S["body"]))

        story.append(HR())

        # ── Flagged Cookies ───────────────────────────────────────────────────
        story.append(Paragraph(f"Flagged Cookies ({len(flagged_c)} items)", S["h1"]))

        if flagged_c:
            rows = [["Risk", "Host", "Name", "Type", "Expires"]]
            for c in sorted(flagged_c, key=lambda x: -x.get("risk_score", 0))[:40]:
                rows.append([
                    Paragraph(str(c.get("risk_score", 0)), S["flag"]),
                    Paragraph((c.get("host") or "")[:30],  S["mono"]),
                    Paragraph((c.get("name") or "")[:25],  S["mono"]),
                    Paragraph(c.get("type") or "Unknown",  S["body"]),
                    Paragraph((c.get("expires") or "Session")[:10], S["mono"]),
                ])
            t = Table(rows, colWidths=[1*cm, 4*cm, 3.5*cm, 2.5*cm, W - 11*cm])
            t.setStyle(_table_style_base())
            story.append(t)
        else:
            story.append(Paragraph("No flagged cookies.", S["body"]))

        story.append(HR())

        # ── Evidence Integrity ────────────────────────────────────────────────
        story.append(Paragraph("Evidence Integrity — SHA-256 Hashes", S["h1"]))

        if hashes:
            rows = [["File", "SHA-256 Hash"]]
            for fname, fhash in hashes.items():
                rows.append([
                    Paragraph(str(fname), S["mono"]),
                    Paragraph(str(fhash), S["mono"]),
                ])
            t = Table(rows, colWidths=[5*cm, W - 5*cm])
            t.setStyle(_table_style_base())
            story.append(t)
        else:
            story.append(Paragraph("No hash data available.", S["body"]))

        story.append(Spacer(1, 0.5*cm))
        story.append(Paragraph(
            f"Generated by BrowserForensix · {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            S["label"]
        ))

        # ── Build PDF ─────────────────────────────────────────────────────────
        try:
            doc.build(story)
        except Exception as e:
            return _err(f"PDF generation failed: {e}")

        buf.seek(0)
        filename = f"browserforensix_{case_num or 'report'}_{rpt_date}.pdf"
        return Response(
            buf.read(),
            mimetype="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Type": "application/pdf",
            }
        )

    app.register_blueprint(pdf_bp)
    print("[PDF] Routes registered — /api/pdf/report")