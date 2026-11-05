"""
IoTGuard Comprehensive System Architecture & Engineering Documentation Generator
Generates a downloadable, highly styled PDF document covering all aspects of IoTGuard.
"""

import sys
from pathlib import Path
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
)
from reportlab.pdfgen import canvas

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_PDF = BASE_DIR / "IoTGuard_Architecture_and_Engineering_Documentation.pdf"


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas to dynamically compute and draw total page numbers and headers/footers."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_decorations(self, page_count):
        if self._pageNumber == 1:
            # Skip decorations on the cover page
            return

        self.saveState()
        self.setFont("Helvetica-Bold", 8)
        self.setFillColor(colors.HexColor("#475569"))
        self.drawString(54, 752, "IoTGuard: Stage-Aware Edge Intrusion Detection & Graded Containment System")

        self.setFont("Helvetica", 8)
        self.drawRightString(558, 752, "Architecture Specification")

        # Header rule
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.75)
        self.line(54, 744, 558, 744)

        # Footer rule
        self.line(54, 46, 558, 46)

        # Footer text
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))
        self.drawString(54, 34, "IoTGuard Technical Reference Manual — Production Grade v2.0")
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(558, 34, page_str)
        self.restoreState()


def build_pdf():
    doc = SimpleDocTemplate(
        str(OUTPUT_PDF),
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=54,
        bottomMargin=54
    )

    styles = getSampleStyleSheet()

    # Custom styles
    c_primary = colors.HexColor("#0F172A")    # Deep slate
    c_indigo = colors.HexColor("#4F46E5")     # Primary brand
    c_slate_dark = colors.HexColor("#1E293B")
    c_body = colors.HexColor("#334155")
    c_emerald = colors.HexColor("#059669")
    c_amber = colors.HexColor("#D97706")

    title_style = ParagraphStyle(
        'CoverTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=26,
        leading=32,
        textColor=c_primary,
        alignment=0
    )

    subtitle_style = ParagraphStyle(
        'CoverSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=13,
        leading=18,
        textColor=c_indigo,
        alignment=0
    )

    meta_style = ParagraphStyle(
        'CoverMeta',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=14,
        textColor=colors.HexColor("#64748B")
    )

    h1_style = ParagraphStyle(
        'Heading1_Custom',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=16,
        leading=20,
        textColor=c_primary,
        spaceBefore=14,
        spaceAfter=8,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'Heading2_Custom',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=12,
        leading=16,
        textColor=c_indigo,
        spaceBefore=10,
        spaceAfter=5,
        keepWithNext=True
    )

    h3_style = ParagraphStyle(
        'Heading3_Custom',
        parent=styles['Heading3'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=14,
        textColor=c_slate_dark,
        spaceBefore=6,
        spaceAfter=3,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'Body_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13.5,
        textColor=c_body,
        spaceBefore=3,
        spaceAfter=5
    )

    bullet_style = ParagraphStyle(
        'Bullet_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=9,
        leading=13,
        textColor=c_body,
        leftIndent=15,
        firstLineIndent=-10,
        spaceBefore=2,
        spaceAfter=2
    )

    callout_style = ParagraphStyle(
        'Callout_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Oblique',
        fontSize=8.5,
        leading=12.5,
        textColor=colors.HexColor("#1E293B")
    )

    code_style = ParagraphStyle(
        'Code_Custom',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7.5,
        leading=10,
        textColor=colors.HexColor("#0F172A")
    )

    table_header_style = ParagraphStyle(
        'TH_Custom',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11,
        textColor=colors.white
    )

    table_cell_style = ParagraphStyle(
        'TC_Custom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8,
        leading=11,
        textColor=c_body
    )

    table_cell_bold = ParagraphStyle(
        'TC_Bold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=11,
        textColor=c_slate_dark
    )

    story = []

    # =========================================================================
    # COVER / TITLE BLOCK
    # =========================================================================
    story.append(Spacer(1, 20))
    story.append(Paragraph("IoTGuard", title_style))
    story.append(Paragraph("Autonomous, Agent-Free Edge Intrusion Detection & Graded Containment System", subtitle_style))
    story.append(Spacer(1, 10))
    story.append(HRFlowable(width="100%", thickness=3, color=c_indigo, spaceBefore=4, spaceAfter=14))

    meta_text = """
    <b>System Classification:</b> Edge Cyber-Physical Security (Tier 1 Gateway)<br/>
    <b>Target Environment:</b> Home Routers, Edge Gateways, Raspberry Pi 4/5, OpenWrt, Linux Gateways<br/>
    <b>Architecture:</b> 3-Tier Multi-Stage Model (Passive Zeek Ingestion, O(1) Sliding Window, Graded nftables)<br/>
    <b>Inference Engine:</b> XGBoost Multi-Class Stage Classifier (< 1ms line-rate latency)<br/>
    <b>Status:</b> Production-Grade Architecture & Verification Report
    """
    story.append(Paragraph(meta_text, meta_style))
    story.append(Spacer(1, 15))

    # Executive Summary Card
    summary_box_data = [[
        Paragraph(
            "<b>Executive Summary:</b> IoTGuard solves the core dilemma of modern IoT security: traditional "
            "agent-based host security cannot run on resource-constrained microcontrollers (Tier 0), while "
            "cloud-based IDSs incur prohibitive latency and violate privacy. IoTGuard runs purely out-of-band on "
            "a Tier 1 Edge Gateway. It extracts 28 features over a rolling 60-second amortized O(1) sliding window, "
            "classifies connections across 5 kill-chain stages in 0.63ms, and enforces an autonomous graded response "
            "using Linux nftables (blocking malicious C2 destinations at Level 2 while preserving legitimate "
            "smart home operations, escalating to full Level 3 device quarantine only upon active lateral propagation).",
            callout_style
        )
    ]]
    summary_box = Table(summary_box_data, colWidths=[504])
    summary_box.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F1F5F9")),
        ('LINELEFT', (0, 0), (0, -1), 3.5, c_indigo),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ('TOPPADDING', (0, 0), (-1, -1), 10),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
        ('LEFTPADDING', (0, 0), (-1, -1), 14),
        ('RIGHTPADDING', (0, 0), (-1, -1), 14),
    ]))
    story.append(summary_box)
    story.append(Spacer(1, 15))

    # =========================================================================
    # SECTION 1: PROJECT OBJECTIVE & THE PROBLEM SPACE
    # =========================================================================
    story.append(Paragraph("1. Project Objectives & Problem Space", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceBefore=2, spaceAfter=8))

    story.append(Paragraph(
        "Commercial and smart-home IoT devices (smart plugs, IP cameras, connected bulbs, thermostats) "
        "have proliferated without adequate native security controls. These devices suffer from hard-coded credentials, "
        "unpatched firmware vulnerabilities, and lack the hardware capability to support traditional Host-based "
        "Intrusion Detection Systems (HIDS) or Endpoint Detection and Response (EDR) agents. Once compromised by "
        "malware families such as Mirai, Hajime, or IRCBot, they are rapidly mobilized into botnets for distributed "
        "denial-of-service (DDoS) attacks, cryptomining, and lateral corporate network reconnaissance.",
        body_style
    ))

    story.append(Paragraph("<b>Primary Engineering Objectives of IoTGuard:</b>", h3_style))
    story.append(Paragraph("• <b>Zero-Touch / Agent-Free Deployment:</b> Operate entirely on Tier 1 edge gateways (routers, gateway appliances) inspecting passive network metadata without altering or installing software on Tier 0 IoT devices.", bullet_style))
    story.append(Paragraph("• <b>Full Kill-Chain Awareness:</b> Detect attacks at their earliest incubation stage (Command & Control contact, payload downloads) rather than waiting for devastating volume attacks (DDoS, aggressive SYN floods).", bullet_style))
    story.append(Paragraph("• <b>Graded Autonomous Containment:</b> Eliminate binary 'all-or-nothing' device disconnection. Implement surgical, graduated policy actions that isolate malicious remote IPs while leaving essential smart-home connectivity operational.", bullet_style))
    story.append(Paragraph("• <b>Sub-Millisecond Line-Rate Throughput:</b> Guarantee average per-connection inference latency under 1ms (<0.63ms measured) and micro-batching throughput exceeding 90,000 flows/sec to prevent gateway CPU saturation.", bullet_style))
    story.append(Paragraph("• <b>Privacy-First & Fail-Open Resilience:</b> Inspect connection metadata only (discarding raw packet payloads) and structure gateway routing so an IDS process crash never interrupts regular internet traffic.", bullet_style))

    story.append(Spacer(1, 10))

    # =========================================================================
    # SECTION 2: UNIQUE SELLING PROPOSITION (USP)
    # =========================================================================
    story.append(Paragraph("2. Unique Selling Proposition (USP) vs. Alternatives", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceBefore=2, spaceAfter=8))

    story.append(Paragraph(
        "Existing intrusion detection paradigms fail in edge IoT environments. Signature-based network IDSs (Snort, Suricata) "
        "struggle with encrypted or novel malware variants and require heavy rule evaluation. Cloud IDSs introduce "
        "bandwidth overhead, high latency, and privacy risks. Endpoint agents are simply impossible on IoT microcontrollers.",
        body_style
    ))

    usp_table_data = [
        [
            Paragraph("Capability / Dimension", table_header_style),
            Paragraph("Snort / Suricata", table_header_style),
            Paragraph("Cloud AI IDS", table_header_style),
            Paragraph("Endpoint EDR", table_header_style),
            Paragraph("IoTGuard (Ours)", table_header_style)
        ],
        [
            Paragraph("<b>Agent Requirement</b>", table_cell_bold),
            Paragraph("None (Network)", table_cell_style),
            Paragraph("None (NetFlow)", table_cell_style),
            Paragraph("Heavy Agent", table_cell_style),
            Paragraph("<b>Zero Agent (Passive Edge)</b>", table_cell_bold)
        ],
        [
            Paragraph("<b>Containment Model</b>", table_cell_bold),
            Paragraph("Binary Drop / Alert", table_cell_style),
            Paragraph("Alert Only (Passive)", table_cell_style),
            Paragraph("Host Quarantine", table_cell_style),
            Paragraph("<b>Graded (L2 Block vs L3 Quarantine)</b>", table_cell_bold)
        ],
        [
            Paragraph("<b>Kill-Chain Stage Detection</b>", table_cell_bold),
            Paragraph("Pattern Match", table_cell_style),
            Paragraph("Binary Malicious/Benign", table_cell_style),
            Paragraph("Process Anomaly", table_cell_style),
            Paragraph("<b>5 Discrete Stages (Benign -> Attack)</b>", table_cell_bold)
        ],
        [
            Paragraph("<b>Inference Latency</b>", table_cell_bold),
            Paragraph("Variable (DFA rules)", table_cell_style),
            Paragraph("200ms – 2000ms", table_cell_style),
            Paragraph("< 10ms", table_cell_style),
            Paragraph("<b>0.63ms (Line-Rate Edge)</b>", table_cell_bold)
        ],
        [
            Paragraph("<b>State Tracking Memory</b>", table_cell_bold),
            Paragraph("High (Flow tables)", table_cell_style),
            Paragraph("Offloaded to Cloud", table_cell_style),
            Paragraph("RAM Intensive", table_cell_style),
            Paragraph("<b>O(1) Amortized Deque Queues</b>", table_cell_bold)
        ],
        [
            Paragraph("<b>Payload Privacy</b>", table_cell_bold),
            Paragraph("Deep Packet Inspect", table_cell_style),
            Paragraph("Raw NetFlow / Logs", table_cell_style),
            Paragraph("Full System Logs", table_cell_style),
            Paragraph("<b>100% Metadata Isolation</b>", table_cell_bold)
        ]
    ]

    usp_table = Table(usp_table_data, colWidths=[94, 95, 95, 95, 125])
    usp_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), c_primary),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
        ('BACKGROUND', (4, 1), (4, -1), colors.HexColor("#EEF2FF")),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(usp_table)
    story.append(Spacer(1, 14))

    # =========================================================================
    # SECTION 3: TECH STACK SELECTION & RATIONALE
    # =========================================================================
    story.append(Paragraph("3. Technical Stack Selection & Justification", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceBefore=2, spaceAfter=8))

    tech_stack_data = [
        [
            Paragraph("Component", table_header_style),
            Paragraph("Technology Chosen", table_header_style),
            Paragraph("Alternatives Considered", table_header_style),
            Paragraph("Technical Justification & Advantage", table_header_style)
        ],
        [
            Paragraph("<b>Traffic Ingestion & Protocol Parsing</b>", table_cell_bold),
            Paragraph("<b>Zeek (formerly Bro)</b>", table_cell_style),
            Paragraph("tcpdump, Suricata, Wireshark/tshark", table_cell_style),
            Paragraph("Zeek specializes in behavioral protocol state machines, reassembling TCP states and emitting structured, compact conn.log JSON records while immediately discarding payload bytes to ensure privacy and low memory.", table_cell_style)
        ],
        [
            Paragraph("<b>Machine Learning Classifier</b>", table_cell_bold),
            Paragraph("<b>XGBoost (Histogram tree method)</b>", table_cell_style),
            Paragraph("Random Forest, PyTorch LSTM, 1D-CNN, SVM", table_cell_style),
            Paragraph("Tabular flow metadata is dominated by non-linear threshold patterns. XGBoost delivers superior F1 score (0.978) with an ultra-lightweight memory footprint (<35MB) and sub-millisecond CPU execution, avoiding heavy GPU runtimes.", table_cell_style)
        ],
        [
            Paragraph("<b>Kernel Firewall Enforcement</b>", table_cell_bold),
            Paragraph("<b>Linux nftables</b>", table_cell_style),
            Paragraph("iptables, ebtables, pfSense, OpenFlow", table_cell_style),
            Paragraph("nftables supports atomic, dynamic kernel set lookups (O(1) sets like inet iotguard blocked_dst). It avoids the severe linear rule search penalty of legacy iptables and allows single-command rule flushes without restarting firewall daemons.", table_cell_style)
        ],
        [
            Paragraph("<b>Sliding Window Engine</b>", table_cell_bold),
            Paragraph("<b>collections.deque + Counter</b>", table_cell_style),
            Paragraph("Pandas rolling(), SQLite in-memory, Redis", table_cell_style),
            Paragraph("Running a sliding window on a home router cannot incur O(N) memory rescans. Python deques allow O(1) popped expirations while hash counters track unique destination IPs and failure rates in amortized O(1) time.", table_cell_style)
        ],
        [
            Paragraph("<b>Operator Dashboard & Visuals</b>", table_cell_bold),
            Paragraph("<b>Streamlit + Plotly</b>", table_cell_style),
            Paragraph("React + Node.js, Grafana + Prometheus", table_cell_style),
            Paragraph("Provides a rapid, single-language (Python) reactive UI with native data science visual integration, avoiding dual backend/frontend synchronization overhead while maintaining a customized Humanised responsive theme.", table_cell_style)
        ],
        [
            Paragraph("<b>Containerization & Packaging</b>", table_cell_bold),
            Paragraph("<b>Docker Compose (Multi-stage)</b>", table_cell_style),
            Paragraph("Bare-metal systemd only, Kubernetes", table_cell_style),
            Paragraph("Guarantees deterministic execution across local development laptops, cloud VMs, and edge gateways with isolated volumes and explicit Linux capability bindings (CAP_NET_ADMIN).", table_cell_style)
        ]
    ]

    tech_table = Table(tech_stack_data, colWidths=[90, 95, 95, 224])
    tech_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), c_primary),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    story.append(tech_table)

    story.append(PageBreak())

    # =========================================================================
    # SECTION 4: ARCHITECTURAL DECISIONS & TRADE-OFFS
    # =========================================================================
    story.append(Paragraph("4. Architectural Decisions & Trade-off Analysis", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceBefore=2, spaceAfter=8))

    story.append(Paragraph(
        "During system development, several critical design forks emerged. Below is the documentation of "
        "every architectural decision, the alternative paths evaluated, and the rationale for the final choice.",
        body_style
    ))

    story.append(Paragraph("Decision 1: XGBoost vs. Deep Neural Networks for Edge Inference", h2_style))
    story.append(Paragraph(
        "<b>Context:</b> Many academic papers propose LSTMs or Transformers for network anomaly detection.<br/>"
        "<b>Decision:</b> Selected XGBoost (300 trees, maximum depth 6, learning rate 0.1, hist tree method).<br/>"
        "<b>Rationale:</b> Edge gateways (e.g. Raspberry Pi or consumer router) have strict 512MB-1GB RAM budgets and lack NPUs/GPUs. "
        "Deep learning frameworks (PyTorch/TensorFlow) incur huge binary sizes (>500MB), multi-second warmups, and high CPU inference "
        "latency (20-80ms). XGBoost achieves <b>0.63ms inference per connection</b> with an in-memory footprint under 35MB, while "
        "yielding superior precision on structured tabular flow features.",
        body_style
    ))

    story.append(Paragraph("Decision 2: Graded Escalation (L2 Block vs L3 Quarantine) vs. Binary Dropping", h2_style))
    story.append(Paragraph(
        "<b>Context:</b> Conventional IDSs trigger an immediate network severance (dropping the device off the network).<br/>"
        "<b>Decision:</b> Implemented a two-tiered graded response engine.<br/>"
        "<b>Rationale:</b> In a smart home, cutting an IoT device completely upon first anomalous connection destroys utility. If a smart bulb "
        "contacts a C2 controller or downloads an unauthorized payload, dropping all traffic immediately disables local lighting control. "
        "IoTGuard's <b>Level 2 Block</b> surgically inserts an nftables drop rule specifically for that foreign destination IP, "
        "allowing the bulb to continue local MQTT and normal cloud operations. Full <b>Level 3 Quarantine</b> is reserved for when the device "
        "exhibits active lateral scanning or volumetric DDoS attacks (accumulating k >= 5 strikes in 60s).",
        body_style
    ))

    story.append(Paragraph("Decision 3: Amortized O(1) Sliding Window with Deque Queues vs. Naive Rolling Scans", h2_style))
    story.append(Paragraph(
        "<b>Context:</b> Calculating dynamic behavioral metrics ($n_h, d_h, p_h, f_h$) over the last $\\tau = 60$ seconds.<br/>"
        "<b>Decision:</b> Implemented `collections.deque` paired with hash tables (`collections.Counter`).<br/>"
        "<b>Rationale:</b> Naively storing timestamps and filtering arrays ($O(N)$) causes exponential CPU spikes during horizontal port "
        "scans (where a device generates 5,000+ SYN packets in seconds). With double-ended queues and counters, checking the head of the deque "
        "for entries older than $(t - \\tau)$ and decrementing the frequency counter executes in <b>amortized O(1) constant time</b>.",
        body_style
    ))

    story.append(Paragraph("Decision 4: Temporal Train/Test Splits vs. Random K-Fold Shuffling", h2_style))
    story.append(Paragraph(
        "<b>Context:</b> Evaluating model performance across the IoT-23 dataset.<br/>"
        "<b>Decision:</b> Enforced strict chronological splitting (first 70% of capture duration for training, remaining 30% for evaluation).<br/>"
        "<b>Rationale:</b> Randomly shuffling network flows creates catastrophic synthetic data leakage, as adjacent flows share identical "
        "TCP session identifiers, resulting in falsely optimistic 99.9% metrics. Temporal splitting rigorously tests the model's ability "
        "to generalize to future, unseen infection phases.",
        body_style
    ))

    story.append(Spacer(1, 10))

    # =========================================================================
    # SECTION 5: DIFFICULTIES FACED & RESOLUTION
    # =========================================================================
    story.append(Paragraph("5. Engineering Difficulties Faced & Overcome", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceBefore=2, spaceAfter=8))

    challenges = [
        ("1. Streamlit CSS Ligature Destruction on Column Filters",
         "When applying custom theme typography, using a universal CSS rule (* { font-family: 'Plus Jakarta Sans' !important; }) destroyed Streamlit's internal icon font ligatures. This caused column header filter popups and sidebar collapse buttons to render raw ligature strings (e.g. 'arrow_upward', 'keyboard_double_arrow_left') directly overlapping text labels ('w_up9wardscending').",
         "Removed the universal wildcard selector and scoped Plus Jakarta Sans exclusively to text and layout tags (p, h1-h6, label, div.stMarkdown). Imported Google's Material Symbols Rounded font and explicitly protected all icon and Glide Data Grid elements with font-feature-settings: 'liga' 1 !important."),

        ("2. Windows File Handle Locking During Tailer Automated Unit Tests",
         "On Windows, tests simulating log rotation and tailing threw PermissionError: [WinError 32] The process cannot access the file because it is being used by another process when temporary test files were unlinked.",
         "Refactored RobustJsonLogTailer to implement explicit context teardown and ensure file.close() executes inside a finally block prior to unlinking, guaranteeing zero file descriptor leakage."),

        ("3. Ground-Truth Data Quality Degradation in Public IoT-23 Datasets",
         "The standard IoT-23 benchmark contains systematic mislabelling: over 82% of benign flows in specific captures (e.g. Capture 35-1 Kenjiro) were actually aggressive port scans labelled as benign. This artificially degraded model specificity, causing a 69.0% leave-one-capture-out false positive rate.",
         "Engineered an automated heuristic auditor module (IoT23LabelAuditor) that detects scan-like benign flows (high destination fan-out dh >= 10 with high failure rates fh >= 0.8). Isolating these mislabelled flows reduced false positive rates from 69.0% to 16.7%."),

        ("4. nftables Atomicity & Least Privilege Isolation",
         "The machine learning inference process should not run with root permissions, yet firewall configuration requires elevated kernel capabilities (CAP_NET_ADMIN).",
         "Decoupled the architecture into an unprivileged detector daemon communicating via an IPC queue/socket to a dedicated response daemon (iotguard/response_daemon.py) running with restricted Linux capabilities.")
    ]

    for title, problem, solution in challenges:
        box_data = [
            [Paragraph(f"<b>Challenge: {title}</b>", table_cell_bold)],
            [Paragraph(f"<b>Root Problem:</b> {problem}", table_cell_style)],
            [Paragraph(f"<b>Engineering Resolution:</b> {solution}", table_cell_style)]
        ]
        t = Table(box_data, colWidths=[504])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            ('LINELEFT', (0, 0), (0, -1), 3, c_amber if "Ligature" in title or "Windows" in title else c_indigo),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ]))
        story.append(t)
        story.append(Spacer(1, 6))

    story.append(PageBreak())

    # =========================================================================
    # SECTION 6: SYSTEM ARCHITECTURE & DATA PIPELINE
    # =========================================================================
    story.append(Paragraph("6. End-to-End System Architecture & Data Pipeline", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceBefore=2, spaceAfter=8))

    story.append(Paragraph(
        "IoTGuard operates on a <b>Three-Tier Hierarchical Model</b> designed for zero overhead on devices, "
        "autonomous real-time protection at the gateway, and cryptographic trust from the cloud.",
        body_style
    ))

    arch_tier_data = [
        [
            Paragraph("Tier Layer", table_header_style),
            Paragraph("Hardware / Location", table_header_style),
            Paragraph("Primary Responsibilities", table_header_style),
            Paragraph("Security & Privilege Scope", table_header_style)
        ],
        [
            Paragraph("<b>Tier 0</b><br/>IoT Devices", table_cell_bold),
            Paragraph("Smart Plugs, IP Cameras, Smart Bulbs, Sensors", table_cell_style),
            Paragraph("Execute intended application functions (video streaming, cloud telemetry, MQTT commands). Completely unmanaged; no software or agents installed.", table_cell_style),
            Paragraph("Zero Trust / Untrusted Network Zone", table_cell_style)
        ],
        [
            Paragraph("<b>Tier 1</b><br/>Edge Gateway<br/>(IoTGuard Core)", table_cell_bold),
            Paragraph("Home Router, Raspberry Pi 4/5, Edge Box (Linux)", table_cell_style),
            Paragraph("1. Passive network traffic sniffing via Zeek.<br/>2. Real-time 28-feature extraction with O(1) sliding window.<br/>3. XGBoost sub-millisecond stage inference.<br/>4. Graded nftables containment (L2 block / L3 quarantine).<br/>5. Local Streamlit security dashboard.", table_cell_style),
            Paragraph("Unprivileged detector + Privileged response daemon (CAP_NET_ADMIN)", table_cell_style)
        ],
        [
            Paragraph("<b>Tier 2</b><br/>Cloud Server", table_cell_bold),
            Paragraph("Central Management Cloud / SOC", table_cell_style),
            Paragraph("Trains global XGBoost models across multi-gateway telemetry, signs model binaries with ECDSA private key, and distributes signed model updates.", table_cell_style),
            Paragraph("Cryptographic Trust Root (ECDSA SECP256k1 Signature)", table_cell_style)
        ]
    ]

    arch_table = Table(arch_tier_data, colWidths=[80, 110, 204, 110])
    arch_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), c_primary),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    story.append(arch_table)
    story.append(Spacer(1, 12))

    story.append(Paragraph("<b>End-to-End Data Pipeline Flow:</b>", h2_style))
    pipeline_steps = [
        "<b>1. Packet Sniffing:</b> Zeek passively monitors local network bridge/mirror interfaces (e.g. br0, eth0) out-of-band without intercepting inline packets.",
        "<b>2. Connection Logging:</b> Zeek tracks TCP state machines and emits JSON lines into conn.log upon connection closure or periodic flush, immediately dropping payloads.",
        "<b>3. Robust File Tailing:</b> RobustJsonLogTailer continuously tails conn.log, handling inode tracking, file truncations, and periodic log rotations without data loss.",
        "<b>4. Feature Extraction:</b> FeatureExtractor processes records, computing 24 static connection attributes and updating DeviceWindowManager's sliding window for 4 dynamic device features.",
        "<b>5. XGBoost Inference:</b> Dual-mode inference: single connections classified in 0.63ms; heavy burst periods micro-batched into 50ms windows achieving 94,700 flows/sec throughput.",
        "<b>6. Policy Evaluation:</b> GradedContainmentPolicy evaluates predicted stage and probability p against threshold theta = 0.80. Download/C2 triggers Level 2 Block; Scan/Attack increments device strike counter toward Level 3 Quarantine (k >= 5).",
        "<b>7. Kernel Enforcement:</b> Dedicated nftables rules added atomically to inet iotguard sets. Alerts written to logs/alerts.json and reflected on the Streamlit dashboard."
    ]
    for step in pipeline_steps:
        story.append(Paragraph(step, bullet_style))

    story.append(Spacer(1, 10))

    # =========================================================================
    # SECTION 7: FOLDER STRUCTURE & CODE EXPLANATIONS
    # =========================================================================
    story.append(Paragraph("7. Codebase Directory Deep-Dive", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceBefore=2, spaceAfter=8))

    file_structure_data = [
        [
            Paragraph("Path / File", table_header_style),
            Paragraph("Module Role", table_header_style),
            Paragraph("Key Responsibilities & Implementation Details", table_header_style)
        ],
        [
            Paragraph("<b>cli.py</b>", code_style),
            Paragraph("Unified CLI Controller", table_cell_bold),
            Paragraph("Main command-line entrypoint. Provides commands: demo, dashboard, test, audit, train, live, and clean.", table_cell_style)
        ],
        [
            Paragraph("<b>app.py</b>", code_style),
            Paragraph("Root UI Launcher", table_cell_bold),
            Paragraph("Enables direct execution of streamlit run app.py from root directory with path resolution.", table_cell_style)
        ],
        [
            Paragraph("<b>config/settings.py</b>", code_style),
            Paragraph("Global Configurations", table_cell_bold),
            Paragraph("Defines window length tau=60s, policy thresholds theta=0.8, k=5, 28 feature column names, IoT-23 stage mapping, and directory paths.", table_cell_style)
        ],
        [
            Paragraph("<b>dashboard/app.py</b>", code_style),
            Paragraph("Interactive Web UI", table_cell_bold),
            Paragraph("Streamlit dashboard featuring 5 reactive tabs: Timeline Replay, Active Firewall, Model Benchmarks, Ground Truth Audit, and Real-Time Inspector.", table_cell_style)
        ],
        [
            Paragraph("<b>iotguard/features.py</b>", code_style),
            Paragraph("Feature Extraction", table_cell_bold),
            Paragraph("Contains DeviceWindowManager (amortized O(1) deque queues) and FeatureExtractor (guarantees identical schema between training and live inference).", table_cell_style)
        ],
        [
            Paragraph("<b>iotguard/models.py</b>", code_style),
            Paragraph("ML Stage Classifiers", table_cell_bold),
            Paragraph("IoTGuardModel (XGBoost multi-class classifier) and BaselineModels (Random Forest, Decision Tree, Ablation model, Isolation Forest).", table_cell_style)
        ],
        [
            Paragraph("<b>iotguard/policy.py</b>", code_style),
            Paragraph("Graded Containment", table_cell_bold),
            Paragraph("GradedContainmentPolicy implementing Level 2 destination block and Level 3 full quarantine logic with nftables rule generation.", table_cell_style)
        ],
        [
            Paragraph("<b>iotguard/tailer.py</b>", code_style),
            Paragraph("Log Rotation Tailer", table_cell_bold),
            Paragraph("RobustJsonLogTailer providing continuous tailing of Zeek JSON log streams, tracking file inodes across log rotations without data loss.", table_cell_style)
        ],
        [
            Paragraph("<b>iotguard/batch.py</b>", code_style),
            Paragraph("Micro-Batch Engine", table_cell_bold),
            Paragraph("MicroBatchInferenceEngine buffering connections over 50ms windows for massive throughput (94,700 flows/sec).", table_cell_style)
        ],
        [
            Paragraph("<b>iotguard/security.py</b>", code_style),
            Paragraph("Model Cryptography", table_cell_bold),
            Paragraph("ModelSecurityManager verifying ECDSA SECP256k1 cryptographic signatures on downloaded model updates to prevent supply chain tampering.", table_cell_style)
        ],
        [
            Paragraph("<b>iotguard/audit.py</b>", code_style),
            Paragraph("Ground Truth Auditor", table_cell_bold),
            Paragraph("IoT23LabelAuditor programmatically isolating mislabelled scan flows in benchmark captures to verify clean evaluation.", table_cell_style)
        ],
        [
            Paragraph("<b>iotguard/replay.py</b>", code_style),
            Paragraph("Simulation Engine", table_cell_bold),
            Paragraph("CaptureReplaySimulator replaying capture logs at line rate, calculating lead time metrics and populating timeline visualizations.", table_cell_style)
        ],
        [
            Paragraph("<b>ebpf/iotguard_xdp.c</b>", code_style),
            Paragraph("eBPF XDP Driver", table_cell_bold),
            Paragraph("Future-proofing in-kernel packet filtering driver to drop malicious packets directly in the NIC driver before user-space processing.", table_cell_style)
        ],
        [
            Paragraph("<b>tests/test_iotguard.py</b>", code_style),
            Paragraph("Automated Test Suite", table_cell_bold),
            Paragraph("8 comprehensive unit tests verifying sliding window eviction, feature extraction, policy escalation, micro-batching, and model verification.", table_cell_style)
        ]
    ]

    files_table = Table(file_structure_data, colWidths=[120, 110, 274])
    files_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), c_primary),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(files_table)

    story.append(PageBreak())

    # =========================================================================
    # SECTION 8: SPECIAL PARAMETERS & MATHEMATICAL FORMULATIONS
    # =========================================================================
    story.append(Paragraph("8. Special Parameters & Mathematical Formulations", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceBefore=2, spaceAfter=8))

    story.append(Paragraph(
        "IoTGuard's operation is governed by specific mathematical relationships, sliding window parameters, "
        "and policy thresholds designed to optimize edge responsiveness while eliminating false alarms.",
        body_style
    ))

    story.append(Paragraph("1. The 4 Per-Device Sliding Window Features", h2_style))
    story.append(Paragraph(
        "For each distinct originator device IP $h$ and current timestamp $t$, the system maintains an active connection queue "
        "$W_h(t) = \\{c \\in \\text{Conn} \\mid \\text{orig\\_h}(c) = h \\land t - \\tau \\le \\text{ts}(c) \\le t\\}$ where $\\tau = 60.0\\text{ s}$:",
        body_style
    ))

    window_feat_data = [
        [
            Paragraph("Feature", table_header_style),
            Paragraph("Symbol & Formula", table_header_style),
            Paragraph("Operational Significance & Threat Detection Role", table_header_style)
        ],
        [
            Paragraph("<b>Connection Rate</b>", table_cell_bold),
            Paragraph("<b>n_h = |W_h(t)|</b>", code_style),
            Paragraph("Measures connection burstiness. Baseline benign IoT devices have low, steady heartbeats. A sudden spike indicates botnet activation.", table_cell_style)
        ],
        [
            Paragraph("<b>Destination Fan-Out</b>", table_cell_bold),
            Paragraph("<b>d_h = |{resp\\_h(c) : c in W_h(t)}|</b>", code_style),
            Paragraph("Measures unique external IP contacts. Benign devices connect only to 1-3 cloud vendors. Horizontal scanners contact hundreds of IPs.", table_cell_style)
        ],
        [
            Paragraph("<b>Port Diversity</b>", table_cell_bold),
            Paragraph("<b>p_h = |{resp\\_p(c) : c in W_h(t)}|</b>", code_style),
            Paragraph("Measures destination port spread. Horizontal scanners target a single port (e.g. 23 Telnet) across many IPs, whereas vertical scanners target multiple ports.", table_cell_style)
        ],
        [
            Paragraph("<b>Connection Failure Ratio</b>", table_cell_bold),
            Paragraph("<b>f_h = |{c in W_h(t) : conn\\_state in F}| / n_h</b>", code_style),
            Paragraph("F is the set of failed Zeek connection states: {S0, REJ, RSTOS0, RSTRH, SH, SHR, OTH}. Scanners hit inactive internet hosts, causing fh to approach 1.0.", table_cell_style)
        ]
    ]

    wf_table = Table(window_feat_data, colWidths=[100, 140, 264])
    wf_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), c_primary),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
    ]))
    story.append(wf_table)
    story.append(Spacer(1, 10))

    story.append(Paragraph("2. Policy Thresholds & Containment Formulas", h2_style))
    story.append(Paragraph("• <b>Confidence Threshold (theta = 0.80):</b> A classification stage prediction is only actionable if its posterior probability $p(s \\mid x) \\ge \\theta$. Predictions with $p < \\theta$ remain in monitoring status to prevent false containment.", bullet_style))
    story.append(Paragraph("• <b>Quarantine Hit Threshold (k = 5):</b> For aggressive stages (Scan and Attack), a single flow does not trigger a device quarantine. The policy maintains a sliding history of strikes $H_h$. If $|H_h| \\ge k$ within $T_q = 60\\text{ s}$, the gateway executes Level 3 Quarantine.", bullet_style))
    story.append(Paragraph("• <b>Lead-Time Containment Advantage:</b> Lead time is defined as $T_{\\text{lead}} = t_{\\text{first\\_scan}} - t_{\\text{first\\_block}}$. In simulated IRCBot scenarios (Capture 39-1), IoTGuard achieves a <b>lead time of 531.8 seconds (8.86 minutes)</b>, completely blocking C2 controllers before any lateral port scan packets can be dispatched.", bullet_style))

    story.append(Spacer(1, 12))

    # =========================================================================
    # SECTION 9: FUTURE EXPANSION & ROADMAP
    # =========================================================================
    story.append(Paragraph("9. Future Expansion & Technical Roadmap", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#CBD5E1"), spaceBefore=2, spaceAfter=8))

    roadmap_data = [
        [
            Paragraph("Phase / Initiative", table_header_style),
            Paragraph("Core Technology", table_header_style),
            Paragraph("Technical Scope & Deliverables", table_header_style)
        ],
        [
            Paragraph("<b>1. In-Kernel eBPF / XDP Offloading</b>", table_cell_bold),
            Paragraph("eBPF (Extended Berkeley Packet Filter) + XDP", table_cell_style),
            Paragraph("Migrate the feature extraction and L2 block checking directly into the Linux network interface driver (XDP hook). Malicious packets are dropped at the wire before Linux network stack allocation, achieving zero CPU penalty under 10Gbps DDoS attacks.", table_cell_style)
        ],
        [
            Paragraph("<b>2. Federated Edge Learning</b>", table_cell_bold),
            Paragraph("Federated Averaging (FedAvg) / Differential Privacy", table_cell_style),
            Paragraph("Enable edge gateways across different smart homes to collaboratively refine XGBoost split trees without sharing private network traffic logs with a central cloud, preserving complete GDPR/consumer privacy.", table_cell_style)
        ],
        [
            Paragraph("<b>3. MUD Profile Integration</b>", table_cell_bold),
            Paragraph("IETF RFC 8520 (Manufacturer Usage Descriptions)", table_cell_style),
            Paragraph("Automatically ingest vendor MUD XML/JSON specifications to seed baseline benign whitelist profiles for newly connected smart appliances, eliminating cold-start classification uncertainty.", table_cell_style)
        ],
        [
            Paragraph("<b>4. Hardware Trust Root (TPM 2.0)</b>", table_cell_bold),
            Paragraph("TPM 2.0 / ARM TrustZone", table_cell_style),
            Paragraph("Store the model signing verification public keys inside a hardware TPM/Secure Enclave on the gateway to prevent physical tampering or rootkit model replacements.", table_cell_style)
        ]
    ]

    roadmap_table = Table(roadmap_data, colWidths=[120, 120, 264])
    roadmap_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), c_primary),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor("#F8FAFC")]),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
    ]))
    story.append(roadmap_table)

    # Build the document using the NumberedCanvas
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"Documentation PDF generated successfully at: {OUTPUT_PDF}")


if __name__ == "__main__":
    build_pdf()
