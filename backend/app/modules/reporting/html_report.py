import html
from typing import Dict, Any, List


def esc(val: Any) -> str:
    """Safely escapes text for inclusion in HTML documents."""
    if val is None:
        return ""
    return html.escape(str(val), quote=True)


def get_severity_badge_html(severity: str) -> str:
    """Generates an accessible, high-contrast severity badge with text indicator."""
    sev = str(severity).strip().capitalize()
    colors = {
        "Critical": ("#7f1d1d", "#fef2f2", "#b91c1c"),
        "High": ("#7c2d12", "#fff7ed", "#ea580c"),
        "Medium": ("#713f12", "#fefce8", "#ca8a04"),
        "Low": ("#0c4a6e", "#f0f9ff", "#0284c7"),
        "Informational": ("#1e293b", "#f8fafc", "#64748b"),
    }
    fg, bg, border = colors.get(sev, ("#1e293b", "#f8fafc", "#64748b"))
    return (
        f'<span style="display:inline-block; padding: 2px 8px; font-size: 11px; '
        f'font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; '
        f'color: {fg}; background-color: {bg}; border: 1px solid {border}; '
        f'border-radius: 4px;">{esc(sev)}</span>'
    )


def get_risk_rating_badge_html(rating: str) -> str:
    """Generates an executive risk rating pill."""
    r = str(rating).strip().capitalize()
    colors = {
        "Clean": ("#065f46", "#ecfdf5", "#059669"),
        "Low": ("#0c4a6e", "#f0f9ff", "#0284c7"),
        "Moderate": ("#713f12", "#fefce8", "#ca8a04"),
        "High": ("#7c2d12", "#fff7ed", "#ea580c"),
        "Critical": ("#7f1d1d", "#fef2f2", "#b91c1c"),
    }
    fg, bg, border = colors.get(r, ("#1e293b", "#f8fafc", "#64748b"))
    return (
        f'<span style="display:inline-block; padding: 4px 12px; font-size: 13px; '
        f'font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; '
        f'color: {fg}; background-color: {bg}; border: 1px solid {border}; '
        f'border-radius: 6px;">{esc(r)}</span>'
    )


def generate_html_report(data: Dict[str, Any]) -> str:
    """
    Renders a self-contained, secure, standalone HTML assessment report.
    All user, firmware, and database inputs are strictly HTML-escaped.
    Zero external fonts, scripts, stylesheets, or network assets are loaded.
    """
    counts = data["summary_counts"]
    findings: List[Dict[str, Any]] = data["findings"]
    device = data["device"]
    partitions: List[Dict[str, Any]] = data["partitions"]
    score_breakdown = data["score_breakdown"]
    breakdown_items = score_breakdown.get("items", [])

    # Render Device Details Table or Offline Banner
    if device:
        device_section_html = f"""
        <table class="data-table">
            <tr><th style="width: 25%;">Connected Port</th><td><code>{esc(device.get("port"))}</code></td></tr>
            <tr><th>ESP32 Chip Model</th><td><strong>{esc(device.get("chip_type"))}</strong></td></tr>
            <tr><th>MAC Address</th><td><code>{esc(device.get("mac_address"))}</code></td></tr>
            <tr><th>Flash Memory Size</th><td>{esc(device.get("flash_size")) or "N/A"}</td></tr>
            <tr><th>Flash Parameters</th><td>Mode: <code>{esc(device.get("flash_mode")) or "N/A"}</code>, Speed: <code>{esc(device.get("flash_speed")) or "N/A"}</code>, Vendor ID: <code>{esc(device.get("flash_vendor_id")) or "N/A"}</code></td></tr>
            <tr><th>Crystal Frequency</th><td>{esc(device.get("crystal_freq")) or "N/A"}</td></tr>
            <tr><th>SDK Version</th><td>{esc(device.get("sdk_version")) or "N/A"}</td></tr>
            <tr><th>Interrogation Time</th><td>{esc(device.get("created_at"))}</td></tr>
        </table>
        """
    else:
        device_section_html = """
        <div class="info-callout">
            <strong>Offline Analysis Scope:</strong> This assessment was performed strictly on an offline firmware binary artifact. 
            No physical ESP32 development board was connected or interrogated over serial. Physical eFuses, hardware Secure Boot registers, 
            and live flash encryption states cannot be verified without hardware connection.
        </div>
        """

    # Render Partition Table if extracted
    if partitions:
        part_rows = "".join(
            f"<tr><td><code>{esc(p.get('label'))}</code></td><td>{esc(p.get('type'))}</td>"
            f"<td>{esc(p.get('subtype'))}</td><td><code>0x{p.get('offset', 0):06x}</code></td>"
            f"<td>{esc(p.get('size_bytes', 0) // 1024)} KB</td><td>{esc(p.get('flags', 'None'))}</td></tr>"
            for p in partitions
        )
        partition_section_html = f"""
        <h3>Flash Partition Table</h3>
        <table class="data-table">
            <thead>
                <tr>
                    <th>Label</th><th>Type</th><th>Subtype</th><th>Offset</th><th>Size</th><th>Flags</th>
                </tr>
            </thead>
            <tbody>
                {part_rows}
            </tbody>
        </table>
        """
    else:
        partition_section_html = "<p class='text-muted'>No embedded partition table detected in this firmware binary.</p>"

    # Render Findings List / Cards
    if findings:
        finding_cards = []
        for idx, f in enumerate(findings, 1):
            additional_offsets_html = ""
            if f.get("additional_offsets"):
                add_str = ", ".join(f"<code>{esc(o)}</code>" for o in f["additional_offsets"])
                additional_offsets_html = f"<div class='f-row'><strong>Additional Offsets ({len(f['additional_offsets'])}):</strong> {add_str}</div>"

            rationale_html = f"<div class='f-row'><strong>Security Rationale:</strong> {esc(f.get('rationale'))}</div>" if f.get('rationale') else ""
            fp_html = f"<div class='f-row'><strong>False Positive Scenarios:</strong> {esc(f.get('false_positive_cases'))}</div>" if f.get('false_positive_cases') else ""
            remed_html = f"<div class='f-row'><strong>Remediation Guidance:</strong> {esc(f.get('remediation'))}</div>" if f.get('remediation') else ""
            limit_html = f"<div class='f-row'><strong>Verification Limitations:</strong> {esc(f.get('verification_limitations'))}</div>" if f.get('verification_limitations') else ""

            card = f"""
            <div class="finding-card" id="finding-{idx}">
                <div class="finding-header">
                    <div>
                        <span class="finding-num">#{idx}</span>
                        <h4 class="finding-title">{esc(f['title'])}</h4>
                        <span class="finding-rule">[{esc(f['rule_id'])}]</span>
                    </div>
                    <div>
                        {get_severity_badge_html(f['severity'])}
                    </div>
                </div>
                <div class="finding-meta">
                    <span><strong>Category:</strong> {esc(f['category'])}</span>
                    <span><strong>Confidence:</strong> {esc(f['confidence'])}</span>
                    <span><strong>Primary Offset:</strong> <code>{esc(f['byte_offset'])}</code></span>
                    <span><strong>Section:</strong> {esc(f['section'])}</span>
                    <span><strong>Status:</strong> <em style="color:#d97706;">Potential Indicator</em></span>
                </div>
                {additional_offsets_html}
                <div class="f-evidence-block">
                    <div class="f-evidence-label">Sanitized Evidence Context:</div>
                    <pre class="evidence-pre"><code>{esc(f['evidence_masked'])}</code></pre>
                </div>
                {rationale_html}
                {fp_html}
                {remed_html}
                {limit_html}
            </div>
            """
            finding_cards.append(card)
        findings_html = "\n".join(finding_cards)
    else:
        findings_html = """
        <div class="clean-callout">
            <h4 style="margin: 0 0 8px 0; color: #065f46;">No Static Security Indicators Detected</h4>
            <p style="margin: 0; color: #047857; font-size: 13px;">
                The automated scanner matched zero configured secret signatures, insecure protocol indicators, or known insecure configuration strings.
                Note that this does not certify that the firmware is free of logical flaws or runtime vulnerabilities.
            </p>
        </div>
        """

    # Render Score Breakdown Table
    if breakdown_items:
        score_rows = "".join(
            f"<tr><td><code>{esc(item.get('rule_id'))}</code></td>"
            f"<td>{esc(item.get('title'))}</td>"
            f"<td>{get_severity_badge_html(item.get('severity', 'Low'))}</td>"
            f"<td>{esc(item.get('confidence'))} ({item.get('confidence_factor', 0.8):.1f})</td>"
            f"<td>{esc(item.get('occurrences', 1))}</td>"
            f"<td>{esc(item.get('multiplier', 1.0))}x</td>"
            f"<td><strong>{esc(item.get('calculated_points', 0.0))} pts</strong></td></tr>"
            for item in breakdown_items
        )
        score_breakdown_html = f"""
        <table class="data-table">
            <thead>
                <tr>
                    <th>Rule ID</th><th>Finding Title</th><th>Severity</th><th>Confidence</th><th>Occurrences (N)</th><th>Multiplier</th><th>Points</th>
                </tr>
            </thead>
            <tbody>
                {score_rows}
            </tbody>
        </table>
        """
    else:
        score_breakdown_html = "<p class='text-muted'>Zero contributing finding points; baseline score is 0.</p>"

    # Full HTML document template with zero remote dependencies
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{esc(data['report_title'])} - {esc(data['assessment_id'][:8])}</title>
    <style>
        /* Standalone High-Contrast CSS with Zero Remote Fonts or Assets */
        :root {{
            --bg-body: #f8fafc;
            --bg-card: #ffffff;
            --text-main: #0f172a;
            --text-muted: #64748b;
            --border-color: #e2e8f0;
            --font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
        }}

        *, *::before, *::after {{
            box-sizing: border-box;
        }}

        body {{
            margin: 0;
            padding: 24px;
            background-color: var(--bg-body);
            color: var(--text-main);
            font-family: var(--font-family);
            font-size: 14px;
            line-height: 1.5;
            -webkit-print-color-adjust: exact;
            print-color-adjust: exact;
        }}

        .container {{
            max-width: 1040px;
            margin: 0 auto;
        }}

        .card {{
            background-color: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}

        /* Header & Cover Banner */
        .header-banner {{
            border-top: 4px solid #0284c7;
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            flex-wrap: wrap;
            gap: 16px;
        }}

        .brand-title {{
            margin: 0 0 4px 0;
            font-size: 22px;
            font-weight: 800;
            letter-spacing: -0.5px;
            color: #0f172a;
        }}

        .brand-sub {{
            margin: 0;
            color: var(--text-muted);
            font-size: 13px;
        }}

        .doc-meta {{
            text-align: right;
            font-size: 12px;
            color: var(--text-muted);
        }}

        /* Typography */
        h2 {{
            font-size: 18px;
            font-weight: 700;
            margin: 0 0 16px 0;
            padding-bottom: 8px;
            border-bottom: 1px solid var(--border-color);
            color: #0f172a;
        }}

        h3 {{
            font-size: 15px;
            font-weight: 600;
            margin: 16px 0 8px 0;
            color: #1e293b;
        }}

        p {{
            margin: 0 0 12px 0;
        }}

        code {{
            font-family: var(--font-mono);
            font-size: 12px;
            background-color: #f1f5f9;
            padding: 2px 6px;
            border-radius: 4px;
            color: #0f172a;
            word-break: break-all;
        }}

        /* Executive Summary Grid */
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 20px;
        }}

        .metric-box {{
            background-color: #f8fafc;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 16px;
            text-align: center;
        }}

        .metric-label {{
            font-size: 11px;
            text-transform: uppercase;
            font-weight: 600;
            color: var(--text-muted);
            margin-bottom: 6px;
        }}

        .metric-value {{
            font-size: 26px;
            font-weight: 800;
            color: #0f172a;
        }}

        /* Tables */
        .data-table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
            margin-bottom: 16px;
        }}

        .data-table th, .data-table td {{
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
            vertical-align: middle;
        }}

        .data-table th {{
            background-color: #f8fafc;
            font-weight: 600;
            color: #475569;
        }}

        .data-table tbody tr:hover {{
            background-color: #f8fafc;
        }}

        /* Callouts */
        .info-callout {{
            background-color: #f0f9ff;
            border-left: 4px solid #0284c7;
            padding: 12px 16px;
            border-radius: 0 4px 4px 0;
            font-size: 13px;
            color: #0369a1;
            margin-bottom: 16px;
        }}

        .clean-callout {{
            background-color: #ecfdf5;
            border: 1px solid #a7f3d0;
            padding: 20px;
            border-radius: 6px;
            text-align: center;
        }}

        /* Finding Card Layout */
        .finding-card {{
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 16px;
            margin-bottom: 16px;
            background-color: #ffffff;
        }}

        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 10px;
        }}

        .finding-num {{
            font-size: 12px;
            font-weight: 700;
            color: var(--text-muted);
            margin-right: 6px;
        }}

        .finding-title {{
            display: inline;
            margin: 0;
            font-size: 15px;
            font-weight: 700;
            color: #0f172a;
        }}

        .finding-rule {{
            font-family: var(--font-mono);
            font-size: 11px;
            color: var(--text-muted);
            margin-left: 6px;
        }}

        .finding-meta {{
            display: flex;
            flex-wrap: wrap;
            gap: 16px;
            font-size: 12px;
            color: #475569;
            background-color: #f8fafc;
            padding: 8px 12px;
            border-radius: 4px;
            margin-bottom: 12px;
        }}

        .f-row {{
            font-size: 13px;
            margin-bottom: 8px;
            color: #1e293b;
        }}

        .f-evidence-block {{
            margin: 10px 0;
        }}

        .f-evidence-label {{
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            color: var(--text-muted);
            margin-bottom: 4px;
        }}

        .evidence-pre {{
            margin: 0;
            padding: 10px 12px;
            background-color: #0f172a;
            color: #f8fafc;
            font-family: var(--font-mono);
            font-size: 12px;
            border-radius: 4px;
            overflow-x: auto;
            max-height: 180px;
            white-space: pre-wrap;
            word-break: break-all;
        }}

        .evidence-pre code {{
            background: none;
            color: inherit;
            padding: 0;
        }}

        .text-muted {{
            color: var(--text-muted);
            font-size: 13px;
        }}

        .footer {{
            text-align: center;
            font-size: 12px;
            color: var(--text-muted);
            padding: 16px 0;
        }}

        @media print {{
            body {{
                background-color: #ffffff;
                padding: 0;
            }}
            .card {{
                box-shadow: none;
                border: 1px solid #cbd5e1;
                page-break-inside: avoid;
            }}
            .finding-card {{
                page-break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
<div class="container">

    <!-- A. Report Cover & Metadata -->
    <div class="card header-banner">
        <div>
            <h1 class="brand-title">Sentinel-X</h1>
            <p class="brand-sub">ESP32 Embedded Device Security Assessment Platform</p>
            <div style="margin-top: 8px;">
                <span style="font-size: 12px; font-weight: 600; color: #475569;">Assessment Status:</span>
                <span style="display:inline-block; padding: 2px 6px; font-size: 11px; font-weight: 700; background-color: #f1f5f9; border-radius: 4px;">{esc(data['status'])}</span>
            </div>
        </div>
        <div class="doc-meta">
            <div><strong>Assessment ID:</strong> <code>{esc(data['assessment_id'])}</code></div>
            <div><strong>Assessment Date:</strong> {esc(data['created_at'])}</div>
            <div><strong>Report Generated:</strong> {esc(data['generated_at'])}</div>
        </div>
    </div>

    <!-- Target Firmware & Device Specification -->
    <div class="card">
        <h2>Target Artifact & Hardware Specifications</h2>
        <table class="data-table">
            <tr>
                <th style="width: 25%;">Target Firmware File</th>
                <td><strong>{esc(data['filename'])}</strong> ({esc(data['file_size_formatted'])})</td>
            </tr>
            <tr>
                <th>SHA-256 Hash</th>
                <td><code>{esc(data['sha256'])}</code></td>
            </tr>
            <tr>
                <th>MD5 Hash</th>
                <td><code>{esc(data['md5'])}</code></td>
            </tr>
            <tr>
                <th>Detected Image Format</th>
                <td><code>{esc(data['image_type'])}</code></td>
            </tr>
        </table>

        <h3>Hardware Association</h3>
        {device_section_html}

        {partition_section_html}
    </div>

    <!-- B. Executive Summary -->
    <div class="card">
        <h2>Executive Summary</h2>
        <div class="summary-grid">
            <div class="metric-box">
                <div class="metric-label">Composite Risk Score</div>
                <div class="metric-value">{esc(data['risk_score'])} <span style="font-size: 14px; font-weight: 500; color: #64748b;">/ 100</span></div>
                <div style="margin-top: 6px;">{get_risk_rating_badge_html(data['risk_rating'])}</div>
            </div>
            <div class="metric-box">
                <div class="metric-label">Total Unique Findings</div>
                <div class="metric-value">{esc(data['total_findings'])}</div>
            </div>
            <div class="metric-box">
                <div class="metric-label">Critical Severity</div>
                <div class="metric-value" style="color: #b91c1c;">{esc(counts['Critical'])}</div>
            </div>
            <div class="metric-box">
                <div class="metric-label">High Severity</div>
                <div class="metric-value" style="color: #ea580c;">{esc(counts['High'])}</div>
            </div>
            <div class="metric-box">
                <div class="metric-label">Medium Severity</div>
                <div class="metric-value" style="color: #ca8a04;">{esc(counts['Medium'])}</div>
            </div>
            <div class="metric-box">
                <div class="metric-label">Low Severity</div>
                <div class="metric-value" style="color: #0284c7;">{esc(counts['Low'])}</div>
            </div>
        </div>

        <div class="info-callout">
            <strong>Defensive Indicator Advisory:</strong> All items in this report represent <em>potential indicators</em> identified 
            through static heuristics, pattern matching, and configuration analysis. Static detection does not constitute confirmed exploitability. 
            Embedded systems engineers and security auditors should manually verify each finding against production device configurations.
        </div>
    </div>

    <!-- C. Assessment Methodology -->
    <div class="card">
        <h2>Assessment Methodology</h2>
        <p>Sentinel-X conducts defensive, non-destructive static security assessments tailored specifically to ESP32 architecture:</p>
        <ul style="margin: 0 0 16px 20px; padding: 0; font-size: 13px; color: #334155;">
            <li><strong>ESP32 Header & Flash Segment Parsing:</strong> Validates the 24-byte ESP image header magic (<code>0xE9</code>), entry address, SPI flash mode/speed, and maps loadable memory segments (IRAM, DRAM, DROM, IROM).</li>
            <li><strong>Partition Table Verification:</strong> Inspects partition table entries at standard flash offsets (<code>0x8000</code>), identifying app slots, NVS partitions, and auditing dual OTA redundancy.</li>
            <li><strong>Printable String Extraction:</strong> Indexes printable ASCII and UTF-8 strings with byte-level boundary offsets across flash sections.</li>
            <li><strong>Secret Token & Entropy Analysis:</strong> Applies compiled regular expression rules with Shannon entropy thresholds to detect hardcoded private keys, cloud tokens, bearer tokens, cleartext Wi-Fi credentials, and insecure URIs.</li>
            <li><strong>Deduplication & Offset Aggregation:</strong> Computes stable cryptographic fingerprints to collapse duplicate occurrences across flash while compiling all spatial offsets.</li>
            <li><strong>Deterministic Risk Scoring:</strong> Evaluates findings using documented severity weights, confidence multipliers, and occurrence dampening.</li>
        </ul>
        <div style="background-color: #f8fafc; border: 1px solid var(--border-color); padding: 12px; border-radius: 4px; font-size: 12px; color: #475569;">
            <strong>Scope Boundary Guarantee:</strong> Sentinel-X strictly excludes destructive operations. It does not flash firmware, alter eFuse registers, execute code on host or microcontroller, or perform dynamic network penetration testing.
        </div>
    </div>

    <!-- D. Detailed Security Findings -->
    <div class="card">
        <h2>Detailed Security Findings ({esc(data['total_findings'])})</h2>
        {findings_html}
    </div>

    <!-- E. Explainable Risk Score Breakdown -->
    <div class="card">
        <h2>Risk Score Methodology & Calculation</h2>
        <p>
            The Sentinel-X Risk Score is calculated deterministically from the deduplicated normalized findings.
            Each finding is evaluated using its assigned severity base weight and confidence factor, with occurrence dampening
            applied to repeated hits of the same pattern across flash offsets:
        </p>
        <div style="background-color: #f8fafc; border: 1px solid var(--border-color); padding: 12px; border-radius: 6px; font-family: var(--font-mono); font-size: 12px; margin-bottom: 16px;">
            Finding Points = Base Weight(Severity) &times; Confidence Multiplier &times; (1.0 + 0.2 &times; min(N - 1, 5))<br>
            Composite Score = min(100, round(&sum; Finding Points))
        </div>

        <h3>Itemized Scoring Breakdown</h3>
        {score_breakdown_html}

        <p class="text-muted" style="margin-top: 12px;">
            <em>{esc(score_breakdown.get('disclaimer'))}</em>
        </p>
    </div>

    <!-- F. Limitations & Defensive Recommendations -->
    <div class="card">
        <h2>Limitations & Defensive Recommendations</h2>
        <h3>Assessment Limitations</h3>
        <ul style="margin: 0 0 16px 20px; padding: 0; font-size: 13px; color: #334155;">
            <li><strong>Static Analysis Boundaries:</strong> String matching cannot detect dynamically generated secrets, XOR-encoded tokens, or credentials loaded securely at runtime via BLE provisioning.</li>
            <li><strong>Encrypted Firmware Images:</strong> Binaries compiled with Flash Encryption enabled cannot be analyzed statically without physical device key extraction.</li>
            <li><strong>Non-Confirmation of Exploits:</strong> Detected endpoints and keys must be audited manually to verify whether they represent production infrastructure or defunct test stubs.</li>
            <li><strong>Hardware Offline Limitations:</strong> Serial-less assessments cannot verify physical pin strapping, UART console status, or eFuse configuration bits.</li>
        </ul>

        <h3>Defensive Recommendations for ESP32 Deployment</h3>
        <ul style="margin: 0 0 16px 20px; padding: 0; font-size: 13px; color: #334155;">
            <li><strong>Enable Flash Encryption & Secure Boot v2:</strong> Protect physical flash contents against offline SPI extraction and prevent unauthorized firmware modification.</li>
            <li><strong>Utilize ESP-IDF NVS Encryption:</strong> Store Wi-Fi credentials and API tokens in an encrypted NVS partition utilizing eFuse-derived keys rather than hardcoding in application binaries.</li>
            <li><strong>Hardware Cryptographic Acceleration:</strong> Utilize the ESP32 Digital Signature (DS) and HMAC peripherals for TLS mutual authentication instead of storing private keys in flash segments.</li>
            <li><strong>Implement Dual OTA Partitioning:</strong> Configure <code>ota_0</code> and <code>ota_1</code> partitions with an <code>otadata</code> slot to enable verified, rollback-safe remote updates.</li>
        </ul>
    </div>

    <div class="footer">
        Generated by Sentinel-X &bull; ESP32 Embedded Device Security Assessment Platform &bull; Strictly Confidential
    </div>

</div>
</body>
</html>
"""
