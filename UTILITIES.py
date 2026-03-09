"""Utility functions for threat hunting operations.

This module provides functions for displaying threat findings,
exporting reports in various formats (JSON, CSV, Markdown, PDF),
and sanitizing query parameters for safe use in Azure Sentinel queries.
"""

import csv
import json
from datetime import datetime
from typing import Any

from colorama import Fore, Style, init

# Optional PDF support
try:
    from fpdf import FPDF  # noqa: F401

    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False


def display_query_context(query_context):
    """Display query context and metadata to the console.

    Args:
        query_context: Dictionary containing query context information including
                      table_name, time_range_hours, fields, device_name, caller,
                      user_principal_name, and rationale.
    """
    print(f"{Fore.LIGHTGREEN_EX}Query context and metadata:")
    print(f"{Fore.WHITE}Table Name:   {query_context['table_name']}")
    print(f"{Fore.WHITE}Time Range:   {query_context['time_range_hours']} hour(s)")
    print(f"{Fore.WHITE}Fields:       {query_context['fields']}")
    if query_context["device_name"] != "":
        print(f"{Fore.WHITE}Device:       {query_context['device_name']}")
    if query_context["caller"] != "":
        print(f"{Fore.WHITE}Caller:       {query_context['caller']}")
    if query_context["user_principal_name"] != "":
        print(f"{Fore.WHITE}Username:     {query_context['user_principal_name']}")
    print(f"{Fore.WHITE}User Related: {query_context['about_individual_user']}")
    print(f"{Fore.WHITE}Host Related: {query_context['about_individual_host']}")
    print(f"{Fore.WHITE}NSG Related:  {query_context['about_network_security_group']}")
    print(f"{Fore.WHITE}Rationale:\n{query_context['rationale']}\n")


def display_threats(threat_list):
    """Display threat findings to the console with formatted output.

    Args:
        threat_list: List of threat dictionaries containing title, description,
                     confidence, mitre info, log lines, IOCs, tags, and recommendations.
    """
    count = 0
    for threat in threat_list:
        count += 1
        print(f"\n=============== Potential Threat #{count} ===============\n")
        print(f"{Fore.LIGHTCYAN_EX}Title: {threat.get('title')}{Fore.RESET}\n")
        print(f"Description: {threat.get('description')}\n")

        init(autoreset=True)  # Automatically resets to default after each print

        confidence = threat.get("confidence", "").lower()

        if confidence == "high":
            color = Fore.LIGHTRED_EX
        elif confidence == "medium":
            color = Fore.LIGHTYELLOW_EX
        elif confidence == "low":
            color = Fore.LIGHTBLUE_EX
        else:
            color = Style.RESET_ALL  # Default/no color

        print(f"{color}Confidence Level: {threat.get('confidence')}")
        print("\nMITRE ATT&CK Info:")
        mitre = threat.get("mitre", {})
        print(f"  Tactic: {mitre.get('tactic')}")
        print(f"  Technique: {mitre.get('technique')}")
        print(f"  Sub-technique: {mitre.get('sub_technique')}")
        print(f"  ID: {mitre.get('id')}")
        print(f"  Description: {mitre.get('description')}")

        print("\nLog Lines:")
        for log in threat.get("log_lines", []):
            print(f"  - {log}")

        print("\nIndicators of Compromise:")
        for ioc in threat.get("indicators_of_compromise", []):
            print(f"  - {ioc}")

        print("\nTags:")
        for tag in threat.get("tags", []):
            print(f"  - {tag}")

        print("\nRecommendations:")
        for rec in threat.get("recommendations", []):
            print(f"  - {rec}")

        print(f"\nNotes: {threat.get('notes')}")

        print("=" * 51)

    append_threats_to_jsonl(threat_list=threat_list)


def append_threats_to_jsonl(threat_list, filename="_threats.jsonl"):
    """Append threat findings to a JSONL file.

    Args:
        threat_list: List of threat dictionaries to append.
        filename: Path to the JSONL file (default: _threats.jsonl).
    """
    count = 0
    with open(filename, "a", encoding="utf-8") as f:
        for threat in threat_list:
            json_line = json.dumps(threat, ensure_ascii=False)
            f.write(json_line + "\n")
            count += 1
        print(f"{Fore.LIGHTBLUE_EX}\nLogged {count} threats to {filename}.\n")


def export_findings(
    findings: list[dict[str, Any]],
    export_format: str = "json",
    filename: str = "threat_report",
    query_context: dict[str, Any] | None = None,
) -> str:
    """
    Export threat hunt findings to various formats.

    Args:
        findings: List of threat finding dictionaries.
        export_format: Output format - "json", "csv", "markdown", or "pdf".
        filename: Output filename (without extension).
        query_context: Optional query context metadata to include in report.

    Returns:
        str: Path to the exported file.

    Raises:
        ValueError: If an unsupported format is specified.
    """
    export_format = export_format.lower()

    if export_format == "json":
        return _export_to_json(findings, filename, query_context)
    elif export_format == "csv":
        return _export_to_csv(findings, filename)
    elif export_format == "markdown":
        return _export_to_markdown(findings, filename, query_context)
    elif export_format == "pdf":
        return _export_to_pdf(findings, filename, query_context)
    else:
        raise ValueError(
            f"Unsupported format: {export_format}. "
            "Supported formats: json, csv, markdown, pdf"
        )


def _export_to_json(
    findings: list[dict[str, Any]],
    filename: str,
    query_context: dict[str, Any] | None = None,
) -> str:
    """Export findings to JSON format."""
    output_path = f"{filename}.json"

    export_data = {
        "export_timestamp": datetime.now().isoformat(),
        "total_findings": len(findings),
        "query_context": query_context,
        "findings": findings,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(export_data, f, indent=2, ensure_ascii=False)

    print(f"{Fore.LIGHTGREEN_EX}Exported {len(findings)} findings to {output_path}")
    return output_path


def _export_to_csv(findings: list[dict[str, Any]], filename: str) -> str:
    """Export findings to CSV format (flattened structure)."""
    output_path = f"{filename}.csv"

    # Flatten findings for CSV
    flattened = []
    for finding in findings:
        flat = {
            "title": finding.get("title", ""),
            "description": finding.get("description", ""),
            "confidence": finding.get("confidence", ""),
            "mitre_tactic": finding.get("mitre", {}).get("tactic", ""),
            "mitre_technique": finding.get("mitre", {}).get("technique", ""),
            "mitre_id": finding.get("mitre", {}).get("id", ""),
            "log_lines": " | ".join(finding.get("log_lines", [])),
            "iocs": " | ".join(finding.get("indicators_of_compromise", [])),
            "tags": " | ".join(finding.get("tags", [])),
            "recommendations": " | ".join(finding.get("recommendations", [])),
            "notes": finding.get("notes", ""),
        }
        flattened.append(flat)

    if not flattened:
        print(f"{Fore.YELLOW}No findings to export.")
        return output_path

    fieldnames = list(flattened[0].keys())

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(flattened)

    print(f"{Fore.LIGHTGREEN_EX}Exported {len(flattened)} findings to {output_path}")
    return output_path


def _export_to_markdown(
    findings: list[dict[str, Any]],
    filename: str,
    query_context: dict[str, Any] | None = None,
) -> str:
    """Export findings to Markdown report format."""
    output_path = f"{filename}.md"

    lines = []
    lines.append("# Threat Hunt Report\n")
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    lines.append(f"**Total Findings:** {len(findings)}\n")

    # Add query context if provided
    if query_context:
        lines.append("\n## Query Context\n")
        lines.append(f"- **Table:** {query_context.get('table_name', 'N/A')}\n")
        lines.append(
            f"- **Time Range:** {query_context.get('time_range_hours', 'N/A')} hours\n"
        )
        lines.append(f"- **Fields:** {query_context.get('fields', 'N/A')}\n")
        if query_context.get("device_name"):
            lines.append(f"- **Device:** {query_context['device_name']}\n")
        if query_context.get("user_principal_name"):
            lines.append(f"- **User:** {query_context['user_principal_name']}\n")

    lines.append("\n---\n")

    # Add each finding
    for i, finding in enumerate(findings, 1):
        confidence = finding.get("confidence", "Unknown").lower()
        confidence_emoji = {"high": "🔴", "medium": "🟡", "low": "🔵"}.get(
            confidence, "⚪"
        )

        lines.append(f"\n## Finding #{i}: {finding.get('title', 'Untitled')}\n")
        lines.append(
            f"**Confidence:** {confidence_emoji} {finding.get('confidence', 'N/A')}\n"
        )

        # Description
        lines.append(f"\n### Description\n{finding.get('description', 'N/A')}\n")

        # MITRE ATT&CK
        mitre = finding.get("mitre", {})
        if mitre:
            lines.append("\n### MITRE ATT&CK\n")
            lines.append(f"- **Tactic:** {mitre.get('tactic', 'N/A')}\n")
            lines.append(f"- **Technique:** {mitre.get('technique', 'N/A')}\n")
            lines.append(f"- **ID:** {mitre.get('id', 'N/A')}\n")
            if mitre.get("description"):
                lines.append(f"- **Description:** {mitre['description']}\n")

        # IOCs
        iocs = finding.get("indicators_of_compromise", [])
        if iocs:
            lines.append("\n### Indicators of Compromise\n")
            for ioc in iocs:
                lines.append(f"- `{ioc}`\n")

        # Log Lines
        log_lines = finding.get("log_lines", [])
        if log_lines:
            lines.append("\n### Relevant Log Lines\n```\n")
            for log in log_lines:
                lines.append(f"{log}\n")
            lines.append("```\n")

        # Tags
        tags = finding.get("tags", [])
        if tags:
            lines.append(f"\n### Tags\n{', '.join(tags)}\n")

        # Recommendations
        recommendations = finding.get("recommendations", [])
        if recommendations:
            lines.append("\n### Recommendations\n")
            for rec in recommendations:
                lines.append(f"- {rec}\n")

        # Notes
        notes = finding.get("notes", "")
        if notes:
            lines.append(f"\n### Notes\n{notes}\n")

        lines.append("\n---\n")

    with open(output_path, "w", encoding="utf-8") as f:
        f.writelines(lines)

    print(f"{Fore.LIGHTGREEN_EX}Exported {len(findings)} findings to {output_path}")
    return output_path


def _export_to_pdf(
    findings: list[dict[str, Any]],
    filename: str,
    query_context: dict[str, Any] | None = None,
) -> str:
    """Export findings to PDF format."""
    output_path = f"{filename}.pdf"

    if not PDF_AVAILABLE:
        print(
            f"{Fore.YELLOW}PDF export not available. "
            f"Install fpdf2: pip install fpdf2"
        )
        print(f"{Fore.LIGHTGREEN_EX}Falling back to Markdown export...")
        return _export_to_markdown(findings, filename, query_context)

    # Helper function to sanitize text for PDF
    def sanitize_for_pdf(text: str) -> str:
        """Replace Unicode characters that fpdf can't handle."""
        if not text:
            return ""
        # Replace common Unicode characters with ASCII equivalents
        replacements = {
            "—": "-",  # em dash
            "–": "-",  # en dash
            '"': '"',  # smart quotes
            '"': '"',
            "'": "'",
            "'": "'",
            "...": "...",  # ellipsis
            "\u2022": "*",  # bullet
            "\u2026": "...",
        }
        result = text
        for uni, ascii_val in replacements.items():
            result = result.replace(uni, ascii_val)
        # Remove any remaining non-ASCII characters
        result = result.encode("ascii", "ignore").decode("ascii")
        return result

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Title
    pdf.set_font("Helvetica", "B", 20)
    pdf.cell(0, 10, "Threat Hunt Report", ln=True, align="C")
    pdf.ln(5)

    # Metadata
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(
        0, 6, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True
    )
    pdf.cell(0, 6, f"Total Findings: {len(findings)}", ln=True)
    pdf.ln(5)

    # Query context
    if query_context:
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 8, "Query Context", ln=True)
        pdf.set_font("Helvetica", "", 10)
        pdf.cell(0, 6, f"  Table: {query_context.get('table_name', 'N/A')}", ln=True)
        pdf.cell(
            0,
            6,
            f"  Time Range: {query_context.get('time_range_hours', 'N/A')} hours",
            ln=True,
        )
        if query_context.get("device_name"):
            pdf.cell(0, 6, f"  Device: {query_context['device_name']}", ln=True)
        pdf.ln(5)

    # Findings
    for i, finding in enumerate(findings, 1):
        pdf.add_page()

        # Title
        pdf.set_font("Helvetica", "B", 14)
        title = sanitize_for_pdf(finding.get("title", "Untitled")[:80])
        pdf.cell(0, 10, f"Finding #{i}: {title}", ln=True)

        # Confidence
        pdf.set_font("Helvetica", "B", 10)
        confidence = finding.get("confidence", "N/A")
        pdf.cell(0, 6, f"Confidence: {confidence}", ln=True)
        pdf.ln(3)

        # Description
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(0, 6, "Description:", ln=True)
        pdf.set_font("Helvetica", "", 9)
        description = sanitize_for_pdf(finding.get("description", "N/A")[:500])
        pdf.multi_cell(0, 5, description)
        pdf.ln(3)

        # MITRE
        mitre = finding.get("mitre", {})
        if mitre:
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 6, "MITRE ATT&CK:", ln=True)
            pdf.set_font("Helvetica", "", 9)
            pdf.cell(
                0,
                5,
                f"  Tactic: {sanitize_for_pdf(mitre.get('tactic', 'N/A'))}",
                ln=True,
            )
            pdf.cell(
                0,
                5,
                f"  Technique: {sanitize_for_pdf(mitre.get('technique', 'N/A'))}",
                ln=True,
            )
            pdf.cell(0, 5, f"  ID: {mitre.get('id', 'N/A')}", ln=True)
            pdf.ln(3)

        # IOCs
        iocs = finding.get("indicators_of_compromise", [])
        if iocs:
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 6, "Indicators of Compromise:", ln=True)
            pdf.set_font("Helvetica", "", 9)
            for ioc in iocs[:10]:  # Limit to 10 IOCs
                pdf.cell(0, 5, f"  - {sanitize_for_pdf(str(ioc))}", ln=True)
            pdf.ln(3)

        # Recommendations
        recommendations = finding.get("recommendations", [])
        if recommendations:
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 6, "Recommendations:", ln=True)
            pdf.set_font("Helvetica", "", 9)
            for rec in recommendations:
                pdf.cell(0, 5, f"  - {sanitize_for_pdf(str(rec))}", ln=True)

    pdf.output(output_path)
    print(f"{Fore.LIGHTGREEN_EX}Exported {len(findings)} findings to {output_path}")
    return output_path


def sanitize_literal(s: str) -> str:
    """Sanitize a string literal for safe use in queries.

    Removes pipe characters, newlines, and semicolons that could
    interfere with query syntax.

    Args:
        s: The string to sanitize.

    Returns:
        str: The sanitized string.
    """
    return str(s).replace("|", " ").replace("\n", " ").replace(";", " ")


def sanitize_query_context(query_context):
    """Sanitize query context dictionary for safe use in queries.

    Ensures all required keys exist with default empty values and
    sanitizes string values that could interfere with query syntax.

    Args:
        query_context: Dictionary containing query context parameters.

    Returns:
        dict: The sanitized query context dictionary.
    """
    if "caller" not in query_context:
        query_context["caller"] = ""

    if "device_name" not in query_context:
        query_context["device_name"] = ""

    if "user_principal_name" not in query_context:
        query_context["user_principal_name"] = ""

    if "device_name" in query_context:
        query_context["device_name"] = sanitize_literal(query_context["device_name"])

    if "caller" in query_context:
        query_context["caller"] = sanitize_literal(query_context["caller"])

    if "user_principal_name" in query_context:
        query_context["user_principal_name"] = sanitize_literal(
            query_context["user_principal_name"]
        )

    query_context["fields"] = ", ".join(query_context["fields"])

    return query_context
