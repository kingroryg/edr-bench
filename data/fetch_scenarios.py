#!/usr/bin/env python3
"""
Fetch the Coach Decision Taxonomy from Google Sheets and turn it into
edr-bench scenario CSVs.

Run from the project root:
    python data/fetch_scenarios.py

Use --skip-fetch if you already have the reference CSVs and just want
to regenerate the scenario files:
    python data/fetch_scenarios.py --skip-fetch
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

# Everything is relative to the repo root (parent of data/)
REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "data"
REF_DIR = DATA_DIR / "reference"
SCENARIO_DIR = DATA_DIR / "scenarios"

GCLOUD_BIN = "/opt/homebrew/share/google-cloud-sdk/bin/gcloud"

# ---------------------------------------------------------------------------
# Spreadsheet details
# ---------------------------------------------------------------------------

SPREADSHEET_ID = "1sAwdKRSGW3A-LBHMfuqQ1EieRvzKtw8I7T4jN4tlR7A"

SHEETS: list[dict] = [
    {
        "name": "Decision Taxonomy",
        "gid": "1377205039",
        "file": "decision_taxonomy.csv",
    },
    {
        "name": "Testbed Infrastructure",
        "gid": "696842453",
        "file": "testbed_infrastructure.csv",
    },
    {
        "name": "MITRE ATT&CK Map",
        "gid": "1104481129",
        "file": "mitre_attack_map.csv",
    },
    {
        "name": "Role × Category Matrix",
        "gid": "1339591276",
        "file": "role_category_matrix.csv",
    },
]

# ---------------------------------------------------------------------------
# Mapping tables
# ---------------------------------------------------------------------------

# T-code -> attack_type  (first match wins if a scenario has multiple codes)
TCODE_TO_ATTACK: dict[str, str] = {
    "T1115": "collection",
    "T1113": "collection",
    "T1005": "collection",
    "T1213": "collection",
    "T1114": "collection",
    "T1074": "collection",
    "T1039": "collection",
    "T1567": "exfiltration",
    "T1048": "exfiltration",
    "T1052": "exfiltration",
    "T1011": "exfiltration",
    "T1029": "exfiltration",
    "T1030": "exfiltration",
    "T1020": "exfiltration",
    "T1537": "exfiltration",
    "T1091": "exfiltration",
    "T1552": "credential_access",
    "T1528": "credential_access",
    "T1056": "credential_access",
    "T1621": "credential_access",
    "T1040": "credential_access",
    "T1550": "credential_access",
    "T1557": "credential_access",
    "T1176": "persistence",
    "T1098": "persistence",
    "T1136": "persistence",
    "T1195": "initial_access",
    "T1566": "initial_access",
    "T1190": "initial_access",
    "T1534": "initial_access",
    "T1598": "initial_access",
    "T1078": "defense_evasion",
    "T1562": "defense_evasion",
    "T1070": "defense_evasion",
    "T1059": "execution",
    "T1204": "execution",
    "T1071": "command_and_control",
    "T1082": "discovery",
    "T1485": "impact",
}

DEFAULT_ATTACK = "collection"

# Category string in the spreadsheet -> CoachCategory enum value
CATEGORY_MAP: dict[str, str] = {
    "Data Leak → AI": "ai_data_leak",
    "Data Leak → Sharing": "file_sharing",
    "Data Leak → Exfil": "exfil_vectors",
    "Secret Exposure": "secret_exposure",
    "Untrusted SW": "untrusted_software",
    "Access Mgmt": "access_management",
    "Authentication": "auth_phishing",
    "Social Engineering": "social_engineering",
    "AI Agent/MCP": "ai_agent_mcp",
    "Config/Posture": "config_posture",
    "Network": "network",
    "Insider Threat": "insider_threat",
}

# Risk column -> complexity
RISK_TO_COMPLEXITY: dict[str, str] = {
    "CRITICAL": "high",
    "HIGH": "medium",
    "MEDIUM": "low",
}

# Which categories go into which output file
CATEGORY_TO_FILE: dict[str, str] = {
    "ai_data_leak": "coach_ai_leak.csv",
    "file_sharing": "coach_sharing.csv",
    "exfil_vectors": "coach_exfil.csv",
    "secret_exposure": "coach_secrets.csv",
    "untrusted_software": "coach_untrusted_sw.csv",
    "access_management": "coach_access_mgmt.csv",
    "auth_phishing": "coach_auth_social.csv",
    "social_engineering": "coach_auth_social.csv",
    "ai_agent_mcp": "coach_ai_agent.csv",
    "config_posture": "coach_config_network.csv",
    "network": "coach_config_network.csv",
    "insider_threat": "coach_config_network.csv",
}

# The columns we write into every scenario CSV
SCENARIO_COLUMNS = [
    "id",
    "name",
    "description",
    "platform",
    "attack_type",
    "mitre_technique_id",
    "mitre_technique_name",
    "complexity",
    "simulation_steps",
    "expected_detections",
    "tags",
    "category",
    "sub_category",
    "risk_level",
    "deploy_surfaces",
    "coach_intervention",
    "success_metric",
    "priority",
    "test_data",
    "target_roles",
    "third_party_systems",
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def get_access_token() -> str:
    """Get a fresh OAuth2 token from gcloud."""
    try:
        result = subprocess.run(
            [GCLOUD_BIN, "auth", "print-access-token"],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except FileNotFoundError:
        print(f"ERROR: gcloud not found at {GCLOUD_BIN}", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as exc:
        print(f"ERROR: gcloud auth failed: {exc.stderr}", file=sys.stderr)
        sys.exit(1)


def fetch_sheet_csv(sheet_id: str, gid: str, token: str) -> str:
    """Download a single sheet as CSV text."""
    url = (
        f"https://docs.google.com/spreadsheets/d/{sheet_id}"
        f"/export?format=csv&gid={gid}"
    )
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8-sig")  # strip BOM if present
    except urllib.error.HTTPError as exc:
        print(f"ERROR: HTTP {exc.code} fetching gid={gid}: {exc.reason}", file=sys.stderr)
        sys.exit(1)


def safe_strip(value: str | None) -> str:
    """Strip whitespace, return empty string for None."""
    return (value or "").strip()


# ---------------------------------------------------------------------------
# Extraction helpers for individual fields
# ---------------------------------------------------------------------------

_TCODE_RE = re.compile(r"T\d{4}(?:\.\d{3})?")


def extract_tcode(mitre_cell: str) -> str:
    """Pull the first T-code out of the MITRE ATT&CK column."""
    m = _TCODE_RE.search(mitre_cell)
    return m.group(0) if m else ""


def extract_technique_name(mitre_cell: str) -> str:
    """Try to grab the human-readable name from parentheses, e.g. '(Phishing)'."""
    m = re.search(r"\(([^)]+)\)", mitre_cell)
    if m:
        return m.group(1).strip()
    # Fall back to the T-code itself
    return extract_tcode(mitre_cell)


def tcode_to_attack_type(tcode: str) -> str:
    """Map a T-code to an attack_type string."""
    # Try the full code first (e.g. T1059.001), then the base (T1059)
    if tcode in TCODE_TO_ATTACK:
        return TCODE_TO_ATTACK[tcode]
    base = tcode.split(".")[0] if "." in tcode else tcode
    if base in TCODE_TO_ATTACK:
        return TCODE_TO_ATTACK[base]
    return DEFAULT_ATTACK


def map_category(raw: str) -> str:
    """Turn the spreadsheet category into a CoachCategory value."""
    raw = raw.strip()
    # Try exact match first
    if raw in CATEGORY_MAP:
        return CATEGORY_MAP[raw]
    # Try a loose match (the sheet might use slightly different arrows, etc.)
    raw_lower = raw.lower()
    for key, val in CATEGORY_MAP.items():
        if key.lower() in raw_lower or raw_lower in key.lower():
            return val
    # Give up gracefully
    return raw.lower().replace(" ", "_")


def map_deploy_surfaces(raw: str) -> list[str]:
    """Parse the Deploy Surface column into a list of enum-friendly strings."""
    if not raw.strip():
        return []
    surfaces: list[str] = []
    # Split on '+' or ',' so "Browser Ext + Desktop Agent" works
    parts = re.split(r"[+,]", raw)
    for part in parts:
        p = part.strip().lower()
        if "browser" in p:
            surfaces.append("browser_extension")
        elif "desktop" in p:
            surfaces.append("desktop_agent")
        elif "ide" in p:
            surfaces.append("ide_plugin")
        elif "cli" in p:
            surfaces.append("cli_hook")
        elif "email" in p:
            surfaces.append("email_plugin")
        elif "slack" in p:
            surfaces.append("slack_bot")
        elif "mobile" in p:
            surfaces.append("mobile_agent")
        elif p:
            # Unknown surface, keep it as-is with underscores
            surfaces.append(re.sub(r"\s+", "_", p))
    return surfaces


def determine_step_role(deploy_surface: str) -> str:
    """Pick the default step role based on the deploy surface."""
    ds = deploy_surface.lower()
    if "cli" in ds:
        return "cli"
    # Everything else (browser, desktop GUI, IDE) is a UI interaction
    return "ui"


def parse_simulation_steps(steps_text: str, deploy_surface: str) -> str:
    """Turn the numbered-steps text into a JSON array of step objects."""
    if not steps_text.strip():
        return "[]"

    role = determine_step_role(deploy_surface)

    # Match lines that start with a number followed by a dot or paren
    lines = re.split(r"\n(?=\d+[\.\)])", steps_text.strip())
    steps: list[dict] = []
    for i, line in enumerate(lines, start=1):
        # Strip leading number + punctuation
        desc = re.sub(r"^\d+[\.\)]\s*", "", line).strip()
        if not desc:
            continue
        step = {
            "order": i,
            "role": role,
            "description": desc,
            "ui_instructions": desc if role == "ui" else None,
            "expected_artifact": None,
            "timeout_seconds": 60,
        }
        steps.append(step)

    # If we didn't manage to parse any numbered steps, treat the whole
    # block as a single step so we don't lose data.
    if not steps and steps_text.strip():
        steps.append(
            {
                "order": 1,
                "role": role,
                "description": steps_text.strip(),
                "ui_instructions": steps_text.strip() if role == "ui" else None,
                "expected_artifact": None,
                "timeout_seconds": 60,
            }
        )

    return json.dumps(steps)


def split_list(value: str) -> str:
    """Split a comma-separated string into a JSON array."""
    if not value.strip():
        return "[]"
    parts = [p.strip() for p in value.split(",") if p.strip()]
    return json.dumps(parts)


# ---------------------------------------------------------------------------
# Main transform: one taxonomy row -> one scenario dict
# ---------------------------------------------------------------------------


def row_to_scenario(row: dict[str, str]) -> dict[str, str]:
    """Convert a single Decision Taxonomy row into a scenario dict."""

    # Grab raw values (column names come straight from the sheet header)
    raw_id = safe_strip(row.get("ID", ""))
    raw_category = safe_strip(row.get("Category", ""))
    raw_sub = safe_strip(row.get("Sub-Category", ""))
    raw_roles = safe_strip(row.get("Role(s)", ""))
    raw_name = safe_strip(row.get("Decision / Scenario", ""))
    raw_desc = safe_strip(row.get("What the User Does", ""))
    raw_risk = safe_strip(row.get("Risk", ""))
    raw_mitre = safe_strip(row.get("MITRE ATT&CK", ""))
    raw_deploy = safe_strip(row.get("Deploy Surface", ""))
    raw_coach = safe_strip(row.get("Coach Intervention", ""))
    raw_metric = safe_strip(row.get("Success Metric", ""))
    raw_priority = safe_strip(row.get("Priority", ""))
    raw_test_data = safe_strip(row.get("Test Data / Fixtures", ""))
    raw_third = safe_strip(row.get("Third-Party Systems for Test", ""))
    raw_steps = safe_strip(row.get("Testbed Simulation Steps", ""))

    # Build the scenario id like COACH-001
    try:
        numeric_id = int(raw_id)
        scenario_id = f"COACH-{numeric_id:03d}"
    except (ValueError, TypeError):
        scenario_id = f"COACH-{raw_id}" if raw_id else "COACH-???"

    tcode = extract_tcode(raw_mitre)
    category = map_category(raw_category)
    sub_category = raw_sub.lower().replace(" ", "_") if raw_sub else ""

    risk_lower = raw_risk.strip().lower()
    complexity = RISK_TO_COMPLEXITY.get(raw_risk.strip().upper(), "low")

    deploy_surfaces = map_deploy_surfaces(raw_deploy)

    # Tags are a grab-bag of useful labels
    tags_list: list[str] = []
    if category:
        tags_list.append(category)
    if sub_category:
        tags_list.append(sub_category)
    if raw_priority:
        tags_list.append(raw_priority)
    for ds in deploy_surfaces:
        tags_list.append(ds)

    return {
        "id": scenario_id,
        "name": raw_name,
        "description": raw_desc,
        "platform": "linux",
        "attack_type": tcode_to_attack_type(tcode),
        "mitre_technique_id": tcode,
        "mitre_technique_name": extract_technique_name(raw_mitre),
        "complexity": complexity,
        "simulation_steps": parse_simulation_steps(raw_steps, raw_deploy),
        "expected_detections": json.dumps([raw_coach]) if raw_coach else "[]",
        "tags": json.dumps(tags_list),
        "category": category,
        "sub_category": sub_category,
        "risk_level": risk_lower if risk_lower else "",
        "deploy_surfaces": json.dumps(deploy_surfaces),
        "coach_intervention": raw_coach,
        "success_metric": raw_metric,
        "priority": raw_priority,
        "test_data": raw_test_data,
        "target_roles": split_list(raw_roles),
        "third_party_systems": split_list(raw_third),
    }


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def fetch_all_sheets() -> None:
    """Download every sheet from Google Sheets and save to data/reference/."""
    REF_DIR.mkdir(parents=True, exist_ok=True)
    token = get_access_token()
    print(f"Got access token ({token[:8]}...)")

    for sheet in SHEETS:
        print(f"  Fetching '{sheet['name']}' (gid={sheet['gid']}) ... ", end="")
        csv_text = fetch_sheet_csv(SPREADSHEET_ID, sheet["gid"], token)
        dest = REF_DIR / sheet["file"]
        dest.write_text(csv_text, encoding="utf-8")
        # Quick sanity check: count rows (minus header)
        row_count = csv_text.count("\n")
        print(f"{row_count} lines -> {dest.relative_to(REPO_ROOT)}")


def generate_scenarios() -> None:
    """Read decision_taxonomy.csv and write per-category scenario CSVs."""
    taxonomy_path = REF_DIR / "decision_taxonomy.csv"
    if not taxonomy_path.exists():
        print(f"ERROR: {taxonomy_path} not found. Run without --skip-fetch first.", file=sys.stderr)
        sys.exit(1)

    # Read all rows from the taxonomy
    with taxonomy_path.open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    print(f"\nRead {len(rows)} rows from decision taxonomy.")

    # Convert each row and bucket by output file
    buckets: dict[str, list[dict[str, str]]] = {}
    skipped = 0

    for row in rows:
        raw_id = safe_strip(row.get("ID", ""))
        raw_name = safe_strip(row.get("Decision / Scenario", ""))

        # Skip rows that look like section headers or are blank
        if not raw_id or not raw_name:
            skipped += 1
            continue

        scenario = row_to_scenario(row)
        category = scenario["category"]
        out_file = CATEGORY_TO_FILE.get(category)
        if not out_file:
            # If we can't figure out the file, put it in config_network as a catch-all
            out_file = "coach_config_network.csv"

        buckets.setdefault(out_file, []).append(scenario)

    if skipped:
        print(f"  Skipped {skipped} rows (blank or header-like).")

    # Write each bucket to its own CSV
    SCENARIO_DIR.mkdir(parents=True, exist_ok=True)
    total_written = 0
    for filename, scenarios in sorted(buckets.items()):
        dest = SCENARIO_DIR / filename
        with dest.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=SCENARIO_COLUMNS)
            writer.writeheader()
            writer.writerows(scenarios)
        total_written += len(scenarios)
        print(f"  Wrote {len(scenarios):3d} scenarios -> {dest.relative_to(REPO_ROOT)}")

    print(f"\nDone! {total_written} total scenarios across {len(buckets)} files.")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fetch Coach Decision Taxonomy and generate edr-bench scenario CSVs."
    )
    parser.add_argument(
        "--skip-fetch",
        action="store_true",
        help="Don't fetch from Google Sheets; just regenerate CSVs from existing reference data.",
    )
    args = parser.parse_args()

    if not args.skip_fetch:
        print("Fetching sheets from Google Sheets...\n")
        fetch_all_sheets()
    else:
        print("Skipping fetch (using existing reference data).\n")

    generate_scenarios()


if __name__ == "__main__":
    main()
