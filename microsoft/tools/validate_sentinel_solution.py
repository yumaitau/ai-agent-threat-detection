#!/usr/bin/env python3
"""Offline validator for:
  1. Microsoft Sentinel Content Hub V3 Solution layout (Solutions/YumaAIAgentThreatDetection/)
  2. Azure-Sentinel YAML schemas (Analytic Rules, Hunting Queries, Parsers)
  3. ARM templates (Package/mainTemplate.json, Playbooks, microsoft/deploy/azuredeploy.json)
  4. Portal UI definition (Package/createUiDefinition.json) parameter parity
  5. Defender XDR custom detection rules (defender-xdr/rules/*.json and defender-xdr/queries/*.kql)

Optionally writes extracted KQL queries to --extract-kql-dir so kqlcheck.js can
parse and semantically bind every embedded query against microsoft/tools/schemas.json.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import uuid
from typing import Any

import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
SOL_DIR_NAME = "YumaAIAgentThreatDetection"
SOL_ROOT = REPO_ROOT / "Solutions" / SOL_DIR_NAME
XDR_ROOT = REPO_ROOT / "defender-xdr"
AZUREDEPLOY_PATH = REPO_ROOT / "microsoft" / "deploy" / "azuredeploy.json"

VALID_SEVERITIES = {"Informational", "Low", "Medium", "High"}
VALID_TACTICS = {
    "Reconnaissance",
    "ResourceDevelopment",
    "InitialAccess",
    "Execution",
    "Persistence",
    "PrivilegeEscalation",
    "DefenseEvasion",
    "CredentialAccess",
    "Discovery",
    "LateralMovement",
    "Collection",
    "CommandAndControl",
    "Exfiltration",
    "Impact",
}
VALID_ENTITY_TYPES = {
    "Account",
    "Host",
    "IP",
    "Malware",
    "File",
    "Process",
    "CloudApplication",
    "DNS",
    "AzureResource",
    "FileHash",
    "RegistryKey",
    "RegistryValue",
    "SecurityGroup",
    "URL",
    "IoTDevice",
    "SecurityAlert",
    "MailCluster",
    "MailMessage",
    "Mailbox",
    "SubmissionMail",
    "NIC",
}
VALID_OPERATORS = {"gt", "lt", "eq", "ne"}
VALID_XDR_FREQUENCIES = {"PT1H", "PT3H", "PT12H", "P1D", "NRT"}
VALID_XDR_SEVERITIES = {"informational", "low", "medium", "high"}
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
DURATION_RE = re.compile(r"^(\d+)([mhd])$")
ISO_DURATION_RE = re.compile(r"^P(?:(\d+)D)?(?:T(?:(\d+)H)?(?:(\d+)M)?)?$")
ARM_SCHEMA_PREFIX = "https://schema.management.azure.com/schemas/"


def parse_guid(value: Any, label: str, errors: list[str], seen_ids: dict[str, str]) -> None:
    if not isinstance(value, str):
        errors.append(f"{label}: id must be a string GUID")
        return
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        errors.append(f"{label}: invalid GUID '{value}'")
        return
    canonical = str(parsed)
    if canonical in seen_ids:
        errors.append(f"{label}: duplicate GUID '{canonical}' (also used by {seen_ids[canonical]})")
    else:
        seen_ids[canonical] = label


def duration_minutes(value: Any, label: str, field: str, errors: list[str]) -> int | None:
    if not isinstance(value, str):
        errors.append(f"{label}: {field} must be a duration string (e.g. 1h, 14d)")
        return None
    m = DURATION_RE.fullmatch(value)
    if not m:
        errors.append(f"{label}: invalid {field} '{value}'")
        return None
    amount = int(m.group(1))
    unit = m.group(2)
    mult = {"m": 1, "h": 60, "d": 1440}[unit]
    return amount * mult


def validate_entity_mappings(mappings: Any, label: str, errors: list[str]) -> None:
    if not isinstance(mappings, list) or not mappings:
        errors.append(f"{label}: entityMappings must be a non-empty list")
        return
    for i, entry in enumerate(mappings):
        if not isinstance(entry, dict):
            errors.append(f"{label}: entityMappings[{i}] must be an object")
            continue
        etype = entry.get("entityType")
        if etype not in VALID_ENTITY_TYPES:
            errors.append(f"{label}: entityMappings[{i}] has invalid entityType '{etype}'")
        fms = entry.get("fieldMappings")
        if not isinstance(fms, list) or not fms:
            errors.append(f"{label}: entityMappings[{i}] must have non-empty fieldMappings")
            continue
        for j, fm in enumerate(fms):
            if not isinstance(fm, dict) or not fm.get("identifier") or not fm.get("columnName"):
                errors.append(f"{label}: entityMappings[{i}].fieldMappings[{j}] requires identifier and columnName")


def validate_connectors(connectors: Any, label: str, errors: list[str]) -> None:
    if not isinstance(connectors, list) or not connectors:
        errors.append(f"{label}: requiredDataConnectors must be a non-empty list")
        return
    for i, conn in enumerate(connectors):
        if not isinstance(conn, dict):
            errors.append(f"{label}: requiredDataConnectors[{i}] must be an object")
            continue
        if not conn.get("connectorId"):
            errors.append(f"{label}: requiredDataConnectors[{i}] missing connectorId")
        dtypes = conn.get("dataTypes")
        if not isinstance(dtypes, list) or not dtypes:
            errors.append(f"{label}: requiredDataConnectors[{i}] requires non-empty dataTypes list")


def validate_arm_template(path: pathlib.Path, errors: list[str], required_params: set[str] | None = None) -> dict[str, Any]:
    rel = str(path.relative_to(REPO_ROOT))
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"{rel}: JSON parse error: {exc}")
        return {}
    if not isinstance(doc, dict):
        errors.append(f"{rel}: ARM template root must be a JSON object")
        return {}
    schema = doc.get("$schema", "")
    if not isinstance(schema, str) or not schema.startswith(ARM_SCHEMA_PREFIX):
        errors.append(f"{rel}: invalid or missing ARM $schema '{schema}'")
    if not isinstance(doc.get("contentVersion"), str) or not doc["contentVersion"]:
        errors.append(f"{rel}: missing contentVersion")
    resources = doc.get("resources")
    if not isinstance(resources, list) or not resources:
        errors.append(f"{rel}: resources must be a non-empty list")
    else:
        for i, res in enumerate(resources):
            if not isinstance(res, dict):
                errors.append(f"{rel}: resources[{i}] must be an object")
                continue
            for key in ("type", "apiVersion", "name"):
                if not res.get(key):
                    errors.append(f"{rel}: resources[{i}] missing '{key}'")
            loc = res.get("location")
            if isinstance(loc, str) and not loc.startswith("["):
                errors.append(f"{rel}: resources[{i}] has hardcoded location '{loc}'")
    params = doc.get("parameters", {})
    if not isinstance(params, dict):
        errors.append(f"{rel}: parameters must be an object")
        params = {}
    if required_params:
        missing = required_params - set(params.keys())
        if missing:
            errors.append(f"{rel}: missing required parameters {sorted(missing)}")
    return doc


def validate_solution(errors: list[str], extract_dir: pathlib.Path | None) -> int:
    seen_ids: dict[str, str] = {}
    extracted = 0

    data_path = SOL_ROOT / "Data" / f"Solution_{SOL_DIR_NAME}.json"
    meta_path = SOL_ROOT / "SolutionMetadata.json"
    if not data_path.exists():
        errors.append(f"Missing solution manifest: {data_path.relative_to(REPO_ROOT)}")
        return 0
    if not meta_path.exists():
        errors.append(f"Missing solution metadata: {meta_path.relative_to(REPO_ROOT)}")
        return 0

    sol_data = json.loads(data_path.read_text(encoding="utf-8"))
    sol_meta = json.loads(meta_path.read_text(encoding="utf-8"))

    for key in ("Name", "Author", "Description", "BasePath", "Version", "Metadata"):
        if not sol_data.get(key):
            errors.append(f"{data_path.relative_to(REPO_ROOT)}: missing required key '{key}'")
    if not SEMVER_RE.fullmatch(str(sol_data.get("Version", ""))):
        errors.append(f"{data_path.relative_to(REPO_ROOT)}: Version must be semver")
    for key in ("publisherId", "offerId", "firstPublishDate", "providers", "categories", "support", "version"):
        if not sol_meta.get(key):
            errors.append(f"{meta_path.relative_to(REPO_ROOT)}: missing required key '{key}'")

    # Analytic Rules
    analytic_ids: set[str] = set()
    for rel in sol_data.get("Analytic Rules", []):
        path = SOL_ROOT / rel
        label = str(path.relative_to(REPO_ROOT))
        if not path.exists():
            errors.append(f"Solution manifest references missing file: {label}")
            continue
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        parse_guid(doc.get("id"), label, errors, seen_ids)
        if isinstance(doc.get("id"), str):
            analytic_ids.add(doc["id"])
        for req in ("name", "description", "query", "version", "kind"):
            if not doc.get(req):
                errors.append(f"{label}: missing '{req}'")
        if doc.get("kind") != "Scheduled":
            errors.append(f"{label}: kind must be 'Scheduled'")
        if doc.get("severity") not in VALID_SEVERITIES:
            errors.append(f"{label}: invalid severity '{doc.get('severity')}'")
        if not SEMVER_RE.fullmatch(str(doc.get("version", ""))):
            errors.append(f"{label}: version must be semver")
        validate_connectors(doc.get("requiredDataConnectors"), label, errors)
        freq = duration_minutes(doc.get("queryFrequency"), label, "queryFrequency", errors)
        period = duration_minutes(doc.get("queryPeriod"), label, "queryPeriod", errors)
        if freq is not None and period is not None:
            if freq < 5 or freq > 14 * 1440:
                errors.append(f"{label}: queryFrequency ({doc.get('queryFrequency')}) must be between 5m and 14d")
            if period < 5 or period > 14 * 1440:
                errors.append(f"{label}: queryPeriod ({doc.get('queryPeriod')}) must be between 5m and 14d")
            if period < freq:
                errors.append(f"{label}: queryPeriod ({doc.get('queryPeriod')}) must be >= queryFrequency ({doc.get('queryFrequency')})")
        if doc.get("triggerOperator") not in VALID_OPERATORS:
            errors.append(f"{label}: invalid triggerOperator '{doc.get('triggerOperator')}'")
        if not isinstance(doc.get("triggerThreshold"), int) or doc["triggerThreshold"] < 0:
            errors.append(f"{label}: triggerThreshold must be a non-negative integer")
        tactics = doc.get("tactics")
        if not isinstance(tactics, list) or not tactics or any(t not in VALID_TACTICS for t in tactics):
            errors.append(f"{label}: invalid tactics {tactics}")
        techs = doc.get("relevantTechniques", [])
        if not isinstance(techs, list) or any(not TECHNIQUE_RE.fullmatch(str(t)) for t in techs):
            errors.append(f"{label}: invalid relevantTechniques {techs}")
        validate_entity_mappings(doc.get("entityMappings"), label, errors)
        if extract_dir and isinstance(doc.get("query"), str):
            (extract_dir / f"solution_ar_{path.stem}.kql").write_text(doc["query"], encoding="utf-8")
            extracted += 1

    # Hunting Queries
    hunting_ids: set[str] = set()
    for rel in sol_data.get("Hunting Queries", []):
        path = SOL_ROOT / rel
        label = str(path.relative_to(REPO_ROOT))
        if not path.exists():
            errors.append(f"Solution manifest references missing file: {label}")
            continue
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        parse_guid(doc.get("id"), label, errors, seen_ids)
        if isinstance(doc.get("id"), str):
            hunting_ids.add(doc["id"])
        for req in ("name", "description", "query", "version"):
            if not doc.get(req):
                errors.append(f"{label}: missing '{req}'")
        if not SEMVER_RE.fullmatch(str(doc.get("version", ""))):
            errors.append(f"{label}: version must be semver")
        validate_connectors(doc.get("requiredDataConnectors"), label, errors)
        tactics = doc.get("tactics")
        if not isinstance(tactics, list) or not tactics or any(t not in VALID_TACTICS for t in tactics):
            errors.append(f"{label}: invalid tactics {tactics}")
        techs = doc.get("relevantTechniques", [])
        if not isinstance(techs, list) or any(not TECHNIQUE_RE.fullmatch(str(t)) for t in techs):
            errors.append(f"{label}: invalid relevantTechniques {techs}")
        validate_entity_mappings(doc.get("entityMappings"), label, errors)
        if extract_dir and isinstance(doc.get("query"), str):
            (extract_dir / f"solution_hq_{path.stem}.kql").write_text(doc["query"], encoding="utf-8")
            extracted += 1

    # Parsers
    parser_ids: set[str] = set()
    for rel in sol_data.get("Parsers", []):
        path = SOL_ROOT / rel
        label = str(path.relative_to(REPO_ROOT))
        if not path.exists():
            errors.append(f"Solution manifest references missing file: {label}")
            continue
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        parse_guid(doc.get("id"), label, errors, seen_ids)
        if isinstance(doc.get("id"), str):
            parser_ids.add(doc["id"])
        fn = doc.get("Function", {})
        if not isinstance(fn, dict) or not fn.get("Title") or not fn.get("Version"):
            errors.append(f"{label}: Function.Title and Function.Version are required")
        for req in ("Category", "FunctionName", "FunctionAlias", "FunctionQuery"):
            if not doc.get(req):
                errors.append(f"{label}: missing '{req}'")
        if extract_dir and isinstance(doc.get("FunctionQuery"), str):
            (extract_dir / f"solution_parser_{path.stem}.kql").write_text(doc["FunctionQuery"], encoding="utf-8")
            extracted += 1

    # Workbooks
    for rel in sol_data.get("Workbooks", []):
        path = SOL_ROOT / rel
        label = str(path.relative_to(REPO_ROOT))
        if not path.exists():
            errors.append(f"Solution manifest references missing file: {label}")
            continue
        wb = json.loads(path.read_text(encoding="utf-8"))
        if wb.get("version") != "Notebook/1.0" or not isinstance(wb.get("items"), list) or not wb["items"]:
            errors.append(f"{label}: workbook must have version 'Notebook/1.0' and non-empty items")

    # Playbooks
    for rel in sol_data.get("Playbooks", []):
        path = SOL_ROOT / rel
        if not path.exists():
            errors.append(f"Solution manifest references missing file: {path.relative_to(REPO_ROOT)}")
            continue
        validate_arm_template(path, errors)

    # Package/mainTemplate.json
    main_tpl_path = SOL_ROOT / "Package" / "mainTemplate.json"
    main_tpl = validate_arm_template(
        main_tpl_path, errors, required_params={"workspace", "workspace-location", "location"}
    )
    if main_tpl:
        resources = main_tpl.get("resources", [])
        packages = [r for r in resources if r.get("type") == "Microsoft.OperationalInsights/workspaces/providers/contentPackages"]
        templates = [r for r in resources if r.get("type") == "Microsoft.OperationalInsights/workspaces/providers/contentTemplates"]
        if len(packages) != 1:
            errors.append(f"{main_tpl_path.relative_to(REPO_ROOT)}: expected exactly 1 contentPackages resource, found {len(packages)}")
        else:
            pkg_props = packages[0].get("properties", {})
            if pkg_props.get("contentSchemaVersion") != "3.0.0":
                errors.append(f"{main_tpl_path.relative_to(REPO_ROOT)}: contentPackages contentSchemaVersion must be 3.0.0")
            dep_ids = {(c["kind"], c["contentId"]) for c in pkg_props.get("dependencies", {}).get("criteria", [])}
            tpl_ids = {
                (t.get("properties", {}).get("contentKind"), t.get("properties", {}).get("contentId"))
                for t in templates
            }
            if dep_ids != tpl_ids:
                errors.append(
                    f"{main_tpl_path.relative_to(REPO_ROOT)}: contentPackages dependencies mismatch contentTemplates "
                    f"(missing={sorted(dep_ids - tpl_ids)}, extra={sorted(tpl_ids - dep_ids)})"
                )
            packaged_ar = {cid for kind, cid in tpl_ids if kind == "AnalyticsRule"}
            packaged_hq = {cid for kind, cid in tpl_ids if kind == "HuntingQuery"}
            packaged_pr = {cid for kind, cid in tpl_ids if kind == "Parser"}
            if packaged_ar != analytic_ids:
                errors.append(f"{main_tpl_path.relative_to(REPO_ROOT)}: AnalyticsRule IDs in mainTemplate do not match YAML rules")
            if packaged_hq != hunting_ids:
                errors.append(f"{main_tpl_path.relative_to(REPO_ROOT)}: HuntingQuery IDs in mainTemplate do not match YAML queries")
            if packaged_pr != parser_ids:
                errors.append(f"{main_tpl_path.relative_to(REPO_ROOT)}: Parser IDs in mainTemplate do not match YAML parsers")
            for idx, tpl in enumerate(templates):
                props = tpl.get("properties", {})
                inner = props.get("mainTemplate")
                if not isinstance(inner, dict):
                    errors.append(f"{main_tpl_path.relative_to(REPO_ROOT)}: contentTemplates[{idx}] missing mainTemplate object")
                    continue
                if not str(inner.get("$schema", "")).startswith(ARM_SCHEMA_PREFIX):
                    errors.append(f"{main_tpl_path.relative_to(REPO_ROOT)}: contentTemplates[{idx}] invalid embedded $schema")
                if not re.fullmatch(r"\d+\.\d+\.\d+\.\d+", str(inner.get("contentVersion", ""))):
                    errors.append(
                        f"{main_tpl_path.relative_to(REPO_ROOT)}: contentTemplates[{idx}] embedded contentVersion must be four-part numeric"
                    )
                if not isinstance(inner.get("resources"), list) or not inner["resources"]:
                    errors.append(f"{main_tpl_path.relative_to(REPO_ROOT)}: contentTemplates[{idx}] embedded mainTemplate has empty resources")
                if props.get("contentKind") == "Playbook":
                    inner_json = json.dumps(inner)
                    if re.search(r'"\[(?!\[)(?:parameters|variables|resourceGroup|subscription|resourceId|reference|concat)\(', inner_json):
                        errors.append(
                            f"{main_tpl_path.relative_to(REPO_ROOT)}: contentTemplates[{idx}] playbook mainTemplate contains unescaped ARM expression"
                        )

    # Package/createUiDefinition.json
    ui_path = SOL_ROOT / "Package" / "createUiDefinition.json"
    if not ui_path.exists():
        errors.append(f"Missing {ui_path.relative_to(REPO_ROOT)}")
    else:
        ui = json.loads(ui_path.read_text(encoding="utf-8"))
        if ui.get("handler") != "Microsoft.Azure.CreateUIDef":
            errors.append(f"{ui_path.relative_to(REPO_ROOT)}: handler must be Microsoft.Azure.CreateUIDef")
        outputs = ui.get("parameters", {}).get("outputs", {})
        if not isinstance(outputs, dict) or "workspace" not in outputs:
            errors.append(f"{ui_path.relative_to(REPO_ROOT)}: parameters.outputs must expose 'workspace'")
        if main_tpl:
            tpl_params = set(main_tpl.get("parameters", {}).keys())
            unknown_outputs = set(outputs.keys()) - tpl_params
            if unknown_outputs:
                errors.append(
                    f"{ui_path.relative_to(REPO_ROOT)}: outputs not present in mainTemplate.json parameters: {sorted(unknown_outputs)}"
                )

    return extracted


def validate_azuredeploy(errors: list[str]) -> None:
    if not AZUREDEPLOY_PATH.exists():
        errors.append(f"Missing {AZUREDEPLOY_PATH.relative_to(REPO_ROOT)}")
        return
    validate_arm_template(AZUREDEPLOY_PATH, errors, required_params={"workspaceName", "location"})


def validate_defender_xdr(errors: list[str], extract_dir: pathlib.Path | None) -> int:
    extracted = 0
    readme = XDR_ROOT / "README.md"
    rules_dir = XDR_ROOT / "rules"
    queries_dir = XDR_ROOT / "queries"
    if not readme.exists():
        errors.append("Missing defender-xdr/README.md")
    rule_files = sorted(rules_dir.glob("*.json")) if rules_dir.exists() else []
    if not rule_files:
        errors.append("No Defender XDR custom detection JSON rules found under defender-xdr/rules/")
    for path in rule_files:
        label = str(path.relative_to(REPO_ROOT))
        doc = json.loads(path.read_text(encoding="utf-8"))
        for key in ("id", "displayName", "status", "queryCondition", "schedule", "detectionAction"):
            if key not in doc:
                errors.append(f"{label}: missing required field '{key}'")
        if doc.get("status") != "disabled":
            errors.append(f"{label}: custom detection rules must default to status 'disabled'")
        freq = doc.get("schedule", {}).get("frequency")
        if freq not in VALID_XDR_FREQUENCIES:
            errors.append(f"{label}: invalid schedule.frequency '{freq}'")
        qtext = doc.get("queryCondition", {}).get("queryText", "")
        if not isinstance(qtext, str) or not qtext.strip():
            errors.append(f"{label}: empty queryCondition.queryText")
        else:
            if "Timestamp" not in qtext or "ReportId" not in qtext:
                errors.append(f"{label}: Defender XDR custom detection query must return Timestamp and ReportId")
            companion_kql = queries_dir / f"{path.stem}.kql"
            if not companion_kql.exists():
                errors.append(f"{label}: missing companion KQL file {companion_kql.relative_to(REPO_ROOT)}")
            else:
                # Strip leading // comments from companion KQL and verify parity with embedded queryText
                raw_lines = companion_kql.read_text(encoding="utf-8").splitlines()
                while raw_lines and raw_lines[0].startswith("//"):
                    raw_lines.pop(0)
                companion_body = "\n".join(raw_lines).strip()
                if companion_body != qtext.strip():
                    errors.append(f"{label}: queryCondition.queryText differs from {companion_kql.relative_to(REPO_ROOT)}")
            if extract_dir:
                (extract_dir / f"xdr_rule_{path.stem}.kql").write_text(qtext.strip() + "\n", encoding="utf-8")
                extracted += 1
        tpl = doc.get("detectionAction", {}).get("alertTemplate", {})
        for key in ("title", "description", "severity", "category", "entityMappings"):
            if not tpl.get(key):
                errors.append(f"{label}: alertTemplate missing '{key}'")
        if tpl.get("severity") not in VALID_XDR_SEVERITIES:
            errors.append(f"{label}: invalid alertTemplate.severity '{tpl.get('severity')}'")
        em = tpl.get("entityMappings", {})
        if not isinstance(em, dict) or not any(em.values()):
            errors.append(f"{label}: alertTemplate.entityMappings must map at least one entity")

    if queries_dir.exists():
        for kql_path in sorted(queries_dir.glob("*.kql")):
            if extract_dir:
                (extract_dir / f"xdr_query_{kql_path.stem}.kql").write_text(
                    kql_path.read_text(encoding="utf-8"), encoding="utf-8"
                )
                extracted += 1
    return extracted


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--extract-kql-dir",
        type=pathlib.Path,
        default=None,
        help="Optional directory to write extracted Solution and Defender XDR KQL queries for kqlcheck.js.",
    )
    args = parser.parse_args()
    if args.extract_kql_dir:
        args.extract_kql_dir.mkdir(parents=True, exist_ok=True)

    errors: list[str] = []
    sol_kql = validate_solution(errors, args.extract_kql_dir)
    validate_azuredeploy(errors)
    xdr_kql = validate_defender_xdr(errors, args.extract_kql_dir)

    if errors:
        print("FAIL: Sentinel solution / ARM / Defender XDR validation errors:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        raise SystemExit(1)

    print(
        f"PASS: Sentinel Content Hub V3 solution, azuredeploy.json and Defender XDR definitions validated "
        f"(extracted {sol_kql + xdr_kql} KQL queries)"
    )


if __name__ == "__main__":
    main()
