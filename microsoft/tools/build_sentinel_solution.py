#!/usr/bin/env python3
"""Build the Microsoft Sentinel Content Hub Solution V3 layout under
Solutions/YumaAIAgentThreatDetection/ from the canonical sources in microsoft/.

Generates:
  - Solutions/YumaAIAgentThreatDetection/Data/Solution_YumaAIAgentThreatDetection.json
  - Solutions/YumaAIAgentThreatDetection/SolutionMetadata.json
  - Solutions/YumaAIAgentThreatDetection/ReleaseNotes.md
  - Solutions/YumaAIAgentThreatDetection/Analytic Rules/*.yaml
  - Solutions/YumaAIAgentThreatDetection/Hunting Queries/*.yaml
  - Solutions/YumaAIAgentThreatDetection/Parsers/*.yaml
  - Solutions/YumaAIAgentThreatDetection/Workbooks/YumaAIAgentRegisterAndISMEvidence.json
  - Solutions/YumaAIAgentThreatDetection/Playbooks/*/azuredeploy.json and readme.md
  - Solutions/YumaAIAgentThreatDetection/Package/mainTemplate.json
  - Solutions/YumaAIAgentThreatDetection/Package/createUiDefinition.json

Follows Azure/Azure-Sentinel Solutions V3 conventions (contentPackages and
contentTemplates with contentSchemaVersion 3.0.0).
"""
from __future__ import annotations

import json
import pathlib
import re
import shutil
import uuid
from typing import Any

import yaml

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
MS_ROOT = REPO_ROOT / "microsoft"
SOL_DIR_NAME = "YumaAIAgentThreatDetection"
SOL_NAME = "Yuma AI Agent Threat Detection"
SOL_ROOT = REPO_ROOT / "Solutions" / SOL_DIR_NAME
SOL_VERSION = "1.0.0"
PUBLISHER_ID = "yumaitau"
OFFER_ID = "yumaitau-ai-agent-threat-detection"
SOLUTION_ID = f"{PUBLISHER_ID}.{OFFER_ID}"
FIRST_PUBLISH_DATE = "2026-11-21"
SUPPORT_LINK = "https://github.com/yumaitau/ai-agent-threat-detection/issues"
REPO_URL = "https://github.com/yumaitau/ai-agent-threat-detection"
LOGO_HTML = ""


class LiteralStr(str):
    """Force PyYAML block scalar formatting for multi-line KQL and descriptions."""


def _literal_representer(dumper: yaml.SafeDumper, data: LiteralStr) -> yaml.ScalarNode:
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")


class SentinelDumper(yaml.SafeDumper):
    pass


SentinelDumper.add_representer(LiteralStr, _literal_representer)


def stable_guid(seed: str) -> str:
    """Return a deterministic UUIDv5 string guaranteed not to contain 12 consecutive digits."""
    value = str(uuid.uuid5(uuid.NAMESPACE_URL, f"https://github.com/yumaitau/ai-agent-threat-detection/{seed}"))
    # Repository hygiene forbids 12 consecutive decimal digits outside 000000000000.
    if re.search(r"(?<!\d)\d{12}(?!\d)", value):
        value = str(uuid.uuid5(uuid.NAMESPACE_URL, f"https://github.com/yumaitau/ai-agent-threat-detection/{seed}/v2"))
    return value


def read_kql(path: pathlib.Path, strip_header: bool = True) -> str:
    lines = path.read_text(encoding="utf-8").splitlines()
    if strip_header:
        while lines and lines[0].startswith("//"):
            lines.pop(0)
    return "\n".join(lines).strip() + "\n"


def duration_to_iso(value: str) -> str:
    """Convert Azure-Sentinel YAML duration (e.g. 10m, 1h, 3h, 14d) to ISO 8601."""
    match = re.fullmatch(r"(\d+)([mhd])", value)
    if not match:
        raise ValueError(f"Unsupported duration: {value}")
    amount, unit = match.group(1), match.group(2)
    if unit == "m":
        return f"PT{amount}M"
    if unit == "h":
        return f"PT{amount}H"
    return f"P{amount}D"


def split_techniques(items: list[str]) -> tuple[list[str], list[str]]:
    base: list[str] = []
    subs: list[str] = []
    for item in items:
        if "." in item:
            subs.append(item)
            parent = item.split(".", 1)[0]
            if parent not in base:
                base.append(parent)
        else:
            if item not in base:
                base.append(item)
    return base, subs


def dump_yaml(data: dict[str, Any]) -> str:
    return yaml.dump(data, Dumper=SentinelDumper, sort_keys=False, allow_unicode=False, width=120)


def escape_arm_expressions(obj: Any) -> Any:
    """Escape ARM template expressions ([...]) as [[...] inside embedded playbook templates
    so the outer Content Hub mainTemplate.json does not attempt to evaluate playbook-local
    parameters or variables at solution registration time."""
    if isinstance(obj, str):
        if obj.startswith("[") and not obj.startswith("[["):
            return "[" + obj
        return obj
    if isinstance(obj, list):
        return [escape_arm_expressions(item) for item in obj]
    if isinstance(obj, dict):
        return {k: escape_arm_expressions(v) for k, v in obj.items()}
    return obj


ANALYTIC_RULES: list[dict[str, Any]] = [
    {
        "slug": "YumaAIA-D04-HighRiskGraphPermission",
        "source_kql": "detections/D04-HighRiskGraphPermissionToAIAgentOrApp.kql",
        "name": "Yuma AIA-D04 High-risk Graph permission granted to AI agent or AI app",
        "description": (
            "Detects when a high-risk Microsoft Graph application or delegated permission is granted to an Entra "
            "agent identity, an AI-named service principal, or self-granted by an application. Suppresses service "
            "principals listed in the YumaAIRegisterApproved watchlist. Maps to ISM-2156, ISM-2137, ISM-2138 and "
            "ISM-2139."
        ),
        "severity": "Medium",
        "requiredDataConnectors": [
            {"connectorId": "AzureActiveDirectory", "dataTypes": ["AuditLogs"]},
        ],
        "queryFrequency": "1h",
        "queryPeriod": "1h",
        "tactics": ["PrivilegeEscalation", "Persistence"],
        "relevantTechniques": ["T1098.003"],
        "entityMappings": [
            {"entityType": "Account", "fieldMappings": [{"identifier": "FullName", "columnName": "InitiatedByUpn"}]},
            {"entityType": "IP", "fieldMappings": [{"identifier": "Address", "columnName": "InitiatedByIp"}]},
            {"entityType": "CloudApplication", "fieldMappings": [{"identifier": "Name", "columnName": "ClientAppName"}]},
        ],
        "customDetails": {
            "ClientSpId": "ClientSpId",
            "ClientAppName": "ClientAppName",
            "Permissions": "GrantedPermissions",
            "AgentType": "TargetAgentType",
        },
        "alertDetailsOverride": {
            "alertDisplayNameFormat": "Yuma AIA-D04: {{ClientAppName}} granted high-risk Graph permission",
            "alertSeverityColumnName": "Severity",
        },
    },
    {
        "slug": "YumaAIA-D05-NewAIAppConsent",
        "source_kql": "detections/D05-NewAIAppConsent.kql",
        "name": "Yuma AIA-D05 New AI app consent (user or admin), first seen",
        "description": (
            "Detects first-seen admin or user OAuth consent to an Entra agent identity or AI-named application. "
            "Approved service principals in the YumaAIRegisterApproved watchlist are suppressed unless consent is "
            "granted by a non-admin user. Maps to ISM-2134, ISM-2135, ISM-2137, ISM-2138 and ISM-2139."
        ),
        "severity": "Low",
        "requiredDataConnectors": [
            {"connectorId": "AzureActiveDirectory", "dataTypes": ["AuditLogs"]},
        ],
        "queryFrequency": "1h",
        "queryPeriod": "14d",
        "tactics": ["CredentialAccess", "Persistence"],
        "relevantTechniques": ["T1528"],
        "entityMappings": [
            {"entityType": "Account", "fieldMappings": [{"identifier": "FullName", "columnName": "ConsentedByUpn"}]},
            {"entityType": "IP", "fieldMappings": [{"identifier": "Address", "columnName": "ConsentedByIp"}]},
            {"entityType": "CloudApplication", "fieldMappings": [{"identifier": "Name", "columnName": "AppName"}]},
        ],
        "customDetails": {
            "AppSpId": "AppSpId",
            "AppName": "AppName",
            "ConsentType": "ConsentType",
            "Scopes": "Scopes",
        },
        "alertDetailsOverride": {
            "alertDisplayNameFormat": "Yuma AIA-D05: new AI app consent for {{AppName}}",
            "alertSeverityColumnName": "Severity",
        },
    },
    {
        "slug": "YumaAIA-D07-AgentIdentitySignInAnomaly",
        "source_kql": "detections/D07-AgentIdentitySignInAnomaly.kql",
        "name": "Yuma AIA-D07 Agent identity or AI service principal sign-in anomaly",
        "description": (
            "Detects an Entra agent identity or AI service principal signing in from a new ASN or IP, to a new "
            "resource, with a new credential type, or with a burst of failures compared to its 14-day baseline. "
            "Maps to ISM-2133, ISM-2136, ISM-2141, ISM-2142 and ISM-2148."
        ),
        "severity": "Medium",
        "requiredDataConnectors": [
            {"connectorId": "AzureActiveDirectory", "dataTypes": ["AADServicePrincipalSignInLogs"]},
        ],
        "queryFrequency": "1h",
        "queryPeriod": "14d",
        "tactics": ["InitialAccess", "DefenseEvasion", "CredentialAccess"],
        "relevantTechniques": ["T1078.004", "T1550.001"],
        "entityMappings": [
            {"entityType": "IP", "fieldMappings": [{"identifier": "Address", "columnName": "IPAddress"}]},
            {"entityType": "CloudApplication", "fieldMappings": [{"identifier": "Name", "columnName": "ServicePrincipalName"}]},
        ],
        "customDetails": {
            "ServicePrincipalId": "ServicePrincipalId",
            "AppId": "AppId",
            "AgentType": "AgentType",
            "Reasons": "Reasons",
        },
        "alertDetailsOverride": {
            "alertDisplayNameFormat": "Yuma AIA-D07: sign-in anomaly for {{ServicePrincipalName}}",
            "alertSeverityColumnName": "Severity",
        },
    },
    {
        "slug": "YumaAIA-D08-AgentGraphDataAccessBurst",
        "source_kql": "detections/D08-AgentGraphDataAccessBurst.kql",
        "name": "Yuma AIA-D08 Agent or AI app Microsoft Graph data-access burst",
        "description": (
            "Detects an AI agent or AI application exceeding its 14-day hourly baseline for sensitive Microsoft Graph "
            "API calls across mail, files, SharePoint sites, chats, directory, or Microsoft MCP Server for Enterprise. "
            "Maps to ISM-2157 and ISM-2159."
        ),
        "severity": "Medium",
        "requiredDataConnectors": [
            {
                "connectorId": "AzureActiveDirectory",
                "dataTypes": ["MicrosoftGraphActivityLogs", "AADServicePrincipalSignInLogs"],
            },
        ],
        "queryFrequency": "1h",
        "queryPeriod": "14d",
        "tactics": ["Collection", "Discovery"],
        "relevantTechniques": ["T1114.002", "T1530", "T1087.004"],
        "entityMappings": [
            {"entityType": "CloudApplication", "fieldMappings": [{"identifier": "Name", "columnName": "AppName"}]},
        ],
        "customDetails": {
            "AppId": "AppId",
            "ServicePrincipalId": "ServicePrincipalId",
            "Requests": "Requests",
            "DistinctTargetUsers": "DistinctTargetUsers",
        },
        "alertDetailsOverride": {
            "alertDisplayNameFormat": "Yuma AIA-D08: Graph data-access burst by {{AppName}}",
            "alertSeverityColumnName": "Severity",
        },
    },
    {
        "slug": "YumaAIA-D10-PromptInjectionThenExfiltration",
        "source_kql": "detections/D10-PromptInjectionThenExfiltration.kql",
        "name": "Yuma AIA-D10 Prompt-injection or jailbreak alert followed by exfiltration activity",
        "description": (
            "Correlates Microsoft Defender XDR prompt-injection alerts or Copilot jailbreak events with "
            "exfiltration-like CloudAppEvents activity by the same user within two hours. Maps to ISM-2158, "
            "ISM-1924 and ISM-2113."
        ),
        "severity": "Medium",
        "requiredDataConnectors": [
            {"connectorId": "MicrosoftThreatProtection", "dataTypes": ["AlertInfo", "AlertEvidence", "CloudAppEvents"]},
            {"connectorId": "MicrosoftCopilot", "dataTypes": ["CopilotActivity"]},
        ],
        "queryFrequency": "1h",
        "queryPeriod": "3h",
        "tactics": ["Exfiltration", "Collection"],
        "relevantTechniques": ["T1567", "T1530", "T1114"],
        "entityMappings": [
            {
                "entityType": "Account",
                "fieldMappings": [
                    {"identifier": "FullName", "columnName": "AccountUpn"},
                    {"identifier": "AadUserId", "columnName": "AccountObjectId"},
                ],
            },
        ],
        "customDetails": {
            "TriggerSource": "TriggerSource",
            "TriggerId": "TriggerId",
            "ExfilEvents": "ExfilEvents",
        },
        "alertDetailsOverride": {
            "alertDisplayNameFormat": "Yuma AIA-D10: post-injection exfiltration activity for {{AccountUpn}}",
            "alertSeverityColumnName": "Severity",
        },
    },
    {
        "slug": "YumaAIA-D14-AISpeedExploitationBurst",
        "source_kql": "detections/D14-AISpeedExploitationBurst.kql",
        "name": "Yuma AIA-D14 AI-speed exploitation burst against App Gateway WAF",
        "description": (
            "Detects a single client IP tripping many distinct Application Gateway WAF rules across many URIs within "
            "10 minutes, characteristic of automated or LLM-driven exploit tooling. Enriches with access logs and "
            "Sentinel threat intelligence indicators. Maps to ISM-2116 and Essential Eight patch applications."
        ),
        "severity": "Medium",
        "requiredDataConnectors": [
            {"connectorId": "WAF", "dataTypes": ["AGWFirewallLogs", "AGWAccessLogs"]},
            {"connectorId": "ThreatIntelligence", "dataTypes": ["ThreatIntelIndicators"]},
        ],
        "queryFrequency": "10m",
        "queryPeriod": "1h",
        "tactics": ["InitialAccess", "Reconnaissance"],
        "relevantTechniques": ["T1190", "T1595.002"],
        "entityMappings": [
            {"entityType": "IP", "fieldMappings": [{"identifier": "Address", "columnName": "ClientIp"}]},
        ],
        "customDetails": {
            "DistinctRules": "DistinctRules",
            "DistinctUris": "DistinctUris",
            "ClaimsAIAgent": "ClaimsAIAgent",
        },
        "alertDetailsOverride": {
            "alertDisplayNameFormat": "Yuma AIA-D14: exploit burst from {{ClientIp}}",
            "alertSeverityColumnName": "Severity",
        },
    },
]

HUNTING_QUERIES: list[dict[str, Any]] = [
    {
        "slug": "YumaAIA-D01-ShadowAINonBrowserProcessToAIAPI",
        "source_kql": "detections/D01-ShadowAI-NonBrowserProcessToAIAPI.kql",
        "name": "Yuma AIA-D01 Shadow AI: non-browser process calling AI model APIs",
        "description": (
            "Hunts DeviceNetworkEvents for non-browser endpoint processes connecting to third-party AI model APIs "
            "(local agents, CLIs and scripts). Tune ApprovedProcesses to match organisational AI policy. Maps to "
            "ISM-2074, ISM-2095 and ISM-2134."
        ),
        "requiredDataConnectors": [
            {"connectorId": "MicrosoftThreatProtection", "dataTypes": ["DeviceNetworkEvents"]},
        ],
        "tactics": ["Exfiltration", "CommandAndControl"],
        "relevantTechniques": ["T1567"],
        "entityMappings": [
            {"entityType": "Host", "fieldMappings": [{"identifier": "HostName", "columnName": "DeviceName"}]},
            {"entityType": "Account", "fieldMappings": [{"identifier": "FullName", "columnName": "InitiatingProcessAccountUpn"}]},
        ],
    },
    {
        "slug": "YumaAIA-D06-AgentIdentityStaticSecret",
        "source_kql": "detections/D06-AgentIdentityStaticSecret.kql",
        "name": "Yuma AIA-D06 Agent identities on static client secrets",
        "description": (
            "Hunts AADServicePrincipalSignInLogs for Entra agent identities and AI service principals authenticating "
            "with static client secrets instead of managed identities, federated credentials or certificates. Maps to "
            "ISM-2141, ISM-2142 and ISM-2146."
        ),
        "requiredDataConnectors": [
            {"connectorId": "AzureActiveDirectory", "dataTypes": ["AADServicePrincipalSignInLogs"]},
        ],
        "tactics": ["CredentialAccess"],
        "relevantTechniques": ["T1552.001"],
        "entityMappings": [
            {"entityType": "CloudApplication", "fieldMappings": [{"identifier": "Name", "columnName": "ServicePrincipalName"}]},
        ],
    },
    {
        "slug": "YumaAIA-D09-AgentRegisterExportISM2135",
        "source_kql": "detections/D09-AgentRegisterExport-ISM2135.kql",
        "name": "Yuma AIA-D09 AI agent register review with ISM gap flags",
        "description": (
            "Reviews Defender XDR AgentsInfo inventory entries with ISM-2133 and ISM-2135 completeness gap flags "
            "(missing owner, purpose, unique Entra identity or instructions, wide sharing, and MCP usage). Maps to "
            "ISM-2133, ISM-2134, ISM-2135 and ISM-2156."
        ),
        "requiredDataConnectors": [
            {"connectorId": "MicrosoftThreatProtection", "dataTypes": ["AgentsInfo"]},
        ],
        "tactics": ["Discovery"],
        "relevantTechniques": [],
        "entityMappings": [
            {"entityType": "CloudApplication", "fieldMappings": [{"identifier": "Name", "columnName": "AgentName"}]},
        ],
    },
    {
        "slug": "YumaAIA-D13-AIAgentCrawlerAndMcpProbe",
        "source_kql": "detections/D13-AIAgentCrawlerAndMcpProbe.kql",
        "name": "Yuma AIA-D13 AI crawler and MCP endpoint probing",
        "description": (
            "Hunts Azure Application Gateway access logs for self-declared AI crawler user agents or probes against "
            "MCP, SSE, LLM API and agent-card endpoints. Maps to ISM-2116."
        ),
        "requiredDataConnectors": [
            {"connectorId": "WAF", "dataTypes": ["AGWAccessLogs"]},
        ],
        "tactics": ["Reconnaissance"],
        "relevantTechniques": ["T1595.002", "T1593"],
        "entityMappings": [
            {"entityType": "IP", "fieldMappings": [{"identifier": "Address", "columnName": "ClientIp"}]},
        ],
    },
    {
        "slug": "YumaAIA-D15-AgenticMcpSensitivePrimitive",
        "source_kql": "detections/D15-AgenticMcpSensitivePrimitive.kql",
        "name": "Yuma AIA-D15 Agentic traffic invoking sensitive MCP primitives or new destinations",
        "description": (
            "Hunts Entra Global Secure Access NetworkAccessTraffic logs for agentic traffic invoking sensitive or "
            "destructive MCP primitives or contacting a newly observed MCP destination. Maps to ISM-2159, ISM-2156 "
            "and ISM-2113."
        ),
        "requiredDataConnectors": [
            {"connectorId": "EntraGlobalSecureAccess", "dataTypes": ["NetworkAccessTraffic"]},
        ],
        "tactics": ["Impact", "Exfiltration"],
        "relevantTechniques": ["T1485", "T1567"],
        "entityMappings": [
            {"entityType": "Account", "fieldMappings": [{"identifier": "FullName", "columnName": "UserPrincipalName"}]},
            {"entityType": "CloudApplication", "fieldMappings": [{"identifier": "Name", "columnName": "AIAgentName"}]},
        ],
    },
]

PARSERS: list[dict[str, Any]] = [
    {
        "alias": "YumaAIRegister",
        "source_kql": "functions/YumaAIRegister.kql",
        "title": "Yuma AI Agent Register view",
        "description": "Returns one row per active AI agent from AIAgentRegister_CL with ISM-2133/2135 gap flags and ISM-2138 review status.",
    },
    {
        "alias": "YumaISMControlStatus",
        "source_kql": "functions/YumaISMControlStatus.kql",
        "title": "Yuma ISM Control Status view",
        "description": "Computes evidence status per ISM control (ISM-2133 to ISM-2140 and ISM-2156 to ISM-2159) from Sentinel logs and the AI agent register.",
    },
    {
        "alias": "YumaEvidenceRegisterCsv",
        "source_kql": "functions/YumaEvidenceRegisterCsv.kql",
        "title": "Yuma Evidence Register CSV formatter",
        "description": "Formats YumaAIRegister() as an RFC 4180 CSV single-cell payload for automated assessor exports (PB5).",
    },
    {
        "alias": "YumaEvidenceControlsCsv",
        "source_kql": "functions/YumaEvidenceControlsCsv.kql",
        "title": "Yuma Evidence Controls CSV formatter",
        "description": "Formats YumaISMControlStatus() as an RFC 4180 CSV single-cell payload for automated assessor exports (PB5).",
    },
    {
        "alias": "YumaEvidenceMarkdown",
        "source_kql": "functions/YumaEvidenceMarkdown.kql",
        "title": "Yuma Evidence Markdown summary formatter",
        "description": "Formats a dated Markdown summary of register counts and ISM control statuses for automated assessor exports (PB5).",
    },
]

PLAYBOOKS: list[dict[str, Any]] = [
    {
        "folder": "Yuma-PB1-Agent-Permission-Containment",
        "source_arm": "deploy/playbook-PB1-agent-containment.json",
        "source_doc": "playbooks/PB1-Agent-Permission-Containment.md",
        "display_name": "Yuma PB1 - Agent Permission Containment",
        "description": (
            "Sentinel incident-triggered Logic App that enriches a service principal from Microsoft Graph, posts an "
            "approval Adaptive Card to Teams, and disables the service principal only after human approval."
        ),
    },
    {
        "folder": "Yuma-PB4-AI-Agent-Register-Sync",
        "source_arm": "deploy/playbook-PB4-register-sync.json",
        "source_doc": "playbooks/PB4-AI-Agent-Register-Sync.md",
        "display_name": "Yuma PB4 - AI Agent Register Sync",
        "description": (
            "Daily recurrence Logic App that queries Defender XDR AgentsInfo via Microsoft Graph runHuntingQuery and "
            "posts snapshots or Retired records to AIAgentRegister_CL through the Logs Ingestion API."
        ),
    },
    {
        "folder": "Yuma-PB5-ISM-Evidence-Export",
        "source_arm": "deploy/playbook-PB5-ism-evidence-export.json",
        "source_doc": "playbooks/PB5-ISM-Evidence-Export.md",
        "display_name": "Yuma PB5 - ISM Evidence Export",
        "description": (
            "Monthly or on-demand Logic App that executes the Yuma evidence functions and writes dated CSV, Markdown "
            "and manifest files to an Azure Blob Storage container."
        ),
    },
]

WORKBOOK_SPEC = {
    "filename": "YumaAIAgentRegisterAndISMEvidence.json",
    "source": "deploy/workbook/yuma-ai-agent-register.workbook.json",
    "display_name": "Yuma AI Agent Register and ISM Evidence",
    "description": (
        "Six-tab Sentinel workbook displaying the AI agent register, ISM-2133 to ISM-2140 and ISM-2156 to ISM-2159 "
        "evidence coverage, Entra consent history, six-monthly review status, and Yuma AI detection alerts."
    ),
    "content_id": stable_guid("workbook/YumaAIAgentRegisterAndISMEvidence"),
}


def support_block() -> dict[str, Any]:
    return {
        "name": "Yuma IT",
        "tier": "Community",
        "link": SUPPORT_LINK,
    }


def author_block() -> dict[str, Any]:
    return {
        "name": "Yuma IT",
    }


def source_block() -> dict[str, Any]:
    return {
        "kind": "Solution",
        "name": SOL_NAME,
        "sourceId": "[variables('_solutionId')]",
    }


def build_solution_files() -> dict[str, Any]:
    for sub in ["Data", "Analytic Rules", "Hunting Queries", "Parsers", "Workbooks", "Playbooks", "Package"]:
        (SOL_ROOT / sub).mkdir(parents=True, exist_ok=True)

    # 1. Analytic Rules YAML
    analytic_paths: list[str] = []
    analytic_records: list[dict[str, Any]] = []
    for spec in ANALYTIC_RULES:
        rule_id = stable_guid(f"analytic-rule/{spec['slug']}")
        kql_text = read_kql(MS_ROOT / spec["source_kql"])
        doc: dict[str, Any] = {
            "id": rule_id,
            "name": spec["name"],
            "description": LiteralStr(spec["description"] + "\n"),
            "severity": spec["severity"],
            "status": "Available",
            "requiredDataConnectors": spec["requiredDataConnectors"],
            "queryFrequency": spec["queryFrequency"],
            "queryPeriod": spec["queryPeriod"],
            "triggerOperator": "gt",
            "triggerThreshold": 0,
            "tactics": spec["tactics"],
            "relevantTechniques": spec["relevantTechniques"],
            "query": LiteralStr(kql_text),
            "entityMappings": spec["entityMappings"],
            "customDetails": spec["customDetails"],
            "alertDetailsOverride": spec["alertDetailsOverride"],
            "eventGroupingSettings": {"aggregationKind": "AlertPerResult"},
            "version": SOL_VERSION,
            "kind": "Scheduled",
        }
        rel_path = f"Analytic Rules/{spec['slug']}.yaml"
        (SOL_ROOT / rel_path).write_text(dump_yaml(doc), encoding="utf-8")
        analytic_paths.append(rel_path)
        analytic_records.append({**spec, "id": rule_id, "query_text": kql_text, "rel_path": rel_path})

    # 2. Hunting Queries YAML
    hunting_paths: list[str] = []
    hunting_records: list[dict[str, Any]] = []
    for spec in HUNTING_QUERIES:
        hunt_id = stable_guid(f"hunting-query/{spec['slug']}")
        kql_text = read_kql(MS_ROOT / spec["source_kql"])
        doc = {
            "id": hunt_id,
            "name": spec["name"],
            "description": LiteralStr(spec["description"] + "\n"),
            "requiredDataConnectors": spec["requiredDataConnectors"],
            "tactics": spec["tactics"],
            "relevantTechniques": spec["relevantTechniques"],
            "query": LiteralStr(kql_text),
            "entityMappings": spec["entityMappings"],
            "version": SOL_VERSION,
        }
        rel_path = f"Hunting Queries/{spec['slug']}.yaml"
        (SOL_ROOT / rel_path).write_text(dump_yaml(doc), encoding="utf-8")
        hunting_paths.append(rel_path)
        hunting_records.append({**spec, "id": hunt_id, "query_text": kql_text, "rel_path": rel_path})

    # 3. Parsers YAML
    parser_paths: list[str] = []
    parser_records: list[dict[str, Any]] = []
    for spec in PARSERS:
        parser_id = stable_guid(f"parser/{spec['alias']}")
        kql_text = read_kql(MS_ROOT / spec["source_kql"])
        doc = {
            "id": parser_id,
            "Function": {
                "Title": spec["title"],
                "Version": SOL_VERSION,
                "LastUpdated": FIRST_PUBLISH_DATE,
            },
            "Category": "Yuma AI Agent Pack",
            "FunctionName": spec["alias"],
            "FunctionAlias": spec["alias"],
            "FunctionQuery": LiteralStr(kql_text),
        }
        rel_path = f"Parsers/{spec['alias']}.yaml"
        (SOL_ROOT / rel_path).write_text(dump_yaml(doc), encoding="utf-8")
        parser_paths.append(rel_path)
        parser_records.append({**spec, "id": parser_id, "query_text": kql_text, "rel_path": rel_path})

    # 4. Workbook JSON
    wb_src = json.loads((MS_ROOT / WORKBOOK_SPEC["source"]).read_text(encoding="utf-8"))
    wb_rel = f"Workbooks/{WORKBOOK_SPEC['filename']}"
    (SOL_ROOT / wb_rel).write_text(json.dumps(wb_src, indent=2) + "\n", encoding="utf-8")

    # 5. Playbooks
    playbook_paths: list[str] = []
    playbook_records: list[dict[str, Any]] = []
    for spec in PLAYBOOKS:
        pb_dir = SOL_ROOT / "Playbooks" / spec["folder"]
        pb_dir.mkdir(parents=True, exist_ok=True)
        arm_obj = json.loads((MS_ROOT / spec["source_arm"]).read_text(encoding="utf-8"))
        arm_rel = f"Playbooks/{spec['folder']}/azuredeploy.json"
        (SOL_ROOT / arm_rel).write_text(json.dumps(arm_obj, indent=2) + "\n", encoding="utf-8")
        shutil.copyfile(MS_ROOT / spec["source_doc"], pb_dir / "readme.md")
        pb_id = stable_guid(f"playbook/{spec['folder']}")
        playbook_paths.append(arm_rel)
        playbook_records.append({**spec, "id": pb_id, "arm": arm_obj, "rel_path": arm_rel})

    # 6. SolutionMetadata.json
    metadata_doc = {
        "publisherId": PUBLISHER_ID,
        "offerId": OFFER_ID,
        "firstPublishDate": FIRST_PUBLISH_DATE,
        "providers": ["Yuma IT"],
        "categories": {
            "domains": ["Security - Threat Protection", "Identity", "Compliance"],
        },
        "support": support_block(),
        "version": SOL_VERSION,
    }
    (SOL_ROOT / "SolutionMetadata.json").write_text(json.dumps(metadata_doc, indent=2) + "\n", encoding="utf-8")

    # 7. Data/Solution_YumaAIAgentThreatDetection.json
    solution_desc = (
        "The Yuma AI Agent Threat Detection solution for Microsoft Sentinel packages analytics rules, hunting queries, "
        "an AI agent register and ISM evidence workbook, saved workspace functions (parsers), and Logic App playbooks "
        "to detect and investigate risky AI and agent activity across Microsoft Entra ID, Microsoft Graph, Defender XDR, "
        "Global Secure Access and Azure Application Gateway WAF. All analytics rules and playbooks deploy disabled "
        "so security teams can tune thresholds in a test workspace before enabling them."
    )
    solution_data = {
        "Name": SOL_NAME,
        "Author": "Yuma IT",
        "Logo": LOGO_HTML,
        "Description": solution_desc,
        "Analytic Rules": analytic_paths,
        "Hunting Queries": hunting_paths,
        "Parsers": parser_paths,
        "Workbooks": [wb_rel],
        "Playbooks": playbook_paths,
        "BasePath": f"Solutions/{SOL_DIR_NAME}",
        "Version": SOL_VERSION,
        "Metadata": "SolutionMetadata.json",
        "TemplateSpec": True,
    }
    (SOL_ROOT / "Data" / f"Solution_{SOL_DIR_NAME}.json").write_text(
        json.dumps(solution_data, indent=2) + "\n", encoding="utf-8"
    )

    # 8. ReleaseNotes.md
    release_notes = f"""# Release notes - {SOL_NAME}

| Version | Date | Notes |
|---|---|---|
| {SOL_VERSION} | {FIRST_PUBLISH_DATE} | Initial Microsoft Sentinel Content Hub V3 solution release: 6 scheduled analytics rules (D04, D05, D07, D08, D10, D14), 5 hunting queries (D01, D06, D09, D13, D15), 5 workspace functions (parsers), 1 six-tab workbook, and 3 Logic App playbooks (PB1, PB4, PB5). All content validated offline; test and tune thresholds in a non-production workspace before enabling. |
"""
    (SOL_ROOT / "ReleaseNotes.md").write_text(release_notes, encoding="utf-8")

    # 9. Package/mainTemplate.json (V3 Content Hub package format)
    main_template = build_main_template(
        solution_desc=solution_desc,
        analytic_records=analytic_records,
        hunting_records=hunting_records,
        parser_records=parser_records,
        workbook_obj=wb_src,
        playbook_records=playbook_records,
    )
    (SOL_ROOT / "Package" / "mainTemplate.json").write_text(
        json.dumps(main_template, indent=2) + "\n", encoding="utf-8"
    )

    # 10. Package/createUiDefinition.json
    ui_def = build_create_ui_definition(
        solution_desc=solution_desc,
        analytic_records=analytic_records,
        hunting_records=hunting_records,
        parser_records=parser_records,
        playbook_records=playbook_records,
    )
    (SOL_ROOT / "Package" / "createUiDefinition.json").write_text(
        json.dumps(ui_def, indent=2) + "\n", encoding="utf-8"
    )

    return {
        "analytic_rules": len(analytic_records),
        "hunting_queries": len(hunting_records),
        "parsers": len(parser_records),
        "workbooks": 1,
        "playbooks": len(playbook_records),
    }


def build_main_template(
    solution_desc: str,
    analytic_records: list[dict[str, Any]],
    hunting_records: list[dict[str, Any]],
    parser_records: list[dict[str, Any]],
    workbook_obj: dict[str, Any],
    playbook_records: list[dict[str, Any]],
) -> dict[str, Any]:
    package_dep = (
        "[extensionResourceId(resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspace')), "
        "'Microsoft.SecurityInsights/contentPackages', variables('_solutionId'))]"
    )

    variables: dict[str, Any] = {
        "_solutionName": SOL_NAME,
        "_solutionVersion": SOL_VERSION,
        "_solutionId": SOLUTION_ID,
        "_solutionTier": "Community",
        "_solutioncontentProductId": (
            "[concat(take(variables('_solutionId'),50),'-','sl','-', "
            "uniqueString(concat(variables('_solutionId'),'-','Solution','-',variables('_solutionId'),'-', "
            "variables('_solutionVersion'))))]"
        ),
        "workspaceResourceId": "[resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspace'))]",
    }

    criteria: list[dict[str, Any]] = []
    resources: list[dict[str, Any]] = []

    # Analytics Rule contentTemplates
    for idx, rec in enumerate(analytic_records, start=1):
        base_techs, sub_techs = split_techniques(rec["relevantTechniques"])
        obj_name = f"analyticRuleObject{idx}"
        content_id = rec["id"]
        prod_expr = (
            f"[concat(take(variables('_solutionId'),50),'-','ar','-', "
            f"uniqueString(concat(variables('_solutionId'),'-','AnalyticsRule','-', '{content_id}', '-', '{SOL_VERSION}')))]"
        )
        variables[obj_name] = {
            f"_analyticRulecontentId{idx}": content_id,
            f"analyticRuleVersion{idx}": SOL_VERSION,
            f"analyticRuleTemplateSpecName{idx}": (
                f"[concat(parameters('workspace'),'/Microsoft.SecurityInsights/', "
                f"concat(parameters('workspace'),'-ar-',uniquestring('{content_id}')))]"
            ),
            f"analyticRuleId{idx}": (
                f"[resourceId('Microsoft.OperationalInsights/workspaces/providers/alertRuleTemplates', "
                f"parameters('workspace'), 'Microsoft.SecurityInsights', '{content_id}')]"
            ),
            f"_analyticRulecontentProductId{idx}": prod_expr,
        }
        criteria.append({"kind": "AnalyticsRule", "contentId": content_id, "version": SOL_VERSION})

        rule_props: dict[str, Any] = {
            "description": rec["description"],
            "displayName": rec["name"],
            "enabled": False,
            "query": rec["query_text"],
            "queryFrequency": duration_to_iso(rec["queryFrequency"]),
            "queryPeriod": duration_to_iso(rec["queryPeriod"]),
            "severity": rec["severity"],
            "suppressionDuration": "PT5H",
            "suppressionEnabled": False,
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 0,
            "status": "Available",
            "requiredDataConnectors": rec["requiredDataConnectors"],
            "tactics": rec["tactics"],
            "techniques": base_techs,
            "entityMappings": rec["entityMappings"],
            "customDetails": rec["customDetails"],
            "alertDetailsOverride": rec["alertDetailsOverride"],
            "eventGroupingSettings": {"aggregationKind": "AlertPerResult"},
        }
        if sub_techs:
            rule_props["subTechniques"] = sub_techs

        resources.append({
            "type": "Microsoft.OperationalInsights/workspaces/providers/contentTemplates",
            "apiVersion": "2023-04-01-preview",
            "name": f"[variables('{obj_name}').analyticRuleTemplateSpecName{idx}]",
            "location": "[parameters('workspace-location')]",
            "condition": "[parameters('DeployAnalyticsRule')]",
            "dependsOn": [package_dep],
            "properties": {
                "description": f"{rec['slug']} Analytics Rule with template version {SOL_VERSION}",
                "mainTemplate": {
                    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                    "contentVersion": "1.0.0.0",
                    "parameters": {},
                    "variables": {},
                    "resources": [
                        {
                            "type": "Microsoft.SecurityInsights/AlertRuleTemplates",
                            "name": content_id,
                            "apiVersion": "2023-02-01-preview",
                            "kind": "Scheduled",
                            "location": "[parameters('workspace-location')]",
                            "properties": rule_props,
                        },
                        {
                            "type": "Microsoft.OperationalInsights/workspaces/providers/metadata",
                            "apiVersion": "2022-01-01-preview",
                            "name": (
                                f"[concat(parameters('workspace'),'/Microsoft.SecurityInsights/',"
                                f"concat('AnalyticsRule-', '{content_id}'))]"
                            ),
                            "properties": {
                                "description": f"{SOL_NAME} Analytics Rule {idx}",
                                "parentId": f"[variables('{obj_name}').analyticRuleId{idx}]",
                                "contentId": content_id,
                                "kind": "AnalyticsRule",
                                "version": SOL_VERSION,
                                "source": source_block(),
                                "author": author_block(),
                                "support": support_block(),
                            },
                        },
                    ],
                },
                "packageKind": "Solution",
                "packageVersion": "[variables('_solutionVersion')]",
                "packageName": "[variables('_solutionName')]",
                "packageId": "[variables('_solutionId')]",
                "contentSchemaVersion": "3.0.0",
                "contentId": content_id,
                "contentKind": "AnalyticsRule",
                "displayName": rec["name"],
                "contentProductId": f"[variables('{obj_name}')._analyticRulecontentProductId{idx}]",
                "id": f"[variables('{obj_name}')._analyticRulecontentProductId{idx}]",
                "version": SOL_VERSION,
            },
        })

    # Hunting Query contentTemplates
    for idx, rec in enumerate(hunting_records, start=1):
        base_techs, _ = split_techniques(rec["relevantTechniques"])
        obj_name = f"huntingQueryObject{idx}"
        content_id = rec["id"]
        saved_name = f"Yuma_AI_Agent_Hunting_Query_{idx}"
        prod_expr = (
            f"[concat(take(variables('_solutionId'),50),'-','hq','-', "
            f"uniqueString(concat(variables('_solutionId'),'-','HuntingQuery','-', '{content_id}', '-', '{SOL_VERSION}')))]"
        )
        variables[obj_name] = {
            f"_huntingQuerycontentId{idx}": content_id,
            f"huntingQueryVersion{idx}": SOL_VERSION,
            f"huntingQueryTemplateSpecName{idx}": (
                f"[concat(parameters('workspace'),'/Microsoft.SecurityInsights/', "
                f"concat(parameters('workspace'),'-hq-',uniquestring('{content_id}')))]"
            ),
            f"huntingQueryId{idx}": (
                f"[resourceId('Microsoft.OperationalInsights/workspaces/savedSearches', "
                f"parameters('workspace'), '{saved_name}')]"
            ),
            f"_huntingQuerycontentProductId{idx}": prod_expr,
        }
        criteria.append({"kind": "HuntingQuery", "contentId": content_id, "version": SOL_VERSION})

        tags = [
            {"name": "description", "value": rec["description"]},
            {"name": "tactics", "value": ",".join(rec["tactics"])},
        ]
        if base_techs:
            tags.append({"name": "techniques", "value": ",".join(base_techs)})

        resources.append({
            "type": "Microsoft.OperationalInsights/workspaces/providers/contentTemplates",
            "apiVersion": "2023-04-01-preview",
            "name": f"[variables('{obj_name}').huntingQueryTemplateSpecName{idx}]",
            "location": "[parameters('workspace-location')]",
            "condition": "[parameters('DeployHuntingQuery')]",
            "dependsOn": [package_dep],
            "properties": {
                "description": f"{rec['slug']} Hunting Query with template version {SOL_VERSION}",
                "mainTemplate": {
                    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                    "contentVersion": "1.0.0.0",
                    "parameters": {},
                    "variables": {},
                    "resources": [
                        {
                            "type": "Microsoft.OperationalInsights/savedSearches",
                            "apiVersion": "2020-08-01",
                            "name": saved_name,
                            "location": "[parameters('workspace-location')]",
                            "properties": {
                                "eTag": "*",
                                "displayName": rec["name"],
                                "category": "Hunting Queries",
                                "query": rec["query_text"],
                                "version": 2,
                                "tags": tags,
                            },
                        },
                        {
                            "type": "Microsoft.OperationalInsights/workspaces/providers/metadata",
                            "apiVersion": "2022-01-01-preview",
                            "name": (
                                f"[concat(parameters('workspace'),'/Microsoft.SecurityInsights/',"
                                f"concat('HuntingQuery-', '{content_id}'))]"
                            ),
                            "properties": {
                                "description": f"{SOL_NAME} Hunting Query {idx}",
                                "parentId": f"[variables('{obj_name}').huntingQueryId{idx}]",
                                "contentId": content_id,
                                "kind": "HuntingQuery",
                                "version": SOL_VERSION,
                                "source": source_block(),
                                "author": author_block(),
                                "support": support_block(),
                            },
                        },
                    ],
                },
                "packageKind": "Solution",
                "packageVersion": "[variables('_solutionVersion')]",
                "packageName": "[variables('_solutionName')]",
                "packageId": "[variables('_solutionId')]",
                "contentSchemaVersion": "3.0.0",
                "contentId": content_id,
                "contentKind": "HuntingQuery",
                "displayName": rec["name"],
                "contentProductId": f"[variables('{obj_name}')._huntingQuerycontentProductId{idx}]",
                "id": f"[variables('{obj_name}')._huntingQuerycontentProductId{idx}]",
                "version": SOL_VERSION,
            },
        })

    # Parser contentTemplates
    for idx, rec in enumerate(parser_records, start=1):
        obj_name = f"parserObject{idx}"
        content_id = rec["id"]
        alias = rec["alias"]
        prod_expr = (
            f"[concat(take(variables('_solutionId'),50),'-','pr','-', "
            f"uniqueString(concat(variables('_solutionId'),'-','Parser','-', '{content_id}', '-', '{SOL_VERSION}')))]"
        )
        variables[obj_name] = {
            f"parserContentId{idx}": content_id,
            f"parserVersion{idx}": SOL_VERSION,
            f"parserTemplateSpecName{idx}": (
                f"[concat(parameters('workspace'),'/Microsoft.SecurityInsights/', "
                f"concat(parameters('workspace'),'-pr-',uniquestring('{content_id}')))]"
            ),
            f"_parserName{idx}": f"[concat(parameters('workspace'), '/yuma-fn-{alias}')]",
            f"_parserId{idx}": (
                f"[resourceId('Microsoft.OperationalInsights/workspaces/savedSearches', "
                f"parameters('workspace'), 'yuma-fn-{alias}')]"
            ),
            f"_parsercontentProductId{idx}": prod_expr,
        }
        criteria.append({"kind": "Parser", "contentId": content_id, "version": SOL_VERSION})

        resources.append({
            "type": "Microsoft.OperationalInsights/workspaces/providers/contentTemplates",
            "apiVersion": "2023-04-01-preview",
            "name": f"[variables('{obj_name}').parserTemplateSpecName{idx}]",
            "location": "[parameters('workspace-location')]",
            "condition": "[parameters('DeployParser')]",
            "dependsOn": [package_dep],
            "properties": {
                "description": f"{alias} Parser with template version {SOL_VERSION}",
                "mainTemplate": {
                    "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                    "contentVersion": "1.0.0.0",
                    "parameters": {},
                    "variables": {},
                    "resources": [
                        {
                            "name": f"[variables('{obj_name}')._parserName{idx}]",
                            "apiVersion": "2020-08-01",
                            "type": "Microsoft.OperationalInsights/workspaces/savedSearches",
                            "location": "[parameters('workspace-location')]",
                            "properties": {
                                "eTag": "*",
                                "displayName": rec["title"],
                                "category": "Yuma AI Agent Pack",
                                "functionAlias": alias,
                                "query": rec["query_text"],
                                "functionParameters": "",
                                "version": 2,
                                "tags": [{"name": "description", "value": rec["description"]}],
                            },
                        },
                        {
                            "type": "Microsoft.OperationalInsights/workspaces/providers/metadata",
                            "apiVersion": "2022-01-01-preview",
                            "name": (
                                f"[concat(parameters('workspace'),'/Microsoft.SecurityInsights/',"
                                f"concat('Parser-', '{alias}'))]"
                            ),
                            "dependsOn": [f"[variables('{obj_name}')._parserId{idx}]"],
                            "properties": {
                                "description": rec["description"],
                                "parentId": f"[variables('{obj_name}')._parserId{idx}]",
                                "contentId": content_id,
                                "kind": "Parser",
                                "version": SOL_VERSION,
                                "source": source_block(),
                                "author": author_block(),
                                "support": support_block(),
                            },
                        },
                    ],
                },
                "packageKind": "Solution",
                "packageVersion": "[variables('_solutionVersion')]",
                "packageName": "[variables('_solutionName')]",
                "packageId": "[variables('_solutionId')]",
                "contentSchemaVersion": "3.0.0",
                "contentId": content_id,
                "contentKind": "Parser",
                "displayName": rec["title"],
                "contentProductId": f"[variables('{obj_name}')._parsercontentProductId{idx}]",
                "id": f"[variables('{obj_name}')._parsercontentProductId{idx}]",
                "version": SOL_VERSION,
            },
        })

    # Workbook contentTemplate
    wb_content_id = WORKBOOK_SPEC["content_id"]
    variables["_workbookContentId1"] = wb_content_id
    variables["workbookVersion1"] = SOL_VERSION
    variables["workbookTemplateSpecName1"] = (
        f"[concat(parameters('workspace'),'/Microsoft.SecurityInsights/', "
        f"concat(parameters('workspace'),'-wb-',uniquestring('{wb_content_id}')))]"
    )
    variables["workbookId1"] = f"[resourceId('Microsoft.Insights/workbooks', '{wb_content_id}')]"
    variables["_workbookcontentProductId1"] = (
        f"[concat(take(variables('_solutionId'),50),'-','wb','-', "
        f"uniqueString(concat(variables('_solutionId'),'-','Workbook','-', '{wb_content_id}', '-', '{SOL_VERSION}')))]"
    )
    criteria.append({"kind": "Workbook", "contentId": wb_content_id, "version": SOL_VERSION})

    serialized_wb = json.dumps(workbook_obj)
    resources.append({
        "type": "Microsoft.OperationalInsights/workspaces/providers/contentTemplates",
        "apiVersion": "2023-04-01-preview",
        "name": "[variables('workbookTemplateSpecName1')]",
        "location": "[parameters('workspace-location')]",
        "condition": "[parameters('DeployWorkbook')]",
        "dependsOn": [package_dep],
        "properties": {
            "description": f"YumaAIAgentRegisterAndISMEvidence Workbook with template version {SOL_VERSION}",
            "mainTemplate": {
                "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                "contentVersion": "1.0.0.0",
                "parameters": {},
                "variables": {},
                "resources": [
                    {
                        "type": "Microsoft.Insights/workbooks",
                        "name": wb_content_id,
                        "location": "[parameters('workspace-location')]",
                        "kind": "shared",
                        "apiVersion": "2022-04-01",
                        "metadata": {"description": WORKBOOK_SPEC["description"]},
                        "properties": {
                            "displayName": "[parameters('workbook1-name')]",
                            "serializedData": serialized_wb,
                            "version": "Notebook/1.0",
                            "sourceId": "[variables('workspaceResourceId')]",
                            "category": "sentinel",
                        },
                    },
                    {
                        "type": "Microsoft.OperationalInsights/workspaces/providers/metadata",
                        "apiVersion": "2022-01-01-preview",
                        "name": (
                            f"[concat(parameters('workspace'),'/Microsoft.SecurityInsights/',"
                            f"concat('Workbook-', '{wb_content_id}'))]"
                        ),
                        "properties": {
                            "description": WORKBOOK_SPEC["description"],
                            "parentId": "[variables('workbookId1')]",
                            "contentId": wb_content_id,
                            "kind": "Workbook",
                            "version": SOL_VERSION,
                            "source": source_block(),
                            "author": author_block(),
                            "support": support_block(),
                        },
                    },
                ],
            },
            "packageKind": "Solution",
            "packageVersion": "[variables('_solutionVersion')]",
            "packageName": "[variables('_solutionName')]",
            "packageId": "[variables('_solutionId')]",
            "contentSchemaVersion": "3.0.0",
            "contentId": wb_content_id,
            "contentKind": "Workbook",
            "displayName": "[parameters('workbook1-name')]",
            "contentProductId": "[variables('_workbookcontentProductId1')]",
            "id": "[variables('_workbookcontentProductId1')]",
            "version": SOL_VERSION,
        },
    })

    # Playbook contentTemplates
    for idx, rec in enumerate(playbook_records, start=1):
        content_id = rec["id"]
        variables[f"_playbookContentId{idx}"] = content_id
        variables[f"playbookVersion{idx}"] = SOL_VERSION
        variables[f"playbookTemplateSpecName{idx}"] = (
            f"[concat(parameters('workspace'),'/Microsoft.SecurityInsights/', "
            f"concat(parameters('workspace'),'-pb-',uniquestring('{content_id}')))]"
        )
        variables[f"_playbookcontentProductId{idx}"] = (
            f"[concat(take(variables('_solutionId'),50),'-','pb','-', "
            f"uniqueString(concat(variables('_solutionId'),'-','Playbook','-', '{content_id}', '-', '{SOL_VERSION}')))]"
        )
        criteria.append({"kind": "Playbook", "contentId": content_id, "version": SOL_VERSION})

        resources.append({
            "type": "Microsoft.OperationalInsights/workspaces/providers/contentTemplates",
            "apiVersion": "2023-04-01-preview",
            "name": f"[variables('playbookTemplateSpecName{idx}')]",
            "location": "[parameters('workspace-location')]",
            "condition": "[parameters('DeployPlaybook')]",
            "dependsOn": [package_dep],
            "properties": {
                "description": f"{rec['folder']} Playbook with template version {SOL_VERSION}",
                "mainTemplate": escape_arm_expressions(rec["arm"]),
                "packageKind": "Solution",
                "packageVersion": "[variables('_solutionVersion')]",
                "packageName": "[variables('_solutionName')]",
                "packageId": "[variables('_solutionId')]",
                "contentSchemaVersion": "3.0.0",
                "contentId": content_id,
                "contentKind": "Playbook",
                "displayName": rec["display_name"],
                "contentProductId": f"[variables('_playbookcontentProductId{idx}')]",
                "id": f"[variables('_playbookcontentProductId{idx}')]",
                "version": SOL_VERSION,
            },
        })

    # Solution contentPackage resource
    prereq_note = (
        "Prerequisite: deploy microsoft/deploy/register-infra.json (or the unified microsoft/deploy/azuredeploy.json) "
        "into the target workspace first to create AIAgentRegister_CL, the direct-ingestion DCR and the "
        "YumaAIRegisterApproved and YumaISMControlMap watchlists."
    )
    description_html = (
        f"<p>{solution_desc}</p>\n"
        f"<p><strong>Prerequisite:</strong> {prereq_note}</p>\n"
        f"<p><strong>Analytic Rules:</strong> {len(analytic_records)}, "
        f"<strong>Hunting Queries:</strong> {len(hunting_records)}, "
        f"<strong>Parsers:</strong> {len(parser_records)}, "
        f"<strong>Workbooks:</strong> 1, "
        f"<strong>Playbooks:</strong> {len(playbook_records)}</p>\n"
        f"<p><a href=\"{REPO_URL}\">Yuma AI Agent Threat Detection repository</a></p>"
    )
    resources.append({
        "type": "Microsoft.OperationalInsights/workspaces/providers/contentPackages",
        "apiVersion": "2023-04-01-preview",
        "name": "[concat(parameters('workspace'),'/Microsoft.SecurityInsights/', variables('_solutionId'))]",
        "location": "[parameters('workspace-location')]",
        "properties": {
            "version": "[variables('_solutionVersion')]",
            "kind": "Solution",
            "contentSchemaVersion": "3.0.0",
            "displayName": SOL_NAME,
            "publisherDisplayName": "Yuma IT",
            "descriptionHtml": description_html,
            "contentKind": "Solution",
            "contentProductId": "[variables('_solutioncontentProductId')]",
            "id": "[variables('_solutioncontentProductId')]",
            "contentId": "[variables('_solutionId')]",
            "parentId": "[variables('_solutionId')]",
            "source": source_block(),
            "author": author_block(),
            "support": support_block(),
            "dependencies": {
                "operator": "AND",
                "criteria": criteria,
            },
            "firstPublishDate": FIRST_PUBLISH_DATE,
            "providers": ["Yuma IT"],
            "categories": {
                "domains": ["Security - Threat Protection", "Identity", "Compliance"],
            },
        },
    })

    return {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "metadata": {
            "author": "Yuma IT",
            "comments": (
                "Microsoft Sentinel Content Hub V3 solution package generated by "
                "microsoft/tools/build_sentinel_solution.py. Checked offline; test in a non-production workspace."
            ),
        },
        "parameters": {
            "location": {
                "type": "string",
                "minLength": 1,
                "defaultValue": "[resourceGroup().location]",
                "metadata": {
                    "description": "Default resource group location; workspace-location is used for Sentinel resources.",
                },
            },
            "workspace-location": {
                "type": "string",
                "defaultValue": "[resourceGroup().location]",
                "metadata": {
                    "description": "Azure region of the target Log Analytics workspace.",
                },
            },
            "workspace": {
                "type": "string",
                "minLength": 1,
                "metadata": {
                    "description": "Log Analytics workspace name where Microsoft Sentinel is enabled.",
                },
            },
            "workbook1-name": {
                "type": "string",
                "defaultValue": WORKBOOK_SPEC["display_name"],
                "minLength": 1,
                "metadata": {
                    "description": "Display name for the AI Agent Register and ISM Evidence workbook.",
                },
            },
            "DeployAnalyticsRule": {
                "type": "bool",
                "defaultValue": True,
                "metadata": {
                    "description": "Deploy Microsoft Sentinel analytics rule templates included in this solution.",
                },
            },
            "DeployHuntingQuery": {
                "type": "bool",
                "defaultValue": True,
                "metadata": {
                    "description": "Deploy Microsoft Sentinel hunting query templates included in this solution.",
                },
            },
            "DeployParser": {
                "type": "bool",
                "defaultValue": True,
                "metadata": {
                    "description": "Deploy Yuma saved workspace function (parser) templates included in this solution.",
                },
            },
            "DeployWorkbook": {
                "type": "bool",
                "defaultValue": True,
                "metadata": {
                    "description": "Deploy the Yuma AI Agent Register and ISM Evidence workbook template.",
                },
            },
            "DeployPlaybook": {
                "type": "bool",
                "defaultValue": True,
                "metadata": {
                    "description": "Register the Logic App playbook templates in Content Hub.",
                },
            },
        },
        "variables": variables,
        "resources": resources,
    }


def build_create_ui_definition(
    solution_desc: str,
    analytic_records: list[dict[str, Any]],
    hunting_records: list[dict[str, Any]],
    parser_records: list[dict[str, Any]],
    playbook_records: list[dict[str, Any]],
) -> dict[str, Any]:
    analytic_sections = [
        {
            "name": f"analytic{idx}",
            "type": "Microsoft.Common.Section",
            "label": rec["name"],
            "elements": [
                {
                    "name": f"analytic{idx}-text",
                    "type": "Microsoft.Common.TextBlock",
                    "options": {"text": rec["description"]},
                }
            ],
        }
        for idx, rec in enumerate(analytic_records, start=1)
    ]
    hunting_sections = [
        {
            "name": f"huntingquery{idx}",
            "type": "Microsoft.Common.Section",
            "label": rec["name"],
            "elements": [
                {
                    "name": f"huntingquery{idx}-text",
                    "type": "Microsoft.Common.TextBlock",
                    "options": {"text": rec["description"]},
                }
            ],
        }
        for idx, rec in enumerate(hunting_records, start=1)
    ]
    parser_sections = [
        {
            "name": f"parser{idx}",
            "type": "Microsoft.Common.Section",
            "label": rec["alias"],
            "elements": [
                {
                    "name": f"parser{idx}-text",
                    "type": "Microsoft.Common.TextBlock",
                    "options": {"text": rec["description"]},
                }
            ],
        }
        for idx, rec in enumerate(parser_records, start=1)
    ]
    playbook_sections = [
        {
            "name": f"playbook{idx}",
            "type": "Microsoft.Common.Section",
            "label": rec["display_name"],
            "elements": [
                {
                    "name": f"playbook{idx}-text",
                    "type": "Microsoft.Common.TextBlock",
                    "options": {"text": rec["description"]},
                }
            ],
        }
        for idx, rec in enumerate(playbook_records, start=1)
    ]

    basics_description = (
        f"{solution_desc}\n\n"
        "**Prerequisite:** Deploy `microsoft/deploy/register-infra.json` (or `microsoft/deploy/azuredeploy.json`) "
        "into the target workspace first to create `AIAgentRegister_CL`, the ingestion DCR and the "
        "`YumaAIRegisterApproved` and `YumaISMControlMap` watchlists.\n\n"
        f"**Analytic Rules:** {len(analytic_records)}, **Hunting Queries:** {len(hunting_records)}, "
        f"**Parsers:** {len(parser_records)}, **Workbooks:** 1, **Playbooks:** {len(playbook_records)}\n\n"
        f"[Repository and documentation]({REPO_URL})"
    )

    return {
        "$schema": "https://schema.management.azure.com/schemas/0.1.2-preview/CreateUIDefinition.MultiVm.json#",
        "handler": "Microsoft.Azure.CreateUIDef",
        "version": "0.1.2-preview",
        "parameters": {
            "config": {
                "isWizard": False,
                "basics": {
                    "description": basics_description,
                    "subscription": {
                        "resourceProviders": [
                            "Microsoft.OperationsManagement/solutions",
                            "Microsoft.OperationalInsights/workspaces/providers/alertRules",
                            "Microsoft.Insights/workbooks",
                            "Microsoft.Logic/workflows",
                        ]
                    },
                    "location": {
                        "metadata": {
                            "hidden": "Location is derived from the selected Log Analytics workspace.",
                        },
                        "visible": False,
                    },
                    "resourceGroup": {
                        "allowExisting": True,
                    },
                },
            },
            "basics": [
                {
                    "name": "getLAWorkspace",
                    "type": "Microsoft.Solutions.ArmApiControl",
                    "toolTip": "Lists Log Analytics workspaces in the selected subscription.",
                    "condition": "[greater(length(resourceGroup().name),0)]",
                    "request": {
                        "method": "GET",
                        "path": "[concat(subscription().id,'/providers/Microsoft.OperationalInsights/workspaces?api-version=2020-08-01')]",
                    },
                },
                {
                    "name": "workspace",
                    "type": "Microsoft.Common.DropDown",
                    "label": "Workspace",
                    "placeholder": "Select a workspace",
                    "toolTip": "Select an existing Log Analytics workspace in the chosen resource group.",
                    "constraints": {
                        "allowedValues": (
                            "[map(filter(basics('getLAWorkspace').value, (filter) => contains(toLower(filter.id), "
                            "toLower(concat('/resourcegroups/', resourceGroup().name, '/')))), (item) => parse(concat('{\"label\":\"', item.name, "
                            "'\",\"value\":\"', item.name, '\"}')))]"
                        ),
                        "required": True,
                    },
                    "visible": True,
                },
            ],
            "steps": [
                {
                    "name": "contentSelection",
                    "label": "Content selection",
                    "elements": [
                        {
                            "name": "DeployAnalyticsRule",
                            "type": "Microsoft.Common.CheckBox",
                            "label": "Deploy analytics rules",
                            "defaultValue": True,
                            "toolTip": "Install the six scheduled Microsoft Sentinel analytics rule templates (disabled by default).",
                        },
                        {
                            "name": "DeployHuntingQuery",
                            "type": "Microsoft.Common.CheckBox",
                            "label": "Deploy hunting queries",
                            "defaultValue": True,
                            "toolTip": "Install the five Microsoft Sentinel hunting queries.",
                        },
                        {
                            "name": "DeployParser",
                            "type": "Microsoft.Common.CheckBox",
                            "label": "Deploy parsers (saved functions)",
                            "defaultValue": True,
                            "toolTip": "Install the five Yuma register and ISM evidence workspace functions.",
                        },
                        {
                            "name": "DeployWorkbook",
                            "type": "Microsoft.Common.CheckBox",
                            "label": "Deploy workbook",
                            "defaultValue": True,
                            "toolTip": "Install the Yuma AI Agent Register and ISM Evidence workbook.",
                        },
                        {
                            "name": "DeployPlaybook",
                            "type": "Microsoft.Common.CheckBox",
                            "label": "Deploy playbook templates",
                            "defaultValue": True,
                            "toolTip": "Register the PB1, PB4 and PB5 Logic App playbook templates.",
                        },
                    ],
                },
                {
                    "name": "workbooks",
                    "label": "Workbooks",
                    "subLabel": {
                        "preValidation": "Configure the workbooks",
                        "postValidation": "Done",
                    },
                    "bladeTitle": "Workbooks",
                    "elements": [
                        {
                            "name": "workbooks-text",
                            "type": "Microsoft.Common.TextBlock",
                            "options": {
                                "text": "This solution installs the Yuma AI Agent Register and ISM Evidence workbook.",
                            },
                        },
                        {
                            "name": "workbook1",
                            "type": "Microsoft.Common.Section",
                            "label": WORKBOOK_SPEC["display_name"],
                            "elements": [
                                {
                                    "name": "workbook1-text",
                                    "type": "Microsoft.Common.TextBlock",
                                    "options": {"text": WORKBOOK_SPEC["description"]},
                                },
                                {
                                    "name": "workbook1-name",
                                    "type": "Microsoft.Common.TextBox",
                                    "label": "Display Name",
                                    "defaultValue": WORKBOOK_SPEC["display_name"],
                                    "toolTip": "Display name for the workbook.",
                                    "constraints": {
                                        "required": True,
                                        "regex": "[a-z0-9A-Z]{1,256}$",
                                        "validationMessage": "Please enter a workbook display name.",
                                    },
                                },
                            ],
                        },
                    ],
                },
                {
                    "name": "analytics",
                    "label": "Analytics",
                    "subLabel": {"preValidation": "Configure the analytics", "postValidation": "Done"},
                    "bladeTitle": "Analytics",
                    "elements": [
                        {
                            "name": "analytics-text",
                            "type": "Microsoft.Common.TextBlock",
                            "options": {
                                "text": "This solution installs the following analytics rule templates. Rules start disabled so you can tune thresholds before enabling them.",
                            },
                        },
                        *analytic_sections,
                    ],
                },
                {
                    "name": "huntingqueries",
                    "label": "Hunting Queries",
                    "bladeTitle": "Hunting Queries",
                    "elements": [
                        {
                            "name": "huntingqueries-text",
                            "type": "Microsoft.Common.TextBlock",
                            "options": {
                                "text": "This solution installs the following hunting queries.",
                            },
                        },
                        *hunting_sections,
                    ],
                },
                {
                    "name": "parsers",
                    "label": "Parsers",
                    "bladeTitle": "Parsers",
                    "elements": [
                        {
                            "name": "parsers-text",
                            "type": "Microsoft.Common.TextBlock",
                            "options": {
                                "text": "This solution installs the following workspace functions (parsers) for the AI agent register and ISM evidence exports.",
                            },
                        },
                        *parser_sections,
                    ],
                },
                {
                    "name": "playbooks",
                    "label": "Playbooks",
                    "bladeTitle": "Playbooks",
                    "elements": [
                        {
                            "name": "playbooks-text",
                            "type": "Microsoft.Common.TextBlock",
                            "options": {
                                "text": "This solution packages the following Logic App playbooks. Playbooks deploy disabled and require managed identity role assignments after deployment.",
                            },
                        },
                        *playbook_sections,
                    ],
                },
            ],
            "outputs": {
                "workspace-location": (
                    "[first(map(filter(basics('getLAWorkspace').value, (filter) => and(contains(toLower(filter.id), "
                    "toLower(concat('/resourcegroups/', resourceGroup().name, '/'))),equals(filter.name,basics('workspace')))), (item) => item.location))]"
                ),
                "location": "[location()]",
                "workspace": "[basics('workspace')]",
                "workbook1-name": "[steps('workbooks').workbook1.workbook1-name]",
                "DeployAnalyticsRule": "[steps('contentSelection').DeployAnalyticsRule]",
                "DeployHuntingQuery": "[steps('contentSelection').DeployHuntingQuery]",
                "DeployParser": "[steps('contentSelection').DeployParser]",
                "DeployWorkbook": "[steps('contentSelection').DeployWorkbook]",
                "DeployPlaybook": "[steps('contentSelection').DeployPlaybook]",
            },
        },
    }


def main() -> None:
    counts = build_solution_files()
    print(
        "Built Sentinel Solution V3 package at "
        f"{SOL_ROOT.relative_to(REPO_ROOT)}: "
        + ", ".join(f"{k}={v}" for k, v in counts.items())
    )


if __name__ == "__main__":
    main()
