#!/usr/bin/env python3
"""
cf-waf-bypass-check

Read-only audit of a Cloudflare WAF configuration for rules that skip, disable,
or downgrade Cloudflare Managed Rules, with specific checks for the php2shell
(CVE-2026-109618 / CVE-2026-109619) protections Cloudflare released on
2026-10-21.

Only HTTP GET requests are issued. Nothing in your account is modified.

Authentication (either):
  * Cloudflare's cf CLI:  npm install -g cf && cf auth login   (no token needed)
  * A scoped API token in CLOUDFLARE_API_TOKEN (Zone:Read + Zone WAF:Read).
    The token is intentionally not accepted as a command-line flag so it does
    not end up in shell history or process lists.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import shutil
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any, Optional

__version__ = "1.0.0"

API_BASE = "https://api.cloudflare.com/client/v4"
USER_AGENT = f"cf-waf-bypass-check/{__version__}"
REQUEST_TIMEOUT_SECONDS = 30
MAX_RETRIES = 4
ZONE_ID_PATTERN = re.compile(r"^[0-9a-f]{32}$")
ZONE_NAME_PATTERN = re.compile(r"^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z0-9-]{2,63}$")

PHASE_CUSTOM = "http_request_firewall_custom"
PHASE_MANAGED = "http_request_firewall_managed"
PHASE_RESPONSE_MANAGED = "http_response_firewall_managed"
MANAGED_PHASES = frozenset({PHASE_MANAGED, PHASE_RESPONSE_MANAGED})

CLOUDFLARE_MANAGED_RULESET_ID = "efb7b8c949ac4650a09736fc376e9aee"
CLOUDFLARE_FREE_MANAGED_RULESET_ID = "77454fe2d30c4220b5701f6fdfb893ba"
MANAGED_RULESET_NAMES = {
    CLOUDFLARE_MANAGED_RULESET_ID: "Cloudflare Managed Ruleset",
    CLOUDFLARE_FREE_MANAGED_RULESET_ID: "Cloudflare Managed Free Ruleset",
}

# Source: https://blog.cloudflare.com/php-vulnerabilities-waf-protection/
PHP2SHELL_RULES_BY_RULESET: dict[str, dict[str, str]] = {
    CLOUDFLARE_MANAGED_RULESET_ID: {
        "c1d409ad838f47f59446f21cc438d5dd": "Generic Rules - Anomalous Execution - 1",
        "f9a45927414245e3a64bb12d0a0c2f64": "Generic Rules - Anomalous Execution - 2",
        "771c654ae1154d4daa72f4e1545d163c": "Generic Rules - Anomalous Execution - 3",
        "217005865f0145f392300bac212afcc9": "Generic Rules - Anomalous Execution - 4",
        "38efdb17ea594501bb55a1d71867b12e": "Generic Rules - Anomalous Execution - 5",
        "4148ae686fdb4d01be673fab9d9c073d": "Generic Rules - Anomalous Execution - 6",
        "1389aa259617437392ce149c48143645": "Generic Rules - Anomalous Execution - 7",
    },
    CLOUDFLARE_FREE_MANAGED_RULESET_ID: {
        "4e315666e8e344cdb64119a3b5ccf32f": "Generic Rules - Anomalous Execution - 1",
        "00c10e6cc4da4bd08722adeebcd95984": "Generic Rules - Anomalous Execution - 2",
        "48ddf592361e4fdb97a8a85982dab691": "Generic Rules - Anomalous Execution - 3",
        "3556683d512a47f2937899c524b1a4c6": "Generic Rules - Anomalous Execution - 4",
        "da07c85852e34625bb478496302ede46": "Generic Rules - Anomalous Execution - 5",
        "19373a83abb840e18ab3ce5a7975ce1b": "Generic Rules - Anomalous Execution - 6",
        "07f0b6ddaabf40b1b2042dade8d613fa": "Generic Rules - Anomalous Execution - 7",
    },
}
PHP2SHELL_RESPONSE_RULE_ID = "afffe22785674c80a31875c848d2242a"
ALL_PHP2SHELL_RULE_IDS = frozenset(
    {rule_id for rules in PHP2SHELL_RULES_BY_RULESET.values() for rule_id in rules}
    | {PHP2SHELL_RESPONSE_RULE_ID}
)

NON_BLOCKING_ACTIONS = frozenset({"log", "skip"})

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# Fields an attacker controls simply by choosing what URL/host/method to send.
REQUEST_TARGET_FIELDS = frozenset({
    "http.host",
    "http.request.uri",
    "http.request.uri.path",
    "http.request.uri.path.extension",
    "http.request.uri.query",
    "http.request.uri.args",
    "http.request.uri.args.names",
    "http.request.uri.args.values",
    "http.request.full_uri",
    "http.request.method",
    "http.request.version",
    "raw.http.request.uri",
    "raw.http.request.uri.path",
    "raw.http.request.uri.query",
    "raw.http.request.full_uri",
    "ssl",
    "cf.zone.name",
})
# Fields whose values are supplied by the client and can be forged.
CLIENT_CONTROLLED_PREFIXES = (
    "http.request.headers",
    "raw.http.request.headers",
    "http.request.cookies",
    "http.cookie",
    "http.user_agent",
    "http.referer",
    "http.x_forwarded_for",
    "http.request.accepted_languages",
    "http.request.body",
)

QUOTED_STRING_PATTERN = re.compile(r'r#*"(?:.|\n)*?"#*|"(?:[^"\\]|\\.)*"')
FIELD_PATTERN = re.compile(r"\b[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+\b")
OR_PATTERN = re.compile(r"\bor\b|\|\|", re.IGNORECASE)

LOGGER = logging.getLogger("cf_waf_bypass_check")


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #

@dataclass
class Finding:
    severity: str
    target: str
    phase: str
    title: str
    detail: str
    recommendation: str
    rule_id: str = ""
    rule_description: str = ""
    expression: str = ""
    ruleset_id: str = ""

    def sort_key(self) -> tuple[int, str, str]:
        return (-SEVERITY_ORDER[self.severity], self.target, self.phase)


@dataclass
class ExpressionScope:
    category: str  # all_traffic | request_target_only | client_controlled | needs_review | restricted
    explanation: str


# --------------------------------------------------------------------------- #
# Expression heuristics
# --------------------------------------------------------------------------- #

def extract_fields(expression: str) -> set[str]:
    """Return the set of Rules language field names referenced in an expression."""
    without_strings = QUOTED_STRING_PATTERN.sub('""', expression or "")
    return set(FIELD_PATTERN.findall(without_strings))


def classify_expression(expression: str) -> ExpressionScope:
    """Estimate how much traffic a rule expression can match, from an attacker's viewpoint."""
    normalized = (expression or "").strip().lower()
    while normalized.startswith("(") and normalized.endswith(")"):
        normalized = normalized[1:-1].strip()

    if normalized in ("", "true"):
        return ExpressionScope("all_traffic", "expression matches every request")

    fields = extract_fields(normalized)
    if not fields:
        return ExpressionScope("all_traffic", "expression references no request fields")

    if fields <= REQUEST_TARGET_FIELDS:
        return ExpressionScope(
            "request_target_only",
            "expression only checks host/path/method/query, which any client can choose",
        )

    has_client_controlled = any(
        field_name.startswith(CLIENT_CONTROLLED_PREFIXES) for field_name in fields
    )
    has_trusted_condition = any(
        not field_name.startswith(CLIENT_CONTROLLED_PREFIXES) and field_name not in REQUEST_TARGET_FIELDS
        for field_name in fields
    )

    if OR_PATTERN.search(normalized):
        return ExpressionScope(
            "needs_review",
            "expression contains OR branches; confirm every branch is restricted to trusted sources",
        )
    if has_client_controlled and not has_trusted_condition:
        return ExpressionScope(
            "client_controlled",
            "expression relies on client-supplied values (headers/cookies/user agent) that can be forged",
        )
    return ExpressionScope(
        "restricted",
        "expression is limited by source conditions (e.g. ip.src, mTLS, verified bots)",
    )


SCOPE_SEVERITY = {
    "all_traffic": "critical",
    "request_target_only": "critical",
    "client_controlled": "high",
    "needs_review": "high",
    "restricted": "medium",
}


def is_enabled(rule: dict[str, Any]) -> bool:
    return rule.get("enabled", True) is not False


def describe(rule: dict[str, Any]) -> str:
    return rule.get("description") or rule.get("ref") or "(no description)"


# --------------------------------------------------------------------------- #
# Analysis (pure functions over ruleset JSON)
# --------------------------------------------------------------------------- #

def analyze_custom_rules(ruleset: dict[str, Any], target: str, phase: str = PHASE_CUSTOM) -> list[Finding]:
    """Flag custom rules that skip managed-rule phases or the legacy WAF product."""
    findings: list[Finding] = []
    for rule in ruleset.get("rules") or []:
        if rule.get("action") != "skip":
            continue
        parameters = rule.get("action_parameters") or {}
        skipped_phases = sorted(set(parameters.get("phases") or []) & MANAGED_PHASES)
        skips_legacy_waf = "waf" in (parameters.get("products") or [])
        if not skipped_phases and not skips_legacy_waf:
            continue

        expression = rule.get("expression", "")
        skipped_label = ", ".join(skipped_phases + (["product: waf (legacy)"] if skips_legacy_waf else []))

        if not is_enabled(rule):
            findings.append(Finding(
                severity="info",
                target=target,
                phase=phase,
                title="Disabled skip rule would bypass managed rules if re-enabled",
                detail=f"Skips: {skipped_label}",
                recommendation="Delete the rule if it is no longer needed.",
                rule_id=rule.get("id", ""),
                rule_description=describe(rule),
                expression=expression,
                ruleset_id=ruleset.get("id", ""),
            ))
            continue

        scope = classify_expression(expression)
        severity = SCOPE_SEVERITY[scope.category] if skipped_phases else "medium"
        findings.append(Finding(
            severity=severity,
            target=target,
            phase=phase,
            title="Custom rule skips Cloudflare managed rules",
            detail=f"Skips: {skipped_label}. Matching requests never reach the php2shell protections; {scope.explanation}.",
            recommendation=(
                "Remove the managed-rules phase from this skip rule, or narrow the expression to "
                "trusted sources (ip.src lists, mTLS). Prefer a managed-rule exception that skips "
                "only the specific false-positive rule IDs."
            ),
            rule_id=rule.get("id", ""),
            rule_description=describe(rule),
            expression=expression,
            ruleset_id=ruleset.get("id", ""),
        ))
    return findings


def effective_rule_state(
    rule_id: str,
    overrides: dict[str, Any],
    rule_metadata: Optional[dict[str, Any]],
) -> tuple[bool, Optional[str], str]:
    """
    Resolve a managed rule's effective enabled/action state.

    Cloudflare precedence: rule override > category override > ruleset override > default.
    Returns (enabled, action, source_of_decision).
    """
    enabled: Optional[bool] = None
    action: Optional[str] = None
    enabled_source = "default"
    action_source = "default"

    for rule_override in overrides.get("rules") or []:
        if rule_override.get("id") == rule_id:
            if "enabled" in rule_override:
                enabled, enabled_source = bool(rule_override["enabled"]), "rule override"
            if rule_override.get("action"):
                action, action_source = rule_override["action"], "rule override"

    rule_categories = set((rule_metadata or {}).get("categories") or [])
    for category_override in overrides.get("categories") or []:
        if category_override.get("category") in rule_categories:
            if enabled is None and "enabled" in category_override:
                enabled = bool(category_override["enabled"])
                enabled_source = f"category override ({category_override['category']})"
            if action is None and category_override.get("action"):
                action = category_override["action"]
                action_source = f"category override ({category_override['category']})"

    if enabled is None and "enabled" in overrides:
        enabled, enabled_source = bool(overrides["enabled"]), "ruleset override"
    if action is None and overrides.get("action"):
        action, action_source = overrides["action"], "ruleset override"

    if enabled is None:
        enabled = (rule_metadata or {}).get("enabled", True) is not False
    if action is None:
        action = (rule_metadata or {}).get("action")

    source = enabled_source if not enabled else action_source
    return enabled, action, source


def analyze_execute_rule(
    rule: dict[str, Any],
    target: str,
    phase: str,
    ruleset_rule_metadata: dict[str, dict[str, Any]],
) -> list[Finding]:
    """Check one execute rule that deploys a Cloudflare managed ruleset."""
    findings: list[Finding] = []
    parameters = rule.get("action_parameters") or {}
    deployed_ruleset_id = parameters.get("id", "")
    ruleset_name = MANAGED_RULESET_NAMES.get(deployed_ruleset_id, deployed_ruleset_id)
    overrides = parameters.get("overrides") or {}
    common = {
        "target": target,
        "phase": phase,
        "rule_id": rule.get("id", ""),
        "rule_description": describe(rule),
        "expression": rule.get("expression", ""),
        "ruleset_id": deployed_ruleset_id,
    }

    if not is_enabled(rule):
        findings.append(Finding(
            severity="critical",
            title=f"{ruleset_name} deployment is disabled",
            detail="The execute rule that deploys the managed ruleset is turned off, so none of its rules run.",
            recommendation="Enable the managed ruleset deployment.",
            **common,
        ))
        return findings

    scope = classify_expression(rule.get("expression", ""))
    if scope.category != "all_traffic":
        findings.append(Finding(
            severity="medium",
            title=f"{ruleset_name} is deployed to a subset of traffic",
            detail="The deployment expression is scoped; requests outside it are not inspected by managed rules.",
            recommendation="Confirm every hostname and path that runs PHP is covered, or deploy with expression 'true'.",
            **common,
        ))

    if overrides.get("enabled") is False:
        findings.append(Finding(
            severity="high",
            title=f"{ruleset_name}: all rules disabled by ruleset-level override",
            detail="A ruleset-wide override sets enabled=false. Only rules explicitly re-enabled will run.",
            recommendation="Remove the ruleset-wide enabled=false override.",
            **common,
        ))
    if overrides.get("action") in NON_BLOCKING_ACTIONS:
        findings.append(Finding(
            severity="high",
            title=f"{ruleset_name}: ruleset-wide action overridden to '{overrides['action']}'",
            detail="Every rule in the ruleset only logs instead of blocking.",
            recommendation="Remove the ruleset-wide action override or set it to block.",
            **common,
        ))

    for category_override in overrides.get("categories") or []:
        if category_override.get("enabled") is False or category_override.get("action") in NON_BLOCKING_ACTIONS:
            php2shell_categories = {
                category
                for rule_id in PHP2SHELL_RULES_BY_RULESET.get(deployed_ruleset_id, {})
                for category in (ruleset_rule_metadata.get(rule_id) or {}).get("categories") or []
            }
            if php2shell_categories and category_override.get("category") not in php2shell_categories:
                continue
            findings.append(Finding(
                severity="medium",
                title=f"{ruleset_name}: category '{category_override.get('category')}' disabled or set to log",
                detail=(
                    "Category overrides can silently cover new rules."
                    if php2shell_categories
                    else "Could not load rule categories to confirm whether php2shell rules are in this category."
                ),
                recommendation="Review whether this category override is still required.",
                **common,
            ))

    for php2shell_rule_id, php2shell_name in PHP2SHELL_RULES_BY_RULESET.get(deployed_ruleset_id, {}).items():
        enabled, action, source = effective_rule_state(
            php2shell_rule_id, overrides, ruleset_rule_metadata.get(php2shell_rule_id)
        )
        if not enabled or action in NON_BLOCKING_ACTIONS:
            state = "disabled" if not enabled else f"action '{action}'"
            findings.append(Finding(
                severity="critical",
                title=f"php2shell rule not blocking: {php2shell_name}",
                detail=f"Managed rule {php2shell_rule_id} is effectively {state} (set by {source}).",
                recommendation="Remove the override so the rule runs with its default (block) action.",
                **common,
            ))
        elif action and action != "block":
            findings.append(Finding(
                severity="low",
                title=f"php2shell rule action changed: {php2shell_name}",
                detail=f"Managed rule {php2shell_rule_id} uses action '{action}' (set by {source}).",
                recommendation="Non-browser exploit tooling cannot pass challenges, but 'block' is the documented default.",
                **common,
            ))

    if phase == PHASE_RESPONSE_MANAGED:
        enabled, action, source = effective_rule_state(PHP2SHELL_RESPONSE_RULE_ID, overrides, None)
        if not enabled or action in NON_BLOCKING_ACTIONS:
            findings.append(Finding(
                severity="critical",
                title="php2shell response rule not blocking",
                detail=f"Response rule {PHP2SHELL_RESPONSE_RULE_ID} is effectively disabled or logging (set by {source}).",
                recommendation="Remove the override on the response firewall rule.",
                **common,
            ))
    return findings


def analyze_managed_phase(
    ruleset: dict[str, Any],
    target: str,
    phase: str,
    plan: str,
    rule_metadata_by_ruleset: dict[str, dict[str, dict[str, Any]]],
    require_deployment: bool = True,
) -> list[Finding]:
    """Check managed ruleset deployments and the exceptions placed in front of them."""
    findings: list[Finding] = []
    rules = ruleset.get("rules") or []
    managed_execute_indexes: list[int] = []
    deployed_ruleset_ids: set[str] = set()

    for index, rule in enumerate(rules):
        if rule.get("action") != "execute":
            continue
        deployed_id = (rule.get("action_parameters") or {}).get("id", "")
        if phase == PHASE_MANAGED and deployed_id not in MANAGED_RULESET_NAMES:
            continue
        managed_execute_indexes.append(index)
        if is_enabled(rule):
            deployed_ruleset_ids.add(deployed_id)
        findings.extend(analyze_execute_rule(
            rule, target, phase, rule_metadata_by_ruleset.get(deployed_id, {})
        ))

    for index, rule in enumerate(rules):
        if rule.get("action") != "skip" or not is_enabled(rule):
            continue
        parameters = rule.get("action_parameters") or {}
        precedes_deployment = any(execute_index > index for execute_index in managed_execute_indexes)
        if not precedes_deployment:
            continue
        skipped_description = ""

        if parameters.get("ruleset") == "current":
            skipped_description = "all remaining managed rules (skip 'current' ruleset)"
        elif set(parameters.get("rulesets") or []) & (set(MANAGED_RULESET_NAMES) | deployed_ruleset_ids):
            skipped_description = "entire managed ruleset(s): " + ", ".join(
                MANAGED_RULESET_NAMES.get(ruleset_id, ruleset_id) for ruleset_id in parameters["rulesets"]
            )
        else:
            skipped_rule_ids = {
                rule_id
                for rule_ids in (parameters.get("rules") or {}).values()
                for rule_id in rule_ids
            }
            hit_php2shell = sorted(skipped_rule_ids & ALL_PHP2SHELL_RULE_IDS)
            if hit_php2shell:
                skipped_description = "php2shell rule IDs: " + ", ".join(hit_php2shell)

        if not skipped_description:
            continue
        scope = classify_expression(rule.get("expression", ""))
        findings.append(Finding(
            severity=SCOPE_SEVERITY[scope.category],
            target=target,
            phase=phase,
            title="Managed rules exception skips php2shell protections",
            detail=f"Skips {skipped_description}; {scope.explanation}.",
            recommendation=(
                "Narrow the exception to the specific false-positive rule IDs and trusted sources, "
                "and never include the php2shell rule IDs."
            ),
            rule_id=rule.get("id", ""),
            rule_description=describe(rule),
            expression=rule.get("expression", ""),
            ruleset_id=ruleset.get("id", ""),
        ))

    if require_deployment and phase == PHASE_MANAGED:
        if plan != "free" and CLOUDFLARE_MANAGED_RULESET_ID not in deployed_ruleset_ids:
            findings.append(Finding(
                severity="critical",
                target=target,
                phase=phase,
                title="Cloudflare Managed Ruleset is not deployed",
                detail=f"Plan '{plan}' includes the Cloudflare Managed Ruleset, which carries the php2shell rules, but no enabled deployment was found.",
                recommendation="Deploy the Cloudflare Managed Ruleset (Security > WAF > Managed rules) in block mode.",
            ))
    return findings


def analyze_dns_records(records: list[dict[str, Any]], target: str) -> list[Finding]:
    unproxied = sorted({
        record.get("name", "")
        for record in records
        if record.get("type") in ("A", "AAAA", "CNAME") and record.get("proxied") is False
    })
    if not unproxied:
        return []
    return [Finding(
        severity="low",
        target=target,
        phase="dns",
        title=f"{len(unproxied)} DNS-only (grey cloud) hostname(s) bypass the WAF entirely",
        detail="Traffic to these names goes straight to the origin: " + ", ".join(unproxied),
        recommendation="Proxy any hostname serving PHP, or make sure those origins are patched first.",
    )]


# --------------------------------------------------------------------------- #
# Cloudflare API client (GET only)
# --------------------------------------------------------------------------- #

class CloudflareApiError(Exception):
    def __init__(self, status: int, message: str) -> None:
        super().__init__(f"HTTP {status}: {message}" if status else message)
        self.status = status


class CloudflareClient:
    def __init__(self, api_token: str, base_url: str = API_BASE) -> None:
        self._api_token = api_token
        self._base_url = base_url.rstrip("/")
        self._ssl_context = ssl.create_default_context()

    def get(self, path: str, params: Optional[dict[str, Any]] = None) -> dict[str, Any]:
        url = f"{self._base_url}{path}"
        if params:
            url = f"{url}?{urllib.parse.urlencode(params)}"
        request = urllib.request.Request(url, method="GET", headers={
            "Authorization": f"Bearer {self._api_token}",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        })

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                with urllib.request.urlopen(
                    request, timeout=REQUEST_TIMEOUT_SECONDS, context=self._ssl_context
                ) as response:
                    return json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                retryable = exc.code == 429 or exc.code >= 500
                if retryable and attempt < MAX_RETRIES:
                    delay = self._retry_delay(exc, attempt)
                    LOGGER.debug("Retrying %s after HTTP %s in %.1fs", path, exc.code, delay)
                    time.sleep(delay)
                    continue
                raise CloudflareApiError(exc.code, self._error_message(exc)) from None
            except urllib.error.URLError as exc:
                if attempt < MAX_RETRIES:
                    time.sleep(2 ** attempt)
                    continue
                raise CloudflareApiError(0, f"network error: {exc.reason}") from None
        raise CloudflareApiError(0, "retries exhausted")

    def get_paginated(self, path: str, params: Optional[dict[str, Any]] = None) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        page = 1
        while True:
            body = self.get(path, {**(params or {}), "page": page, "per_page": 50})
            results.extend(body.get("result") or [])
            total_pages = (body.get("result_info") or {}).get("total_pages", 1)
            if page >= total_pages:
                return results
            page += 1

    def get_optional(self, path: str) -> Optional[dict[str, Any]]:
        """GET a single resource, returning None when it does not exist (404)."""
        try:
            return self.get(path).get("result")
        except CloudflareApiError as exc:
            if exc.status == 404:
                return None
            raise

    # Semantic operations shared with CfCliClient --------------------------

    def get_entrypoint(self, scope_kind: str, scope_id: str, phase: str) -> Optional[dict[str, Any]]:
        return self.get_optional(f"/{scope_kind}/{scope_id}/rulesets/phases/{phase}/entrypoint")

    def get_ruleset(self, scope_kind: str, scope_id: str, ruleset_id: str) -> Optional[dict[str, Any]]:
        return self.get_optional(f"/{scope_kind}/{scope_id}/rulesets/{ruleset_id}")

    def get_zone(self, zone_id: str) -> Optional[dict[str, Any]]:
        return self.get_optional(f"/zones/{zone_id}")

    def find_zones_by_name(self, zone_name: str) -> list[dict[str, Any]]:
        return self.get("/zones", {"name": zone_name}).get("result") or []

    def list_zones(self, account_id: Optional[str]) -> list[dict[str, Any]]:
        return self.get_paginated("/zones", {"account.id": account_id} if account_id else None)

    def list_dns_records(self, zone_id: str) -> list[dict[str, Any]]:
        return self.get_paginated(f"/zones/{zone_id}/dns_records")

    @staticmethod
    def _retry_delay(error: urllib.error.HTTPError, attempt: int) -> float:
        retry_after = error.headers.get("Retry-After") if error.headers else None
        if retry_after and retry_after.isdigit():
            return min(float(retry_after), 60.0)
        return float(2 ** attempt)

    @staticmethod
    def _error_message(error: urllib.error.HTTPError) -> str:
        try:
            body = json.loads(error.read().decode("utf-8"))
            messages = [item.get("message", "") for item in body.get("errors") or []]
            return "; ".join(message for message in messages if message) or error.reason
        except (ValueError, AttributeError):
            return str(error.reason)


class CfCliClient:
    """
    Uses Cloudflare's `cf` CLI (npm install -g cf) so users can authenticate with
    `cf auth login` instead of creating an API token. Only read commands are run,
    always as an argument list (never through a shell).
    """

    PER_PAGE = 50
    MAX_PAGES = 1000
    COMMAND_TIMEOUT_SECONDS = 120
    ANSI_PATTERN = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
    STATUS_PATTERN = re.compile(r"\b([1-5]\d\d)\b[^\n]*·\s*HTTP")

    def __init__(self, executable: str) -> None:
        self._executable = executable

    def _run(self, arguments: list[str], account_id: Optional[str] = None) -> Optional[Any]:
        environment = {
            name: value for name, value in os.environ.items()
            if name not in ("CLOUDFLARE_ZONE_ID", "CLOUDFLARE_ACCOUNT_ID")
        }
        if account_id:
            environment["CLOUDFLARE_ACCOUNT_ID"] = account_id
        environment["NO_COLOR"] = "1"
        command = [self._executable, *arguments, "--quiet"]
        LOGGER.debug("Running: %s", " ".join(command))
        try:
            completed = subprocess.run(
                command, capture_output=True, text=True, env=environment,
                timeout=self.COMMAND_TIMEOUT_SECONDS, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise CloudflareApiError(0, f"failed to run cf CLI: {exc}") from None

        if completed.returncode != 0:
            stderr = self.ANSI_PATTERN.sub("", completed.stderr or "")
            status_match = self.STATUS_PATTERN.search(stderr)
            status = int(status_match.group(1)) if status_match else 0
            if status == 404:
                return None
            message_lines = [line.strip(" │┌└") for line in stderr.splitlines() if line.strip(" │┌└")]
            raise CloudflareApiError(status, " / ".join(message_lines[-3:]) or "cf CLI command failed")

        try:
            parsed = json.loads(completed.stdout or "null")
        except ValueError:
            raise CloudflareApiError(0, "cf CLI returned non-JSON output") from None
        if isinstance(parsed, dict) and "result" in parsed and "success" in parsed:
            return parsed["result"]
        return parsed

    def _run_paginated(self, arguments: list[str]) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for page in range(1, self.MAX_PAGES + 1):
            batch = self._run([*arguments, "--page", str(page), "--per-page", str(self.PER_PAGE)]) or []
            items.extend(batch)
            if len(batch) < self.PER_PAGE:
                break
        return items

    def get_entrypoint(self, scope_kind: str, scope_id: str, phase: str) -> Optional[dict[str, Any]]:
        if scope_kind == "zones":
            return self._run(["rulesets", "entrypoint", "get", phase, "--zone", scope_id])
        return self._run(["rulesets", "entrypoint", "get", phase], account_id=scope_id)

    def get_ruleset(self, scope_kind: str, scope_id: str, ruleset_id: str) -> Optional[dict[str, Any]]:
        if scope_kind == "zones":
            return self._run(["rulesets", "get", ruleset_id, "--zone", scope_id])
        return self._run(["rulesets", "get", ruleset_id], account_id=scope_id)

    def get_zone(self, zone_id: str) -> Optional[dict[str, Any]]:
        return self._run(["zones", "get", "--zone", zone_id])

    def find_zones_by_name(self, zone_name: str) -> list[dict[str, Any]]:
        return self._run(["zones", "list", "--name", zone_name]) or []

    def list_zones(self, account_id: Optional[str]) -> list[dict[str, Any]]:
        zones = self._run_paginated(["zones", "list"])
        if account_id:
            zones = [zone for zone in zones if (zone.get("account") or {}).get("id") == account_id]
        return zones

    def list_dns_records(self, zone_id: str) -> list[dict[str, Any]]:
        return self._run_paginated(["dns", "records", "list", "--zone", zone_id])


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #

ApiClient = Any  # CloudflareClient or CfCliClient (same semantic methods)


def load_rule_metadata(client: ApiClient, scope_kind: str, scope_id: str, ruleset_id: str) -> dict[str, dict[str, Any]]:
    """Best-effort fetch of a managed ruleset's rules (for categories/defaults)."""
    try:
        ruleset = client.get_ruleset(scope_kind, scope_id, ruleset_id) or {}
    except CloudflareApiError as exc:
        LOGGER.debug("Could not load ruleset %s: %s", ruleset_id, exc)
        return {}
    return {rule["id"]: rule for rule in ruleset.get("rules") or [] if rule.get("id")}


def audit_zone(client: ApiClient, zone: dict[str, Any], check_dns: bool) -> list[Finding]:
    zone_id = zone["id"]
    target = f"zone {zone.get('name', zone_id)}"
    plan = ((zone.get("plan") or {}).get("legacy_id") or "unknown").lower()
    findings: list[Finding] = []

    custom = client.get_entrypoint("zones", zone_id, PHASE_CUSTOM)
    if custom:
        findings.extend(analyze_custom_rules(custom, target))

    rule_metadata = {
        ruleset_id: load_rule_metadata(client, "zones", zone_id, ruleset_id)
        for ruleset_id in MANAGED_RULESET_NAMES
    }

    managed = client.get_entrypoint("zones", zone_id, PHASE_MANAGED) or {"rules": []}
    findings.extend(analyze_managed_phase(managed, target, PHASE_MANAGED, plan, rule_metadata))

    response_managed = client.get_entrypoint("zones", zone_id, PHASE_RESPONSE_MANAGED)
    if response_managed:
        findings.extend(analyze_managed_phase(
            response_managed, target, PHASE_RESPONSE_MANAGED, plan, {}, require_deployment=False
        ))

    if check_dns:
        try:
            findings.extend(analyze_dns_records(client.list_dns_records(zone_id), target))
        except CloudflareApiError as exc:
            LOGGER.warning("%s: skipped DNS check (%s). Needs Zone > DNS > Read.", target, exc)
    return findings


def audit_account(client: ApiClient, account_id: str) -> list[Finding]:
    target = f"account {account_id}"
    findings: list[Finding] = []

    custom = client.get_entrypoint("accounts", account_id, PHASE_CUSTOM)
    if custom:
        findings.extend(analyze_custom_rules(custom, target))
        for rule in custom.get("rules") or []:
            deployed_id = (rule.get("action_parameters") or {}).get("id")
            if rule.get("action") == "execute" and deployed_id:
                custom_ruleset = client.get_ruleset("accounts", account_id, deployed_id)
                if custom_ruleset:
                    findings.extend(analyze_custom_rules(
                        custom_ruleset, f"{target} (custom ruleset {custom_ruleset.get('name', deployed_id)})"
                    ))

    managed = client.get_entrypoint("accounts", account_id, PHASE_MANAGED)
    if managed:
        rule_metadata = {
            ruleset_id: load_rule_metadata(client, "accounts", account_id, ruleset_id)
            for ruleset_id in MANAGED_RULESET_NAMES
        }
        findings.extend(analyze_managed_phase(
            managed, target, PHASE_MANAGED, "enterprise", rule_metadata, require_deployment=False
        ))
    return findings


def resolve_zones(client: ApiClient, zone_args: list[str], all_zones: bool, account_id: Optional[str]) -> list[dict[str, Any]]:
    if all_zones:
        return client.list_zones(account_id)

    zones: list[dict[str, Any]] = []
    for zone_arg in zone_args:
        zone_arg = zone_arg.strip().lower()
        if ZONE_ID_PATTERN.match(zone_arg):
            zone = client.get_zone(zone_arg)
            matches = [zone] if zone else []
        elif ZONE_NAME_PATTERN.match(zone_arg):
            matches = client.find_zones_by_name(zone_arg)
        else:
            raise CloudflareApiError(0, f"'{zone_arg}' is not a valid zone name or 32-character zone ID")
        if not matches:
            raise CloudflareApiError(404, f"zone '{zone_arg}' not found or token lacks access")
        zones.extend(matches)
    return zones


# --------------------------------------------------------------------------- #
# Output
# --------------------------------------------------------------------------- #

def render_text(findings: list[Finding], audited_targets: list[str]) -> str:
    lines: list[str] = []
    by_target: dict[str, list[Finding]] = {}
    for finding in sorted(findings, key=Finding.sort_key):
        by_target.setdefault(finding.target, []).append(finding)

    for target in audited_targets:
        target_findings = by_target.get(target, [])
        lines.append(f"\n== {target} ==")
        if not target_findings:
            lines.append("  OK: no rules found that skip or downgrade the php2shell managed protections.")
            continue
        for finding in target_findings:
            lines.append(f"  [{finding.severity.upper()}] {finding.title}")
            lines.append(f"      Phase: {finding.phase}")
            if finding.rule_id:
                lines.append(f"      Rule:  {finding.rule_description} ({finding.rule_id})")
            if finding.expression:
                lines.append(f"      Expr:  {finding.expression}")
            lines.append(f"      Why:   {finding.detail}")
            lines.append(f"      Fix:   {finding.recommendation}")

    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity] += 1
    summary = ", ".join(f"{counts[severity]} {severity}" for severity in reversed(list(SEVERITY_ORDER)))
    lines.append(f"\nSummary: {summary}")
    lines.append("Reminder: WAF rules are a stopgap. Patch PHP to 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 or later.")
    return "\n".join(lines)


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Read-only audit for Cloudflare WAF rules that skip or weaken managed rules (php2shell).",
    )
    selection = parser.add_mutually_exclusive_group(required=True)
    selection.add_argument("--zone", action="append", default=[], help="Zone name or zone ID (repeatable)")
    selection.add_argument("--all-zones", action="store_true", help="Audit every zone the token can read")
    parser.add_argument("--account-id", help="Also audit account-level rulesets (and filter --all-zones to this account)")
    parser.add_argument("--check-dns", action="store_true", help="Also list DNS-only hostnames (needs DNS:Read)")
    parser.add_argument("--auth", choices=["auto", "token", "cf-cli"], default="auto",
                        help="auto: CLOUDFLARE_API_TOKEN if set, otherwise the cf CLI login (default)")
    parser.add_argument("--cf-bin", help="Path to the Cloudflare cf CLI (default: 'cloudflare' or 'cf' on PATH)")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text")
    parser.add_argument("--fail-on", choices=list(SEVERITY_ORDER), default="high",
                        help="Exit 2 when any finding is at or above this severity (default: high)")
    parser.add_argument("--verbose", action="store_true", help="Debug logging")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = parser.parse_args(argv)
    if args.account_id and not re.match(r"^[0-9a-f]{32}$", args.account_id):
        parser.error("--account-id must be a 32-character hex ID")
    return args


CF_CLI_UPDATE_HELP = (
    "Update it with:  npm install -g cf@latest\n"
    "cf 1.0 needs Node.js 22.23+, 24.22+ or 26.12+ (check with: node --version).\n"
    "Or skip the CLI and set CLOUDFLARE_API_TOKEN to a read-only token instead."
)
CF_CLI_VERSION_PATTERN = re.compile(r"v?(\d+)\.(\d+)\.(\d+)")


def run_quietly(command: list[str]) -> str:
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=60, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return CfCliClient.ANSI_PATTERN.sub("", (completed.stdout or "") + (completed.stderr or ""))


def find_cf_cli(explicit_path: Optional[str]) -> Optional[str]:
    """Locate Cloudflare's cf CLI. 'cloudflare' is preferred because 'cf' can be the Cloud Foundry CLI."""
    if explicit_path:
        return shutil.which(explicit_path) or (explicit_path if os.path.isfile(explicit_path) else None)
    for candidate in ("cloudflare", "cf"):
        location = shutil.which(candidate)
        if not location:
            continue
        version_output = run_quietly([location, "--version"]).lower()
        if candidate == "cloudflare" or "cf version" not in version_output:
            return location
    return None


def check_cf_cli_supported(executable: str) -> Optional[str]:
    """Return an error message if this cf CLI lacks the ruleset commands the audit needs."""
    version_match = CF_CLI_VERSION_PATTERN.search(run_quietly([executable, "--version"]))
    version_label = ".".join(version_match.groups()) if version_match else "unknown"
    if version_match and int(version_match.group(1)) < 1:
        return f"Your cf CLI is v{version_label}; this audit needs cf 1.0 or later.\n{CF_CLI_UPDATE_HELP}"
    probe_output = run_quietly([executable, "rulesets", "entrypoint", "get", "--help"])
    if "unknown command" in probe_output.lower():
        return f"Your cf CLI (v{version_label}) has no 'rulesets entrypoint' command.\n{CF_CLI_UPDATE_HELP}"
    return None


def build_client(auth_mode: str, cf_bin: Optional[str]) -> Optional[ApiClient]:
    api_token = os.environ.get("CLOUDFLARE_API_TOKEN", "").strip()
    if auth_mode == "token" or (auth_mode == "auto" and api_token):
        if not api_token:
            LOGGER.error("Set CLOUDFLARE_API_TOKEN to a scoped, read-only API token.")
            return None
        return CloudflareClient(api_token)

    executable = find_cf_cli(cf_bin)
    if not executable:
        LOGGER.error(
            "No credentials found. Either install the Cloudflare CLI and log in "
            "(npm install -g cf@latest && cf auth login) or set CLOUDFLARE_API_TOKEN."
        )
        return None
    unsupported_reason = check_cf_cli_supported(executable)
    if unsupported_reason:
        LOGGER.error(unsupported_reason)
        return None
    LOGGER.debug("Using cf CLI at %s", executable)
    return CfCliClient(executable)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING,
                        format="%(levelname)s %(message)s")

    client = build_client(args.auth, args.cf_bin)
    if client is None:
        return 1
    findings: list[Finding] = []
    audited_targets: list[str] = []
    try:
        if args.account_id:
            audited_targets.append(f"account {args.account_id}")
            findings.extend(audit_account(client, args.account_id))
        for zone in resolve_zones(client, args.zone, args.all_zones, args.account_id):
            audited_targets.append(f"zone {zone.get('name', zone['id'])}")
            findings.extend(audit_zone(client, zone, args.check_dns))
    except CloudflareApiError as exc:
        hint = (
            " Check permissions (Zone:Read, Zone WAF:Read) or re-run 'cf auth login'."
            if exc.status in (400, 401, 403) else ""
        )
        LOGGER.error("Cloudflare API error: %s.%s", exc, hint)
        return 1

    if args.json:
        print(json.dumps({
            "version": __version__,
            "audited": audited_targets,
            "findings": [asdict(finding) for finding in sorted(findings, key=Finding.sort_key)],
        }, indent=2))
    else:
        print(render_text(findings, audited_targets))

    threshold = SEVERITY_ORDER[args.fail_on]
    return 2 if any(SEVERITY_ORDER[finding.severity] >= threshold for finding in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
