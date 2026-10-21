import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cf_waf_bypass_check as checker  # noqa: E402

MANAGED_ID = checker.CLOUDFLARE_MANAGED_RULESET_ID
FREE_ID = checker.CLOUDFLARE_FREE_MANAGED_RULESET_ID
PHP2SHELL_RULE = "c1d409ad838f47f59446f21cc438d5dd"
TARGET = "zone example.com"


def skip_rule(expression, phases=None, enabled=True, **extra_parameters):
    parameters = {"phases": phases or [checker.PHASE_MANAGED], **extra_parameters}
    return {"id": "skip1", "action": "skip", "expression": expression,
            "enabled": enabled, "description": "test skip", "action_parameters": parameters}


def execute_rule(ruleset_id=MANAGED_ID, expression="true", enabled=True, overrides=None):
    parameters = {"id": ruleset_id}
    if overrides is not None:
        parameters["overrides"] = overrides
    return {"id": "exec1", "action": "execute", "expression": expression,
            "enabled": enabled, "action_parameters": parameters}


def severities(findings):
    return sorted(finding.severity for finding in findings)


class ClassifyExpressionTests(unittest.TestCase):
    def test_true_is_all_traffic(self):
        self.assertEqual(checker.classify_expression("(true)").category, "all_traffic")

    def test_path_only_is_request_target(self):
        scope = checker.classify_expression('http.request.uri.path contains "/upload.php"')
        self.assertEqual(scope.category, "request_target_only")

    def test_dotted_string_literal_is_not_a_field(self):
        scope = checker.classify_expression('http.host eq "ip.src.example.com"')
        self.assertEqual(scope.category, "request_target_only")

    def test_header_only_is_client_controlled(self):
        scope = checker.classify_expression('any(http.request.headers["x-scanner"][*] eq "abc")')
        self.assertEqual(scope.category, "client_controlled")

    def test_ip_list_is_restricted(self):
        scope = checker.classify_expression("ip.src in $trusted_scanners")
        self.assertEqual(scope.category, "restricted")

    def test_or_needs_review(self):
        scope = checker.classify_expression('ip.src in $office or http.host eq "a.example.com"')
        self.assertEqual(scope.category, "needs_review")


class CustomRuleTests(unittest.TestCase):
    def test_broad_skip_of_managed_phase_is_critical(self):
        findings = checker.analyze_custom_rules({"rules": [skip_rule("true")]}, TARGET)
        self.assertEqual(severities(findings), ["critical"])

    def test_ip_restricted_skip_is_medium(self):
        findings = checker.analyze_custom_rules({"rules": [skip_rule("ip.src in {192.0.2.0/24}")]}, TARGET)
        self.assertEqual(severities(findings), ["medium"])

    def test_disabled_skip_is_info(self):
        findings = checker.analyze_custom_rules({"rules": [skip_rule("true", enabled=False)]}, TARGET)
        self.assertEqual(severities(findings), ["info"])

    def test_skip_of_unrelated_phase_is_ignored(self):
        findings = checker.analyze_custom_rules(
            {"rules": [skip_rule("true", phases=["http_ratelimit"])]}, TARGET)
        self.assertEqual(findings, [])

    def test_skip_current_ruleset_only_is_ignored(self):
        rule = {"id": "skip2", "action": "skip", "expression": "true",
                "action_parameters": {"ruleset": "current"}}
        self.assertEqual(checker.analyze_custom_rules({"rules": [rule]}, TARGET), [])

    def test_legacy_waf_product_skip_is_medium(self):
        rule = {"id": "skip3", "action": "skip", "expression": "true",
                "action_parameters": {"products": ["waf"]}}
        self.assertEqual(severities(checker.analyze_custom_rules({"rules": [rule]}, TARGET)), ["medium"])


class ManagedPhaseTests(unittest.TestCase):
    def analyze(self, rules, plan="business", metadata=None):
        return checker.analyze_managed_phase(
            {"id": "entry", "rules": rules}, TARGET, checker.PHASE_MANAGED, plan, metadata or {})

    def test_clean_deployment_has_no_findings(self):
        self.assertEqual(self.analyze([execute_rule()]), [])

    def test_paid_plan_without_deployment_is_critical(self):
        self.assertEqual(severities(self.analyze([])), ["critical"])

    def test_free_plan_without_visible_deployment_is_ok(self):
        self.assertEqual(self.analyze([], plan="free"), [])

    def test_disabled_deployment_is_critical(self):
        findings = self.analyze([execute_rule(enabled=False)])
        self.assertIn("critical", severities(findings))

    def test_php2shell_rule_disabled_by_rule_override(self):
        overrides = {"rules": [{"id": PHP2SHELL_RULE, "enabled": False}]}
        findings = self.analyze([execute_rule(overrides=overrides)])
        self.assertEqual(severities(findings), ["critical"])

    def test_php2shell_rule_set_to_log(self):
        overrides = {"rules": [{"id": PHP2SHELL_RULE, "action": "log"}]}
        self.assertEqual(severities(self.analyze([execute_rule(overrides=overrides)])), ["critical"])

    def test_ruleset_log_override_flags_every_php2shell_rule(self):
        findings = self.analyze([execute_rule(overrides={"action": "log"})])
        self.assertEqual(severities(findings).count("critical"), 7)
        self.assertIn("high", severities(findings))

    def test_rule_override_wins_over_ruleset_override(self):
        rule_overrides = [{"id": rule_id, "enabled": True, "action": "block"}
                          for rule_id in checker.PHP2SHELL_RULES_BY_RULESET[MANAGED_ID]]
        findings = self.analyze([execute_rule(overrides={"enabled": False, "rules": rule_overrides})])
        self.assertEqual(severities(findings), ["high"])

    def test_category_override_uses_rule_metadata(self):
        metadata = {MANAGED_ID: {PHP2SHELL_RULE: {"id": PHP2SHELL_RULE, "categories": ["php"]}}}
        overrides = {"categories": [{"category": "php", "enabled": False}]}
        findings = self.analyze([execute_rule(overrides=overrides)], metadata=metadata)
        self.assertIn("critical", severities(findings))

    def test_unrelated_category_override_ignored_when_metadata_known(self):
        metadata = {MANAGED_ID: {PHP2SHELL_RULE: {"id": PHP2SHELL_RULE, "categories": ["php"]}}}
        overrides = {"categories": [{"category": "wordpress", "enabled": False}]}
        self.assertEqual(self.analyze([execute_rule(overrides=overrides)], metadata=metadata), [])

    def test_scoped_deployment_is_medium(self):
        findings = self.analyze([execute_rule(expression='http.host eq "www.example.com"')])
        self.assertEqual(severities(findings), ["medium"])

    def test_exception_before_deployment_is_flagged(self):
        exception = {"id": "exc1", "action": "skip", "expression": "true",
                     "action_parameters": {"ruleset": "current"}}
        findings = self.analyze([exception, execute_rule()])
        self.assertEqual(severities(findings), ["critical"])

    def test_exception_after_deployment_is_ignored(self):
        exception = {"id": "exc1", "action": "skip", "expression": "true",
                     "action_parameters": {"ruleset": "current"}}
        self.assertEqual(self.analyze([execute_rule(), exception]), [])

    def test_exception_skipping_php2shell_rule_id(self):
        exception = {"id": "exc2", "action": "skip", "expression": "ip.src in $scanners",
                     "action_parameters": {"rules": {MANAGED_ID: [PHP2SHELL_RULE]}}}
        self.assertEqual(severities(self.analyze([exception, execute_rule()])), ["medium"])

    def test_exception_skipping_unrelated_rule_is_ignored(self):
        exception = {"id": "exc3", "action": "skip", "expression": "true",
                     "action_parameters": {"rules": {MANAGED_ID: ["0" * 32]}}}
        self.assertEqual(self.analyze([exception, execute_rule()]), [])

    def test_free_ruleset_rules_checked(self):
        free_rule = next(iter(checker.PHP2SHELL_RULES_BY_RULESET[FREE_ID]))
        overrides = {"rules": [{"id": free_rule, "enabled": False}]}
        findings = self.analyze([execute_rule(ruleset_id=FREE_ID, overrides=overrides)], plan="free")
        self.assertEqual(severities(findings), ["critical"])


class ResponsePhaseTests(unittest.TestCase):
    def test_response_rule_disabled_is_critical(self):
        overrides = {"rules": [{"id": checker.PHP2SHELL_RESPONSE_RULE_ID, "enabled": False}]}
        findings = checker.analyze_managed_phase(
            {"rules": [execute_rule(ruleset_id="1" * 32, overrides=overrides)]},
            TARGET, checker.PHASE_RESPONSE_MANAGED, "pro", {}, require_deployment=False)
        self.assertEqual(severities(findings), ["critical"])


class DnsTests(unittest.TestCase):
    def test_grey_cloud_records_reported(self):
        records = [{"type": "A", "name": "origin.example.com", "proxied": False},
                   {"type": "A", "name": "www.example.com", "proxied": True},
                   {"type": "TXT", "name": "example.com", "proxied": False}]
        findings = checker.analyze_dns_records(records, TARGET)
        self.assertEqual(len(findings), 1)
        self.assertIn("origin.example.com", findings[0].detail)


class CfCliVersionTests(unittest.TestCase):
    def check_with_output(self, version_output, probe_output=""):
        responses = {"--version": version_output, "--help": probe_output}
        with mock.patch.object(checker, "run_quietly",
                               side_effect=lambda command: responses[command[-1]]):
            return checker.check_cf_cli_supported("cloudflare")

    def test_old_version_rejected_with_update_command(self):
        message = self.check_with_output("🍊☁️  cf · v0.15.0")
        self.assertIn("npm install -g cf@latest", message)

    def test_v1_beta_accepted(self):
        self.assertIsNone(self.check_with_output("1.0.0-beta.20"))

    def test_missing_command_rejected(self):
        message = self.check_with_output("2.0.0", "Unknown commands: entrypoint")
        self.assertIn("npm install -g cf@latest", message)


class CliTests(unittest.TestCase):
    def test_missing_token_returns_error(self):
        saved = os.environ.pop("CLOUDFLARE_API_TOKEN", None)
        try:
            self.assertEqual(checker.main(["--zone", "example.com"]), 1)
        finally:
            if saved is not None:
                os.environ["CLOUDFLARE_API_TOKEN"] = saved

    def test_bad_account_id_rejected(self):
        with self.assertRaises(SystemExit):
            checker.parse_args(["--zone", "example.com", "--account-id", "not-an-id"])


if __name__ == "__main__":
    unittest.main()
