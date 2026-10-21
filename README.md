# cf-waf-bypass-check

A read-only audit that finds Cloudflare WAF rules that **skip, disable, or downgrade Cloudflare Managed Rules**. It was built for the php2shell protections (CVE-2026-109618 / CVE-2026-109619) that Cloudflare released on 2026-10-21.

Cloudflare's managed rules for php2shell are on by default. That only helps if traffic actually reaches them. A custom rule with a `skip` action that includes the managed rules phase, an exception placed in front of the managed ruleset, or an override that sets rules to Log will quietly bypass that protection. This tool finds those cases.

## Quick start

You need **Python 3.9+** and **one** way to authenticate. Nothing else to install.

**Option 1: read-only API token (recommended for work accounts)**

In the Cloudflare dashboard, go to My Profile → API Tokens → Create Token. Give it **Zone → Zone → Read** and **Zone → Zone WAF → Read**.

```bash
git clone https://github.com/<owner>/cf-waf-bypass-check && cd cf-waf-bypass-check
export CLOUDFLARE_API_TOKEN=<your-token>        # Windows PowerShell: $env:CLOUDFLARE_API_TOKEN="<your-token>"
python3 cf_waf_bypass_check.py --zone example.com
```

**Option 2: Cloudflare `cf` CLI (no token)**

The CLI needs to be **v1.0 or later** and Node.js 22.23+, 24.22+ or 26.12+. Older versions (0.x) do not have the ruleset commands.

```bash
node --version                     # upgrade Node first if it's older than the above
npm install -g cf@latest           # also updates an existing older install
cf --version                       # should print 1.0.0 or later
cf auth login
python3 cf_waf_bypass_check.py --zone example.com
```

Use `--all-zones` instead of `--zone` to check everything you can access. Run it once against a single zone first.

> WAF rules are a stopgap. The fix is patching PHP to 8.5.12, 8.4.27, 8.3.36, 8.2.35 or later. See the [PHP advisory](https://www.php.net/archive/2026.php#2026-10-21-5) and [Cloudflare's write-up](https://blog.cloudflare.com/php-vulnerabilities-waf-protection/).

## What it checks

| Where | What gets flagged |
|---|---|
| Custom rules (`http_request_firewall_custom`) | `skip` rules that skip `http_request_firewall_managed` / `http_response_firewall_managed`, or the legacy `waf` product |
| Managed rules (`http_request_firewall_managed`) | Cloudflare Managed Ruleset not deployed (paid plans), deployment disabled, deployment scoped to a subset of traffic |
| | The **effective** state of each of the 7 php2shell rule IDs, resolved with Cloudflare's precedence (rule override > category override > ruleset override). A rule that ends up disabled or set to Log is critical. |
| | Exceptions placed before the deployment that skip all remaining rules, the whole ruleset, or php2shell rule IDs |
| Response firewall (`http_response_firewall_managed`) | Overrides or skips affecting the new full-transaction rule `afffe22785674c80a31875c848d2242a` |
| Account level (`--account-id`) | The same checks for account-level entrypoints and for custom rulesets deployed from them |
| DNS (`--check-dns`) | DNS-only (grey cloud) hostnames, whose traffic never touches the WAF |

### How skip rules are rated

The rating comes from the fields in the rule expression and reflects how easy it is for an attacker to match the rule:

- **Critical:** the expression is `true`, or it only checks host, path, query or method. Any attacker can send a request that matches.
- **High:** it relies on headers, cookies or the user agent, which clients control, or it has `or` branches that need manual review.
- **Medium:** it is limited to trusted sources such as `ip.src` lists, mTLS or verified bots.
- **Info:** the skip rule is disabled.

This is a heuristic. It tells you where to look and does not prove you are protected. Review every finding by hand.

## Requirements

Python 3.9 or later. Standard library only, no `pip install`.

## Authentication

Pick one.

**Option A: Cloudflare's `cf` CLI (no API token)**

```bash
npm install -g cf@latest # cf 1.0+, Node.js 22.23+ / 24.22+ / 26.12+
cf auth login            # browser approval
python3 cf_waf_bypass_check.py --zone example.com
```

Cloudflare's docs don't say what access `cf auth login` grants. This script only reads, but if you want the access itself limited to read-only, use a scoped token (Option B).

The script uses `cf` when `CLOUDFLARE_API_TOKEN` is not set. If your `cf` is older than 1.0, it stops and prints the update command. It looks for the `cloudflare` binary first, because `cf` can be the Cloud Foundry CLI. Use `--cf-bin` to point at a specific path.

**Option B: a scoped API token**

Create a token with read-only permissions:

- Zone → Zone → Read
- Zone → Zone WAF → Read
- Zone → DNS → Read (only for `--check-dns`)
- Account → Account Rulesets → Read and Account → Account WAF → Read (only for `--account-id`)

```bash
export CLOUDFLARE_API_TOKEN=...   # deliberately not accepted as a CLI flag
python3 cf_waf_bypass_check.py --zone example.com
```

Both options only send GET requests. Nothing in your account is modified.

## Usage

```bash
# One or more zones (name or zone ID)
python3 cf_waf_bypass_check.py --zone example.com --zone shop.example.com

# Every zone you can read, plus DNS-only hostnames
python3 cf_waf_bypass_check.py --all-zones --check-dns

# Include account-level rulesets (Enterprise)
python3 cf_waf_bypass_check.py --all-zones --account-id <ACCOUNT_ID>

# JSON for pipelines; fail the job on anything high or worse
python3 cf_waf_bypass_check.py --all-zones --json --fail-on high
```

Exit codes: `0` means no findings at or above `--fail-on` (default `high`). `2` means findings at or above it. `1` means a usage, auth or API error.

### Example output

```
== zone example.com ==
  [CRITICAL] Custom rule skips Cloudflare managed rules
      Phase: http_request_firewall_custom
      Rule:  Allow upload API (r1)
      Expr:  (http.request.uri.path wildcard "/api/upload*")
      Why:   Skips: http_request_firewall_managed. Matching requests never reach the php2shell
             protections; expression only checks host/path/method/query, which any client can choose.
      Fix:   Remove the managed-rules phase from this skip rule, or narrow the expression to trusted
             sources (ip.src lists, mTLS). Prefer a managed-rule exception that skips only the
             specific false-positive rule IDs.
```

## Fixing a finding

1. **Broad skip rules:** remove "All managed rules" from the skip rule's WAF components. If the skip exists because of a false positive, replace it with a managed-rules **exception** that skips only the specific rule ID that fired, limited to a trusted source.
2. **Overrides:** in the managed ruleset deployment, remove rule or category overrides that disable or log the php2shell rule IDs listed in `cf_waf_bypass_check.py`.
3. **Check it worked:** go to Security → Security Analytics → Events and filter by the php2shell rule IDs.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

## Limitations

- Rule IDs come from Cloudflare's 2026-10-21 post. Cloudflare may add or change rules. Watch the [WAF changelog](https://developers.cloudflare.com/waf/change-log/changelog/) and update `PHP2SHELL_RULES_BY_RULESET`.
- Not covered: deprecated Firewall Rules or Page Rules, Workers that call origins directly, and origins reachable without Cloudflare (lock your origin to Cloudflare IPs or use Tunnel).
- Expression ratings are heuristics, not a parser of the Rules language.

## Disclaimer

This is a community tool. It is not affiliated with or endorsed by Cloudflare. It is provided as-is under the MIT License, with no warranty.
