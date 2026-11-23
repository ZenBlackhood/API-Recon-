#!/usr/bin/env python3
"""
bola-recon: authorized, non-destructive API recon and IDOR/BOLA scanner.

  recon  Map an API's attack surface from its OpenAPI 3 spec (no API traffic).
  scan   Confirm BOLA with two accounts you control, using baseline and
         negative-control requests to rule out false positives.

Read-only by design: only GET/HEAD/OPTIONS are sent, to allowlisted hosts.
Only use against systems you own or are explicitly authorized to test.
"""
from __future__ import annotations

import argparse
import difflib
import json
import os
import re
import sys
import time
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlparse

import requests
import yaml

__version__ = "0.2.0"

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
HTTP_METHODS = {"get", "put", "post", "delete", "patch", "head", "options", "trace"}

# Names that usually reference an object: id, uuid, user_id, orderId, slug...
ID_NAME_RE = re.compile(
    r"^(id|uuid|guid|slug)$|[_-](id|uuid|guid|key|ref|number|no)$"
    r"|[a-z0-9](Id|ID|Uuid|UUID|Guid|Key|Ref|Number)$",
)
UUID_RE = re.compile(r"^[0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12}$", re.I)

CONFIRMED, NEEDS_REVIEW, PUBLIC = "CONFIRMED", "NEEDS_REVIEW", "PUBLIC"
INCONCLUSIVE, NOT_VULNERABLE, SKIPPED = "INCONCLUSIVE", "NOT_VULNERABLE", "SKIPPED"
VERDICT_ORDER = [CONFIRMED, NEEDS_REVIEW, PUBLIC, INCONCLUSIVE, NOT_VULNERABLE, SKIPPED]


# ----------------------------------------------------------------- recon ---
@dataclass
class Param:
    name: str
    location: str  # path | query | header | cookie
    required: bool
    type: str = "string"
    format: str = ""


@dataclass
class Endpoint:
    method: str
    path: str
    summary: str = ""
    params: list[Param] = field(default_factory=list)
    auth_required: bool | None = None  # None = spec doesn't say
    object_params: list[str] = field(default_factory=list)

    @property
    def is_candidate(self) -> bool:
        return bool(self.object_params)

    @property
    def state_changing(self) -> bool:
        return self.method not in SAFE_METHODS

    @property
    def key(self) -> str:
        return f"{self.method} {self.path}"


def load_spec(source: str) -> dict:
    if source.startswith(("http://", "https://")):
        resp = requests.get(source, timeout=20)
        resp.raise_for_status()
        text = resp.text
    else:
        text = Path(source).read_text(encoding="utf-8")
    spec = yaml.safe_load(text)  # YAML is a superset of JSON
    if not isinstance(spec, dict) or not str(spec.get("openapi", "")).startswith("3"):
        raise ValueError(f"{source} is not an OpenAPI 3 document")
    return spec


def resolve(spec: dict, obj: Any) -> Any:
    """Follow local $ref pointers like #/components/parameters/UserId."""
    for _ in range(25):
        if not (isinstance(obj, dict) and str(obj.get("$ref", "")).startswith("#/")):
            return obj
        node: Any = spec
        for part in obj["$ref"][2:].split("/"):
            node = node.get(part.replace("~1", "/").replace("~0", "~"), {}) if isinstance(node, dict) else {}
        obj = node
    return obj


def is_object_param(p: Param) -> bool:
    if p.location not in ("path", "query"):
        return False
    if ID_NAME_RE.search(p.name) or p.name.lower() in ("id", "uuid", "guid", "slug"):
        return True
    # Path params typed as integers or UUIDs are almost always object references.
    return p.location == "path" and (p.type == "integer" or p.format == "uuid")


def parse_endpoints(spec: dict) -> list[Endpoint]:
    endpoints = []
    for path, item in (spec.get("paths") or {}).items():
        item = resolve(spec, item)
        if not isinstance(item, dict):
            continue
        shared = item.get("parameters") or []
        for method, op in item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(op, dict):
                continue
            params: dict[tuple[str, str], Param] = {}
            for raw in shared + (op.get("parameters") or []):
                p = resolve(spec, raw)
                if isinstance(p, dict) and "name" in p and "in" in p:
                    schema = resolve(spec, p.get("schema") or {})
                    params[(p["name"], p["in"])] = Param(
                        p["name"], p["in"], bool(p.get("required")) or p["in"] == "path",
                        str(schema.get("type", "string")), str(schema.get("format", "")),
                    )
            for name in re.findall(r"{([^}/]+)}", path):  # undeclared template vars
                params.setdefault((name, "path"), Param(name, "path", True))

            # Security is a list of alternatives; an empty {} means auth is optional.
            security = op.get("security", spec.get("security"))
            auth = None if security is None else bool(security) and {} not in security

            ep = Endpoint(method.upper(), path, str(op.get("summary") or ""), list(params.values()), auth)
            ep.object_params = [p.name for p in ep.params if is_object_param(p)]
            endpoints.append(ep)
    return endpoints


def base_url_from_spec(spec: dict) -> str | None:
    server = (spec.get("servers") or [{}])[0]
    url = server.get("url", "")
    for var, meta in (server.get("variables") or {}).items():
        url = url.replace("{" + var + "}", str(meta.get("default", "")))
    return url if url.startswith(("http://", "https://")) else None


def recon_summary(endpoints: list[Endpoint]) -> dict:
    return {
        "total_endpoints": len(endpoints),
        "auth_required": sum(e.auth_required is True for e in endpoints),
        "no_auth_declared": sum(e.auth_required is False for e in endpoints),
        "auth_unspecified": sum(e.auth_required is None for e in endpoints),
        "object_level_candidates": sum(e.is_candidate for e in endpoints),
        "testable_candidates": sum(e.is_candidate and not e.state_changing for e in endpoints),
        "state_changing_candidates": sum(e.is_candidate and e.state_changing for e in endpoints),
    }


# --------------------------------------------------------- safe client ---
class ScopeError(RuntimeError):
    pass


class BudgetExceeded(RuntimeError):
    pass


def host_in_scope(host: str | None, scope: list[str]) -> bool:
    host = (host or "").lower()
    for entry in (s.lower().strip() for s in scope):
        if entry.startswith("*.") and host.endswith(entry[1:]) and host != entry[2:]:
            return True
        if host and host == entry:
            return True
    return False


@dataclass
class Observation:
    label: str
    status: int
    length: int
    text: str = field(repr=False, default="")


class ScopedClient:
    """Read-only, allowlisted, rate-limited HTTP client with a request budget."""

    def __init__(self, scope_hosts: list[str], rate_limit_rps: float = 2.0, timeout: float = 15.0,
                 max_requests: int = 500, extra_headers: dict | None = None,
                 proxy: str | None = None, ca_bundle: str | None = None):
        if not scope_hosts:
            raise ValueError("scope_hosts must list at least one host")
        self.scope, self.timeout, self.max_requests = scope_hosts, timeout, max_requests
        self.min_interval = 1.0 / rate_limit_rps if rate_limit_rps > 0 else 0.0
        self.extra_headers = extra_headers or {}
        self.sent, self._last = 0, 0.0
        self.session = requests.Session()
        self.session.headers["User-Agent"] = f"bola-recon/{__version__} (authorized security testing)"
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        if ca_bundle:
            self.session.verify = ca_bundle

    def send(self, label: str, method: str, url: str, headers: dict) -> Observation:
        method = method.upper()
        if method not in SAFE_METHODS:
            raise ScopeError(f"Refusing non-read-only method {method}")
        if not host_in_scope(urlparse(url).hostname, self.scope):
            raise ScopeError(f"Refusing out-of-scope URL {url}")
        if self.sent >= self.max_requests:
            raise BudgetExceeded(f"Request budget of {self.max_requests} reached")
        time.sleep(max(0.0, self.min_interval - (time.monotonic() - self._last)))
        self._last, self.sent = time.monotonic(), self.sent + 1
        resp = self.session.request(method, url, headers={**self.extra_headers, **headers},
                                    timeout=self.timeout, allow_redirects=False)
        return Observation(label, resp.status_code, len(resp.content), resp.text)


# ------------------------------------------------------------- verdicts ---
COMPARE_LIMIT = 6000


def _strip_keys(data: Any, ignore: set[str]) -> Any:
    if isinstance(data, dict):
        return {k: _strip_keys(v, ignore) for k, v in data.items() if k not in ignore}
    if isinstance(data, list):
        return [_strip_keys(v, ignore) for v in data]
    return data


def normalize_body(text: str, ignore_keys: set[str]) -> str:
    try:
        return json.dumps(_strip_keys(json.loads(text), ignore_keys), sort_keys=True)
    except (ValueError, TypeError):
        return (text or "").strip()


def similarity(a: str, b: str) -> float:
    a, b = a[:COMPARE_LIMIT], b[:COMPARE_LIMIT]
    if not a and not b:
        return 1.0
    return round(difflib.SequenceMatcher(None, a, b, autojunk=False).ratio(), 3)


def _ok(o: Observation | None) -> bool:
    return o is not None and 200 <= o.status < 300


def assess(baseline: Observation, cross: Observation | None, no_auth: Observation | None = None,
           bogus: Observation | None = None, own_b: Observation | None = None,
           a_markers: list[str] | None = None, b_markers: list[str] | None = None,
           threshold: float = 0.9, ignore_keys: set[str] | None = None) -> tuple[str, str, dict]:
    """Return (verdict, reason, similarity scores). Pure function, easy to test."""
    norm = {o.label: normalize_body(o.text, ignore_keys or set())
            for o in (baseline, cross, no_auth, bogus, own_b) if o}
    base = norm[baseline.label]
    sims: dict[str, float] = {}

    if not _ok(baseline):
        return INCONCLUSIVE, f"Baseline failed: account A got HTTP {baseline.status} for its own object.", sims
    if _ok(bogus):
        sims["bogus_vs_baseline"] = similarity(norm[bogus.label], base)
        if sims["bogus_vs_baseline"] >= threshold:
            return INCONCLUSIVE, "A non-existent ID returned the same data; the endpoint likely ignores the ID.", sims
    if _ok(no_auth):
        sims["no_auth_vs_baseline"] = similarity(norm[no_auth.label], base)
        if sims["no_auth_vs_baseline"] >= threshold:
            return PUBLIC, "Object is served with no credentials: public by design, or missing authentication.", sims
    if cross is None:
        return SKIPPED, "Cross-account request was not sent.", sims
    if cross.status in (401, 403, 404):
        return NOT_VULNERABLE, f"Account B was denied (HTTP {cross.status}).", sims
    if not _ok(cross):
        return INCONCLUSIVE, f"Cross-account request returned unexpected HTTP {cross.status}.", sims

    s_a = sims["cross_vs_baseline"] = similarity(norm[cross.label], base)
    s_b = sims["cross_vs_own_b"] = similarity(norm[cross.label], norm[own_b.label]) if _ok(own_b) else None
    if s_b is None:
        sims.pop("cross_vs_own_b")

    if any(m and m in cross.text for m in a_markers or []):
        return CONFIRMED, "Account B's response contains data unique to account A.", sims
    if any(m and m in cross.text for m in b_markers or []) or (s_b is not None and s_b >= threshold and s_b > s_a):
        return NOT_VULNERABLE, "Account B received its own data, not A's; the endpoint scopes to the caller.", sims
    if s_a >= threshold and s_b is not None:
        return CONFIRMED, "Account B received A's object: matches A's baseline and differs from B's own.", sims
    if s_a >= threshold:
        return NEEDS_REVIEW, "Matches A's baseline. Add B's object IDs or A-only markers to confirm.", sims
    return NEEDS_REVIEW, "Account B got a 2xx with different content than A's (possible partial exposure).", sims


# ----------------------------------------------------------------- scan ---
@dataclass
class Account:
    headers: dict[str, str]
    objects: dict[str, str]
    markers: list[str]


@dataclass
class Finding:
    method: str
    path: str
    url: str
    verdict: str
    reason: str
    evidence: dict = field(default_factory=dict)
    similarities: dict = field(default_factory=dict)
    cross_snippet: str = ""
    repro: str = ""


def fake_id(value: str) -> str:
    if value.isdigit():
        return "9" * max(9, len(value) + 2)
    return str(uuid.uuid4()) if UUID_RE.match(value) else f"nonexistent-{uuid.uuid4().hex[:12]}"


def build_url(base: str, ep: Endpoint, values: dict, defaults: dict) -> tuple[str | None, str]:
    """Fill path/query params. Returns (url, "") or (None, reason to skip)."""
    path, query = ep.path, []
    for p in ep.params:
        val = values.get(p.name, defaults.get(p.name))
        if p.location == "path":
            if val is None:
                return None, f"No value for path parameter '{p.name}'"
            path = path.replace("{" + p.name + "}", quote(str(val), safe=""))
        elif p.location == "query" and val is not None:
            query.append(f"{quote(p.name, safe='')}={quote(str(val), safe='')}")
        elif p.location == "query" and p.required:
            return None, f"No value for required query parameter '{p.name}'"
    return base.rstrip("/") + path + ("?" + "&".join(query) if query else ""), ""


def redacted_curl(method: str, url: str, header_names: list[str], extra: dict) -> str:
    parts = [f"curl -s -X {method} '{url}'"] + [f"-H '{k}: {v}'" for k, v in extra.items()]
    parts += [f"-H '{h}: <ACCOUNT_B_{h.upper().replace('-', '_')}>'" for h in header_names]
    return " \\\n  ".join(parts)


def expand_env(mapping: dict | None, where: str) -> dict[str, str]:
    """Expand ${VAR} in header values so tokens never live in the config file."""
    out = {}
    for k, v in (mapping or {}).items():
        out[k] = os.path.expandvars(str(v))
        if re.search(r"\$\{?[A-Za-z_]", out[k]):
            raise SystemExit(f"Unresolved environment variable in {where}.{k}. Export it first.")
    return out


def load_config(path: str) -> dict:
    cfg = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    if (cfg.get("authorization") or {}).get("confirmed") is not True:
        raise SystemExit("Refusing to scan: set authorization.confirmed: true, and only if you own the\n"
                         "target or have written permission (e.g. a bug bounty program scope).")
    if "target" not in cfg or not {"a", "b"} <= set(cfg.get("accounts") or {}):
        raise SystemExit("Config needs a 'target' section and two accounts: accounts.a and accounts.b")
    return cfg


class Scanner:
    def __init__(self, cfg: dict, log=print):
        target, settings = cfg["target"], cfg.get("settings") or {}
        self.log = log
        self.spec = load_spec(target["openapi"])
        self.base = target.get("base_url") or base_url_from_spec(self.spec)
        if not self.base:
            raise SystemExit("No absolute base URL found. Set target.base_url in the config.")
        self.accounts = {
            name: Account(expand_env(raw.get("headers"), f"accounts.{name}.headers"),
                          {k: str(v) for k, v in (raw.get("objects") or {}).items()},
                          [str(m) for m in raw.get("markers") or []])
            for name, raw in cfg["accounts"].items() if name in ("a", "b")
        }
        self.defaults = {k: str(v) for k, v in (target.get("defaults") or {}).items()}
        self.threshold = float(settings.get("similarity_threshold", 0.9))
        self.ignore_keys = set(settings.get("ignore_keys") or [])
        self.methods = {m.upper() for m in settings.get("methods", ["GET"])}
        if self.methods - SAFE_METHODS:
            raise SystemExit(f"bola-recon is read-only; cannot scan {', '.join(self.methods - SAFE_METHODS)}")
        self.extra_headers = expand_env(settings.get("extra_headers"), "settings.extra_headers")
        self.client = ScopedClient(
            scope_hosts=target.get("scope_hosts") or [urlparse(self.base).hostname],
            rate_limit_rps=float(settings.get("rate_limit_rps", 2)),
            timeout=float(settings.get("timeout", 15)),
            max_requests=int(settings.get("max_requests", 500)),
            extra_headers=self.extra_headers,
            proxy=settings.get("proxy"),
            ca_bundle=settings.get("ca_bundle"),
        )
        self.endpoints = parse_endpoints(self.spec)

    def test_endpoint(self, ep: Endpoint) -> Finding:
        a, b = self.accounts["a"], self.accounts["b"]
        url, why = build_url(self.base, ep, a.objects, self.defaults)
        if url is None or not any(p in a.objects for p in ep.object_params):
            return Finding(ep.method, ep.path, url or "", SKIPPED, why or "No account A IDs for this endpoint")

        owned = [p for p in ep.object_params if p in a.objects]
        bogus_url, _ = build_url(self.base, ep, {**a.objects, **{p: fake_id(a.objects[p]) for p in owned}}, self.defaults)
        own_b_url = build_url(self.base, ep, {**a.objects, **b.objects}, self.defaults)[0] \
            if all(p in b.objects for p in owned) else None

        send = self.client.send
        obs = {"baseline": send("baseline", ep.method, url, a.headers)}
        if _ok(obs["baseline"]):
            obs["no_auth"] = send("no_auth", ep.method, url, {})
            obs["bogus_id"] = send("bogus_id", ep.method, bogus_url, a.headers)
            if own_b_url:
                obs["own_b"] = send("own_b", ep.method, own_b_url, b.headers)
            obs["cross"] = send("cross", ep.method, url, b.headers)

        verdict, reason, sims = assess(
            obs["baseline"], obs.get("cross"), obs.get("no_auth"), obs.get("bogus_id"), obs.get("own_b"),
            a.markers, b.markers, self.threshold, self.ignore_keys,
        )
        f = Finding(ep.method, ep.path, url, verdict, reason, similarities=sims,
                    evidence={k: {"status": o.status, "bytes": o.length} for k, o in obs.items()},
                    repro=redacted_curl(ep.method, url, list(b.headers), self.extra_headers))
        if verdict in (CONFIRMED, NEEDS_REVIEW):
            f.cross_snippet = obs["cross"].text[:400]
        return f

    def run(self, path_filter: str | None = None) -> list[Finding]:
        rx = re.compile(path_filter) if path_filter else None
        targets = [e for e in self.endpoints
                   if e.is_candidate and e.method in self.methods and (rx is None or rx.search(e.path))]
        self.log(f"[*] {len(targets)} candidate endpoint(s) to test against {self.base}")
        findings = []
        for ep in targets:
            try:
                f = self.test_endpoint(ep)
            except BudgetExceeded as exc:
                self.log(f"[!] {exc}; stopping.")
                break
            except (ScopeError, requests.RequestException) as exc:
                f = Finding(ep.method, ep.path, "", INCONCLUSIVE, f"Request error: {exc}")
            self.log(f"    {f.verdict:<15} {ep.key}")
            findings.append(f)
        return sorted(findings, key=lambda x: VERDICT_ORDER.index(x.verdict))


# ------------------------------------------------------------------ CLI ---
def write_json(out_dir: str, name: str, data: dict) -> Path:
    path = Path(out_dir) / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    return path


def cmd_recon(args) -> int:
    spec = load_spec(args.spec)
    endpoints = parse_endpoints(spec)
    summary = recon_summary(endpoints)
    print(f"[*] {(spec.get('info') or {}).get('title', args.spec)}: {summary['total_endpoints']} endpoints, "
          f"{summary['object_level_candidates']} object-level candidates")
    auth_label = {True: "auth", False: "NO AUTH", None: "auth ?"}
    for e in sorted(endpoints, key=lambda e: (not e.is_candidate, e.path)):
        if e.is_candidate:
            note = "test manually (state-changing)" if e.state_changing else "BOLA candidate"
            print(f"    {e.method:<7} {e.path:<45} {auth_label[e.auth_required]:<8} {note}")
    path = write_json(args.out, "recon.json", {
        "tool": f"bola-recon {__version__}", "spec": args.spec, "base_url": base_url_from_spec(spec),
        "summary": summary, "endpoints": [{**asdict(e), "is_candidate": e.is_candidate} for e in endpoints],
    })
    print(f"[+] Wrote {path}")
    return 0


def cmd_scan(args) -> int:
    cfg = load_config(args.config)
    scanner = Scanner(cfg)
    program = cfg["authorization"].get("program", "unspecified")
    print(f"[*] bola-recon {__version__} | authorization: {program}")
    findings = scanner.run(path_filter=args.only_path)
    path = write_json(args.out, "scan.json", {
        "tool": f"bola-recon {__version__}", "target": scanner.base, "authorization": program,
        "requests_sent": scanner.client.sent, "findings": [asdict(f) for f in findings],
    })
    confirmed = sum(f.verdict == CONFIRMED for f in findings)
    review = sum(f.verdict == NEEDS_REVIEW for f in findings)
    print(f"[+] {confirmed} confirmed, {review} need review, {scanner.client.sent} requests sent")
    print(f"[+] Wrote {path}")
    return 2 if confirmed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bola-recon", description="Authorized API recon and BOLA/IDOR scanner")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    r = sub.add_parser("recon", help="Map the attack surface from an OpenAPI 3 spec (no API traffic)")
    r.add_argument("--spec", required=True, help="Path or URL to an OpenAPI 3 document")
    r.add_argument("--out", default="reports", help="Output directory (default: reports)")
    r.set_defaults(func=cmd_recon)

    s = sub.add_parser("scan", help="Test object-level authorization with two accounts you control")
    s.add_argument("--config", required=True, help="YAML config (see config.example.yaml)")
    s.add_argument("--only-path", help="Only test paths matching this regex")
    s.add_argument("--out", default="reports", help="Output directory (default: reports)")
    s.set_defaults(func=cmd_scan)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
