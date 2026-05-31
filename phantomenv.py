#!/usr/bin/env python3
"""
phantomenv 🔍  v2.0
Scans a project folder (and optionally git history) for accidentally exposed
secrets before you push to GitHub.

New in v2:
  • 40+ curated patterns covering all major platforms
  • Shannon entropy scoring to catch unknown secrets
  • Git history scanning via gitpython
  • Allowlist / suppression via phantomenv.yaml
  • .gitignore-aware severity downgrading
  • JSON / YAML structured-file parsing
  • False-positive reduction heuristics
"""

import hashlib
import json
import math
import os
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Optional

# ──────────────────────────────────────────────────────────────────────────────
# Optional deps — degrade gracefully if missing
# ──────────────────────────────────────────────────────────────────────────────
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:
    import git as gitpython
    HAS_GIT = True
except ImportError:
    HAS_GIT = False

# ──────────────────────────────────────────────────────────────────────────────
# ANSI colours
# ──────────────────────────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

# ──────────────────────────────────────────────────────────────────────────────
# Pattern registry
# Each entry: (name, regex, severity)
# severity: "critical" | "high" | "medium"
# ──────────────────────────────────────────────────────────────────────────────
PATTERNS = [
    # ── Cloud / Infrastructure ──────────────────────────────────────────────
    ("AWS Access Key ID",
     re.compile(r"(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])"),
     "critical"),
    ("AWS Secret Access Key",
     re.compile(r"(?i)(aws_secret_access_key|aws_secret)\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
     "critical"),
    ("AWS Session Token",
     re.compile(r"(?i)aws_session_token\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{100,}['\"]?"),
     "critical"),
    ("GCP Service Account Key",
     re.compile(r'"type"\s*:\s*"service_account"'),
     "critical"),
    ("Azure Storage Account Key",
     re.compile(r"(?i)(AccountKey|DefaultEndpointsProtocol)\s*=\s*[A-Za-z0-9+/=]{44,}"),
     "critical"),

    # ── AI / ML Services ────────────────────────────────────────────────────
    ("OpenAI API Key",
     re.compile(r"sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}"),
     "critical"),
    ("OpenAI API Key (generic)",
     re.compile(r"sk-[A-Za-z0-9\-_]{32,}"),
     "critical"),
    ("Anthropic API Key",
     re.compile(r"sk-ant-[A-Za-z0-9\-_]{32,}"),
     "critical"),

    # ── Source Control Tokens ───────────────────────────────────────────────
    ("GitHub Personal Access Token",
     re.compile(r"ghp_[A-Za-z0-9]{36}"),
     "critical"),
    ("GitHub OAuth Token",
     re.compile(r"gho_[A-Za-z0-9]{36}"),
     "critical"),
    ("GitHub Actions Token",
     re.compile(r"ghs_[A-Za-z0-9]{36}"),
     "critical"),
    ("GitHub Refresh Token",
     re.compile(r"ghr_[A-Za-z0-9]{36}"),
     "critical"),
    ("GitHub App User Token",
     re.compile(r"ghu_[A-Za-z0-9]{36}"),
     "critical"),
    ("GitLab Personal Access Token",
     re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"),
     "critical"),

    # ── Payment ─────────────────────────────────────────────────────────────
    ("Stripe Secret Key",
     re.compile(r"sk_(live|test)_[A-Za-z0-9]{24,}"),
     "critical"),
    ("Stripe Publishable Key",
     re.compile(r"pk_(live|test)_[A-Za-z0-9]{24,}"),
     "high"),
    ("Square Access Token",
     re.compile(r"sq0atp-[A-Za-z0-9\-_]{22,}"),
     "critical"),
    ("PayPal Client Secret",
     re.compile(r"(?i)paypal.*client.?secret\s*[=:]\s*['\"]?[A-Za-z0-9\-_]{20,}['\"]?"),
     "critical"),

    # ── Communication ────────────────────────────────────────────────────────
    ("Twilio Account SID",
     re.compile(r"AC[a-fA-F0-9]{32}"),
     "high"),
    ("Twilio Auth Token",
     re.compile(r"(?i)twilio.*auth.?token\s*[=:]\s*['\"]?[a-fA-F0-9]{32}['\"]?"),
     "critical"),
    ("SendGrid API Key",
     re.compile(r"SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}"),
     "critical"),
    ("Mailgun API Key",
     re.compile(r"key-[a-fA-F0-9]{32}"),
     "critical"),
    ("Slack Bot Token",
     re.compile(r"xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24}"),
     "critical"),
    ("Slack User Token",
     re.compile(r"xoxp-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{32}"),
     "critical"),
    ("Slack Webhook URL",
     re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+"),
     "high"),
    ("Discord Bot Token",
     re.compile(r"[MN][A-Za-z0-9]{23}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27}"),
     "critical"),

    # ── Social / Advertising ─────────────────────────────────────────────────
    ("Facebook Access Token",
     re.compile(r"EAA[A-Za-z0-9]{100,}"),
     "critical"),
    ("Twitter/X Bearer Token",
     re.compile(r"AAAA[A-Za-z0-9%]{80,}"),
     "critical"),

    # ── Auth / Identity ──────────────────────────────────────────────────────
    ("Google OAuth / Service Account",
     re.compile(r"ya29\.[A-Za-z0-9\-_]+"),
     "critical"),
    ("Google API Key",
     re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
     "critical"),
    ("JWT Token",
     re.compile(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"),
     "high"),

    # ── Package Registries ───────────────────────────────────────────────────
    ("npm Token",
     re.compile(r"npm_[A-Za-z0-9]{36}"),
     "critical"),
    ("PyPI Token",
     re.compile(r"pypi-[A-Za-z0-9\-_]{50,}"),
     "critical"),

    # ── Databases ────────────────────────────────────────────────────────────
    ("Database Connection String",
     re.compile(r"(postgres|postgresql|mysql|mongodb|redis|mssql|oracle):\/\/[^:]+:[^@\s]+@[^\s\"'<>]+"),
     "critical"),

    # ── Crypto / PKI ─────────────────────────────────────────────────────────
    ("Private Key Block",
     re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
     "critical"),
    ("PGP Private Key Block",
     re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"),
     "critical"),

    # ── Generic catch-alls ───────────────────────────────────────────────────
    ("Generic Password (assignment)",
     re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{6,}['\"]"),
     "high"),
    ("Generic Secret / Token",
     re.compile(r"(?i)(secret|token|api_key|apikey|auth_key|access_token|client_secret)\s*[=:]\s*['\"][^'\"]{8,}['\"]"),
     "medium"),
    ("Hardcoded IP with Credentials",
     re.compile(r"(?i)(user(name)?|login)\s*[=:]\s*['\"][^'\"]+['\"].*\d{1,3}(\.\d{1,3}){3}"),
     "high"),

    # ── Filesystem ───────────────────────────────────────────────────────────
    (".env Backup File Detected",
     re.compile(r"\.env\.(bak|backup|old|copy|save|[0-9]+)$"),
     "high"),
]

# ──────────────────────────────────────────────────────────────────────────────
# False-positive suppression: if any of these strings appear in the line,
# skip the generic/medium patterns.
# ──────────────────────────────────────────────────────────────────────────────
FP_SUPPRESSORS = re.compile(
    r"(?i)(example|placeholder|changeme|your[_\-]|<[A-Z_]+>|TODO|FIXME|"
    r"xxx|test|dummy|fake|sample|insert.?here|replace.?me|default|n/?a)"
)

# Patterns that are immune to FP suppression (known-format tokens don't need it)
FP_IMMUNE_PATTERNS = {
    "AWS Access Key ID", "AWS Secret Access Key", "AWS Session Token",
    "OpenAI API Key", "OpenAI API Key (generic)", "Anthropic API Key",
    "GitHub Personal Access Token", "GitHub OAuth Token", "GitHub Actions Token",
    "GitHub Refresh Token", "GitHub App User Token", "GitLab Personal Access Token",
    "Stripe Secret Key", "SendGrid API Key", "Slack Bot Token", "Slack User Token",
    "Discord Bot Token", "Google API Key", "npm Token", "PyPI Token",
    "Private Key Block", "PGP Private Key Block", "Database Connection String",
    "JWT Token",
}

# Dirs / extensions to skip
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", ".idea",
    ".mypy_cache", "dist", "build", ".tox", ".eggs", "coverage",
}
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp",
    ".pdf", ".zip", ".tar", ".gz", ".exe", ".bin", ".so", ".dll",
    ".pyc", ".class", ".mp3", ".mp4", ".woff", ".woff2", ".ttf",
    ".otf", ".eot", ".lock",
}

# Structured file extensions that get parsed rather than line-scanned
STRUCTURED_EXTENSIONS = {".json", ".yaml", ".yml", ".toml", ".ini", ".env"}

# Entropy thresholds
ENTROPY_MIN_LENGTH  = 20   # tokens shorter than this are skipped
ENTROPY_THRESHOLD   = 4.5  # bits/char — above this is likely a secret
ENTROPY_MAX_LENGTH  = 200  # sanity cap; very long strings are usually not secrets

# ──────────────────────────────────────────────────────────────────────────────
# Shannon entropy
# ──────────────────────────────────────────────────────────────────────────────
def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    n = len(s)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())


def high_entropy_tokens(line: str) -> list[tuple[str, float]]:
    """Return (token, entropy) pairs for suspiciously high-entropy tokens."""
    # Match long alphanumeric/base64-like strings
    tokens = re.findall(r"[A-Za-z0-9+/=\-_]{%d,%d}" % (ENTROPY_MIN_LENGTH, ENTROPY_MAX_LENGTH), line)
    results = []
    for token in tokens:
        e = shannon_entropy(token)
        if e >= ENTROPY_THRESHOLD:
            results.append((token, e))
    return results


# ──────────────────────────────────────────────────────────────────────────────
# Secret masking
# ──────────────────────────────────────────────────────────────────────────────
def mask_secret(value: str) -> str:
    value = value.strip()
    if len(value) <= 8:
        return "****"
    return value[:4] + "****" + value[-4:]


def mask_line(line: str) -> str:
    def replacer(m):
        token = m.group(0)
        return mask_secret(token) if len(token) >= 8 else token
    return re.sub(r"[A-Za-z0-9/+=\-_]{8,}", replacer, line).strip()


# ──────────────────────────────────────────────────────────────────────────────
# Severity helpers
# ──────────────────────────────────────────────────────────────────────────────
def severity_color(severity: str) -> str:
    return {
        "critical": RED,
        "high":     YELLOW,
        "medium":   CYAN,
        "entropy":  BLUE,
    }.get(severity, RESET)


def finding_fingerprint(filepath: str, line_num: int, pattern: str, masked: str) -> str:
    raw = f"{filepath}:{line_num}:{pattern}:{masked}"
    return hashlib.sha1(raw.encode()).hexdigest()[:16]


# ──────────────────────────────────────────────────────────────────────────────
# Allowlist loader
# ──────────────────────────────────────────────────────────────────────────────
def load_allowlist(root: str) -> dict:
    """Load phantomenv.yaml from the scanned root if present."""
    config_path = os.path.join(root, "phantomenv.yaml")
    default = {"ignore_paths": [], "ignore_patterns": [], "ignore_fingerprints": []}
    if not os.path.exists(config_path):
        return default
    if not HAS_YAML:
        print(f"{YELLOW}⚠  phantomenv.yaml found but PyYAML is not installed — ignoring allowlist.{RESET}")
        return default
    try:
        with open(config_path) as f:
            data = yaml.safe_load(f) or {}
        return {
            "ignore_paths":        data.get("ignore", {}).get("paths", []),
            "ignore_patterns":     data.get("ignore", {}).get("patterns", []),
            "ignore_fingerprints": data.get("ignore", {}).get("fingerprints", []),
        }
    except Exception as e:
        print(f"{YELLOW}⚠  Could not parse phantomenv.yaml: {e}{RESET}")
        return default


def is_allowlisted(hit: dict, allowlist: dict, root: str) -> bool:
    rel = os.path.relpath(hit["file"], root)

    # Path glob matching
    for pattern in allowlist["ignore_paths"]:
        # Simple glob: support * and **
        regex = re.escape(pattern).replace(r"\*\*", ".*").replace(r"\*", "[^/]*")
        if re.fullmatch(regex, rel):
            return True

    # Pattern name matching
    if hit["pattern"] in allowlist["ignore_patterns"]:
        return True

    # Fingerprint matching
    if hit.get("fingerprint") in allowlist["ignore_fingerprints"]:
        return True

    return False


# ──────────────────────────────────────────────────────────────────────────────
# .gitignore awareness
# ──────────────────────────────────────────────────────────────────────────────
def load_gitignore_patterns(root: str) -> list[re.Pattern]:
    """Parse .gitignore and return compiled regex patterns."""
    gitignore = os.path.join(root, ".gitignore")
    patterns = []
    if not os.path.exists(gitignore):
        return patterns
    try:
        with open(gitignore) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Convert gitignore glob to regex (simplified)
                regex = re.escape(line).replace(r"\*\*", ".*").replace(r"\*", "[^/]*").replace(r"\?", ".")
                if not regex.startswith("/"):
                    regex = "(^|.*?/)" + regex
                patterns.append(re.compile(regex))
    except Exception:
        pass
    return patterns


def is_gitignored(filepath: str, root: str, gitignore_patterns: list) -> bool:
    rel = os.path.relpath(filepath, root)
    for pat in gitignore_patterns:
        if pat.search(rel):
            return True
    return False


# ──────────────────────────────────────────────────────────────────────────────
# Structured-file key extraction (JSON / YAML / TOML / INI / .env)
# Returns a flat list of (key, value, approx_line) tuples
# ──────────────────────────────────────────────────────────────────────────────
def extract_kv_pairs(filepath: str) -> list[tuple[str, str, int]]:
    ext = os.path.splitext(filepath)[1].lower()
    pairs = []

    if ext == ".json":
        try:
            with open(filepath, encoding="utf-8", errors="strict") as f:
                content = f.read()
            data = json.loads(content)
            pairs = _flatten_dict(data)
        except Exception:
            pass

    elif ext in (".yaml", ".yml") and HAS_YAML:
        try:
            with open(filepath, encoding="utf-8", errors="strict") as f:
                data = yaml.safe_load(f)
            if isinstance(data, dict):
                pairs = _flatten_dict(data)
        except Exception:
            pass

    elif ext in (".env", ".ini", ".toml"):
        # Simple key=value parsing
        try:
            with open(filepath, encoding="utf-8", errors="strict") as f:
                for i, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\s*[=:]\s*(.*)$", line)
                    if m:
                        pairs.append((m.group(1), m.group(2).strip("'\"\r\n"), i))
        except Exception:
            pass

    return pairs


def _flatten_dict(d, prefix="", pairs=None) -> list:
    if pairs is None:
        pairs = []
    if isinstance(d, dict):
        for k, v in d.items():
            full_key = f"{prefix}.{k}" if prefix else k
            _flatten_dict(v, full_key, pairs)
    elif isinstance(d, list):
        for i, v in enumerate(d):
            _flatten_dict(v, f"{prefix}[{i}]", pairs)
    else:
        pairs.append((prefix, str(d), 0))
    return pairs


# ──────────────────────────────────────────────────────────────────────────────
# Core: scan a single line against all patterns + entropy
# ──────────────────────────────────────────────────────────────────────────────
_ENV_BACKUP_RE = re.compile(r"\.env\.(bak|backup|old|copy|save|[0-9]+)$")


def scan_line(
    line: str,
    filepath: str,
    line_number: int,
    gitignored: bool = False,
    check_entropy: bool = True,
) -> list:
    hits = []
    has_fp_suppressor = bool(FP_SUPPRESSORS.search(line))

    for pattern_name, regex, severity in PATTERNS:
        if pattern_name == ".env Backup File Detected":
            continue  # handled at file level

        if regex.search(line):
            # Apply false-positive suppression to non-immune patterns
            if has_fp_suppressor and pattern_name not in FP_IMMUNE_PATTERNS:
                continue

            effective_severity = severity
            if gitignored and severity == "critical":
                effective_severity = "high"
            elif gitignored:
                effective_severity = "medium"

            masked = mask_line(line)
            fp = finding_fingerprint(filepath, line_number, pattern_name, masked)
            hits.append({
                "file":        filepath,
                "line_num":    line_number,
                "pattern":     pattern_name,
                "severity":    effective_severity,
                "masked":      masked,
                "fingerprint": fp,
                "gitignored":  gitignored,
                "source":      "pattern",
            })

    # Entropy scan — skip if a pattern already flagged this line
    if check_entropy and not hits:
        for token, entropy in high_entropy_tokens(line):
            if has_fp_suppressor:
                continue
            severity = "high" if gitignored else "critical"
            masked = mask_secret(token)
            fp = finding_fingerprint(filepath, line_number, "High Entropy String", masked)
            hits.append({
                "file":        filepath,
                "line_num":    line_number,
                "pattern":     f"High Entropy String (entropy={entropy:.2f})",
                "severity":    "medium" if gitignored else "high",
                "masked":      masked,
                "fingerprint": fp,
                "gitignored":  gitignored,
                "source":      "entropy",
            })

    return hits


# ──────────────────────────────────────────────────────────────────────────────
# Core: scan one file
# ──────────────────────────────────────────────────────────────────────────────
def scan_file(filepath: str, gitignored: bool = False) -> list:
    hits = []

    # .env backup check on filename
    if _ENV_BACKUP_RE.search(os.path.basename(filepath)):
        hits.append({
            "file":        filepath,
            "line_num":    0,
            "pattern":     ".env Backup File Detected",
            "severity":    "medium" if gitignored else "high",
            "masked":      os.path.basename(filepath),
            "fingerprint": finding_fingerprint(filepath, 0, ".env Backup File Detected", filepath),
            "gitignored":  gitignored,
            "source":      "filename",
        })

    ext = os.path.splitext(filepath)[1].lower()
    if ext in SKIP_EXTENSIONS:
        return hits

    # Structured file: parse as KV pairs
    if ext in STRUCTURED_EXTENSIONS:
        kv_pairs = extract_kv_pairs(filepath)
        for key, value, approx_line in kv_pairs:
            # Build a synthetic "line" like `key = "value"` for pattern matching
            synthetic = f'{key} = "{value}"'
            line_hits = scan_line(synthetic, filepath, approx_line or 1, gitignored)
            hits.extend(line_hits)
        # Also fall through to line scan for .env files (catches comments/inline)

    # Line-by-line scan
    try:
        with open(filepath, "r", encoding="utf-8", errors="strict") as f:
            for line_number, line in enumerate(f, start=1):
                line_hits = scan_line(line, filepath, line_number, gitignored)
                hits.extend(line_hits)
    except (UnicodeDecodeError, PermissionError):
        pass

    # Deduplicate (fingerprint-based) — structured + line scans can overlap
    seen = set()
    deduped = []
    for h in hits:
        if h["fingerprint"] not in seen:
            seen.add(h["fingerprint"])
            deduped.append(h)

    return deduped


# ──────────────────────────────────────────────────────────────────────────────
# Core: walk a folder
# ──────────────────────────────────────────────────────────────────────────────
def walk_folder(folder: str, gitignore_patterns: list) -> list:
    all_hits = []
    for root, dirs, files in os.walk(folder):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for filename in files:
            filepath = os.path.join(root, filename)
            gitignored = is_gitignored(filepath, folder, gitignore_patterns)
            file_hits = scan_file(filepath, gitignored)
            all_hits.extend(file_hits)
    return all_hits


# ──────────────────────────────────────────────────────────────────────────────
# Git history scanning
# ──────────────────────────────────────────────────────────────────────────────
def scan_git_history(folder: str) -> list:
    if not HAS_GIT:
        print(f"{YELLOW}⚠  gitpython not installed — skipping git history scan.{RESET}")
        print(f"{DIM}   Install with: pip install gitpython{RESET}\n")
        return []

    try:
        repo = gitpython.Repo(folder, search_parent_directories=True)
    except gitpython.InvalidGitRepositoryError:
        print(f"{DIM}   No git repository found — skipping history scan.{RESET}\n")
        return []

    print(f"{DIM}  Scanning git history...{RESET}", end="", flush=True)

    hits = []
    seen_fps = set()
    commit_count = 0

    try:
        for commit in repo.iter_commits():
            commit_count += 1
            for diff in commit.diff(commit.parents[0] if commit.parents else gitpython.NULL_TREE):
                try:
                    if diff.b_blob is None:
                        continue
                    content = diff.b_blob.data_stream.read()
                    try:
                        text = content.decode("utf-8", errors="strict")
                    except UnicodeDecodeError:
                        continue

                    fake_path = diff.b_path or "unknown"
                    for line_number, line in enumerate(text.splitlines(), 1):
                        for pattern_name, regex, severity in PATTERNS:
                            if pattern_name == ".env Backup File Detected":
                                continue
                            if regex.search(line):
                                masked = mask_line(line)
                                fp = finding_fingerprint(fake_path, line_number, pattern_name, masked)
                                if fp in seen_fps:
                                    continue
                                seen_fps.add(fp)
                                hits.append({
                                    "file":        fake_path,
                                    "line_num":    line_number,
                                    "pattern":     pattern_name,
                                    "severity":    severity,
                                    "masked":      masked,
                                    "fingerprint": fp,
                                    "gitignored":  False,
                                    "source":      "git",
                                    "commit":      commit.hexsha[:8],
                                    "commit_msg":  commit.message.strip()[:60],
                                })
                except Exception:
                    continue
    except Exception:
        pass

    print(f"\r{DIM}  Scanned {commit_count} commits.{RESET}           ")
    return hits


# ──────────────────────────────────────────────────────────────────────────────
# Output: print the final report
# ──────────────────────────────────────────────────────────────────────────────
def print_report(
    hits: list,
    git_hits: list,
    scanned_root: str,
    files_scanned: int,
) -> None:
    print()
    print(f"{BOLD}phantomenv 🔍  Secret Scanner  v2.0{RESET}")
    print(f"  Root   : {CYAN}{os.path.abspath(scanned_root)}{RESET}")
    print(f"  Files  : {files_scanned}")
    print()

    all_hits = hits + git_hits

    if not all_hits:
        print(f"{GREEN}✅  No secrets detected. Your project looks clean!{RESET}")
        print()
        return

    # Summary counts
    critical = sum(1 for h in all_hits if h["severity"] == "critical")
    high     = sum(1 for h in all_hits if h["severity"] == "high")
    medium   = sum(1 for h in all_hits if h["severity"] == "medium")
    gitignored_count = sum(1 for h in hits if h.get("gitignored"))

    print(f"{BOLD}{'─'*64}{RESET}")
    print(f"{BOLD}  SUMMARY{RESET}  —  {len(all_hits)} finding(s)")
    print(
        f"  {RED}● Critical: {critical}{RESET}   "
        f"{YELLOW}● High: {high}{RESET}   "
        f"{CYAN}● Medium: {medium}{RESET}"
    )
    if gitignored_count:
        print(f"  {DIM}ℹ  {gitignored_count} finding(s) in .gitignored files (lower risk){RESET}")
    if git_hits:
        print(f"  {BLUE}⏳  {len(git_hits)} finding(s) in git history{RESET}")
    print(f"{BOLD}{'─'*64}{RESET}")
    print()

    # ── Working-tree findings ────────────────────────────────────────────────
    if hits:
        print(f"{BOLD}📁  WORKING TREE{RESET}")
        print()
        by_file = defaultdict(list)
        for hit in hits:
            by_file[hit["file"]].append(hit)

        for filepath in sorted(by_file):
            rel = os.path.relpath(filepath, scanned_root)
            gi_note = f"  {DIM}[gitignored]{RESET}" if by_file[filepath][0].get("gitignored") else ""
            print(f"{BOLD}  📄  {rel}{RESET}{gi_note}")

            for hit in by_file[filepath]:
                color = severity_color(hit["severity"])
                label = f"[{hit['severity'].upper()}]".ljust(10)
                location = f"line {hit['line_num']}" if hit["line_num"] else "filename"
                print(f"     {color}{label}{RESET} {hit['pattern']}")
                print(f"              {CYAN}{location}{RESET}  →  {hit['masked']}")
                print(f"              {DIM}fingerprint: {hit['fingerprint']}{RESET}")
            print()

    # ── Git history findings ─────────────────────────────────────────────────
    if git_hits:
        print(f"{BOLD}⏳  GIT HISTORY{RESET}")
        print()
        for hit in git_hits:
            color = severity_color(hit["severity"])
            label = f"[{hit['severity'].upper()}]".ljust(10)
            print(f"  {BLUE}commit {hit['commit']}{RESET}  {DIM}{hit.get('commit_msg', '')}{RESET}")
            print(f"  {color}{label}{RESET} {hit['pattern']}")
            print(f"            {CYAN}{hit['file']}:{hit['line_num']}{RESET}  →  {hit['masked']}")
            print()

    # ── Remediation hints ────────────────────────────────────────────────────
    print(f"{BOLD}{'─'*64}{RESET}")
    print(f"{BOLD}  NEXT STEPS{RESET}")
    if critical > 0:
        print(f"  {RED}1. Rotate ALL critical secrets immediately — treat them as compromised.{RESET}")
    print(f"  2. Add secrets to a secrets manager (AWS Secrets Manager, Vault, Doppler).")
    print(f"  3. Use environment variables — never hardcode credentials.")
    print(f"  4. Add phantomenv as a pre-commit hook:")
    print(f"     {DIM}echo 'phantomenv .' > .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit{RESET}")
    if gitignored_count:
        print(f"  5. Even .gitignored secrets are a risk — rotate them anyway.")
    print()

    print(f"  {DIM}To suppress a false positive, add to phantomenv.yaml:{RESET}")
    print(f"  {DIM}ignore:{RESET}")
    print(f"  {DIM}  fingerprints: ['<fingerprint>']{RESET}")
    print()


# ──────────────────────────────────────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────────────────────────────────────
def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="phantomenv 🔍  v2.0 — secret scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  phantomenv .                    Scan current directory
  phantomenv /path/to/project     Scan a specific folder
  phantomenv . --no-git           Skip git history scan
  phantomenv . --no-entropy       Skip entropy analysis
  phantomenv . --only-critical    Only show critical findings
        """,
    )
    parser.add_argument("folder", nargs="?", default=".", help="Folder to scan (default: .)")
    parser.add_argument("--no-git",      action="store_true", help="Skip git history scan")
    parser.add_argument("--no-entropy",  action="store_true", help="Skip entropy analysis")
    parser.add_argument("--only-critical", action="store_true", help="Only report critical findings")
    args = parser.parse_args()

    folder = args.folder
    if not os.path.isdir(folder):
        print(f"{RED}Error: '{folder}' is not a valid directory.{RESET}", file=sys.stderr)
        sys.exit(2)

    # Load config
    allowlist         = load_allowlist(folder)
    gitignore_patterns = load_gitignore_patterns(folder)

    # Working-tree scan
    hits = walk_folder(folder, gitignore_patterns)

    # Count scanned files (approximate)
    files_scanned = sum(
        len(files)
        for root, dirs, files in os.walk(folder)
        if not any(skip in root for skip in SKIP_DIRS)
    )

    # Apply allowlist
    hits = [h for h in hits if not is_allowlisted(h, allowlist, folder)]

    # Apply entropy flag
    if args.no_entropy:
        hits = [h for h in hits if h["source"] != "entropy"]

    # Apply severity filter
    if args.only_critical:
        hits = [h for h in hits if h["severity"] == "critical"]

    # Git history scan
    git_hits = []
    if not args.no_git:
        git_hits = scan_git_history(folder)
        git_hits = [h for h in git_hits if not is_allowlisted(h, allowlist, folder)]
        if args.only_critical:
            git_hits = [h for h in git_hits if h["severity"] == "critical"]

    print_report(hits, git_hits, folder, files_scanned)

    sys.exit(1 if (hits or git_hits) else 0)


if __name__ == "__main__":
    main()
