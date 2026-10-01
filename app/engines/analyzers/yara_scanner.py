"""
YARA Scanner — Runs YARA rules against file bytes.

YARA is a pattern-matching tool designed for malware researchers.
Each rule defines:
  - meta:      Description, severity, author tags
  - strings:   Text, hex, or regex patterns to search for
  - condition: Boolean logic combining matches

This scanner:
  1. Loads all .yar files from the rules directory (once, cached)
  2. Provides scan() to run all compiled rules against raw bytes
  3. Returns structured match results with severity and score contributions

============================================================
HOW TO ADD YOUR OWN YARA RULES
============================================================
1. Create a new .yar file in app/engines/rules/
2. Write your rule following the format in existing .yar files
3. The scanner will pick it up automatically on next restart
   (or immediately if you call reload_rules())

Example minimal rule:
------
rule MyCustomRule : tag1 tag2
{
    meta:
        description = "Detects something suspicious"
        severity    = "high"

    strings:
        $s1 = "bad string"   nocase ascii wide
        $s2 = { DE AD BE EF }

    condition:
        any of them
}
------
============================================================
"""

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any

from app.engines.analyzers.file_types import parse_applies_to

logger = logging.getLogger(__name__)

# Rules directory — relative to this file's location
_RULES_DIR = Path(__file__).parent.parent / "rules"


def _preview(raw: bytes, limit: int = 64) -> str:
    """Printable ASCII preview of matched bytes (binary → '.')."""
    shown = raw[:limit]
    text = "".join(chr(b) if 32 <= b < 127 else "." for b in shown)
    suffix = "…" if len(raw) > limit else ""
    return text + suffix

# Severity order for score mapping
_SEVERITY_SCORES: Dict[str, float] = {
    "critical": 85.0,
    "high":     65.0,
    "medium":   35.0,
    "low":      15.0,
    "info":      5.0,
}


@dataclass
class YaraMatch:
    """Represents a single YARA rule that matched."""
    rule_name: str
    tags: List[str]
    meta: Dict[str, Any]
    matched_strings: List[str]   # Human-readable list of which strings matched
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    #   [{"string": "$enc4", "offset": 988475, "preview": "-eC ", "count": 1}]

    @property
    def severity(self) -> str:
        return str(self.meta.get("severity", "medium")).lower()

    @property
    def description(self) -> str:
        return str(self.meta.get("description", self.rule_name))

    @property
    def explanation(self) -> str:
        """Why the rule exists (rule author's meta.explanation)."""
        return str(self.meta.get("explanation", ""))

    @property
    def applies_to(self) -> str:
        """Raw applies_to meta (comma-separated buckets), '' = any file."""
        return str(self.meta.get("applies_to", ""))

    @property
    def score_contribution(self) -> float:
        """Score this match contributes to the overall risk score."""
        return _SEVERITY_SCORES.get(self.severity, 35.0)


@dataclass
class YaraScanResult:
    """Result of running all YARA rules against a file."""
    matched: bool = False
    matches: List[YaraMatch] = field(default_factory=list)
    yara_score: float = 0.0         # 0–100 aggregate score
    error: Optional[str] = None     # Error message if scan failed
    suppressed: List[str] = field(default_factory=list)
    #   Human-readable notes for rules that matched raw bytes but were
    #   dropped because the rule does not apply to this file type.

    @property
    def findings(self) -> List[str]:
        """Human-readable finding strings for each match."""
        return [
            f"YARA [{m.severity.upper()}] {m.rule_name}: {m.description}"
            for m in self.matches
        ]


class YaraScanner:
    """
    Loads and executes YARA rules against file bytes.

    The compiled rules are cached in memory — loading only happens once
    per process lifetime (or on explicit reload_rules() call).
    """

    _compiled_rules = None   # Module-level cache — shared across all instances
    _rules_loaded: bool = False
    _rules_error: Optional[str] = None

    def __init__(self):
        if not YaraScanner._rules_loaded:
            self._load_rules()

    # ── Public API ─────────────────────────────────────────────────────────────

    def scan(
        self,
        data: bytes,
        filename: str = "unknown",
        bucket: Optional[str] = None,
    ) -> YaraScanResult:
        """
        Run all loaded YARA rules against raw file bytes.

        Args:
            data    : Raw bytes of the file to scan
            filename: Original filename (for logging only)
            bucket  : File-type bucket from file_types.classify_bucket().
                      Rules whose meta.applies_to does not include this
                      bucket are suppressed (not counted, not scored).
                      None = apply every rule (email bodies, unknown files).

        Returns:
            YaraScanResult with all matched rules and aggregate score
        """
        result = YaraScanResult()

        if YaraScanner._rules_error:
            result.error = f"YARA rules failed to load: {YaraScanner._rules_error}"
            logger.warning(f"YARA scan skipped for '{filename}': {result.error}")
            return result

        if YaraScanner._compiled_rules is None:
            result.error = "YARA rules not loaded"
            return result

        try:
            raw_matches = YaraScanner._compiled_rules.match(data=data)
        except Exception as e:
            result.error = f"YARA scan error: {e}"
            logger.debug(f"YARA scan failed on '{filename}': {e}")
            return result

        if not raw_matches:
            return result

        total_score = 0.0

        for match in raw_matches:
            applies_raw = str(match.meta.get("applies_to", "")).strip()
            if bucket and applies_raw:
                allowed = parse_applies_to(applies_raw)
                if bucket not in allowed:
                    note = (
                        f"YARA rule '{match.rule}' matched raw bytes but was "
                        f"suppressed: it applies to [{applies_raw}] files, not "
                        f"'{bucket}' (likely byte coincidence)"
                    )
                    result.suppressed.append(note)
                    logger.info(f"YARA suppression for '{filename}': {note}")
                    continue

            # Build list of matched string identifiers + hard evidence
            matched_str_names = list({
                str(s.identifier) for s in match.strings if s.instances
            })
            evidence: List[Dict[str, Any]] = []
            for s in match.strings:
                if not s.instances:
                    continue
                inst = s.instances[0]
                evidence.append({
                    "string": str(s.identifier),
                    "offset": int(inst.offset),
                    "preview": _preview(inst.matched_data),
                    "count": len(s.instances),
                })

            yara_match = YaraMatch(
                rule_name=match.rule,
                tags=list(match.tags),
                meta=dict(match.meta),
                matched_strings=matched_str_names,
                evidence=evidence,
            )
            result.matches.append(yara_match)

            # Accumulate score (capped at 100)
            total_score += yara_match.score_contribution

        if not result.matches:
            # Everything was suppressed — this is NOT a match.
            return result

        result.matched = True
        result.yara_score = min(100.0, round(total_score, 1))

        logger.info(
            f"YARA matched {len(result.matches)} rule(s) on '{filename}': "
            f"score={result.yara_score} "
            f"rules=[{', '.join(m.rule_name for m in result.matches)}]"
            + (f" suppressed={len(result.suppressed)}" if result.suppressed else "")
        )
        return result

    def reload_rules(self) -> bool:
        """Force a reload of YARA rules from disk. Returns True on success."""
        YaraScanner._rules_loaded = False
        YaraScanner._compiled_rules = None
        YaraScanner._rules_error = None
        return self._load_rules()

    def is_available(self) -> bool:
        """Check if YARA is installed and rules loaded successfully."""
        return YaraScanner._rules_loaded and YaraScanner._compiled_rules is not None

    # ── Private helpers ────────────────────────────────────────────────────────

    @classmethod
    def _load_rules(cls) -> bool:
        """
        Compile all .yar files in the rules directory.

        YARA compiles rules upfront — scanning is fast because compilation
        already happened. This is called once at startup.
        """
        try:
            import yara  # Lazy import — requires yara-python
        except ImportError:
            cls._rules_error = "yara-python package not installed"
            cls._rules_loaded = True  # Mark as "attempted" to avoid repeated attempts
            logger.warning(
                "yara-python not installed — YARA scanning disabled. "
                "Install with: pip install yara-python"
            )
            return False

        rule_files = list(_RULES_DIR.glob("*.yar"))

        if not rule_files:
            cls._rules_error = f"No .yar files found in {_RULES_DIR}"
            cls._rules_loaded = True
            logger.warning(cls._rules_error)
            return False

        # YARA's parser accepts ASCII source. The maintained rules use Unicode
        # punctuation in comments/metadata for readability, so normalize only
        # the compiled in-memory copy rather than rewriting the source files.
        def compile_source(rule_file: Path) -> str:
            lines = []
            for line in rule_file.read_text(encoding="utf-8").splitlines():
                # The educational rule files use shell-style heading comments;
                # translate them to YARA comment syntax for the parser.
                stripped = line.lstrip()
                if stripped.startswith("#"):
                    indent = line[: len(line) - len(stripped)]
                    line = f"{indent}//{stripped[1:]}"
                lines.append(line)
            return "\n".join(lines).encode("ascii", errors="replace").decode("ascii")

        sources: Dict[str, str] = {
            rule_file.stem: compile_source(rule_file) for rule_file in rule_files
        }

        try:
            cls._compiled_rules = yara.compile(sources=sources)
            cls._rules_loaded = True
            cls._rules_error = None
            logger.info(
                f"YARA: compiled {len(rule_files)} rule file(s) from {_RULES_DIR}: "
                f"{[f.name for f in rule_files]}"
            )
            return True
        except yara.SyntaxError as e:
            cls._rules_error = f"YARA syntax error: {e}"
            cls._rules_loaded = True
            logger.error(f"YARA rule compilation failed: {e}")
            return False
        except Exception as e:
            cls._rules_error = f"Unexpected error compiling YARA rules: {e}"
            cls._rules_loaded = True
            logger.error(cls._rules_error)
            return False
