"""Correlate ground truth events with EDR findings."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Sequence

import numpy as np
import structlog
from scipy.optimize import linear_sum_assignment

from edr_bench.models.finding import Finding
from edr_bench.models.ground_truth import GroundTruthEvent

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Lookup tables for semantic / data-classification matching
# ---------------------------------------------------------------------------

# Maps canonical data_classification values to sets of keywords that EDR
# descriptions or rule names commonly use when referring to that class.
_DATA_CLASSIFICATION_SYNONYMS: dict[str, set[str]] = {
    "pii": {
        "pii", "personally identifiable", "personal data", "personal information",
        "ssn", "social security", "date of birth", "email address", "phone number",
        "name and address", "customer data", "customer record", "sensitive data",
        "gdpr", "ccpa", "privacy",
    },
    "credentials": {
        "credentials", "credential", "password", "secret", "api key", "apikey",
        "access token", "token", "private key", "ssh key", "auth", "authentication",
        "login", "secret key", "passphrase",
    },
    "phi": {
        "phi", "protected health", "health information", "hipaa", "medical record",
        "patient data", "patient record", "health data", "diagnosis",
    },
    "financial": {
        "financial", "credit card", "bank account", "routing number", "payment",
        "invoice", "billing", "pci", "cardholder",
    },
    "proprietary_code": {
        "proprietary", "source code", "intellectual property", "trade secret",
        "internal code", "confidential code", "proprietary code",
    },
}

# Maps canonical action_type values to sets of keywords likely to appear in
# EDR finding descriptions or rule names.
_ACTION_TYPE_KEYWORDS: dict[str, set[str]] = {
    "upload_file": {"upload", "file transfer", "file upload", "exfiltration", "exfil", "sent file"},
    "paste_text": {"paste", "clipboard", "copy paste", "pasted", "clipboard content"},
    "download": {"download", "file download", "downloaded", "retrieval"},
    "send_message": {"send", "message", "chat", "post", "submit", "sent"},
    "share_link": {"share", "sharing", "shared link", "link sharing"},
    "email": {"email", "mail", "smtp", "sent mail", "attachment"},
    "print": {"print", "printer", "printed"},
    "screen_capture": {"screenshot", "screen capture", "screen recording", "screengrab"},
}


@dataclass
class CorrelationResult:
    """Result of correlating ground truth with EDR findings."""

    matched_pairs: list[tuple[GroundTruthEvent, Finding]] = field(default_factory=list)
    unmatched_gt: list[GroundTruthEvent] = field(default_factory=list)
    unmatched_findings: list[Finding] = field(default_factory=list)

    @property
    def false_positives(self) -> list[Finding]:
        """Alias for findings that did not match any ground truth event."""
        return self.unmatched_findings


class GroundTruthCorrelator:
    """Match ground truth events to EDR findings using optimal assignment.

    Uses the Hungarian algorithm (scipy ``linear_sum_assignment``) to find
    the globally optimal one-to-one matching between ground truth events
    and EDR findings, maximising total overlap score.

    For each ``(gt, finding)`` pair, a score in ``[0, 1]`` is computed
    from temporal proximity and attribute overlap.  Pairs outside the
    time window or with zero attribute overlap receive a score of 0 and
    are never matched.
    """

    # Minimum score a pair must reach to be considered a valid match.
    _MATCH_THRESHOLD = 0.05

    def __init__(self, window_seconds: float = 30.0) -> None:
        self._window_seconds = window_seconds

    def correlate(
        self,
        ground_truth: Sequence[GroundTruthEvent],
        findings: Sequence[Finding],
    ) -> CorrelationResult:
        """Correlate *ground_truth* events against *findings*.

        Returns a :class:`CorrelationResult` containing matched pairs
        and the unmatched remainders on both sides.
        """
        if not ground_truth or not findings:
            return CorrelationResult(
                matched_pairs=[],
                unmatched_gt=list(ground_truth),
                unmatched_findings=list(findings),
            )

        n_gt = len(ground_truth)
        n_f = len(findings)

        # Build the score matrix (rows = GT events, cols = findings).
        score_matrix = np.zeros((n_gt, n_f), dtype=np.float64)
        for gi, gt in enumerate(ground_truth):
            for fi, finding in enumerate(findings):
                score_matrix[gi, fi] = self._score_pair(gt, finding)

        # Hungarian algorithm minimises cost, so we negate the scores.
        cost_matrix = -score_matrix
        row_ind, col_ind = linear_sum_assignment(cost_matrix)

        matched_gt_indices: set[int] = set()
        matched_f_indices: set[int] = set()
        matched_pairs: list[tuple[GroundTruthEvent, Finding]] = []

        for gi, fi in zip(row_ind, col_ind):
            if score_matrix[gi, fi] >= self._MATCH_THRESHOLD:
                matched_gt_indices.add(int(gi))
                matched_f_indices.add(int(fi))
                matched_pairs.append((ground_truth[gi], findings[fi]))

        unmatched_gt = [
            gt for i, gt in enumerate(ground_truth) if i not in matched_gt_indices
        ]
        unmatched_findings = [
            f for i, f in enumerate(findings) if i not in matched_f_indices
        ]

        logger.info(
            "correlator.result",
            matched=len(matched_pairs),
            unmatched_gt=len(unmatched_gt),
            false_positives=len(unmatched_findings),
        )

        return CorrelationResult(
            matched_pairs=matched_pairs,
            unmatched_gt=unmatched_gt,
            unmatched_findings=unmatched_findings,
        )

    # ------------------------------------------------------------------
    # Scoring
    # ------------------------------------------------------------------

    def _score_pair(self, gt: GroundTruthEvent, finding: Finding) -> float:
        """Compute a match score for a (ground truth, finding) pair.

        Returns 0.0 if the pair is outside the correlation time window.
        Otherwise returns a score in ``(0, 1]`` based on attribute overlap.
        """
        # Temporal proximity check
        time_delta = abs((finding.timestamp - gt.timestamp).total_seconds())
        if time_delta > self._window_seconds:
            return 0.0

        # Temporal score: closer in time -> higher score
        temporal_score = 1.0 - (time_delta / self._window_seconds)

        # Attribute overlap score
        attr_score = self._attribute_overlap(gt, finding)

        if attr_score == 0.0:
            return 0.0

        # Combined score: weighted average
        return 0.4 * temporal_score + 0.6 * attr_score

    @staticmethod
    def _keyword_overlap(text_a: str, text_b: str) -> float:
        """Compute Jaccard similarity between word tokens of two strings.

        Both strings are lowercased and split on whitespace / punctuation
        boundaries.  Returns a float in ``[0, 1]``.
        """
        if not text_a or not text_b:
            return 0.0

        tokens_a = set(re.split(r"[\s\W_]+", text_a.lower())) - {""}
        tokens_b = set(re.split(r"[\s\W_]+", text_b.lower())) - {""}

        if not tokens_a or not tokens_b:
            return 0.0

        intersection = tokens_a & tokens_b
        union = tokens_a | tokens_b
        return len(intersection) / len(union)

    @staticmethod
    def _attribute_overlap(gt: GroundTruthEvent, finding: Finding) -> float:
        """Score attribute overlap between a ground truth event and finding.

        Compares classic telemetry attributes (process_name, command_line,
        file_path, network_dst) as well as Coach-specific semantic
        dimensions (destination_site, content/description keywords,
        data_classification, action_type).

        Returns a value in ``[0, 1]``.
        """
        # Each entry is ``(matched: bool, weight: float)``.
        # Only checks where *both* sides have data are appended.
        checks: list[tuple[bool, float]] = []

        # ------------------------------------------------------------------
        # 1. Process name match  (weight 1.0)
        #    When both sides have a process name and they don't match,
        #    treat as a hard mismatch (return 0.0 immediately).
        # ------------------------------------------------------------------
        if gt.process_name and finding.process_name:
            gt_proc = gt.process_name.lower()
            f_proc = finding.process_name.lower()
            match = (
                gt_proc == f_proc
                or gt_proc in f_proc
                or f_proc in gt_proc
            )
            if not match:
                return 0.0
            checks.append((True, 1.0))

        # ------------------------------------------------------------------
        # 2. Command line overlap  (weight 1.0)
        # ------------------------------------------------------------------
        if gt.command_line and finding.command_line:
            gt_tokens = set(gt.command_line.lower().split())
            f_tokens = set(finding.command_line.lower().split())
            if gt_tokens and f_tokens:
                overlap = len(gt_tokens & f_tokens) / max(
                    len(gt_tokens), len(f_tokens)
                )
                checks.append((overlap > 0.3, overlap))

        # ------------------------------------------------------------------
        # 3. File path match  (weight 1.0)
        # ------------------------------------------------------------------
        if gt.file_path and finding.file_path:
            match = (
                gt.file_path == finding.file_path
                or gt.file_path.endswith(finding.file_path)
                or finding.file_path.endswith(gt.file_path)
            )
            checks.append((match, 1.0 if match else 0.0))

        # ------------------------------------------------------------------
        # 4. Network destination match  (weight 1.0)
        # ------------------------------------------------------------------
        if gt.network_dst and finding.network_dst:
            match = gt.network_dst == finding.network_dst
            checks.append((match, 1.0 if match else 0.0))

        # ------------------------------------------------------------------
        # 5. Destination site match  (weight 0.8)
        #    Compare gt.destination_site against:
        #      - finding.network_dst  (exact / substring)
        #      - finding.description  (substring in free text)
        # ------------------------------------------------------------------
        if gt.destination_site:
            dst_lower = gt.destination_site.lower()
            candidate_texts: list[str] = []
            if finding.network_dst:
                candidate_texts.append(finding.network_dst.lower())
            if finding.description:
                candidate_texts.append(finding.description.lower())
            if finding.rule_name:
                candidate_texts.append(finding.rule_name.lower())

            if candidate_texts:
                matched_dst = any(dst_lower in t for t in candidate_texts)
                checks.append((matched_dst, 0.8))

        # ------------------------------------------------------------------
        # 6. Description / content keyword overlap  (weight 0.7)
        #    Combine gt.content_summary + gt.action_type as the ground truth
        #    text and compare against finding.description + finding.rule_name.
        # ------------------------------------------------------------------
        gt_text_parts: list[str] = []
        if gt.content_summary:
            gt_text_parts.append(gt.content_summary)
        if gt.action_type:
            gt_text_parts.append(gt.action_type)

        finding_text_parts: list[str] = []
        if finding.description:
            finding_text_parts.append(finding.description)
        if finding.rule_name:
            finding_text_parts.append(finding.rule_name)

        if gt_text_parts and finding_text_parts:
            gt_text = " ".join(gt_text_parts)
            finding_text = " ".join(finding_text_parts)
            kw_score = GroundTruthCorrelator._keyword_overlap(gt_text, finding_text)
            # Treat a Jaccard score > 0.1 as a positive signal
            checks.append((kw_score > 0.1, kw_score * 0.7))

        # ------------------------------------------------------------------
        # 7. Data classification match  (weight 0.6)
        #    If gt.data_classification is set, look for synonym keywords in
        #    the finding description / rule_name.
        # ------------------------------------------------------------------
        if gt.data_classification and (finding.description or finding.rule_name):
            classification_key = gt.data_classification.lower().strip()
            synonyms = _DATA_CLASSIFICATION_SYNONYMS.get(classification_key)

            # Build the full text to search in from the finding
            search_text = " ".join(
                t for t in [finding.description, finding.rule_name] if t
            ).lower()

            if synonyms:
                matched_cls = any(syn in search_text for syn in synonyms)
            else:
                # Fallback: check if the raw classification string appears
                matched_cls = classification_key in search_text
            checks.append((matched_cls, 0.6))

        # ------------------------------------------------------------------
        # 8. Action type match  (weight 0.5)
        #    If gt.action_type is set, look for action-related keywords in
        #    the finding description / rule_name.
        # ------------------------------------------------------------------
        if gt.action_type and (finding.description or finding.rule_name):
            action_key = gt.action_type.lower().strip()
            action_keywords = _ACTION_TYPE_KEYWORDS.get(action_key)

            search_text_action = " ".join(
                t for t in [finding.description, finding.rule_name] if t
            ).lower()

            if action_keywords:
                matched_action = any(kw in search_text_action for kw in action_keywords)
            else:
                # Fallback: split the action_type on underscores and check
                # if any fragment appears in the finding text.
                fragments = action_key.replace("_", " ").split()
                matched_action = any(frag in search_text_action for frag in fragments)
            checks.append((matched_action, 0.5))

        # ------------------------------------------------------------------
        # Aggregate
        # ------------------------------------------------------------------
        if not checks:
            # No overlapping attributes to compare; give a small base score
            # so temporal-only matches can still succeed (weakly).
            return 0.1

        total_weight = sum(weight for _, weight in checks)
        matched_weight = sum(weight for is_match, weight in checks if is_match)
        return matched_weight / total_weight if total_weight > 0 else 0.0
