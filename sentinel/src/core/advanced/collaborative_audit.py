"""
Collaborative Audit Module

Support multi-auditor workflows:
1. Finding deduplication - Merge similar findings
2. Severity consensus - Vote on severity
3. Coverage assignment - Divide work
4. Review workflows - Peer review findings
5. Audit trail - Track all changes

Use cases:
- Team audits
- Audit competitions
- Internal security reviews
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from datetime import datetime
import hashlib
import json
from collections import Counter


class AuditPhase(Enum):
    """Phases of a collaborative audit."""
    SETUP = "setup"
    INDIVIDUAL_REVIEW = "individual_review"
    DEDUPLICATION = "deduplication"
    CONSENSUS = "consensus"
    FINAL_REVIEW = "final_review"
    COMPLETE = "complete"


class FindingStatus(Enum):
    """Status of a finding in the workflow."""
    DRAFT = "draft"
    SUBMITTED = "submitted"
    UNDER_REVIEW = "under_review"
    DUPLICATE = "duplicate"
    CONFIRMED = "confirmed"
    DISPUTED = "disputed"
    REJECTED = "rejected"
    FINAL = "final"


class VoteType(Enum):
    """Types of votes on findings."""
    SEVERITY = "severity"
    VALIDITY = "validity"
    DUPLICATE = "duplicate"


@dataclass
class Auditor:
    """An auditor participating in the audit."""
    id: str
    name: str
    email: Optional[str] = None
    assigned_contracts: list[str] = field(default_factory=list)
    findings_submitted: int = 0
    expertise: list[str] = field(default_factory=list)


@dataclass
class AuditFinding:
    """A finding in the collaborative audit."""
    id: str
    auditor_id: str
    title: str
    severity: str
    description: str
    affected_code: str
    contract: str
    function: Optional[str]
    status: FindingStatus = FindingStatus.DRAFT
    created_at: datetime = field(default_factory=datetime.now)
    updated_at: datetime = field(default_factory=datetime.now)
    votes: list[dict] = field(default_factory=list)
    comments: list[dict] = field(default_factory=list)
    duplicate_of: Optional[str] = None
    merged_from: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)


@dataclass
class AuditSession:
    """A collaborative audit session."""
    id: str
    name: str
    target_contracts: list[str]
    auditors: list[Auditor]
    findings: list[AuditFinding]
    phase: AuditPhase = AuditPhase.SETUP
    created_at: datetime = field(default_factory=datetime.now)
    deadline: Optional[datetime] = None


class CollaborativeAudit:
    """
    Manage collaborative audit workflows.

    Features:
    - Finding deduplication with similarity scoring
    - Severity consensus voting
    - Coverage assignment
    - Review workflows
    - Audit trail
    """

    def __init__(self, session_name: str = "Audit"):
        self.session = AuditSession(
            id=self._generate_id(session_name),
            name=session_name,
            target_contracts=[],
            auditors=[],
            findings=[],
        )
        self.audit_log: list[dict] = []

    def _generate_id(self, seed: str) -> str:
        """Generate unique ID."""
        timestamp = datetime.now().isoformat()
        return hashlib.sha256(f"{seed}{timestamp}".encode()).hexdigest()[:12]

    def _log_action(self, action: str, details: dict) -> None:
        """Log an action to audit trail."""
        self.audit_log.append({
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "details": details,
        })

    # =========================================================================
    # SETUP
    # =========================================================================

    def add_auditor(
        self,
        name: str,
        email: Optional[str] = None,
        expertise: Optional[list[str]] = None,
    ) -> Auditor:
        """Add an auditor to the session."""
        auditor = Auditor(
            id=self._generate_id(name),
            name=name,
            email=email,
            expertise=expertise or [],
        )
        self.session.auditors.append(auditor)
        self._log_action("add_auditor", {"auditor": name})
        return auditor

    def add_target_contract(self, contract_path: str) -> None:
        """Add a contract to be audited."""
        self.session.target_contracts.append(contract_path)
        self._log_action("add_contract", {"contract": contract_path})

    def assign_coverage(
        self,
        strategy: str = "round_robin",
    ) -> dict[str, list[str]]:
        """
        Assign contracts to auditors.

        Strategies:
        - round_robin: Distribute evenly
        - expertise: Match based on auditor expertise
        - overlap: Each contract gets multiple auditors
        """
        assignments = {a.id: [] for a in self.session.auditors}
        contracts = self.session.target_contracts

        if strategy == "round_robin":
            for i, contract in enumerate(contracts):
                auditor_idx = i % len(self.session.auditors)
                auditor = self.session.auditors[auditor_idx]
                auditor.assigned_contracts.append(contract)
                assignments[auditor.id].append(contract)

        elif strategy == "overlap":
            # Each contract gets 2 auditors
            for i, contract in enumerate(contracts):
                for j in range(min(2, len(self.session.auditors))):
                    auditor_idx = (i + j) % len(self.session.auditors)
                    auditor = self.session.auditors[auditor_idx]
                    if contract not in auditor.assigned_contracts:
                        auditor.assigned_contracts.append(contract)
                        assignments[auditor.id].append(contract)

        elif strategy == "expertise":
            # Match based on expertise keywords in contract path
            for contract in contracts:
                best_match = None
                best_score = 0

                for auditor in self.session.auditors:
                    score = sum(
                        1 for exp in auditor.expertise
                        if exp.lower() in contract.lower()
                    )
                    # Also consider workload
                    workload_penalty = len(auditor.assigned_contracts) * 0.5
                    score -= workload_penalty

                    if score > best_score:
                        best_score = score
                        best_match = auditor

                if best_match:
                    best_match.assigned_contracts.append(contract)
                    assignments[best_match.id].append(contract)
                else:
                    # Fallback to least loaded
                    least_loaded = min(
                        self.session.auditors,
                        key=lambda a: len(a.assigned_contracts)
                    )
                    least_loaded.assigned_contracts.append(contract)
                    assignments[least_loaded.id].append(contract)

        self._log_action("assign_coverage", {"strategy": strategy, "assignments": assignments})
        return assignments

    # =========================================================================
    # FINDINGS MANAGEMENT
    # =========================================================================

    def submit_finding(
        self,
        auditor_id: str,
        title: str,
        severity: str,
        description: str,
        affected_code: str,
        contract: str,
        function: Optional[str] = None,
        tags: Optional[list[str]] = None,
    ) -> AuditFinding:
        """Submit a new finding."""
        finding = AuditFinding(
            id=self._generate_id(title),
            auditor_id=auditor_id,
            title=title,
            severity=severity,
            description=description,
            affected_code=affected_code,
            contract=contract,
            function=function,
            status=FindingStatus.SUBMITTED,
            tags=tags or [],
        )
        self.session.findings.append(finding)

        # Update auditor stats
        for auditor in self.session.auditors:
            if auditor.id == auditor_id:
                auditor.findings_submitted += 1
                break

        self._log_action("submit_finding", {
            "finding_id": finding.id,
            "auditor": auditor_id,
            "title": title,
            "severity": severity,
        })

        return finding

    def add_comment(
        self,
        finding_id: str,
        auditor_id: str,
        comment: str,
    ) -> None:
        """Add a comment to a finding."""
        for finding in self.session.findings:
            if finding.id == finding_id:
                finding.comments.append({
                    "auditor_id": auditor_id,
                    "comment": comment,
                    "timestamp": datetime.now().isoformat(),
                })
                finding.updated_at = datetime.now()
                break

        self._log_action("add_comment", {
            "finding_id": finding_id,
            "auditor": auditor_id,
        })

    def vote_on_finding(
        self,
        finding_id: str,
        auditor_id: str,
        vote_type: VoteType,
        value: str,
        reason: Optional[str] = None,
    ) -> None:
        """Cast a vote on a finding."""
        for finding in self.session.findings:
            if finding.id == finding_id:
                finding.votes.append({
                    "auditor_id": auditor_id,
                    "vote_type": vote_type.value,
                    "value": value,
                    "reason": reason,
                    "timestamp": datetime.now().isoformat(),
                })
                finding.updated_at = datetime.now()
                break

        self._log_action("vote", {
            "finding_id": finding_id,
            "auditor": auditor_id,
            "vote_type": vote_type.value,
            "value": value,
        })

    # =========================================================================
    # DEDUPLICATION
    # =========================================================================

    def find_duplicates(
        self,
        similarity_threshold: float = 0.7,
    ) -> list[tuple[str, str, float]]:
        """
        Find potential duplicate findings.

        Returns list of (finding1_id, finding2_id, similarity_score) tuples.
        """
        duplicates = []

        for i, f1 in enumerate(self.session.findings):
            for f2 in self.session.findings[i+1:]:
                similarity = self._calculate_similarity(f1, f2)
                if similarity >= similarity_threshold:
                    duplicates.append((f1.id, f2.id, similarity))

        return sorted(duplicates, key=lambda x: x[2], reverse=True)

    def _calculate_similarity(self, f1: AuditFinding, f2: AuditFinding) -> float:
        """Calculate similarity between two findings."""
        score = 0.0
        weights = 0.0

        # Same contract - high weight
        if f1.contract == f2.contract:
            score += 0.3
        weights += 0.3

        # Same function - medium weight
        if f1.function and f2.function and f1.function == f2.function:
            score += 0.2
        weights += 0.2

        # Similar severity
        if f1.severity == f2.severity:
            score += 0.1
        weights += 0.1

        # Title similarity (Jaccard)
        title_sim = self._jaccard_similarity(
            set(f1.title.lower().split()),
            set(f2.title.lower().split())
        )
        score += title_sim * 0.2
        weights += 0.2

        # Description similarity
        desc_sim = self._jaccard_similarity(
            set(f1.description.lower().split()[:50]),
            set(f2.description.lower().split()[:50])
        )
        score += desc_sim * 0.2
        weights += 0.2

        return score / weights if weights > 0 else 0

    def _jaccard_similarity(self, set1: set, set2: set) -> float:
        """Calculate Jaccard similarity between two sets."""
        if not set1 or not set2:
            return 0.0
        intersection = len(set1 & set2)
        union = len(set1 | set2)
        return intersection / union if union > 0 else 0

    def merge_findings(
        self,
        primary_id: str,
        duplicate_ids: list[str],
    ) -> AuditFinding:
        """
        Merge duplicate findings into primary.

        Primary finding is kept, duplicates are marked as such.
        """
        primary = None
        for finding in self.session.findings:
            if finding.id == primary_id:
                primary = finding
                break

        if not primary:
            raise ValueError(f"Finding {primary_id} not found")

        for dup_id in duplicate_ids:
            for finding in self.session.findings:
                if finding.id == dup_id:
                    finding.status = FindingStatus.DUPLICATE
                    finding.duplicate_of = primary_id
                    primary.merged_from.append(dup_id)

                    # Add note about merge
                    primary.comments.append({
                        "auditor_id": "system",
                        "comment": f"Merged with duplicate finding from {finding.auditor_id}",
                        "timestamp": datetime.now().isoformat(),
                    })
                    break

        primary.updated_at = datetime.now()

        self._log_action("merge_findings", {
            "primary": primary_id,
            "duplicates": duplicate_ids,
        })

        return primary

    # =========================================================================
    # CONSENSUS
    # =========================================================================

    def calculate_severity_consensus(
        self,
        finding_id: str,
    ) -> dict:
        """
        Calculate consensus severity from votes.

        Returns dict with consensus severity and breakdown.
        """
        finding = None
        for f in self.session.findings:
            if f.id == finding_id:
                finding = f
                break

        if not finding:
            raise ValueError(f"Finding {finding_id} not found")

        # Get severity votes
        severity_votes = [
            v["value"] for v in finding.votes
            if v["vote_type"] == VoteType.SEVERITY.value
        ]

        if not severity_votes:
            return {
                "consensus_severity": finding.severity,
                "vote_count": 0,
                "breakdown": {},
                "agreement": 0.0,
            }

        # Count votes
        vote_counts = Counter(severity_votes)
        total_votes = len(severity_votes)

        # Consensus is most common vote
        consensus = vote_counts.most_common(1)[0][0]
        agreement = vote_counts[consensus] / total_votes

        return {
            "consensus_severity": consensus,
            "vote_count": total_votes,
            "breakdown": dict(vote_counts),
            "agreement": agreement,
        }

    def finalize_finding(
        self,
        finding_id: str,
        final_severity: Optional[str] = None,
    ) -> AuditFinding:
        """Finalize a finding after consensus."""
        for finding in self.session.findings:
            if finding.id == finding_id:
                if final_severity:
                    finding.severity = final_severity

                finding.status = FindingStatus.FINAL
                finding.updated_at = datetime.now()

                self._log_action("finalize_finding", {
                    "finding_id": finding_id,
                    "final_severity": final_severity or finding.severity,
                })

                return finding

        raise ValueError(f"Finding {finding_id} not found")

    # =========================================================================
    # REPORTING
    # =========================================================================

    def get_status_summary(self) -> dict:
        """Get summary of audit status."""
        status_counts = Counter(f.status.value for f in self.session.findings)
        severity_counts = Counter(
            f.severity for f in self.session.findings
            if f.status != FindingStatus.DUPLICATE
        )

        auditor_stats = {}
        for auditor in self.session.auditors:
            findings = [
                f for f in self.session.findings
                if f.auditor_id == auditor.id
            ]
            auditor_stats[auditor.name] = {
                "findings_submitted": len(findings),
                "unique_findings": len([
                    f for f in findings if f.status != FindingStatus.DUPLICATE
                ]),
                "contracts_assigned": len(auditor.assigned_contracts),
            }

        return {
            "session_name": self.session.name,
            "phase": self.session.phase.value,
            "total_findings": len(self.session.findings),
            "unique_findings": len([
                f for f in self.session.findings
                if f.status != FindingStatus.DUPLICATE
            ]),
            "by_status": dict(status_counts),
            "by_severity": dict(severity_counts),
            "by_auditor": auditor_stats,
            "contracts_covered": len(self.session.target_contracts),
            "auditors": len(self.session.auditors),
        }

    def export_findings(self, format: str = "json") -> str:
        """Export findings to specified format."""
        findings_data = []

        for finding in self.session.findings:
            if finding.status == FindingStatus.DUPLICATE:
                continue

            findings_data.append({
                "id": finding.id,
                "title": finding.title,
                "severity": finding.severity,
                "description": finding.description,
                "contract": finding.contract,
                "function": finding.function,
                "affected_code": finding.affected_code,
                "status": finding.status.value,
                "auditor": next(
                    (a.name for a in self.session.auditors if a.id == finding.auditor_id),
                    "Unknown"
                ),
                "comments": finding.comments,
                "tags": finding.tags,
            })

        if format == "json":
            return json.dumps(findings_data, indent=2)
        elif format == "markdown":
            return self._export_markdown(findings_data)
        else:
            return json.dumps(findings_data)

    def _export_markdown(self, findings: list[dict]) -> str:
        """Export findings as markdown."""
        lines = [
            f"# {self.session.name} - Audit Findings\n",
            f"**Total Findings:** {len(findings)}\n",
            "",
        ]

        # Group by severity
        by_severity = {}
        for f in findings:
            sev = f["severity"]
            if sev not in by_severity:
                by_severity[sev] = []
            by_severity[sev].append(f)

        # Order: Critical, High, Medium, Low
        severity_order = ["Critical", "High", "Medium", "Low", "Informational"]

        for severity in severity_order:
            if severity in by_severity:
                lines.append(f"## {severity} Severity\n")

                for finding in by_severity[severity]:
                    lines.append(f"### [{finding['id'][:8]}] {finding['title']}\n")
                    lines.append(f"**Contract:** {finding['contract']}")
                    if finding["function"]:
                        lines.append(f" | **Function:** {finding['function']}")
                    lines.append("\n")
                    lines.append(f"\n{finding['description']}\n")
                    if finding["affected_code"]:
                        lines.append(f"\n```solidity\n{finding['affected_code']}\n```\n")
                    lines.append("")

        return "\n".join(lines)

    def get_audit_trail(self) -> list[dict]:
        """Get complete audit trail."""
        return self.audit_log.copy()


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

def create_audit_session(
    name: str,
    contracts: list[str],
    auditors: list[str],
) -> CollaborativeAudit:
    """Create a new collaborative audit session."""
    audit = CollaborativeAudit(name)

    for contract in contracts:
        audit.add_target_contract(contract)

    for auditor_name in auditors:
        audit.add_auditor(auditor_name)

    audit.assign_coverage("overlap")

    return audit


def merge_findings_from_auditors(
    findings: dict[str, list[dict]],
) -> list[dict]:
    """
    Merge findings from multiple auditors with deduplication.

    Args:
        findings: Dict mapping auditor name to list of their findings

    Returns:
        Deduplicated list of findings
    """
    audit = CollaborativeAudit("Merge Session")

    # Add auditors and their findings
    for auditor_name, auditor_findings in findings.items():
        auditor = audit.add_auditor(auditor_name)

        for f in auditor_findings:
            audit.submit_finding(
                auditor_id=auditor.id,
                title=f.get("title", ""),
                severity=f.get("severity", "Medium"),
                description=f.get("description", ""),
                affected_code=f.get("affected_code", ""),
                contract=f.get("contract", ""),
                function=f.get("function"),
            )

    # Find and merge duplicates
    duplicates = audit.find_duplicates(similarity_threshold=0.7)

    merged_groups = {}
    for f1_id, f2_id, _ in duplicates:
        # Group duplicates
        if f1_id not in merged_groups and f2_id not in merged_groups:
            merged_groups[f1_id] = [f2_id]
        elif f1_id in merged_groups:
            merged_groups[f1_id].append(f2_id)
        elif f2_id in merged_groups:
            merged_groups[f2_id].append(f1_id)

    for primary, dups in merged_groups.items():
        audit.merge_findings(primary, dups)

    # Export merged findings
    return json.loads(audit.export_findings("json"))
