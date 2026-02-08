"""
Multi-LLM Consensus - When One AI Isn't Enough

Why use multiple LLMs?
1. Different models have different blind spots
2. Consensus = higher confidence
3. Disagreement = needs human review
4. Catch hallucinations by cross-validation

Strategy:
- Claude: Deep reasoning, novel vulnerabilities
- GPT-4: Broad knowledge, common patterns
- Gemini: Different perspective, cross-check
- Local models: Fast pre-filtering

If 3/3 agree: HIGH CONFIDENCE
If 2/3 agree: MEDIUM CONFIDENCE
If 1/3 agree: LOW CONFIDENCE (needs review)
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Any
import asyncio


class LLMProvider(Enum):
    CLAUDE = "claude"
    GPT4 = "gpt4"
    GEMINI = "gemini"
    LLAMA = "llama"
    MISTRAL = "mistral"


class ConsensusLevel(Enum):
    UNANIMOUS = "unanimous"      # All agree
    MAJORITY = "majority"        # Most agree
    SPLIT = "split"             # Disagreement
    SINGLE = "single"           # Only one model


@dataclass
class LLMFinding:
    """Finding from a single LLM."""
    provider: LLMProvider
    severity: str
    title: str
    description: str
    root_cause: str
    poc_code: str
    confidence: float
    reasoning: str


@dataclass
class ConsensusResult:
    """Result of multi-LLM consensus."""
    consensus_level: ConsensusLevel
    final_severity: str
    final_title: str
    final_description: str
    agreement_score: float  # 0-1
    individual_findings: list[LLMFinding]
    disagreements: list[str]
    combined_poc: str
    recommendation: str


@dataclass
class ModelConfig:
    """Configuration for an LLM."""
    provider: LLMProvider
    model_id: str
    api_key_env: str
    max_tokens: int = 4096
    temperature: float = 0.1
    weight: float = 1.0  # Weight in consensus


class MultiLLMConsensus:
    """
    Run multiple LLMs and build consensus.

    This catches:
    - Hallucinations (other models disagree)
    - Blind spots (one model sees what others miss)
    - False positives (no consensus = likely false)
    """

    DEFAULT_MODELS = [
        ModelConfig(
            provider=LLMProvider.CLAUDE,
            model_id="claude-opus-4-5-20251101",
            api_key_env="ANTHROPIC_API_KEY",
            weight=1.5,  # Higher weight for Claude
        ),
        ModelConfig(
            provider=LLMProvider.GPT4,
            model_id="gpt-4-turbo",
            api_key_env="OPENAI_API_KEY",
            weight=1.0,
        ),
        ModelConfig(
            provider=LLMProvider.GEMINI,
            model_id="gemini-pro",
            api_key_env="GOOGLE_API_KEY",
            weight=0.8,
        ),
    ]

    def __init__(self, models: Optional[list[ModelConfig]] = None):
        self.models = models or self.DEFAULT_MODELS
        self.results: dict[LLMProvider, list[LLMFinding]] = {}

    async def analyze_with_all(
        self,
        code: str,
        prompt_template: str,
    ) -> dict[LLMProvider, list[LLMFinding]]:
        """
        Run analysis with all configured LLMs in parallel.

        Returns findings from each model.
        """
        tasks = []
        for model in self.models:
            task = self._analyze_with_model(code, prompt_template, model)
            tasks.append(task)

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for model, result in zip(self.models, results):
            if isinstance(result, Exception):
                self.results[model.provider] = []
            else:
                self.results[model.provider] = result

        return self.results

    async def _analyze_with_model(
        self,
        code: str,
        prompt_template: str,
        model: ModelConfig,
    ) -> list[LLMFinding]:
        """Run analysis with a single model."""
        # Build provider-specific prompt
        prompt = self._adapt_prompt_for_model(prompt_template, model.provider)

        # Call API (implementation depends on provider)
        if model.provider == LLMProvider.CLAUDE:
            response = await self._call_claude(prompt, code, model)
        elif model.provider == LLMProvider.GPT4:
            response = await self._call_gpt4(prompt, code, model)
        elif model.provider == LLMProvider.GEMINI:
            response = await self._call_gemini(prompt, code, model)
        else:
            response = ""

        # Parse response into findings
        return self._parse_findings(response, model.provider)

    def _adapt_prompt_for_model(self, template: str, provider: LLMProvider) -> str:
        """Adapt prompt for specific model's strengths."""
        adaptations = {
            LLMProvider.CLAUDE: """
Focus on:
- Deep reasoning chains
- Novel attack patterns
- Business logic vulnerabilities
- Unusual edge cases
""",
            LLMProvider.GPT4: """
Focus on:
- Common vulnerability patterns
- Standard security checks
- Well-known exploit types
- Code quality issues
""",
            LLMProvider.GEMINI: """
Focus on:
- Mathematical invariants
- Logical inconsistencies
- Cross-reference with documentation
- Alternative interpretations
""",
        }

        return template + "\n\n" + adaptations.get(provider, "")

    async def _call_claude(
        self,
        prompt: str,
        code: str,
        model: ModelConfig,
    ) -> str:
        """Call Claude API."""
        # In production, use actual API
        # import anthropic
        # client = anthropic.Anthropic()
        # response = client.messages.create(...)
        return ""

    async def _call_gpt4(
        self,
        prompt: str,
        code: str,
        model: ModelConfig,
    ) -> str:
        """Call GPT-4 API."""
        # In production, use actual API
        # import openai
        # client = openai.OpenAI()
        # response = client.chat.completions.create(...)
        return ""

    async def _call_gemini(
        self,
        prompt: str,
        code: str,
        model: ModelConfig,
    ) -> str:
        """Call Gemini API."""
        # In production, use actual API
        # import google.generativeai as genai
        # model = genai.GenerativeModel(...)
        # response = model.generate_content(...)
        return ""

    def _parse_findings(
        self,
        response: str,
        provider: LLMProvider,
    ) -> list[LLMFinding]:
        """Parse LLM response into structured findings."""
        # This would use regex or structured output parsing
        # to extract findings from the model's response
        findings = []

        # Example parsing (simplified)
        # In production, use structured output or better parsing

        return findings

    def build_consensus(self) -> list[ConsensusResult]:
        """
        Build consensus from all model results.

        Groups similar findings and determines agreement level.
        """
        consensus_results = []

        # Group findings by similarity
        all_findings = []
        for provider, findings in self.results.items():
            for finding in findings:
                all_findings.append((provider, finding))

        # Cluster similar findings
        clusters = self._cluster_findings(all_findings)

        for cluster in clusters:
            consensus = self._build_cluster_consensus(cluster)
            consensus_results.append(consensus)

        return consensus_results

    def _cluster_findings(
        self,
        findings: list[tuple[LLMProvider, LLMFinding]],
    ) -> list[list[tuple[LLMProvider, LLMFinding]]]:
        """
        Cluster similar findings together.

        Uses semantic similarity to group findings about the same issue.
        """
        # Simplified clustering - in production use embeddings
        clusters = []

        for provider, finding in findings:
            # Find existing cluster or create new one
            matched = False
            for cluster in clusters:
                if self._findings_similar(finding, cluster[0][1]):
                    cluster.append((provider, finding))
                    matched = True
                    break

            if not matched:
                clusters.append([(provider, finding)])

        return clusters

    def _findings_similar(self, f1: LLMFinding, f2: LLMFinding) -> bool:
        """Check if two findings are about the same issue."""
        # Simple heuristic - in production use embeddings
        title_overlap = len(set(f1.title.lower().split()) & set(f2.title.lower().split()))
        severity_match = f1.severity == f2.severity

        return title_overlap >= 2 and severity_match

    def _build_cluster_consensus(
        self,
        cluster: list[tuple[LLMProvider, LLMFinding]],
    ) -> ConsensusResult:
        """Build consensus for a cluster of similar findings."""
        providers = [p for p, f in cluster]
        findings = [f for p, f in cluster]

        # Determine consensus level
        num_models = len(self.models)
        num_agreeing = len(cluster)

        if num_agreeing == num_models:
            level = ConsensusLevel.UNANIMOUS
            agreement_score = 1.0
        elif num_agreeing >= num_models / 2:
            level = ConsensusLevel.MAJORITY
            agreement_score = num_agreeing / num_models
        elif num_agreeing > 1:
            level = ConsensusLevel.SPLIT
            agreement_score = num_agreeing / num_models
        else:
            level = ConsensusLevel.SINGLE
            agreement_score = 1 / num_models

        # Combine findings (prefer Claude's description if available)
        primary_finding = next(
            (f for p, f in cluster if p == LLMProvider.CLAUDE),
            findings[0]
        )

        # Combine PoCs from all models
        combined_poc = "\n\n// --- Combined from multiple models ---\n\n".join(
            f"// From {p.value}:\n{f.poc_code}"
            for p, f in cluster
            if f.poc_code
        )

        # Note disagreements
        disagreements = []
        severities = set(f.severity for f in findings)
        if len(severities) > 1:
            disagreements.append(f"Severity disagreement: {severities}")

        return ConsensusResult(
            consensus_level=level,
            final_severity=primary_finding.severity,
            final_title=primary_finding.title,
            final_description=primary_finding.description,
            agreement_score=agreement_score,
            individual_findings=findings,
            disagreements=disagreements,
            combined_poc=combined_poc,
            recommendation=self._get_recommendation(level),
        )

    def _get_recommendation(self, level: ConsensusLevel) -> str:
        """Get recommendation based on consensus level."""
        recommendations = {
            ConsensusLevel.UNANIMOUS: "HIGH CONFIDENCE - All models agree. Proceed with exploit development.",
            ConsensusLevel.MAJORITY: "MEDIUM CONFIDENCE - Most models agree. Verify with manual review.",
            ConsensusLevel.SPLIT: "LOW CONFIDENCE - Models disagree. Requires human expert review.",
            ConsensusLevel.SINGLE: "UNVERIFIED - Only one model found this. May be hallucination.",
        }
        return recommendations.get(level, "Unknown")


def get_consensus_finding(
    code: str,
    prompt: str,
    models: Optional[list[ModelConfig]] = None,
) -> list[ConsensusResult]:
    """
    Get consensus findings from multiple LLMs.

    This is the recommended way to validate important findings.
    """
    consensus = MultiLLMConsensus(models)

    # Run async analysis
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(consensus.analyze_with_all(code, prompt))
    finally:
        loop.close()

    return consensus.build_consensus()


class HallucinationDetector:
    """
    Detect LLM hallucinations in security findings.

    Common hallucination patterns:
    - Referencing non-existent functions
    - Wrong line numbers
    - Impossible exploit scenarios
    - Invented vulnerability types
    """

    def __init__(self, code: str):
        self.code = code
        self.functions = self._extract_functions()
        self.variables = self._extract_variables()
        self.line_count = len(code.split('\n'))

    def _extract_functions(self) -> set[str]:
        """Extract all function names from code."""
        import re
        pattern = r'function\s+(\w+)\s*\('
        return set(re.findall(pattern, self.code))

    def _extract_variables(self) -> set[str]:
        """Extract all variable names from code."""
        import re
        patterns = [
            r'(?:uint256|address|bool|bytes32|mapping)\s+(?:public|private|internal)?\s*(\w+)',
            r'(\w+)\s*=',
        ]
        variables = set()
        for pattern in patterns:
            variables.update(re.findall(pattern, self.code))
        return variables

    def check_finding(self, finding: LLMFinding) -> list[str]:
        """
        Check finding for hallucination indicators.

        Returns list of issues found.
        """
        issues = []

        # Check for non-existent function references
        words = finding.description.split() + finding.root_cause.split()
        for word in words:
            if word.endswith('()') and word[:-2] not in self.functions:
                if word[:-2].isalpha() and len(word) > 3:
                    issues.append(f"References non-existent function: {word}")

        # Check for impossible line numbers
        import re
        line_refs = re.findall(r'line\s*(\d+)', finding.description, re.IGNORECASE)
        for line_num in line_refs:
            if int(line_num) > self.line_count:
                issues.append(f"Invalid line number: {line_num} (code has {self.line_count} lines)")

        # Check PoC for syntax issues
        if finding.poc_code:
            if 'function' in finding.poc_code.lower():
                # Basic Solidity syntax check
                if finding.poc_code.count('{') != finding.poc_code.count('}'):
                    issues.append("PoC has unbalanced braces")

        return issues

    def filter_hallucinations(
        self,
        findings: list[LLMFinding],
    ) -> tuple[list[LLMFinding], list[LLMFinding]]:
        """
        Separate valid findings from likely hallucinations.

        Returns (valid_findings, hallucinations)
        """
        valid = []
        hallucinations = []

        for finding in findings:
            issues = self.check_finding(finding)
            if issues:
                hallucinations.append(finding)
            else:
                valid.append(finding)

        return valid, hallucinations
