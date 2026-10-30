"""Post-Generation Groundedness (Anti-Hallucination) Verifier & Output DLP Guardrail."""
from __future__ import annotations

import re
from typing import Any

from app.domain.models import DocumentChunk, ToolInvocation, UserIdentity
from app.domain.ports import PrivacyGuardPort


class GroundednessAndOutputGuard:
    """
    Verifies that generated answers in regulated domains (Insurance, Health, Finance)
    are strictly grounded in authorized retrieved chunks or tool outputs, and applies
    a final Output DLP Guardrail before returning text to the client.
    """

    def __init__(self, privacy_guard: PrivacyGuardPort) -> None:
        self.privacy_guard = privacy_guard

    def verify_and_guard_output(
        self,
        answer_text: str,
        allowed_chunks: list[DocumentChunk],
        tool_invocations: list[ToolInvocation],
        user: UserIdentity,
    ) -> dict[str, Any]:
        # Build combined reference corpus from authorized chunks and executed tools
        evidence_corpus = "\n".join(c.content for c in allowed_chunks)
        for t in tool_invocations:
            evidence_corpus += f"\n{t.result_summary} {t.raw_output}"
        evidence_lower = evidence_corpus.lower()

        # 1. Extract numerical/identifier claims (UF, %, CLP amounts, Policy/Claim IDs, CIE-10 codes)
        claim_patterns = re.findall(
            r"\b(?:SIN-\d{4}-\d{4,6}|POL-\d{4}-\d{4,6}|FAC-\d{4,6}|\d+(?:[.,]\d+)?\s*(?:UF|%)|CIE-10\s*[A-Z]\d{2}(?:\.\d)?)\b",
            answer_text,
            flags=re.IGNORECASE,
        )

        verified_claims: list[str] = []
        unverified_claims: list[str] = []
        for claim in claim_patterns:
            norm_claim = re.sub(r"\s+", " ", claim.strip().lower())
            if norm_claim in evidence_lower or norm_claim.replace(",", ".") in evidence_lower:
                verified_claims.append(claim)
            else:
                unverified_claims.append(claim)

        if not allowed_chunks and not tool_invocations:
            groundedness_score = 1.0  # Standard refusal/empty-context message is 100% policy-aligned
        elif not claim_patterns:
            groundedness_score = 0.95
        else:
            groundedness_score = round(len(verified_claims) / len(claim_patterns), 2)

        # 2. Final Output DLP Scrubbing for users without `can_view_raw_pii`
        dlp_scrubbed_on_output = False
        safe_answer = answer_text
        if not user.can_view_raw_pii:
            post_pii = self.privacy_guard.anonymize(answer_text)
            if len(post_pii.entities) > 0:
                safe_answer = post_pii.anonymized_text
                dlp_scrubbed_on_output = True

        # 3. Build structured regulatory citations
        citations = [
            {
                "chunk_id": c.chunk_id,
                "document_id": c.document_id,
                "title": c.title,
                "department": c.department,
                "classification": c.classification,
                "source_system": c.source_system,
                "relevance_score": c.score,
            }
            for c in allowed_chunks
        ]

        return {
            "guarded_answer": safe_answer,
            "groundedness_score": groundedness_score,
            "is_fully_grounded": len(unverified_claims) == 0,
            "verified_factual_claims": verified_claims,
            "unverified_claims_flagged": unverified_claims,
            "output_dlp_scrubbed": dlp_scrubbed_on_output,
            "citations": citations,
        }
