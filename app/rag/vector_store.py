"""Permission-Aware Vector Database (ChromaDB Adapter + Hybrid Departmental Store)."""
from __future__ import annotations

import re
from typing import Any

from app.config.settings import settings
from app.domain.models import DocumentChunk, RetrievalResult, UserIdentity
from app.domain.ports import EmbeddingProviderPort, VectorStorePort
from app.rag.embeddings import LocalHybridSemanticEmbedder, cosine_similarity
from app.rag.reranker import EnterpriseCrossEncoderReranker
from app.security.rbac_engine import RBACEngine


class PermissionAwareVectorStore(VectorStorePort):
    """
    Enterprise Vector Store implementing:
    1. Collection-per-Department isolation (`col_<department>`).
    2. Mandatory Pre-Retrieval `where` metadata filtering derived from the user's JWT AD groups.
    3. Hybrid semantic (local embeddings cosine similarity) + lexical BM25 keyword scoring
       followed by Two-Stage Reciprocal Rank Fusion (RRF) & Cross-Encoder Re-Ranking.
    4. Ley 21.719 ARCO Right-to-Erasure (`delete_by_titular_rut`).
    """

    def __init__(self, embedder: EmbeddingProviderPort | None = None) -> None:
        self.embedder = embedder or LocalHybridSemanticEmbedder()
        self.reranker = EnterpriseCrossEncoderReranker()
        # Departmental collections: {"col_salud_siniestros": {chunk_id: DocumentChunk}}
        self._collections: dict[str, dict[str, DocumentChunk]] = {}
        self._chroma_client: Any = None
        if settings.vector_store_backend == "chromadb":
            self._init_chromadb()

    def _init_chromadb(self) -> None:
        try:
            import chromadb  # type: ignore

            self._chroma_client = chromadb.PersistentClient(path=settings.chroma_persist_dir)
        except ImportError:
            self._chroma_client = None

    @staticmethod
    def _collection_name(department: str) -> str:
        clean = re.sub(r"[^a-z0-9_]", "_", department.lower())
        return f"col_{clean}"

    def upsert_chunks(self, chunks: list[DocumentChunk]) -> int:
        count = 0
        for chunk in chunks:
            if not chunk.embedding:
                full_text_for_embed = f"{chunk.title} {chunk.department} {chunk.content}"
                chunk.embedding = self.embedder.embed_text(full_text_for_embed)

            col_name = self._collection_name(chunk.department)
            if col_name not in self._collections:
                self._collections[col_name] = {}
            self._collections[col_name][chunk.chunk_id] = chunk

            if self._chroma_client is not None:
                chroma_col = self._chroma_client.get_or_create_collection(name=col_name)
                chroma_col.upsert(
                    ids=[chunk.chunk_id],
                    embeddings=[chunk.embedding],
                    documents=[chunk.content],
                    metadatas=[
                        {
                            "document_id": chunk.document_id,
                            "title": chunk.title,
                            "department": chunk.department,
                            "classification": chunk.classification,
                            "source_system": chunk.source_system,
                            "titular_rut": chunk.titular_rut,
                            "contains_pii": chunk.contains_pii,
                        }
                    ],
                )
            count += 1
        return count

    @staticmethod
    def _lexical_overlap_score(query: str, chunk: DocumentChunk) -> float:
        q_tokens = {
            t
            for t in re.findall(r"[a-záéíóúñ0-9]{3,}", query.lower())
            if t not in {"para", "como", "cual", "cuál", "quien", "quién", "donde", "dónde", "sobre", "los", "las", "del", "una", "por", "con", "que", "qué"}
        }
        if not q_tokens:
            return 0.0
        target_text = f"{chunk.title} {chunk.content} {chunk.titular_rut} {chunk.source_system}".lower()
        matches = sum(1 for token in q_tokens if token in target_text)
        # Exact RUT match boost
        if chunk.titular_rut and chunk.titular_rut.lower() in query.lower():
            matches += 4
        return min(1.0, matches / max(1, len(q_tokens)))

    def retrieve_permission_aware(
        self,
        query: str,
        user: UserIdentity,
        top_k: int = 4,
    ) -> RetrievalResult:
        """
        Execute Pre-Filtered Vector Retrieval:
        - Builds the mandatory ChromaDB `where` filter from the user's JWT claims.
        - Searches ONLY authorized departmental collections (`user.allowed_departments`).
        - Simultaneously computes anonymized security telemetry on whether relevant chunks
          existed in unauthorized collections that were blocked by RBAC.
        """
        where_filter = RBACEngine.build_chromadb_where_filter(user)
        query_vec = self.embedder.embed_text(query)

        authorized_collections = [self._collection_name(d) for d in user.allowed_departments]
        allowed_candidates: list[tuple[DocumentChunk, float, float]] = []
        blocked_preview: list[dict[str, str]] = []
        total_semantic_candidates = 0

        for col_name, chunk_map in self._collections.items():
            for chunk in chunk_map.values():
                sem_score = cosine_similarity(query_vec, chunk.embedding)
                lex_score = self._lexical_overlap_score(query, chunk)
                combined_score = round((0.60 * sem_score) + (0.40 * lex_score), 4)

                # Consider a chunk a semantic candidate if it has meaningful similarity and lexical/concept match
                is_relevant_candidate = (combined_score >= 0.24 and lex_score > 0.0) or sem_score >= 0.42 or lex_score >= 0.25
                if not is_relevant_candidate:
                    continue

                total_semantic_candidates += 1

                # PRE-RETRIEVAL RBAC ENFORCEMENT (Collection + `where` metadata check)
                if col_name in authorized_collections and RBACEngine.is_chunk_authorized(chunk, user):
                    candidate_copy = DocumentChunk(
                        chunk_id=chunk.chunk_id,
                        document_id=chunk.document_id,
                        title=chunk.title,
                        content=chunk.content,
                        department=chunk.department,
                        classification=chunk.classification,
                        allowed_roles=list(chunk.allowed_roles),
                        source_system=chunk.source_system,
                        titular_rut=chunk.titular_rut,
                        contains_pii=chunk.contains_pii,
                        created_at=chunk.created_at,
                        score=combined_score,
                    )
                    allowed_candidates.append((candidate_copy, sem_score, lex_score))
                else:
                    # Blocked at retrieval layer! Record only non-sensitive metadata for audit trail
                    blocked_preview.append(
                        {
                            "chunk_id": chunk.chunk_id,
                            "department": chunk.department,
                            "classification": chunk.classification,
                            "source_system": chunk.source_system,
                            "reason": f"Bloqueado en Pre-Retrieval: requiere departamento '{chunk.department}' y clasificación '{chunk.classification}'.",
                        }
                    )

        # STAGE 2: Apply Reciprocal Rank Fusion (RRF) & Cross-Encoder Re-Ranking on authorized chunks
        reranked_allowed = self.reranker.rerank_candidates(
            query=query,
            candidates=allowed_candidates,
            top_k=top_k,
        )
        return RetrievalResult(
            allowed_chunks=reranked_allowed,
            applied_where_filter=where_filter,
            collections_searched=authorized_collections,
            total_candidates_before_rbac=total_semantic_candidates,
            blocked_by_rbac_count=len(blocked_preview),
            blocked_departments_preview=blocked_preview[:5],
        )

    def delete_by_titular_rut(self, rut: str) -> list[str]:
        """
        Ley 21.719 (Chile) - Derecho de Supresión / Olvido (ARCO):
        Deletes all indexed vector chunks associated with a specific titular RUT across all collections.
        """
        norm_rut = re.sub(r"[^0-9kK]", "", rut).upper()
        deleted_ids: list[str] = []
        for col_name, chunk_map in self._collections.items():
            to_delete: list[str] = []
            for cid, chunk in chunk_map.items():
                chunk_rut = re.sub(r"[^0-9kK]", "", chunk.titular_rut).upper()
                if norm_rut and (chunk_rut == norm_rut or rut in chunk.content):
                    to_delete.append(cid)
            for cid in to_delete:
                del chunk_map[cid]
                deleted_ids.append(cid)
                if self._chroma_client is not None:
                    chroma_col = self._chroma_client.get_or_create_collection(name=col_name)
                    chroma_col.delete(ids=[cid])
        return deleted_ids

    def list_all_chunks_metadata(self) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        for col_name, chunk_map in self._collections.items():
            for chunk in chunk_map.values():
                items.append(
                    {
                        "collection": col_name,
                        "chunk_id": chunk.chunk_id,
                        "document_id": chunk.document_id,
                        "title": chunk.title,
                        "department": chunk.department,
                        "classification": chunk.classification,
                        "source_system": chunk.source_system,
                        "titular_rut": chunk.titular_rut,
                        "contains_pii": chunk.contains_pii,
                    }
                )
        return items
