"""
Semantic Code Matching - Vector embeddings for similarity search.

Uses embeddings to find:
- Similar vulnerable code patterns
- Related historical exploits
- Semantically similar functions

Supports:
- OpenAI embeddings (ada-002, text-embedding-3)
- Local embeddings (sentence-transformers)
- ChromaDB for vector storage
"""

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Callable
import re

from rich.console import Console

console = Console()


@dataclass
class CodeChunk:
    """A chunk of code for embedding."""
    id: str
    content: str
    source_file: str
    start_line: int
    end_line: int
    chunk_type: str  # function, contract, snippet
    metadata: dict = field(default_factory=dict)


@dataclass
class SimilarityMatch:
    """A similarity match result."""
    chunk: CodeChunk
    similarity: float
    matched_to: str  # What was it matched to (exploit, pattern, etc.)
    explanation: str


class EmbeddingProvider:
    """Base class for embedding providers."""

    def embed(self, text: str) -> list[float]:
        raise NotImplementedError

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        return [self.embed(t) for t in texts]


class OpenAIEmbeddings(EmbeddingProvider):
    """OpenAI embeddings via API."""

    def __init__(self, model: str = "text-embedding-3-small", api_key: Optional[str] = None):
        self.model = model
        self.api_key = api_key
        self._client = None

    @property
    def client(self):
        if self._client is None:
            import os
            try:
                from openai import OpenAI
                self._client = OpenAI(api_key=self.api_key or os.getenv("OPENAI_API_KEY"))
            except ImportError:
                raise ImportError("OpenAI not installed. Run: pip install openai")
        return self._client

    def embed(self, text: str) -> list[float]:
        response = self.client.embeddings.create(
            input=text,
            model=self.model,
        )
        return response.data[0].embedding

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        response = self.client.embeddings.create(
            input=texts,
            model=self.model,
        )
        return [d.embedding for d in response.data]


class LocalEmbeddings(EmbeddingProvider):
    """Local embeddings using sentence-transformers."""

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self.model_name = model_name
        self._model = None

    @property
    def model(self):
        if self._model is None:
            try:
                from sentence_transformers import SentenceTransformer
                self._model = SentenceTransformer(self.model_name)
            except ImportError:
                raise ImportError("sentence-transformers not installed. Run: pip install sentence-transformers")
        return self._model

    def embed(self, text: str) -> list[float]:
        return self.model.encode(text).tolist()

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        return self.model.encode(texts).tolist()


class VectorStore:
    """Vector store for similarity search."""

    def __init__(self, persist_dir: Optional[Path] = None):
        self.persist_dir = persist_dir
        self._collection = None

    @property
    def collection(self):
        if self._collection is None:
            try:
                import chromadb
                if self.persist_dir:
                    client = chromadb.PersistentClient(path=str(self.persist_dir))
                else:
                    client = chromadb.Client()
                self._collection = client.get_or_create_collection(
                    name="code_embeddings",
                    metadata={"hnsw:space": "cosine"},
                )
            except ImportError:
                console.print("[yellow]ChromaDB not installed. Using in-memory fallback.[/yellow]")
                self._collection = InMemoryCollection()
        return self._collection

    def add(
        self,
        ids: list[str],
        embeddings: list[list[float]],
        documents: list[str],
        metadatas: list[dict],
    ) -> None:
        """Add embeddings to the store."""
        self.collection.add(
            ids=ids,
            embeddings=embeddings,
            documents=documents,
            metadatas=metadatas,
        )

    def query(
        self,
        query_embedding: list[float],
        n_results: int = 5,
        where: Optional[dict] = None,
    ) -> list[dict]:
        """Query for similar embeddings."""
        results = self.collection.query(
            query_embeddings=[query_embedding],
            n_results=n_results,
            where=where,
            include=["documents", "metadatas", "distances"],
        )

        matches = []
        for i in range(len(results["ids"][0])):
            matches.append({
                "id": results["ids"][0][i],
                "document": results["documents"][0][i],
                "metadata": results["metadatas"][0][i] if results["metadatas"] else {},
                "distance": results["distances"][0][i] if results["distances"] else 0,
                "similarity": 1 - results["distances"][0][i] if results["distances"] else 1,
            })

        return matches


class InMemoryCollection:
    """Fallback in-memory vector store."""

    def __init__(self):
        self.data = {}

    def add(self, ids, embeddings, documents, metadatas):
        for i, id_ in enumerate(ids):
            self.data[id_] = {
                "embedding": embeddings[i],
                "document": documents[i],
                "metadata": metadatas[i],
            }

    def query(self, query_embeddings, n_results=5, where=None, include=None):
        import math

        def cosine_similarity(a, b):
            dot = sum(x * y for x, y in zip(a, b))
            norm_a = math.sqrt(sum(x * x for x in a))
            norm_b = math.sqrt(sum(x * x for x in b))
            return dot / (norm_a * norm_b) if norm_a and norm_b else 0

        query_emb = query_embeddings[0]
        results = []

        for id_, item in self.data.items():
            sim = cosine_similarity(query_emb, item["embedding"])
            results.append((id_, item, 1 - sim))  # distance = 1 - similarity

        results.sort(key=lambda x: x[2])
        results = results[:n_results]

        return {
            "ids": [[r[0] for r in results]],
            "documents": [[r[1]["document"] for r in results]],
            "metadatas": [[r[1]["metadata"] for r in results]],
            "distances": [[r[2] for r in results]],
        }


class CodeEmbedder:
    """
    Embed and search code for similarity matching.

    Features:
    - Chunk code into meaningful units (functions, contracts)
    - Generate embeddings for each chunk
    - Search for similar code patterns
    - Match against historical exploits
    """

    def __init__(
        self,
        embedding_provider: Optional[EmbeddingProvider] = None,
        vector_store: Optional[VectorStore] = None,
    ):
        self.embedder = embedding_provider or LocalEmbeddings()
        self.store = vector_store or VectorStore()

    def chunk_solidity(self, source: str, file_path: str = "unknown") -> list[CodeChunk]:
        """Chunk Solidity code into meaningful units."""
        chunks = []

        # Extract contracts
        contract_pattern = r'(contract|interface|library)\s+(\w+)[^{]*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}'
        for match in re.finditer(contract_pattern, source, re.DOTALL):
            contract_type = match.group(1)
            contract_name = match.group(2)
            contract_body = match.group(3)
            start_line = source[:match.start()].count('\n') + 1
            end_line = source[:match.end()].count('\n') + 1

            chunks.append(CodeChunk(
                id=f"{file_path}:{contract_name}",
                content=match.group(0),
                source_file=file_path,
                start_line=start_line,
                end_line=end_line,
                chunk_type=contract_type,
                metadata={"name": contract_name, "type": contract_type},
            ))

            # Extract functions within contract
            func_pattern = r'function\s+(\w+)\s*\([^)]*\)[^{]*\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}'
            for func_match in re.finditer(func_pattern, contract_body):
                func_name = func_match.group(1)
                func_start = start_line + contract_body[:func_match.start()].count('\n')
                func_end = func_start + func_match.group(0).count('\n')

                chunks.append(CodeChunk(
                    id=f"{file_path}:{contract_name}.{func_name}",
                    content=func_match.group(0),
                    source_file=file_path,
                    start_line=func_start,
                    end_line=func_end,
                    chunk_type="function",
                    metadata={
                        "name": func_name,
                        "contract": contract_name,
                        "type": "function",
                    },
                ))

        return chunks

    def index_code(self, chunks: list[CodeChunk]) -> None:
        """Index code chunks for similarity search."""
        if not chunks:
            return

        ids = [c.id for c in chunks]
        documents = [c.content for c in chunks]
        metadatas = [
            {
                "source_file": c.source_file,
                "start_line": c.start_line,
                "end_line": c.end_line,
                "chunk_type": c.chunk_type,
                **c.metadata,
            }
            for c in chunks
        ]

        # Generate embeddings
        console.print(f"[cyan]Generating embeddings for {len(chunks)} chunks...[/cyan]")
        embeddings = self.embedder.embed_batch(documents)

        # Store
        self.store.add(ids, embeddings, documents, metadatas)
        console.print(f"[green]Indexed {len(chunks)} code chunks[/green]")

    def find_similar(
        self,
        code: str,
        n_results: int = 5,
        chunk_type: Optional[str] = None,
    ) -> list[SimilarityMatch]:
        """Find similar code chunks."""
        # Generate embedding for query
        query_embedding = self.embedder.embed(code)

        # Build filter
        where = None
        if chunk_type:
            where = {"chunk_type": chunk_type}

        # Search
        results = self.store.query(query_embedding, n_results, where)

        # Convert to matches
        matches = []
        for result in results:
            chunk = CodeChunk(
                id=result["id"],
                content=result["document"],
                source_file=result["metadata"].get("source_file", ""),
                start_line=result["metadata"].get("start_line", 0),
                end_line=result["metadata"].get("end_line", 0),
                chunk_type=result["metadata"].get("chunk_type", ""),
                metadata=result["metadata"],
            )

            matches.append(SimilarityMatch(
                chunk=chunk,
                similarity=result["similarity"],
                matched_to="indexed_code",
                explanation=f"Similarity: {result['similarity']:.2%}",
            ))

        return matches


class ExploitEmbedder:
    """
    Embed historical exploits for similarity search.

    Matches new code against patterns from known exploits.
    """

    def __init__(
        self,
        exploits_path: Optional[Path] = None,
        embedding_provider: Optional[EmbeddingProvider] = None,
    ):
        self.exploits_path = exploits_path or Path(__file__).parent.parent.parent / "knowledge_base" / "exploits"
        self.embedder = embedding_provider or LocalEmbeddings()
        self.store = VectorStore()
        self._indexed = False

    def index_exploits(self) -> None:
        """Index all exploits from the knowledge base."""
        if self._indexed:
            return

        import yaml

        # Load main database
        db_path = self.exploits_path / "database.yaml"
        if not db_path.exists():
            console.print(f"[yellow]Exploit database not found: {db_path}[/yellow]")
            return

        with open(db_path) as f:
            data = yaml.safe_load(f)

        exploits = data.get("exploits", [])

        ids = []
        documents = []
        metadatas = []

        for exp in exploits:
            # Create searchable text from exploit
            text = f"""
            {exp.get('name', '')}
            {exp.get('vulnerability_type', '')}
            {exp.get('root_cause', '')}
            {exp.get('attack_vector', '')}
            {exp.get('vulnerable_pattern', '')}
            """

            ids.append(f"exploit-{exp.get('id', '')}")
            documents.append(text)
            metadatas.append({
                "name": exp.get("name", ""),
                "date": exp.get("date", ""),
                "amount_lost": exp.get("amount_lost", 0),
                "vulnerability_type": exp.get("vulnerability_type", ""),
                "type": "exploit",
            })

        if ids:
            embeddings = self.embedder.embed_batch(documents)
            self.store.add(ids, embeddings, documents, metadatas)
            console.print(f"[green]Indexed {len(ids)} exploits[/green]")

        self._indexed = True

    def find_similar_exploits(
        self,
        code: str,
        n_results: int = 5,
    ) -> list[SimilarityMatch]:
        """Find exploits similar to given code."""
        self.index_exploits()

        query_embedding = self.embedder.embed(code)
        results = self.store.query(query_embedding, n_results)

        matches = []
        for result in results:
            if result["similarity"] < 0.5:  # Skip low similarity
                continue

            matches.append(SimilarityMatch(
                chunk=CodeChunk(
                    id=result["id"],
                    content=result["document"],
                    source_file="exploits",
                    start_line=0,
                    end_line=0,
                    chunk_type="exploit",
                    metadata=result["metadata"],
                ),
                similarity=result["similarity"],
                matched_to=result["metadata"].get("name", "Unknown exploit"),
                explanation=f"Similar to {result['metadata'].get('name')} ({result['metadata'].get('date')}) - ${result['metadata'].get('amount_lost', 0):,} lost",
            ))

        return matches


# Convenience functions
def embed_code(source: str, file_path: str = "unknown") -> list[CodeChunk]:
    """Quick code embedding."""
    embedder = CodeEmbedder()
    chunks = embedder.chunk_solidity(source, file_path)
    embedder.index_code(chunks)
    return chunks


def find_similar_exploits(code: str, n_results: int = 5) -> list[SimilarityMatch]:
    """Find exploits similar to code."""
    embedder = ExploitEmbedder()
    return embedder.find_similar_exploits(code, n_results)
