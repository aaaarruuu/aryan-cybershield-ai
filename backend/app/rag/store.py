"""RAG knowledge base: extraction -> cleaning -> chunking -> embeddings -> ChromaDB -> retrieval with citations.

Embeddings: a local, deterministic hashing embedder (sklearn HashingVectorizer, uni+bigrams, L2-normalised).
It needs no network or model download, so demo mode works offline. It is LEXICAL (term-overlap) similarity,
not deep semantic similarity; swap `HashingEmbedding` for a sentence-embedding model to improve recall on
paraphrased queries. Retrieval returns nothing when similarity is below MIN_SIMILARITY, so the caller can state
that the knowledge base has no relevant information instead of guessing.

Security: uploaded/retrieved text is UNTRUSTED. Chunks that look like prompt-injection are flagged, excluded
from agent context, and never able to alter tools, permissions or state (they are passed only as quoted data).
"""
import hashlib
import io
import json
import re
from pathlib import Path

import chromadb
import numpy as np
from chromadb import Documents, EmbeddingFunction, Embeddings
from pypdf import PdfReader
from sklearn.feature_extraction.text import HashingVectorizer

from app.core.config import get_settings

ALLOWED_EXT = {".pdf", ".txt", ".md", ".csv", ".json"}
CHUNK_SIZE, CHUNK_OVERLAP = 900, 150
MIN_SIMILARITY = 0.12
MAX_PDF_PAGES = 300
INJECTION_PATTERNS = [
    r"ignore (all |any )?(previous|prior|above) (instructions|prompts?|rules)",
    r"disregard (the |all |any )?(previous|prior|above|system)",
    r"you are now\b", r"new (system )?instructions?:", r"system prompt", r"act as (an? )?(admin|root|system)",
    r"reveal (your|the) (prompt|instructions|api key|secret)", r"override (the )?(safety|security|approval)",
    r"(approve|execute|run) (this|the) (action|command) (automatically|without)", r"</?(system|assistant|tool)>",
    r"\bsudo\b|\brm -rf\b|curl [^\n]*\|\s*(ba)?sh",
]
_INJ = re.compile("|".join(INJECTION_PATTERNS), re.I)


class DocumentError(ValueError):
    pass


class HashingEmbedding(EmbeddingFunction):
    def __init__(self):
        self._vec = HashingVectorizer(n_features=2048, alternate_sign=False, norm="l2", ngram_range=(1, 2),
                                      stop_words="english", lowercase=True)

    def __call__(self, input: Documents) -> Embeddings:
        return [row.astype(np.float32) for row in self._vec.transform(list(input)).toarray()]

    @staticmethod
    def name() -> str:
        return "aryan-hashing-embedding"

    def get_config(self) -> dict:
        return {}

    @staticmethod
    def build_from_config(config: dict) -> "HashingEmbedding":
        return HashingEmbedding()


_client = None


def _collection():
    global _client
    path = get_settings().chroma_path
    if _client is None or getattr(_client, "_cs_path", None) != path:
        Path(path).mkdir(parents=True, exist_ok=True)
        _client = chromadb.PersistentClient(path=path)
        _client._cs_path = path
    return _client.get_or_create_collection("security_knowledge", embedding_function=HashingEmbedding(),
                                            metadata={"hnsw:space": "cosine"})


# ---------- extraction / cleaning / chunking ----------
def extract_text(filename: str, content: bytes) -> str:
    ext = Path(filename or "").suffix.lower()
    if ext not in ALLOWED_EXT:
        raise DocumentError(f"Unsupported file type '{ext}'. Allowed: {', '.join(sorted(ALLOWED_EXT))}")
    if not content:
        raise DocumentError("File is empty")
    if len(content) > get_settings().upload_max_mb * 1024 * 1024:
        raise DocumentError(f"File exceeds {get_settings().upload_max_mb} MB limit")
    if ext == ".pdf":
        if not content.startswith(b"%PDF"):
            raise DocumentError("File content is not a valid PDF")
        try:
            reader = PdfReader(io.BytesIO(content))
            if reader.is_encrypted:
                raise DocumentError("Encrypted PDFs are not supported")
            if len(reader.pages) > MAX_PDF_PAGES:
                raise DocumentError(f"PDF has too many pages (limit {MAX_PDF_PAGES})")
            text = "\n\n".join((p.extract_text() or "") for p in reader.pages)
        except DocumentError:
            raise
        except Exception:
            raise DocumentError("Could not read PDF")
    else:
        if b"\x00" in content[:2048]:
            raise DocumentError("File appears to be binary, not text")
        try:
            text = content.decode("utf-8-sig")
        except UnicodeDecodeError:
            raise DocumentError("Text files must be UTF-8")
        if ext == ".json":
            try:
                text = json.dumps(json.loads(text), indent=1)
            except json.JSONDecodeError:
                raise DocumentError("Invalid JSON")
    text = clean_text(text)
    if len(text) < 20:
        raise DocumentError("No extractable text found (scanned PDFs need OCR, which is not supported)")
    return text


def clean_text(text: str) -> str:
    text = text.replace("\x00", "")
    text = re.sub(r"[^\S\n]+", " ", text)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def chunk_text(text: str) -> list[str]:
    paras = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
    chunks, cur = [], ""
    for p in paras:
        while len(p) > CHUNK_SIZE:  # split oversize paragraphs on sentence/space boundary
            cut = max(p.rfind(". ", 0, CHUNK_SIZE), p.rfind(" ", 0, CHUNK_SIZE))
            cut = cut if cut > CHUNK_SIZE // 2 else CHUNK_SIZE
            if cur:
                chunks.append(cur)
                cur = ""
            chunks.append(p[:cut + 1].strip())
            p = p[max(cut + 1 - CHUNK_OVERLAP, 1):].strip()
        if len(cur) + len(p) + 2 <= CHUNK_SIZE:
            cur = f"{cur}\n\n{p}".strip()
        else:
            if cur:
                chunks.append(cur)
            cur = p
    if cur:
        chunks.append(cur)
    return [c for c in chunks if len(c) > 15]


def looks_like_injection(text: str) -> bool:
    return bool(_INJ.search(text))


# ---------- storage ----------
def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def add_document(doc_id: int, filename: str, text: str) -> dict:
    chunks = chunk_text(text)
    if not chunks:
        raise DocumentError("Document produced no usable text chunks")
    flags = [looks_like_injection(c) for c in chunks]
    col = _collection()
    for i in range(0, len(chunks), 200):
        sl = slice(i, i + 200)
        col.add(ids=[f"{doc_id}:{j}" for j in range(len(chunks))][sl], documents=chunks[sl],
                metadatas=[{"doc_id": doc_id, "filename": filename, "chunk": j, "injection_suspected": flags[j]}
                           for j in range(len(chunks))][sl])
    return {"chunks": len(chunks), "injection_flagged_chunks": int(sum(flags))}


def delete_document(doc_id: int) -> None:
    _collection().delete(where={"doc_id": doc_id})


def search(query: str, k: int = 4, include_flagged: bool = False) -> dict:
    """Returns {"results": [...], "has_relevant": bool}. Results are untrusted data with citations."""
    col = _collection()
    if not query.strip() or col.count() == 0:
        return {"results": [], "has_relevant": False,
                "message": "The knowledge base is empty." if col.count() == 0 else "Empty query."}
    res = col.query(query_texts=[query[:2000]], n_results=min(k * 2, col.count()))
    out = []
    for text, meta, dist in zip(res["documents"][0], res["metadatas"][0], res["distances"][0]):
        sim = round(1.0 - float(dist), 4)
        if sim < MIN_SIMILARITY:
            continue
        flagged = bool(meta.get("injection_suspected"))
        if flagged and not include_flagged:
            continue
        out.append({"text": text, "filename": meta["filename"], "doc_id": meta["doc_id"], "chunk": meta["chunk"],
                    "similarity": sim, "injection_suspected": flagged,
                    "citation": f"{meta['filename']} (chunk {meta['chunk']})"})
        if len(out) >= k:
            break
    return {"results": out, "has_relevant": bool(out),
            "message": "" if out else "No relevant information found in the knowledge base for this query."}


def wrap_untrusted(results: list[dict]) -> str:
    """Format retrieved text as quoted, inert data. Provided for any future LLM integration; the current agents are deterministic."""
    return "\n".join(f'<untrusted_document source="{r["citation"]}">\n{r["text"]}\n</untrusted_document>' for r in results)
