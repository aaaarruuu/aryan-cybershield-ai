from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Query, Request, UploadFile
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.database.session import get_db
from app.models.entities import KnowledgeDocument, User
from app.rag import store
from app.security.auth import audit, require_admin, require_analyst

router = APIRouter(prefix="/api/knowledge", tags=["knowledge"])
BUILTIN = Path(__file__).resolve().parents[3] / "sample_data" / "knowledge"


def _doc(d: KnowledgeDocument) -> dict:
    return {"id": d.id, "filename": d.filename, "content_type": d.content_type, "size_bytes": d.size_bytes,
            "chunk_count": d.chunk_count, "created_at": d.created_at.isoformat()}


def _ingest(db: Session, filename: str, content: bytes, user: User) -> dict:
    h = store.sha256(content)
    if db.scalar(select(KnowledgeDocument).where(KnowledgeDocument.sha256 == h)):
        raise HTTPException(409, "This document has already been uploaded")
    try:
        text = store.extract_text(filename, content)
    except store.DocumentError as e:
        raise HTTPException(422, str(e))
    doc = KnowledgeDocument(filename=Path(filename).name[:255], content_type=Path(filename).suffix.lower().lstrip("."), size_bytes=len(content),
                            sha256=h, uploaded_by_id=user.id)
    db.add(doc)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "This document has already been uploaded")
    try:
        info = store.add_document(doc.id, doc.filename, text)
    except store.DocumentError as e:
        db.rollback()
        raise HTTPException(422, str(e))
    doc.chunk_count = info["chunks"]
    db.commit()
    return {**_doc(doc), "injection_flagged_chunks": info["injection_flagged_chunks"]}


@router.post("/documents", status_code=201)
async def upload(request: Request, file: UploadFile = File(...), user: User = Depends(require_analyst), db: Session = Depends(get_db)):
    limit = get_settings().upload_max_mb * 1024 * 1024
    content = await file.read(limit + 1)
    if len(content) > limit:
        raise HTTPException(413, f"File exceeds {get_settings().upload_max_mb} MB limit")
    out = _ingest(db, file.filename or "upload", content, user)
    audit(db, "knowledge.uploaded", user, "document", out["id"], {"filename": out["filename"], "chunks": out["chunk_count"],
                                                                   "injection_flagged": out["injection_flagged_chunks"]}, request)
    return out


@router.post("/load-builtin", status_code=201)
def load_builtin(request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    """Ingest the bundled MITRE ATT&CK summary and incident-response playbooks (skips ones already loaded)."""
    loaded, skipped = [], []
    for p in sorted(BUILTIN.glob("*.md")):
        try:
            loaded.append(_ingest(db, p.name, p.read_bytes(), user)["filename"])
        except HTTPException as e:
            skipped.append(f"{p.name}: {e.detail}")
    audit(db, "knowledge.builtin_loaded", user, "document", "", {"loaded": loaded}, request)
    return {"loaded": loaded, "skipped": skipped}


@router.get("/documents")
def list_docs(_: User = Depends(require_analyst), db: Session = Depends(get_db)):
    return [_doc(d) for d in db.scalars(select(KnowledgeDocument).order_by(KnowledgeDocument.created_at.desc()))]


@router.delete("/documents/{doc_id}", status_code=204)
def delete(doc_id: int, request: Request, user: User = Depends(require_admin), db: Session = Depends(get_db)):
    d = db.get(KnowledgeDocument, doc_id)
    if not d:
        raise HTTPException(404, "Document not found")
    store.delete_document(doc_id)
    db.delete(d)
    db.commit()
    audit(db, "knowledge.deleted", user, "document", doc_id, {"filename": d.filename}, request)


@router.get("/search")
def search(q: str = Query(min_length=2, max_length=500), k: int = Query(4, ge=1, le=10), _: User = Depends(require_analyst)):
    return store.search(q, k=k, include_flagged=True)
