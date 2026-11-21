"""
intel/youtube_learning_api.py — FastAPI Router for YouTube AI Learning subsystem.

Exposes REST endpoints for:
- Analyzing videos & extracting transcripts
- Listing and deleting saved learning sessions
- Grounded video-specific Q&A
- Generating learning artifacts (Quiz, Flashcards, Notes)
- Exporting lessons as PDF, PPTX, or Markdown
"""

from __future__ import annotations
from typing import Any, Optional

try:
    from fastapi import APIRouter, Query, Request, HTTPException, Response
    from fastapi.responses import JSONResponse, Response as FastAPIResponse
    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False

from .youtube_learning_service import (
    get_youtube_learning_service,
    LearningArtifactService,
    YouTubeLearningService,
)

_service_instance: Optional[YouTubeLearningService] = None


def get_service() -> YouTubeLearningService:
    global _service_instance
    if _service_instance is None:
        _service_instance = get_youtube_learning_service()
    return _service_instance


def set_service(svc: Optional[YouTubeLearningService]) -> None:
    global _service_instance
    _service_instance = svc


if _FASTAPI_AVAILABLE:
    router = APIRouter(prefix="/api/youtube-learning", tags=["YouTube AI Learning"])

    @router.post("/analyze")
    async def analyze_video_ep(req: Request) -> Any:
        try:
            body = await req.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")

        url = (body.get("url") or "").strip()
        if not url:
            raise HTTPException(status_code=400, detail="Missing required 'url' parameter")

        language = body.get("language") or "English"
        level = body.get("level") or "Intermediate"
        style = body.get("style") or "Step-by-step"
        user_transcript = body.get("transcript")

        svc = get_service()
        try:
            session, notice = svc.analyze_and_create_session(
                url=url,
                language=language,
                level=level,
                style=style,
                user_transcript=user_transcript,
            )
            return JSONResponse({
                "ok": True,
                "session": session.to_dict(),
                "notice": notice,
            })
        except ValueError as ve:
            raise HTTPException(status_code=400, detail=str(ve))
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Analysis failed: {str(exc)}")

    @router.get("/sessions")
    async def list_sessions_ep(
        q: Optional[str] = Query(None, description="Search term for title, summary, or author"),
        language: Optional[str] = Query(None, description="Filter by language"),
        level: Optional[str] = Query(None, description="Filter by level"),
        limit: int = Query(50, ge=1, le=100),
        offset: int = Query(0, ge=0),
    ) -> Any:
        svc = get_service()
        sessions = svc.list_sessions(
            search=q or "",
            language=language,
            level=level,
            limit=limit,
            offset=offset,
        )
        return JSONResponse({
            "ok": True,
            "total": len(sessions),
            "sessions": sessions,
        })

    @router.get("/sessions/{session_id}")
    async def get_session_ep(session_id: str) -> Any:
        svc = get_service()
        session = svc.get_session(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")
        return JSONResponse({"ok": True, "session": session.to_dict()})

    @router.delete("/sessions/{session_id}")
    async def delete_session_ep(session_id: str) -> Any:
        svc = get_service()
        deleted = svc.delete_session(session_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Session not found")
        return JSONResponse({"ok": True, "deleted": session_id})

    @router.post("/sessions/{session_id}/ask")
    async def ask_question_ep(session_id: str, req: Request) -> Any:
        try:
            body = await req.json()
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid JSON body")

        question = (body.get("question") or "").strip()
        if not question:
            raise HTTPException(status_code=400, detail="Question cannot be empty")

        svc = get_service()
        try:
            turn = svc.ask_question(session_id=session_id, question=question)
            return JSONResponse({"ok": True, "turn": turn.to_dict()})
        except KeyError:
            raise HTTPException(status_code=404, detail="Session not found")
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Q&A failed: {str(exc)}")

    @router.post("/sessions/{session_id}/artifacts")
    async def regenerate_artifacts_ep(session_id: str, req: Request) -> Any:
        try:
            body = await req.json()
        except Exception:
            body = {}

        artifact_type = (body.get("artifact_type") or "all").lower()
        svc = get_service()
        session = svc.get_session(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")

        if artifact_type in ("quiz", "all"):
            session.quiz = LearningArtifactService.generate_quiz(
                session.title, session.summary, session.full_transcript
            )
        if artifact_type in ("flashcards", "all"):
            session.flashcards = LearningArtifactService.generate_flashcards(
                session.title, session.summary, session.full_transcript
            )
        if artifact_type in ("notes", "all"):
            session.notes_markdown = LearningArtifactService.generate_notes_markdown(session)

        svc.save_session(session)
        return JSONResponse({"ok": True, "session": session.to_dict()})

    @router.get("/sessions/{session_id}/export")
    async def export_session_ep(
        session_id: str,
        format: str = Query("markdown", pattern="^(markdown|pdf|pptx|text)$"),
    ) -> Any:
        svc = get_service()
        session = svc.get_session(session_id)
        if not session:
            raise HTTPException(status_code=404, detail="Session not found")

        safe_title = "".join(c for c in session.title if c.isalnum() or c in (" ", "_", "-")).rstrip()
        safe_title = (safe_title[:40] or "youtube_lesson").replace(" ", "_")

        if format == "pdf":
            try:
                pdf_bytes = LearningArtifactService.export_pdf(session)
                return FastAPIResponse(
                    content=pdf_bytes,
                    media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{safe_title}.pdf"'},
                )
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"PDF export failed: {e}")

        elif format == "pptx":
            try:
                pptx_bytes = LearningArtifactService.export_pptx(session)
                return FastAPIResponse(
                    content=pptx_bytes,
                    media_type="application/vnd.openxmlformats-officedocument.presentationml.presentation",
                    headers={"Content-Disposition": f'attachment; filename="{safe_title}.pptx"'},
                )
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"PPTX export failed: {e}")

        elif format in ("markdown", "text"):
            md_content = session.notes_markdown or LearningArtifactService.generate_notes_markdown(session)
            media_type = "text/markdown" if format == "markdown" else "text/plain"
            ext = "md" if format == "markdown" else "txt"
            return FastAPIResponse(
                content=md_content,
                media_type=media_type,
                headers={"Content-Disposition": f'attachment; filename="{safe_title}.{ext}"'},
            )

        raise HTTPException(status_code=400, detail="Unsupported export format")
else:
    router = None
