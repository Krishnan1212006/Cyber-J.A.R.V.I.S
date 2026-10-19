"""
intel/information_api.py — FastAPI Router for Dedicated Information Pages.

Exposes REST endpoints:
- GET /api/information
- GET /api/information/{page_id}
- POST /api/information/route-and-generate
- POST /api/information/{page_id}/bookmark
- DELETE /api/information/{page_id}
- GET /api/information/{page_id}/export
"""

from __future__ import annotations
from typing import Any, Optional

try:
    from fastapi import APIRouter, Query, Request, HTTPException
    from fastapi.responses import JSONResponse, Response, PlainTextResponse
    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False

from .information_service import get_information_service, InformationService
from .response_router import PresentationMode

_info_service_instance: Optional[InformationService] = None


def get_service() -> InformationService:
    """Return active InformationService instance."""
    global _info_service_instance
    if _info_service_instance is None:
        _info_service_instance = get_information_service()
    return _info_service_instance


def set_service(svc: Optional[InformationService]) -> None:
    """Explicitly set service instance (useful for testing)."""
    global _info_service_instance
    _info_service_instance = svc


if _FASTAPI_AVAILABLE:
    router = APIRouter(prefix="/api/information", tags=["Dedicated Information Pages"])

    @router.get("")
    async def list_pages_ep(
        category: Optional[str] = Query(None, description="Filter by category"),
        type: Optional[str] = Query(None, description="Filter by presentation type"),
        bookmarked: Optional[bool] = Query(None, description="Filter bookmarked only"),
        q: Optional[str] = Query(None, description="Full-text search query"),
        limit: int = Query(50, ge=1, le=100),
        offset: int = Query(0, ge=0),
    ) -> Any:
        svc = get_service()
        if q and q.strip():
            pages = svc.db.search_information_pages(query=q.strip(), limit=limit)
            # If bookmarked filter also set
            if bookmarked:
                pages = [p for p in pages if p.user_bookmarked]
            if category:
                pages = [p for p in pages if p.category.lower() == category.lower()]
            if type:
                pages = [p for p in pages if p.presentation_type.lower() == type.lower()]
        else:
            pages = svc.db.list_information_pages(
                category=category,
                presentation_type=type,
                bookmarked_only=bool(bookmarked),
                limit=limit,
                offset=offset,
            )

        return {
            "total": len(pages),
            "pages": [
                {
                    "id": p.id,
                    "title": p.title,
                    "summary": p.summary,
                    "category": p.category,
                    "tags": p.tags,
                    "presentation_type": p.presentation_type,
                    "user_bookmarked": p.user_bookmarked,
                    "model_provider": p.model_provider,
                    "created_at": p.created_at,
                    "updated_at": p.updated_at,
                }
                for p in pages
            ],
        }

    @router.get("/{page_id}")
    async def get_page_ep(page_id: str) -> Any:
        svc = get_service()
        page = svc.db.get_information_page(page_id)
        if not page:
            raise HTTPException(status_code=404, detail="Information page record not found.")
        return page.to_dict()

    @router.post("/route-and-generate")
    async def route_and_generate_ep(req: Request) -> Any:
        try:
            body = await req.json()
        except Exception:
            body = {}

        query = str(body.get("query", "")).strip()
        attachments = body.get("attachments", [])
        if not query and not attachments:
            raise HTTPException(status_code=400, detail="Query or attachments required.")

        if attachments:
            from .attachment_service import get_attachment_service, AttachmentItem
            att_items = []
            for att_dict in attachments:
                if isinstance(att_dict, dict):
                    att_items.append(AttachmentItem(
                        id=att_dict.get("id", ""),
                        name=att_dict.get("name", "attachment"),
                        path=att_dict.get("path", ""),
                        is_directory=bool(att_dict.get("is_directory", False)),
                        size_bytes=int(att_dict.get("size_bytes", 0)),
                        file_count=int(att_dict.get("file_count", 1)),
                        category=att_dict.get("category", "unknown"),
                        icon=att_dict.get("icon", "📎"),
                        status=att_dict.get("status", "ready"),
                        discovered_files=att_dict.get("discovered_files", []),
                    ))
            query = get_attachment_service().compose_prompt(query, att_items)

        force_mode = body.get("force_mode")
        force_refresh = bool(body.get("force_refresh", False))

        svc = get_service()
        result = svc.process_request(
            query=query,
            force_mode=force_mode,
            force_refresh=force_refresh,
        )

        # Notify dashboard server if available (broadcast page navigation event)
        dashboard_srv = getattr(req.app.state, "dashboard_server", None)
        if dashboard_srv and result.get("is_page") and result.get("page"):
            page_data = result["page"]
            # Push page navigation event to all connected dashboard WebSocket clients
            import asyncio
            asyncio.create_task(
                dashboard_srv.broadcast({
                    "type": "open_page",
                    "page_id": page_data["id"],
                    "title": page_data["title"],
                    "mode": page_data["presentation_type"],
                    "speech": result["jarvis_response"],
                })
            )
            # Also log Jarvis's vocal/text response in chat feed
            asyncio.create_task(
                dashboard_srv.broadcast({
                    "type": "log",
                    "speaker": "jarvis",
                    "text": result["jarvis_response"],
                })
            )

        return result

    @router.post("/{page_id}/bookmark")
    async def toggle_bookmark_ep(page_id: str, req: Request) -> Any:
        try:
            body = await req.json()
            explicit_val = body.get("bookmarked")
        except Exception:
            explicit_val = None

        svc = get_service()
        new_status = svc.db.toggle_page_bookmark(page_id=page_id, bookmarked=explicit_val)
        return {"ok": True, "page_id": page_id, "user_bookmarked": new_status}

    @router.delete("/{page_id}")
    async def delete_page_ep(page_id: str) -> Any:
        svc = get_service()
        deleted = svc.db.delete_information_page(page_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Page not found or already deleted.")
        return {"ok": True, "page_id": page_id}

    @router.get("/{page_id}/export")
    async def export_page_ep(page_id: str, format: str = Query("markdown", description="markdown | html | json")) -> Response:
        svc = get_service()
        page = svc.db.get_information_page(page_id)
        if not page:
            raise HTTPException(status_code=404, detail="Information page record not found.")

        filename = f"{page.title.lower().replace(' ', '_')[:30]}"

        if format.lower() == "json":
            import json as _json
            return Response(
                content=_json.dumps(page.to_dict(), indent=2),
                media_type="application/json",
                headers={"Content-Disposition": f'attachment; filename="{filename}.json"'},
            )

        if format.lower() == "html":
            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{page.title} — JARVIS 24 Intelligence</title>
<style>
  body {{ background: #00060a; color: #8ffcff; font-family: 'Segoe UI', system-ui, sans-serif; max-width: 900px; margin: 40px auto; padding: 20px; line-height: 1.6; }}
  h1, h2, h3 {{ color: #00d4ff; border-bottom: 1px solid #0d3347; padding-bottom: 6px; }}
  pre {{ background: #010d14; border: 1px solid #1a5c7a; padding: 14px; border-radius: 6px; overflow-x: auto; color: #d8f8ff; }}
  table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
  th, td {{ border: 1px solid #0d3347; padding: 8px 12px; text-align: left; }}
  th {{ background: #010f18; color: #00d4ff; }}
  blockquote {{ border-left: 3px solid #00d4ff; margin: 0; padding-left: 14px; color: #5ab8cc; }}
  a {{ color: #00d4ff; }}
</style>
</head>
<body>
<h1>{page.title}</h1>
<p><strong>Category:</strong> {page.category} | <strong>Type:</strong> {page.presentation_type} | <strong>Generated:</strong> {page.created_at}</p>
<hr>
<div>
<pre>{page.content}</pre>
</div>
</body>
</html>"""
            return Response(
                content=html_content,
                media_type="text/html",
                headers={"Content-Disposition": f'attachment; filename="{filename}.html"'},
            )

        # Default markdown export
        return PlainTextResponse(
            content=page.content,
            headers={"Content-Disposition": f'attachment; filename="{filename}.md"'},
        )
else:
    router = None
