"""HTTP API for the liquid-xenon calibration archive."""
from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .config import Settings
from .service import ArchiveService, ConflictError, NotFoundError
from .storage import Database

WEB_DIR = Path(__file__).resolve().parent / "web"
ID_PATTERN = r"^[A-Za-z0-9._-]{1,128}$"


class RecordIn(BaseModel):
    content: str = Field(min_length=1, max_length=1_000_000)
    record_id: Optional[str] = Field(default=None, pattern=ID_PATTERN)


class RotationIn(BaseModel):
    operation_id: str = Field(pattern=ID_PATTERN)
    target_version: Optional[int] = Field(default=None, ge=1)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    service = ArchiveService(Database(settings.db_path), settings.rotation_step_delay_ms)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        # A previous process may have died mid-rotation: resume every
        # interrupted rotation from its persisted progress.
        service.resume_interrupted()
        yield

    app = FastAPI(title="LXe Calibration Archive", lifespan=lifespan)
    app.state.service = service
    app.state.settings = settings

    def health() -> dict:
        return {"status": "ok", "service": "lx-archive"}

    app.add_api_route(settings.health_path, health, methods=["GET"], include_in_schema=False)

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(WEB_DIR / "index.html")

    @app.get("/api/state")
    def get_state() -> dict:
        state = service.state()
        state["health_path"] = settings.health_path
        return state

    @app.post("/api/records", status_code=201)
    def post_record(body: RecordIn) -> dict:
        try:
            return service.create_record(body.content, body.record_id)
        except ConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc

    @app.get("/api/records")
    def get_records() -> dict:
        return {"records": service.list_records()}

    @app.get("/api/records/{record_id}")
    def get_record(record_id: str) -> dict:
        try:
            return service.get_record(record_id)
        except NotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/api/records/{record_id}/verify")
    def post_verify(record_id: str) -> dict:
        try:
            return service.verify_record(record_id)
        except NotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/api/rotations")
    def post_rotation(body: RotationIn, response: Response) -> dict:
        try:
            status, created = service.start_rotation(
                body.operation_id, body.target_version
            )
        except ConflictError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        response.status_code = 201 if created else 200
        return status

    @app.get("/api/rotations")
    def get_rotations() -> dict:
        return {"rotations": service.list_rotations()}

    @app.get("/api/rotations/{operation_id}")
    def get_rotation(operation_id: str) -> dict:
        try:
            return service.rotation_status(operation_id)
        except NotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    return app


def main() -> None:
    settings = Settings.from_env()
    app = create_app(settings)
    uvicorn.run(app, host=settings.host, port=settings.port, log_level="info")


if __name__ == "__main__":
    main()
