from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from src.core.logging import get_logger
from src.storage.postgres import PostgresStorage
from src.storage.elasticsearch import ElasticsearchStorage

logger = get_logger(__name__)

app = FastAPI(
    title="Honeypot Detection API",
    description="REST API for querying honeypot attack intelligence",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)

# These are set by main.py after storage is initialised
_postgres: PostgresStorage | None = None
_elasticsearch: ElasticsearchStorage | None = None


def set_storage(postgres: PostgresStorage, es: ElasticsearchStorage) -> None:
    global _postgres, _elasticsearch
    _postgres = postgres
    _elasticsearch = es


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


@app.get("/api/events")
async def get_events(limit: int = Query(default=100, le=1000)) -> list[dict]:
    if not _postgres:
        raise HTTPException(status_code=503, detail="Storage not ready")
    events = await _postgres.get_recent_events(limit=limit)
    # Convert UUID and datetime to strings for JSON serialisation
    for e in events:
        e["event_id"] = str(e["event_id"])
        e["timestamp"] = e["timestamp"].isoformat()
    return events


@app.get("/api/stats")
async def get_stats() -> dict:
    if not _postgres:
        raise HTTPException(status_code=503, detail="Storage not ready")
    return await _postgres.get_stats()


@app.get("/api/search")
async def search(q: str = Query(..., min_length=2)) -> list[dict]:
    if not _elasticsearch:
        raise HTTPException(status_code=503, detail="Storage not ready")
    return await _elasticsearch.search_events(q)