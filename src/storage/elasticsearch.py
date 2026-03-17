from datetime import UTC, datetime

from elasticsearch import AsyncElasticsearch, NotFoundError

from src.core.events import AttackEvent
from src.core.logging import get_logger

logger = get_logger(__name__)

INDEX_MAPPING = {
    "mappings": {
        "properties": {
            "event_id":          {"type": "keyword"},
            "timestamp":         {"type": "date"},
            "source_ip":         {"type": "ip"},
            "source_port":       {"type": "integer"},
            "target_service":    {"type": "keyword"},
            "attack_type":       {"type": "keyword"},
            "severity":          {"type": "keyword"},
            "threat_score":      {"type": "float"},
            "summary":           {"type": "text", "analyzer": "english"},
            "attacker_intent":   {"type": "keyword"},
            "iocs":              {"type": "keyword"},
            "deception_response":{"type": "text"},
            "country":           {"type": "keyword"},
            "city":              {"type": "keyword"},
            "raw_payload":       {"type": "text"},
        }
    },
    "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0,
    },
}


class ElasticsearchStorage:
    def __init__(self, url: str, index: str) -> None:
        self._client = AsyncElasticsearch(url)
        self._index = index

    async def connect(self) -> None:
        try:
            await self._client.indices.get(index=self._index)
        except NotFoundError:
            await self._client.indices.create(
                index=self._index, body=INDEX_MAPPING
            )
            logger.info("elasticsearch_index_created", index=self._index)
        logger.info("elasticsearch_connected", index=self._index)

    async def disconnect(self) -> None:
        await self._client.close()
        logger.info("elasticsearch_disconnected")

    async def save_event(self, event: AttackEvent) -> None:
        doc = {
            "event_id":           str(event.event_id),
            "timestamp":          event.timestamp.isoformat(),
            "source_ip":          event.source_ip,
            "source_port":        event.source_port,
            "target_service":     event.target_service,
            "attack_type":        event.attack_type.value,
            "severity":           event.severity.value,
            "threat_score":       event.threat_score,
            "summary":            event.summary,
            "attacker_intent":    event.attacker_intent,
            "iocs":               event.iocs,
            "deception_response": event.deception_response,
            "country":            event.country,
            "city":               event.city,
            "raw_payload":        event.raw_payload[:5000],
        }

        await self._client.index(
            index=self._index,
            id=str(event.event_id),
            document=doc,
        )

        logger.info(
            "event_saved_elasticsearch",
            event_id=str(event.event_id),
        )

    async def search_events(self, query: str, size: int = 50) -> list[dict]:
        """Full-text search across all event fields — this is the killer feature
        over plain PostgreSQL."""
        response = await self._client.search(
            index=self._index,
            body={
                "query": {
                    "multi_match": {
                        "query": query,
                        "fields": [
                            "summary", "raw_payload", "iocs",
                            "attacker_intent", "source_ip"
                        ],
                    }
                },
                "sort": [{"timestamp": {"order": "desc"}}],
                "size": size,
            },
        )
        return [hit["_source"] for hit in response["hits"]["hits"]]