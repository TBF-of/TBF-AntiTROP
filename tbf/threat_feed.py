#!/usr/bin/env python3
"""
TBF-AntiTROP :: threat feed
Подтягивает свежие SHA256 из MalwareBazaar (abuse.ch) и вливает их
в data/signatures.json. Только stdlib (urllib) — без requests.

Нужен бесплатный Auth-Key: https://auth.abuse.ch/
Передавай его через --auth-key или переменную окружения MB_AUTH_KEY.
"""

import json
import urllib.request
import urllib.error
import urllib.parse

from .core import SIGNATURES_FILE, load_json, save_json

MB_API_URL = "https://mb-api.abuse.ch/api/v1/"


class ThreatFeedError(Exception):
    pass


def fetch_recent(auth_key: str, limit: int = 100, timeout: int = 20):
    """
    Тянет последние добавленные хэши с MalwareBazaar.
    query=get_recent&selector=<N> — документированный community-запрос,
    требует HTTP-заголовок Auth-Key (см. https://bazaar.abuse.ch/api/).
    """
    if not auth_key:
        raise ThreatFeedError(
            "нужен Auth-Key от MalwareBazaar (бесплатно на https://auth.abuse.ch/), "
            "передай его через --auth-key или переменную окружения MB_AUTH_KEY"
        )

    data = urllib.parse.urlencode({"query": "get_recent", "selector": str(limit)}).encode()
    req = urllib.request.Request(
        MB_API_URL, data=data, method="POST",
        headers={"Auth-Key": auth_key, "User-Agent": "TBF-AntiTROP/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raise ThreatFeedError(f"MalwareBazaar HTTP {e.code}: {e.reason}") from e
    except urllib.error.URLError as e:
        raise ThreatFeedError(f"не смог достучаться до MalwareBazaar: {e.reason}") from e
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise ThreatFeedError(f"кривой ответ от MalwareBazaar: {e}") from e

    if payload.get("query_status") != "ok":
        raise ThreatFeedError(f"MalwareBazaar вернул статус: {payload.get('query_status')}")

    return payload.get("data", [])


def merge_into_signatures(entries):
    """entries: список объектов MalwareBazaar с sha256_hash / signature / file_type."""
    sigs = load_json(SIGNATURES_FILE, {"sha256": {}})
    sigs.setdefault("sha256", {})
    added = 0
    for e in entries:
        h = e.get("sha256_hash")
        if not h:
            continue
        label = e.get("signature") or e.get("file_type") or "MalwareBazaar"
        if h not in sigs["sha256"]:
            added += 1
        sigs["sha256"][h] = f"{label} (MalwareBazaar)"
    save_json(SIGNATURES_FILE, sigs)
    return added, len(sigs["sha256"])


def update_from_malwarebazaar(auth_key: str, limit: int = 100):
    entries = fetch_recent(auth_key, limit=limit)
    return merge_into_signatures(entries)
