from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any

import httpx

from .config import settings


def _sort_obj(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _sort_obj(value[k]) for k in sorted(value)}
    if isinstance(value, list):
        return [_sort_obj(item) for item in value]
    return value


def verify_ipn(body: dict[str, Any], signature: str) -> bool:
    if not settings.nowpayments_ipn_secret or not signature:
        return False
    payload = json.dumps(_sort_obj(body), separators=(",", ":"), ensure_ascii=False)
    digest = hmac.new(
        settings.nowpayments_ipn_secret.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha512,
    ).hexdigest()
    return hmac.compare_digest(digest, signature.lower())


async def create_invoice(
    *,
    order_id: str,
    amount: float,
    description: str,
    success_url: str,
    cancel_url: str,
    ipn_url: str,
) -> dict[str, Any]:
    headers = {
        "x-api-key": settings.nowpayments_api_key,
        "Content-Type": "application/json",
    }
    payload = {
        "price_amount": amount,
        "price_currency": "usd",
        "order_id": order_id,
        "order_description": description,
        "ipn_callback_url": ipn_url,
        "success_url": success_url,
        "cancel_url": cancel_url,
    }
    async with httpx.AsyncClient(timeout=20.0) as client:
        response = await client.post(
            f"{settings.nowpayments_api_url}/invoice",
            headers=headers,
            json=payload,
        )
        response.raise_for_status()
        return response.json()
