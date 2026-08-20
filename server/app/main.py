from datetime import datetime, timedelta, timezone
from pathlib import Path
import json

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from .admin import router as admin_router
from .config import settings
from .db import Order, get_db, init_db
from .keys import new_license_key, new_order_id
from .nowpayments import create_invoice, verify_ipn
from .plans import PLANS

ROOT = Path(__file__).resolve().parents[1]
DEBUG_DIR = ROOT / "debug-logs"
templates = Jinja2Templates(directory=str(ROOT / "templates"))
app = FastAPI(title="KingVCam", docs_url=None, redoc_url=None)
app.mount("/static", StaticFiles(directory=str(ROOT / "static")), name="static")
app.include_router(admin_router)


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    location = (exc.headers or {}).get("Location")
    if location and exc.status_code in {303, 307}:
        return RedirectResponse(location, status_code=exc.status_code)
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=exc.headers)


@app.on_event("startup")
def on_startup() -> None:
    init_db()
    DEBUG_DIR.mkdir(parents=True, exist_ok=True)


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(
        "index.html",
        {"request": request, "plans": list(PLANS.values())},
    )


@app.get("/obrigado", response_class=HTMLResponse)
def thanks(request: Request, order: str = ""):
    return templates.TemplateResponse(
        "success.html",
        {"request": request, "order_id": order},
    )


@app.post("/api/checkout/{plan_id}")
async def checkout(plan_id: str, db: Session = Depends(get_db)):
    plan = PLANS.get(plan_id)
    if plan is None:
        raise HTTPException(404, "plano invalido")
    order_id = new_order_id()
    success_url = f"{settings.public_url}/obrigado?order={order_id}"
    cancel_url = f"{settings.public_url}/"
    ipn_url = f"{settings.public_url}/api/payments/ipn"
    try:
        invoice = await create_invoice(
            order_id=order_id,
            amount=plan["price_usd"],
            description=f"KingVCam {plan['label']}",
            success_url=success_url,
            cancel_url=cancel_url,
            ipn_url=ipn_url,
        )
    except Exception as exc:
        raise HTTPException(502, f"falha ao criar invoice: {exc}") from exc
    invoice_url = invoice.get("invoice_url")
    if not invoice_url:
        raise HTTPException(502, "NOWPayments nao devolveu invoice_url")
    order = Order(
        id=order_id,
        plan_id=plan_id,
        price_usd=f"{plan['price_usd']:.2f}",
        days=plan["days"],
        status="pending",
        invoice_id=str(invoice.get("id") or ""),
        invoice_url=invoice_url,
    )
    db.add(order)
    db.commit()
    return RedirectResponse(invoice_url, status_code=303)


@app.get("/api/orders/{order_id}")
def order_status(order_id: str, db: Session = Depends(get_db)):
    order = db.get(Order, order_id)
    if order is None:
        raise HTTPException(404, "pedido nao encontrado")
    return {
        "id": order.id,
        "status": order.status,
        "plan_id": order.plan_id,
        "license_key": order.license_key,
        "expires_at": order.expires_at.isoformat() if order.expires_at else None,
    }


@app.post("/api/payments/ipn")
async def payments_ipn(request: Request, db: Session = Depends(get_db)):
    signature = request.headers.get("x-nowpayments-sig", "")
    body = await request.json()
    if not verify_ipn(body, signature):
        raise HTTPException(401, "assinatura IPN invalida")
    order_id = str(body.get("order_id") or "")
    status = str(body.get("payment_status") or "")
    order = db.get(Order, order_id)
    if order is None:
        return JSONResponse({"ok": False, "reason": "order_not_found"})
    order.payment_id = str(body.get("payment_id") or order.payment_id or "")
    if status in {"finished", "confirmed"} and order.status != "paid":
        now = datetime.now(timezone.utc)
        order.status = "paid"
        order.paid_at = now
        order.expires_at = now + timedelta(days=order.days)
        if not order.license_key:
            order.license_key = new_license_key()
    elif status in {"failed", "expired", "refunded"} and order.status != "paid":
        order.status = status
    db.commit()
    return {"ok": True}


@app.post("/api/activate")
def activate(payload: dict, db: Session = Depends(get_db)):
    return _activate_payload(payload, db)


@app.post("/v1/auth/login")
@app.post("/auth/login")
def auth_login(payload: dict, db: Session = Depends(get_db)):
    device_id = _extract_device_id(payload)
    key = _extract_license_key(payload) or _normalize_key(str(payload.get("key") or ""))
    _store_debug_log(
        device_id,
        key,
        str(payload.get("debug_log") or payload.get("log") or ""),
    )
    result = _activate_payload(payload, db, raise_http=False)
    if not result.get("ok"):
        return {
            "ok": False,
            "success": False,
            "status": "error",
            "valid": False,
            "error": result.get("error", "chave invalida"),
            "message": result.get("error", "chave invalida"),
        }
    return {
        "ok": True,
        "success": True,
        "status": "ok",
        "valid": True,
        "authorized": True,
        "token": result.get("license_key"),
        "credential": result.get("license_key"),
        "plan": result.get("plan_id"),
        "plan_id": result.get("plan_id"),
        "expires_at": result.get("expires_at"),
        "user": {
            "id": result.get("order_id"),
            "email": result.get("key"),
            "plan": result.get("plan_id"),
            "wallet": 0,
        },
    }


@app.api_route("/v1/auth/validate", methods=["GET", "POST"])
@app.api_route("/auth/validate", methods=["GET", "POST"])
def auth_validate(payload: dict | None = None):
    if payload:
        device_id = _extract_device_id(payload)
        key = _extract_license_key(payload) or _normalize_key(str(payload.get("key") or ""))
        _store_debug_log(
            device_id,
            key,
            str(payload.get("debug_log") or payload.get("log") or ""),
        )
    return {"ok": True, "success": True, "status": "ok", "valid": True, "authorized": True}


def _store_debug_log(device_id: str, key: str, log_text: str) -> None:
    if not log_text.strip():
        return
    safe_name = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in device_id)
    target = DEBUG_DIR / f"{safe_name or 'unknown'}.json"
    record = {
        "device_id": device_id or "unknown",
        "key": key[:64],
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "log": log_text[:200000],
    }
    target.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")


@app.post("/v1/debug/log")
def debug_log(payload: dict):
    device_id = str(payload.get("device_id") or "unknown").strip()[:128] or "unknown"
    key = str(payload.get("key") or "").strip()[:64]
    log_text = str(payload.get("log") or "")
    if not log_text:
        raise HTTPException(400, "log obrigatorio")
    _store_debug_log(device_id, key, log_text)
    return {"ok": True}


@app.get("/v1/debug/read")
def debug_read(device_id: str = "ios"):
    safe_name = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in device_id)
    target = DEBUG_DIR / f"{safe_name}.json"
    if not target.is_file():
        raise HTTPException(404, "log nao encontrado")
    return json.loads(target.read_text(encoding="utf-8"))


def _normalize_key(raw: str) -> str:
    return raw.strip().upper().replace(" ", "")


def _extract_license_key(payload: dict) -> str:
    for field in ("key", "license_key", "email", "password"):
        value = _normalize_key(str(payload.get(field) or ""))
        if value.startswith("KV-"):
            return value
    return ""


def _extract_device_id(payload: dict) -> str:
    for field in ("device_id", "dHash", "deviceHash", "sysId"):
        value = str(payload.get(field) or "").strip()
        if value:
            return value[:128]
    parts = [str(payload.get(field) or "").strip() for field in ("device_model", "ios_version")]
    joined = "|".join(part for part in parts if part)
    return (joined or "ios-unknown")[:128]


def _activate_payload(payload: dict, db: Session, raise_http: bool = True) -> dict:
    key = _extract_license_key(payload) or _normalize_key(str(payload.get("key") or ""))
    device_id = _extract_device_id(payload)
    if not key or not device_id:
        if raise_http:
            raise HTTPException(400, "key e device_id obrigatorios")
        return {"ok": False, "error": "key e device_id obrigatorios"}
    order = db.query(Order).filter(Order.license_key == key).one_or_none()
    if order is None or order.status != "paid":
        if raise_http:
            raise HTTPException(403, "chave invalida")
        return {"ok": False, "error": "chave invalida"}
    now = datetime.now(timezone.utc)
    expires = order.expires_at
    if expires is not None and expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if expires and expires < now:
        if raise_http:
            raise HTTPException(403, "chave expirada")
        return {"ok": False, "error": "chave expirada"}
    if order.device_id and order.device_id != device_id:
        if raise_http:
            raise HTTPException(403, "chave ja ativada em outro aparelho")
        return {"ok": False, "error": "chave ja ativada em outro aparelho"}
    order.device_id = device_id
    db.commit()
    return {
        "ok": True,
        "plan_id": order.plan_id,
        "expires_at": order.expires_at.isoformat() if order.expires_at else None,
        "license_key": order.license_key,
        "order_id": order.id,
        "key": key,
    }
