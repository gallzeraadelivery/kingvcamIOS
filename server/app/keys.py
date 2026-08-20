import secrets


def new_license_key() -> str:
    raw = secrets.token_hex(8).upper()
    return f"KV-{raw[0:4]}-{raw[4:8]}-{raw[8:12]}-{raw[12:16]}"


def new_order_id() -> str:
    return secrets.token_hex(12)
