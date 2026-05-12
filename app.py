from flask import Flask, render_template, request, jsonify, session
import time
import json
import os
from jwt_core import (
    create_jwt_hmac, verify_jwt_hmac,
    generate_rsa_keys, create_jwt_rsa, verify_jwt_rsa,
    attack_alg_none, decode_token_parts
)

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Глобально генерируем RSA ключи при старте
_private_key, _private_pem, _public_pem = generate_rsa_keys()


@app.route('/')
def index():
    return render_template('index.html')


# ── HMAC ──────────────────────────────────────

@app.route('/api/hmac/create', methods=['POST'])
def hmac_create():
    data = request.json
    secret = data.get('secret', 'my-secret-key')
    payload = {
        "sub": data.get('sub', 'user123'),
        "name": data.get('name', 'Иван Иванов'),
        "role": data.get('role', 'user'),
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600
    }
    result = create_jwt_hmac(payload, secret)
    return jsonify(result)


@app.route('/api/hmac/verify', methods=['POST'])
def hmac_verify():
    data = request.json
    token = data.get('token', '')
    secret = data.get('secret', '')
    result = verify_jwt_hmac(token, secret)
    return jsonify(result)


# ── RSA ───────────────────────────────────────

@app.route('/api/rsa/keys', methods=['GET'])
def rsa_keys():
    return jsonify({
        "private_pem": _private_pem,
        "public_pem": _public_pem,
        "key_size": 2048
    })


@app.route('/api/rsa/create', methods=['POST'])
def rsa_create():
    data = request.json
    payload = {
        "sub": data.get('sub', 'user456'),
        "name": data.get('name', 'Мария Петрова'),
        "role": data.get('role', 'user'),
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600
    }
    result = create_jwt_rsa(payload, _private_key)
    return jsonify(result)


@app.route('/api/rsa/verify', methods=['POST'])
def rsa_verify():
    data = request.json
    token = data.get('token', '')
    result = verify_jwt_rsa(token, _public_pem)
    return jsonify(result)


# ── Атака alg:none ────────────────────────────

@app.route('/api/attack/algnone', methods=['POST'])
def attack():
    data = request.json
    token = data.get('token', '')
    if not token or len(token.split('.')) < 3:
        # Создаём тестовый токен автоматически
        test_payload = {"sub": "user1", "name": "Обычный пользователь", "role": "user", "iat": int(time.time())}
        created = create_jwt_hmac(test_payload, "secret")
        token = created['token']

    result = attack_alg_none(token)
    # Попытка верификации уязвимой системой (принимает alg:none)
    result['server_response_secure'] = "❌ ОТКЛОНЁН — сервер не принимает alg:none"
    result['server_response_vulnerable'] = "✅ ПРИНЯТ — уязвимый сервер не проверил подпись!"
    return jsonify(result)


# ── Декодирование ─────────────────────────────

@app.route('/api/decode', methods=['POST'])
def decode():
    data = request.json
    token = data.get('token', '')
    result = decode_token_parts(token)
    return jsonify(result)


if __name__ == '__main__':
    print("\n" + "="*55)
    print("  🔐 JWT Лаборатория — Задание №27")
    print("  Криптография | Cybersecurity | Курс 2")
    print("="*55)
    print("  Открой браузер: http://127.0.0.1:5000")
    print("="*55 + "\n")
    app.run(debug=True, port=5000)
