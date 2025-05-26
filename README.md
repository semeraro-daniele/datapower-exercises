# Esercizi IBM DataPower: OAuth2 e JWT - Versione Sprint (2-3 giorni)

## Backend Python Semplici

### Backend 1: Echo Server Custom
```python
# simple_echo.py
from flask import Flask, request, jsonify
import time

app = Flask(__name__)

@app.route('/echo', methods=['GET', 'POST', 'PUT', 'DELETE'])
def echo():
    return jsonify({
        'method': request.method,
        'path': request.path,
        'headers': dict(request.headers),
        'body': request.get_data(as_text=True),
        'timestamp': time.time()
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
```

### Backend 2: JWT Validator con Auto-Generated Keys
```python
# jwt_backend.py
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
import json
import base64

app = Flask(__name__)

# Genera coppia di chiavi all'avvio
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# Serializza chiavi
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
)

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

@app.route('/.well-known/jwks.json')
def jwks():
    """Fornisce la chiave pubblica in formato JWK"""
    
    # Converti chiave pubblica in formato JWK
    public_numbers = public_key.public_numbers()
    
    def int_to_base64url(val):
        byte_length = (val.bit_length() + 7) // 8
        return base64.urlsafe_b64encode(val.to_bytes(byte_length, 'big')).decode().rstrip('=')
    
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "kid": "test-key-1",
        "n": int_to_base64url(public_numbers.n),
        "e": int_to_base64url(public_numbers.e),
        "alg": "RS256"
    }
    
    return jsonify({"keys": [jwk]})

@app.route('/protected', methods=['GET', 'POST'])
def protected():
    """Endpoint che richiede JWT valido"""
    auth = request.headers.get('Authorization')
    if not auth or not auth.startswith('Bearer '):
        return jsonify({'error': 'JWT required'}), 401
    
    token = auth[7:]
    try:
        payload = jwt.decode(token, public_pem, algorithms=['RS256'])
        return jsonify({
            'message': 'JWT valid!',
            'payload': payload,
            'headers': dict(request.headers)
        })
    except jwt.ExpiredSignatureError:
        return jsonify({'error': 'Token expired'}), 401
    except jwt.InvalidTokenError as e:
        return jsonify({'error': f'Invalid token: {str(e)}'}), 401

@app.route('/private', methods=['GET'])
def private():
    """Endpoint per testare la chiave privata"""
    return jsonify({
        'private_key': private_pem.decode('utf-8'),
        'message': 'Private key accessed successfully'
    })

@app.route('/info')
def info():
    return jsonify({
        'message': 'JWT Backend Ready',
        'jwks_url': '/.well-known/jwks.json',
        'protected_url': '/protected'
    })

if __name__ == '__main__':
    print("🔑 JWT Backend started")
    print("📋 JWKS endpoint: http://localhost:5001/.well-known/jwks.json")
    print("🔒 Protected endpoint: http://localhost:5001/protected")
    app.run(host='0.0.0.0', port=5001, debug=True)
```

### Backend 3: Simple Auth Provider
```python
# auth_provider.py
from flask import Flask, request, jsonify
import time
import hashlib

app = Flask(__name__)

# Database stupido
USERS = {'alice': 'pass123', 'bob': 'pass456'}
CLIENTS = {'app1': 'secret1', 'app2': 'secret2'}

@app.route('/validate', methods=['POST'])
def validate():
    """Valida username/password o client_id/secret"""
    data = request.json
    
    if 'username' in data:
        # User validation
        user = data.get('username')
        pwd = data.get('password')
        if user in USERS and USERS[user] == pwd:
            return jsonify({
                'valid': True,
                'type': 'user',
                'subject': user,
                'scopes': ['read', 'write']
            })
    
    elif 'client_id' in data:
        # Client validation  
        client = data.get('client_id')
        secret = data.get('client_secret')
        if client in CLIENTS and CLIENTS[client] == secret:
            return jsonify({
                'valid': True,
                'type': 'client', 
                'subject': client,
                'scopes': ['api_access']
            })
    
    return jsonify({'valid': False}), 401

@app.route('/users')
def list_users():
    return jsonify({'users': list(USERS.keys()), 'clients': list(CLIENTS.keys())})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5002, debug=True)
```

---

## Esercizio 1: Token Issuer (Giorno 1)

### Obiettivo
Creare un token endpoint OAuth2 che rilasci JWT firmati.

### Task Unico
Implementare endpoint DataPower `/oauth/token` (porta 8080) che:

1. **Accetti Basic Auth** - validi contro auth provider (porta 5002)
2. **Accetti Client Credentials** - stesso validation endpoint
3. **Rilasci JWT** - usa le chiavi del JWT backend (porta 5001)
4. **Response standard** - formato OAuth2

### Implementazione
- Usa **GatewayScript** per tutto
- Recupera JWK da `http://localhost:5001/.well-known/jwks.json`
- Chiama validator `http://localhost:5002/validate`
- Genera JWT con claim: `sub`, `iss`, `exp`, `scope`

### Test
```bash
# Test 1: Basic Auth
curl -X POST http://datapower:8080/oauth/token \
  -H "Authorization: Basic $(echo -n 'alice:pass123' | base64)" \
  -d "grant_type=password"

# Test 2: Client Credentials
curl -X POST http://datapower:8080/oauth/token \
  -d "grant_type=client_credentials&client_id=app1&client_secret=secret1"
```

**Risultato atteso:** Token JWT valido

---

## Esercizio 2: Gateway di Protezione (Giorno 2-3)

### Obiettivo
Creare due gateway che trasformino l'autenticazione.

### Task 2A: JWT → Echo (Protezione JWT)
Gateway DataPower porta 8081 → Echo server porta 5000

**Cosa fare:**
- Validare JWT Bearer token
- Verificare contro JWT backend (porta 5001)  
- Inoltrare richiesta pulita all'echo server
- Aggiungere header `X-User: <subject>`

### Task 2B: Echo → JWT (Trasformazione)
Gateway DataPower porta 8082 → JWT backend porta 5001

**Cosa fare:**
- Ricevere richieste senza auth
- Generare JWT automaticamente (utente fisso "gateway-user")
- Inoltrare con `Authorization: Bearer <jwt>`

### Implementazione Semplificata
```javascript
// Esempio GatewayScript per validazione JWT
var authHeader = session.name('var://service/header/Authorization');
if (!authHeader || !authHeader.startsWith('Bearer ')) {
    session.reject('JWT required');
}

var token = authHeader.substring(7);
// Chiamare JWT backend per validazione
// Inoltrare se OK
```

### Test
```bash
# Test 2A: 
# Prima ottenere JWT dall'esercizio 1, poi:
curl -H "Authorization: Bearer <jwt>" http://datapower:8081/echo

# Test 2B:
curl http://datapower:8082/protected
```

---

## Challenge Bonus (Opzionale)

### PKCE Mini-Implementation
Se finisci prima, aggiungi endpoint PKCE basic:

```javascript
// GatewayScript per PKCE
function validatePKCE(verifier, challenge) {
    var crypto = require('crypto');
    var hash = crypto.createHash('sha256').update(verifier).digest('base64url');
    return hash === challenge;
}
```

---

## Setup Rapido

### 1. Avvia Backend
```bash
# Terminale 1
python simple_echo.py

# Terminale 2
python jwt_backend.py

# Terminale 3  
python auth_provider.py
```

### 2. Verifica Backend
```bash
curl http://localhost:5000/echo
curl http://localhost:5001/info
curl http://localhost:5002/users
```

### 3. Implementa DataPower
- Crea domain `OAuth_Lab`
- 3 Multi-Protocol Gateway
- Policy con GatewayScript

## Checklist Finale

**Giorno 1:**
- [ ] Token endpoint funzionante
- [ ] Basic Auth → JWT
- [ ] Client Credentials → JWT

**Giorno 2:**
- [ ] Gateway JWT protection
- [ ] Gateway JWT injection

**Giorno 3:**
- [ ] Test completi
- [ ] Debug e fix
- [ ] (Bonus) PKCE

## Deliverables

1. **Export DataPower** con 3 gateway configurati
2. **Script di test** che dimostri tutti i flussi
3. **Screenshot** dei test funzionanti

**Tempo:** 2-3 giorni massimo  
**Focus:** Implementazione pratica, non teoria
