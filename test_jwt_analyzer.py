"""
Test de l'outil jwt_analyzer.

Exécution : python test_jwt_analyzer.py

On teste avec plusieurs JWT : un avec secret faible, un avec algo 'none',
un avec données sensibles. L'outil est générique : il analyse tout JWT.
"""

import base64
import hashlib
import hmac
import json
from pentagon.tools.jwt_analyzer_tool import run_jwt_analysis


def make_jwt(payload: dict, secret: str = "secret", alg: str = "HS256") -> str:
    """Fabrique un JWT de test (pour valider l'outil)."""
    header = {"alg": alg, "typ": "JWT"}
    
    def b64(data):
        return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()
    
    header_b64 = b64(header)
    payload_b64 = b64(payload)
    signing_input = f"{header_b64}.{payload_b64}".encode()
    
    if alg == "none":
        signature = ""
    else:
        sig = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
        signature = base64.urlsafe_b64encode(sig).rstrip(b"=").decode()
    
    return f"{header_b64}.{payload_b64}.{signature}"


def analyze_and_print(label: str, token: str):
    print(f"\n{'─' * 70}")
    print(f">>> {label}")
    print(f"{'─' * 70}")
    print(f"Token : {token[:50]}...")
    
    result = run_jwt_analysis(token)
    
    if result["status"] != "success":
        print(f"  ✗ {result['error']}")
        return
    
    print(f"  Algorithme : {result['algorithm']}")
    print(f"  Payload    : {result['payload']}")
    if result["cracked_secret"]:
        print(f"  🔓 SECRET CASSÉ : '{result['cracked_secret']}'")
    
    if result["findings"]:
        print(f"\n  🚨 FAIBLESSES DÉTECTÉES ({len(result['findings'])}) :")
        for f in result["findings"]:
            print(f"     [{f['severity'].upper()}] {f['title']}")
            print(f"        OWASP : {f['owasp']} | CWE : {f['cwe']}")
    else:
        print(f"  ✓ Aucune faiblesse détectée")


def main():
    print("=" * 70)
    print("PENTAGON — Test de l'outil d'analyse JWT")
    print("=" * 70)
    
    # Cas 1 : JWT avec secret faible "secret"
    token1 = make_jwt({"sub": "user1", "role": "user", "exp": 9999999999}, secret="secret")
    analyze_and_print("JWT avec secret faible ('secret')", token1)
    
    # Cas 2 : JWT avec algorithme 'none'
    token2 = make_jwt({"sub": "admin", "role": "admin"}, alg="none")
    analyze_and_print("JWT avec algorithme 'none'", token2)
    
    # Cas 3 : JWT sans expiration + données sensibles
    token3 = make_jwt({"sub": "user2", "password": "leaked", "role": "admin"}, secret="123456")
    analyze_and_print("JWT sans exp + données sensibles + secret faible", token3)
    
    # Cas 4 : JWT avec secret fort (ne devrait pas être cassé)
    token4 = make_jwt({"sub": "user3", "exp": 9999999999}, secret="X9k$2mP!qR7zW3nY8vL5tA1bC6dE0fG")
    analyze_and_print("JWT avec secret fort (ne doit PAS être cassé)", token4)
    
    print("\n" + "=" * 70)
    print("Test terminé.")
    print("=" * 70)


if __name__ == "__main__":
    main()
