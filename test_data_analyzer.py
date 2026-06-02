"""
Test de l'outil data_analyzer.

Exécution : python test_data_analyzer.py

On le teste sur les données réelles de TechShop (récupérées via l'API),
mais l'outil lui-même ne connaît rien de TechShop : il analyse une
structure JSON quelconque.
"""

import requests
from pentagon.tools.data_analyzer_tool import run_data_analysis


def main():
    print("=" * 70)
    print("PENTAGON — Test de l'outil d'analyse de données sensibles")
    print("=" * 70)
    
    # On récupère des données réelles depuis une API (ici TechShop pour valider)
    # L'outil analyserait n'importe quelle réponse JSON de la même façon.
    url = "https://techshop-backend-cc1t.onrender.com/api/users"
    print(f"\n📥 Récupération de données depuis : {url}")
    
    try:
        response = requests.get(url, timeout=30)
        data = response.json()
        print(f"   ✓ {len(data) if isinstance(data, list) else 1} enregistrement(s) récupéré(s)")
    except Exception as e:
        print(f"   ✗ Erreur : {e}")
        return
    
    # Analyse des données (l'outil est générique)
    print(f"\n🔬 Analyse des données...")
    result = run_data_analysis(data)
    
    print(f"\n✓ Analyse terminée en {result['duration_seconds']:.3f}s")
    
    s = result["summary"]
    print(f"\n📊 RÉSUMÉ")
    print(f"   • Hashes faibles      : {s['weak_hash_count']}")
    print(f"   • Mots de passe cassés : {s['cracked_password_count']}")
    print(f"   • Cartes exposées     : {s['exposed_card_count']}")
    
    if result["cracked_passwords"]:
        print(f"\n🔓 MOTS DE PASSE CASSÉS :")
        for c in result["cracked_passwords"]:
            print(f"   • Champ '{c['field']}' ({c['algorithm']}) → mot de passe : \"{c['plaintext']}\"")
    
    if result["exposed_cards"]:
        print(f"\n💳 CARTES BANCAIRES EXPOSÉES :")
        for c in result["exposed_cards"]:
            print(f"   • {c['card_type']} : {c['masked']} (champ '{c['field']}')")
    
    if result["findings"]:
        print(f"\n🚨 FINDINGS ({len(result['findings'])}) :")
        for f in result["findings"]:
            print(f"\n   [{f['severity'].upper()}] {f['title']}")
            print(f"      OWASP : {f['owasp']}")
            print(f"      CWE   : {f['cwe']}")
            print(f"      {f['description']}")
    
    print("\n" + "=" * 70)
    print("Test terminé.")
    print("=" * 70)


if __name__ == "__main__":
    main()
