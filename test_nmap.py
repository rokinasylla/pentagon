"""
Test de l'outil Nmap, indépendamment de tout agent ou LLM.

Exécution : python test_nmap.py

ATTENTION : ce test émet du trafic actif vers la cible.
N'exécuter QUE sur des cibles dont vous avez l'autorisation légale.
"""

import json
from pentagon.tools.nmap_tool import run_nmap_scan, SCAN_PROFILES


def main():
    print("=" * 70)
    print("PENTAGON — Test de l'outil Nmap")
    print("=" * 70)
    
    # Liste les profils disponibles
    print("\n📋 Profils de scan disponibles :")
    for name, config in SCAN_PROFILES.items():
        print(f"   • {name:14s} → {config['description']}")
    
    # Cible : ton application (autorisation = OK)
    target = "techshop-vuln.rokina-sylla.me"
    profile = "web_focused"
    
    print(f"\n🎯 Cible      : {target}")
    print(f"⚙️  Profil     : {profile}")
    print(f"⏱️  Démarrage du scan (peut prendre 30-90 secondes)...")
    print("-" * 70)
    
    # Lance le scan
    result = run_nmap_scan(target=target, profile=profile)
    
    # Affiche le résultat
    if result["status"] == "success":
        print(f"\n✓ Scan terminé en {result['duration_seconds']:.1f}s")
        print(f"\n📊 RÉSUMÉ")
        print(f"   • Hôtes scannés    : {result['summary']['hosts_scanned']}")
        print(f"   • Hôtes actifs     : {result['summary']['hosts_up']}")
        print(f"   • Ports ouverts    : {result['summary']['open_ports_total']}")
        print(f"   • Services         : {', '.join(result['summary']['services_detected']) or '(aucun)'}")
        
        # Détail par hôte
        for host, host_data in result["hosts"].items():
            print(f"\n🖥️  Hôte : {host}")
            print(f"   État       : {host_data['state']}")
            print(f"   Hostnames  : {host_data['hostnames']}")
            print(f"   Adresses   : {host_data['addresses']}")
            
            if host_data["ports"]:
                print(f"   Ports détectés :")
                for p in host_data["ports"]:
                    if p["state"] == "open":
                        service_str = p["service"]
                        if p["product"]:
                            service_str += f" ({p['product']}"
                            if p["version"]:
                                service_str += f" {p['version']}"
                            service_str += ")"
                        print(f"      🟢 {p['port']:5d}/{p['protocol']:3s}  {service_str}")
            else:
                print(f"   Aucun port détecté.")
    else:
        print(f"\n✗ Erreur : {result['error']}")
    
    print("\n" + "=" * 70)
    print("Test terminé.")
    print("=" * 70)


if __name__ == "__main__":
    main()
