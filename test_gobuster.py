"""
Test de l'outil Gobuster, indépendamment de tout agent.

Exécution : python test_gobuster.py

ATTENTION : génère beaucoup de trafic HTTP vers la cible.
"""

from pentagon.tools.gobuster_tool import run_gobuster_scan


def main():
    print("=" * 70)
    print("PENTAGON — Test de l'outil Gobuster (mode SPA-aware)")
    print("=" * 70)
    
    target = "https://techshop-vuln.rokina-sylla.me"
    wordlist = "small"
    
    # SPA detection : on exclut la taille du index.html retourné en fallback
    # (détectée lors du précédent scan : 611 bytes)
    exclude_length = "611"
    
    print(f"\n🎯 Cible          : {target}")
    print(f"📖 Wordlist       : {wordlist}")
    print(f"🚫 Tailles exclues : {exclude_length} bytes (filtre SPA fallback)")
    print(f"⏳ Démarrage du scan Gobuster (peut prendre 2-10 minutes)...")
    print("-" * 70)
    
    result = run_gobuster_scan(
        target_url=target,
        wordlist=wordlist,
        exclude_length=exclude_length,
    )
    
    if result["status"] in ("success", "partial"):
        print(f"\n✓ Scan terminé en {result['duration_seconds']:.1f}s")
        print(f"  Wordlist : {result['wordlist_used']} ({result['wordlist_size']} mots)")
        print(f"  Threads  : {result['threads_used']}")
        
        print(f"\n📊 RÉSULTATS")
        print(f"  Endpoints trouvés (hors faux-positifs SPA) : {result['findings_count']}")
        
        if result["findings_count"] == 0:
            print(f"\n  💡 Aucun endpoint backend distinct détecté.")
            print(f"     L'application est une SPA pure : le routing est géré côté")
            print(f"     client (React/Vue/Angular). Gobuster ne peut pas découvrir")
            print(f"     les vraies routes via brute-force HTTP. Une analyse du")
            print(f"     bundle JavaScript serait plus pertinente.")
        else:
            if result["findings_by_status"]:
                print(f"\n  📈 Répartition par code HTTP :")
                for status_code, paths in sorted(result["findings_by_status"].items()):
                    print(f"     {status_code} : {len(paths)} endpoint(s)")
            
            if result["sensitive_findings"]:
                print(f"\n🚨 ENDPOINTS SENSIBLES DÉCOUVERTS ({len(result['sensitive_findings'])}) :")
                for f in result["sensitive_findings"]:
                    print(f"   ⚠️  {f['path']:40s}  [{f['status_code']}]  {f['sensitivity_reason']}")
            
            if result["findings"]:
                print(f"\n📋 TOUS LES FINDINGS :")
                for f in result["findings"][:30]:
                    size_str = f"  {f['size_bytes']}b" if f['size_bytes'] else ""
                    redirect_str = f"  → {f['redirect_to']}" if f['redirect_to'] else ""
                    print(f"   • {f['path']:40s}  [{f['status_code']}]{size_str}{redirect_str}")
                if len(result["findings"]) > 30:
                    print(f"   ... et {len(result['findings']) - 30} autres")
        
        if result["status"] == "partial":
            print(f"\n⚠️  Note : {result['error']}")
    else:
        print(f"\n✗ Erreur : {result['error']}")
    
    print("\n" + "=" * 70)
    print("Test terminé.")
    print("=" * 70)


if __name__ == "__main__":
    main()
