"""
Tests hors-ligne du store de sites per-operator (Lot UI-6).

Stdlib seulement : pas de Flask, pas de réseau.

    python -m unittest tests.test_site_store
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from pentagon.core.site_store import SiteStore, host_of


class TestHost(unittest.TestCase):
    def test_host_of(self):
        self.assertEqual(host_of("https://acme.example.com/path"), "acme.example.com")
        self.assertEqual(host_of("ACME.io"), "acme.io")
        self.assertEqual(host_of(""), "")


class TestSiteStore(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".json")
        os.close(fd)
        os.remove(self.path)  # repartir d'un fichier absent
        self.s = SiteStore(self.path)

    def tearDown(self):
        if os.path.exists(self.path):
            os.remove(self.path)

    def test_authorize_and_lookup(self):
        self.s.authorize("acme-staging.example.com", "n.sylla", ["passive", "active_scan"], "Mandat signé", "a.diop")
        rec = self.s.find("https://acme-staging.example.com/login")
        self.assertIsNotNone(rec)
        self.assertEqual(rec["operator"], "n.sylla")
        self.assertEqual(rec["status"], "autorise")
        self.assertIn("acme-staging.example.com", self.s.authorized_domains())

    def test_persisted_across_instances(self):
        self.s.authorize("shop.acme.io", "n.sylla", ["passive"], "Propriétaire vérifié", "a.diop")
        again = SiteStore(self.path)
        self.assertIsNotNone(again.find("shop.acme.io"))

    def test_for_operator_isolates(self):
        self.s.authorize("a.example.com", "n.sylla", ["passive"], "", "a.diop")
        self.s.authorize("b.example.com", "m.fall", ["passive"], "", "a.diop")
        mine = [r["domain"] for r in self.s.for_operator("n.sylla")]
        self.assertEqual(mine, ["a.example.com"])

    def test_max_categories_deny_by_default(self):
        self.s.authorize("a.example.com", "n.sylla", ["passive", "active_scan"], "", "a.diop")
        # opérateur attribué -> son périmètre
        self.assertEqual(self.s.max_categories("a.example.com", "n.sylla", "user"), ["passive", "active_scan"])
        # autre opérateur -> rien (deny)
        self.assertIsNone(self.s.max_categories("a.example.com", "m.fall", "user"))
        # admin -> tout site autorisé
        self.assertEqual(self.s.max_categories("a.example.com", "a.diop", "admin"), ["passive", "active_scan"])
        # cible inconnue -> rien
        self.assertIsNone(self.s.max_categories("inconnu.example.com", "a.diop", "admin"))

    def test_access_request_flow(self):
        self.s.request_access("intranet.acme.local", "n.sylla")
        self.assertEqual([r["domain"] for r in self.s.pending()], ["intranet.acme.local"])
        # demande = pas encore de périmètre
        self.assertIsNone(self.s.max_categories("intranet.acme.local", "n.sylla", "user"))
        # l'admin valide
        self.s.approve("intranet.acme.local", ["passive"], "Mandat signé", "a.diop", operator="n.sylla")
        self.assertEqual(self.s.pending(), [])
        self.assertEqual(self.s.max_categories("intranet.acme.local", "n.sylla", "user"), ["passive"])

    def test_request_then_reject(self):
        self.s.request_access("x.example.com", "n.sylla")
        self.assertTrue(self.s.reject("x.example.com"))
        self.assertIsNone(self.s.find("x.example.com"))

    def test_request_ignored_if_already_authorized(self):
        self.s.authorize("a.example.com", "n.sylla", ["passive"], "", "a.diop")
        self.s.request_access("a.example.com", "m.fall")
        self.assertEqual(self.s.find("a.example.com")["status"], "autorise")
        self.assertEqual(self.s.pending(), [])

    def test_revoke(self):
        self.s.authorize("a.example.com", "n.sylla", ["passive"], "", "a.diop")
        self.assertTrue(self.s.revoke("a.example.com"))
        self.assertNotIn("a.example.com", self.s.authorized_domains())
        self.assertIsNone(self.s.max_categories("a.example.com", "n.sylla", "user"))

    def test_seed_if_empty(self):
        users = {
            "a.diop": {"role": "admin"},
            "n.sylla": {"role": "user", "sites": ["acme-staging.example.com"]},
        }
        seeded = self.s.seed_if_empty(["acme-staging.example.com", "shop.acme.io"], ["passive", "active_scan"], users)
        self.assertTrue(seeded)
        self.assertEqual(self.s.find("acme-staging.example.com")["operator"], "n.sylla")
        self.assertIsNone(self.s.find("shop.acme.io")["operator"])
        # idempotent : ne ré-amorce pas un store non vide
        self.assertFalse(self.s.seed_if_empty(["x"], [], {}))

    def test_to_public_scope_string(self):
        self.s.authorize("a.example.com", "n.sylla", ["passive", "active_scan"], "", "a.diop")
        self.s.request_access("b.example.com", "m.fall")
        pub = {p["domain"]: p for p in self.s.to_public()}
        self.assertEqual(pub["a.example.com"]["scope"], "passive · active_scan")
        self.assertEqual(pub["b.example.com"]["scope"], "à définir")


if __name__ == "__main__":
    unittest.main(verbosity=2)
