"""
Tests hors-ligne du routage de modele par role (Lot L1, SS15.1).

Ne depend QUE de la bibliotheque standard : ni openai, ni cle API, ni reseau.
La logique de selection (fournisseur/modele/parametres par role) et le suivi
de budget vivent dans pentagon/core/model_router.py et sont entierement
testables ici.

Execution :
    python -m unittest tests.test_model_router        (depuis la racine du repo)
    python tests/test_model_router.py
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from pentagon.core.model_router import (
    BudgetExceededError,
    BudgetTracker,
    ModelRouter,
)

# Config minimale ecrite sur disque pour des tests deterministes, independants
# du contenu reel de pentagon/config/models.json.
SAMPLE_CONFIG = {
    "default_provider": "deepseek",
    "default_model": "deepseek-chat",
    "default_params": {"temperature": 0.3, "max_tokens": 2000},
    "providers": {
        "deepseek": {
            "base_url": "https://api.deepseek.com",
            "api_key_env": "DEEPSEEK_API_KEY",
        },
        "anthropic": {
            "base_url": "https://api.anthropic.com/v1/",
            "api_key_env": "ANTHROPIC_API_KEY",
        },
    },
    "roles": {
        "planner": {
            "provider": "anthropic",
            "model": "claude-opus-5-5",
            "temperature": 0.2,
            "max_tokens": 4000,
        },
        "osint": {"provider": "deepseek", "model": "deepseek-chat"},
    },
    "budget": {"per_campaign_max_tokens": 1000, "warn_ratio": 0.8},
}


def _write_config(data) -> str:
    """Ecrit une config JSON dans un fichier temporaire et renvoie son chemin."""
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    return path


class TestModelRouting(unittest.TestCase):
    def setUp(self):
        self.path = _write_config(SAMPLE_CONFIG)
        self.router = ModelRouter(self.path)

    def tearDown(self):
        os.remove(self.path)

    def test_no_role_uses_defaults(self):
        route = self.router.resolve(None)
        self.assertEqual(route.provider, "deepseek")
        self.assertEqual(route.model, "deepseek-chat")
        self.assertEqual(route.base_url, "https://api.deepseek.com")
        self.assertEqual(route.api_key_env, "DEEPSEEK_API_KEY")
        self.assertEqual(route.temperature, 0.3)
        self.assertEqual(route.max_tokens, 2000)

    def test_known_role_routes_to_its_provider_and_model(self):
        route = self.router.resolve("planner")
        self.assertEqual(route.provider, "anthropic")
        self.assertEqual(route.model, "claude-opus-5-5")
        self.assertEqual(route.base_url, "https://api.anthropic.com/v1/")
        self.assertEqual(route.api_key_env, "ANTHROPIC_API_KEY")
        self.assertEqual(route.temperature, 0.2)
        self.assertEqual(route.max_tokens, 4000)

    def test_role_inherits_default_params_when_unspecified(self):
        # osint ne precise ni temperature ni max_tokens -> defauts globaux.
        route = self.router.resolve("osint")
        self.assertEqual(route.model, "deepseek-chat")
        self.assertEqual(route.temperature, 0.3)
        self.assertEqual(route.max_tokens, 2000)

    def test_unknown_role_falls_back_to_defaults(self):
        route = self.router.resolve("role-inexistant")
        self.assertEqual(route.provider, "deepseek")
        self.assertEqual(route.model, "deepseek-chat")

    def test_missing_config_file_uses_hard_defaults(self):
        router = ModelRouter("/chemin/qui/n/existe/pas.json")
        route = router.resolve("planner")
        # Pas de roles dispo -> repli dur deepseek-chat.
        self.assertEqual(route.provider, "deepseek")
        self.assertEqual(route.model, "deepseek-chat")

    def test_malformed_config_uses_hard_defaults(self):
        path = _write_config("ceci n'est pas un objet")  # JSON valide mais pas un dict
        try:
            router = ModelRouter(path)
            route = router.resolve("planner")
            self.assertEqual(route.model, "deepseek-chat")
        finally:
            os.remove(path)

    def test_shipped_config_loads_with_expected_roles(self):
        # Verifie que le vrai fichier livre est coherent et route les roles reels.
        router = ModelRouter()  # pentagon/config/models.json
        for role in [
            "orchestrator", "planner", "osint", "scanning",
            "web_app", "exploitation", "reporting", "assistant",
        ]:
            route = router.resolve(role)
            self.assertTrue(route.model, f"modele vide pour le role {role}")
            self.assertTrue(route.base_url.startswith("http"))
            self.assertIn("API_KEY", route.api_key_env)


class TestBudgetTracker(unittest.TestCase):
    def test_disabled_when_no_cap(self):
        b = BudgetTracker(max_tokens=0)
        self.assertFalse(b.enabled)
        self.assertIsNone(b.remaining)
        self.assertFalse(b.is_warning)
        self.assertFalse(b.add(10_000))  # jamais d'avertissement
        b.check()  # ne leve pas

    def test_accumulates_and_reports_remaining(self):
        b = BudgetTracker(max_tokens=1000, warn_ratio=0.8)
        b.add(300)
        self.assertEqual(b.used_tokens, 300)
        self.assertEqual(b.remaining, 700)
        self.assertFalse(b.is_warning)

    def test_warns_once_past_threshold(self):
        b = BudgetTracker(max_tokens=1000, warn_ratio=0.8)
        self.assertFalse(b.add(700))   # 700 < 800, pas d'avertissement
        self.assertTrue(b.add(150))    # 850 >= 800 -> avertit (1re fois)
        self.assertTrue(b.is_warning)
        self.assertFalse(b.add(10))    # deja averti -> plus de True

    def test_check_raises_once_cap_reached(self):
        b = BudgetTracker(max_tokens=1000)
        b.add(1000)
        with self.assertRaises(BudgetExceededError):
            b.check()

    def test_remaining_never_negative(self):
        b = BudgetTracker(max_tokens=1000)
        b.add(1500)
        self.assertEqual(b.remaining, 0)

    def test_factory_from_config(self):
        path = _write_config(SAMPLE_CONFIG)
        try:
            router = ModelRouter(path)
            b = router.new_budget_tracker()
            self.assertEqual(b.max_tokens, 1000)
            self.assertEqual(b.warn_ratio, 0.8)
        finally:
            os.remove(path)


if __name__ == "__main__":
    unittest.main(verbosity=2)
