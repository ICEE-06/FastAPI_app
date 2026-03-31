"""
test_app.py — Suite de tests
==============================
Tests unitaires et d'intégration pour la démo DevSecOps.
Ces tests sont exécutés dans le pipeline Jenkins (Stage 1 ou Stage 2).

Lancer manuellement :
    pytest tests/ -v --tb=short
    pytest tests/ -v --cov=src --cov-report=xml:reports/coverage.xml
"""

import pytest
from fastapi.testclient import TestClient

from src.app import app
from src.database import init_db
from src.utils import hash_password, get_version, sanitize_input


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def setup_db():
    """Initialise la DB avant chaque test."""
    init_db()


@pytest.fixture
def client():
    """Client de test FastAPI."""
    return TestClient(app)


@pytest.fixture
def auth_header():
    """Header d'autorisation avec le token admin de démo."""
    return {"Authorization": "Bearer super-secret-admin-token-1234"}


@pytest.fixture
def registered_user(client):
    """Crée un utilisateur de test et retourne ses credentials."""
    payload = {
        "username": "testuser",
        "password": "testpass123",
        "email": "test@example.com",
        "role": "user",
    }
    client.post("/users/register", json=payload)
    return payload


# ── Tests : Health & Info ─────────────────────────────────────────────────────

class TestHealth:

    def test_root_returns_200(self, client):
        resp = client.get("/")
        assert resp.status_code == 200

    def test_root_has_version(self, client):
        data = client.get("/").json()
        assert "version" in data
        assert "status" in data
        assert data["status"] == "running"

    def test_health_endpoint(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_info_endpoint(self, client):
        resp = client.get("/info")
        data = resp.json()
        assert resp.status_code == 200
        assert "version" in data
        assert "build_number" in data
        assert "git_commit" in data


# ── Tests : Utilisateurs ──────────────────────────────────────────────────────

class TestUsers:

    def test_register_user_success(self, client):
        resp = client.post("/users/register", json={
            "username": "alice",
            "password": "password123",
            "email": "alice@example.com",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["username"] == "alice"
        assert "id" in data

    def test_register_duplicate_user(self, client):
        payload = {"username": "bob", "password": "pass", "email": "bob@test.com"}
        client.post("/users/register", json=payload)
        resp = client.post("/users/register", json=payload)
        assert resp.status_code == 409

    def test_login_valid_credentials(self, client, registered_user):
        resp = client.post("/users/login", json={
            "username": registered_user["username"],
            "password": registered_user["password"],
        })
        assert resp.status_code == 200
        assert "token" in resp.json()

    def test_login_invalid_password(self, client, registered_user):
        resp = client.post("/users/login", json={
            "username": registered_user["username"],
            "password": "mauvais-mot-de-passe",
        })
        assert resp.status_code == 401

    def test_list_users_requires_auth(self, client):
        resp = client.get("/users")
        assert resp.status_code == 403

    def test_list_users_with_auth(self, client, auth_header):
        resp = client.get("/users", headers=auth_header)
        assert resp.status_code == 200
        assert "users" in resp.json()


# ── Tests : Produits ──────────────────────────────────────────────────────────

class TestProducts:

    def test_list_products_public(self, client):
        """Les produits sont accessibles sans authentification."""
        resp = client.get("/products")
        assert resp.status_code == 200
        data = resp.json()
        assert "products" in data
        assert "total" in data
        # Les seeds doivent être présents
        assert data["total"] >= 5

    def test_filter_products_by_category(self, client):
        resp = client.get("/products?category=informatique")
        assert resp.status_code == 200
        products = resp.json()["products"]
        for p in products:
            assert p["category"] == "informatique"

    def test_get_product_by_id(self, client):
        resp = client.get("/products/1")
        assert resp.status_code == 200
        data = resp.json()
        assert "name" in data
        assert "price" in data

    def test_get_product_not_found(self, client):
        resp = client.get("/products/99999")
        assert resp.status_code == 404

    def test_create_product_requires_auth(self, client):
        resp = client.post("/products", json={
            "name": "Test",
            "description": "desc",
            "price": 9.99,
            "category": "test",
        })
        assert resp.status_code == 403

    def test_create_product_with_auth(self, client, auth_header):
        resp = client.post("/products", headers=auth_header, json={
            "name": "Nouveau produit",
            "description": "Un produit de test",
            "price": 19.99,
            "category": "test",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "Nouveau produit"
        assert data["price"] == 19.99

    def test_search_products(self, client):
        resp = client.post("/products/search", json={"query": "Laptop"})
        assert resp.status_code == 200
        data = resp.json()
        assert "results" in data
        assert data["count"] >= 1


# ── Tests : Sécurité (démonstration des vulnérabilités) ──────────────────────

class TestSecurityVulnerabilities:
    """
    Ces tests démontrent les vulnérabilités présentes dans l'app.
    En Phase 4, ils seront modifiés pour prouver que les failles sont corrigées.
    """

    def test_sql_injection_in_category_filter(self, client):
        """
        VULN [B608] : le filtre catégorie est vulnérable à l'injection SQL.
        Cette requête ne devrait pas retourner tous les produits.
        """
        # Injection SQL basique : ' OR '1'='1
        resp = client.get("/products?category=' OR '1'='1")
        # En prod sécurisée, cela devrait retourner 0 résultats ou une erreur
        # Ici, l'injection fonctionne — c'est le but de la démo
        assert resp.status_code == 200  # L'app ne plante pas, mais la requête est corrompue

    def test_debug_env_exposed(self, client):
        """
        VULN : endpoint de debug qui expose les variables d'environnement.
        Doit être supprimé ou protégé en production.
        """
        import os
        os.environ["ENV"] = "development"  # Forcer env dev pour le test
        resp = client.get("/debug/env")
        # En dev, retourne les env vars — dangereux !
        assert resp.status_code in [200, 500]  # 500 si assert échoue

    def test_password_hashed_with_md5(self):
        """
        VULN [B303] : les mots de passe sont hachés en MD5.
        MD5 est insuffisant pour le stockage de mots de passe.
        En Phase 4, remplacer par bcrypt.
        """
        hashed = hash_password("monmotdepasse")
        # MD5 produit 32 caractères hex
        assert len(hashed) == 32
        # MD5 est déterministe et sans salt — vulnérable aux rainbow tables
        assert hashed == hash_password("monmotdepasse")

    def test_sanitize_input_insufficient(self):
        """
        La fonction sanitize_input ne protège pas contre toutes les injections.
        """
        # Ces payloads passent la sanitisation basique
        payload_1 = "test` OR 1=1--"
        payload_2 = "test UNION SELECT * FROM users"

        result_1 = sanitize_input(payload_1)
        result_2 = sanitize_input(payload_2)

        # La sanitisation ne bloque pas ces cas
        assert "UNION" in result_2   # Injection non bloquée


# ── Tests : Utilitaires ───────────────────────────────────────────────────────

class TestUtils:

    def test_get_version_returns_string(self):
        version = get_version()
        assert isinstance(version, str)
        assert len(version) > 0

    def test_hash_password_consistent(self):
        """Un même mot de passe doit toujours produire le même hash."""
        assert hash_password("abc") == hash_password("abc")

    def test_hash_password_different_inputs(self):
        """Des mots de passe différents doivent produire des hashes différents."""
        assert hash_password("abc") != hash_password("xyz")