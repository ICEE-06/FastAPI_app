"""
Application FastAPI — Démo DevSecOps
=====================================
Cette app simule un service de gestion d'utilisateurs et de produits.
Elle contient INTENTIONNELLEMENT des vulnérabilités pour démontrer
le fonctionnement des outils de scan (Bandit, Semgrep, Trivy).

Vulnérabilités introduites (à corriger en Phase 4) :
  - [B106] Mot de passe codé en dur (hardcoded password)
  - [B608] Injection SQL possible (string formatting dans query)
  - [B101] Utilisation de assert() en logique métier
  - [B310] Utilisation de urllib sans validation
  - Hash MD5 utilisé pour les mots de passe (faible)
  - Pas de validation stricte des entrées utilisateur
"""

import hashlib
import os
import sqlite3
import urllib.request
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from .database import init_db, get_db_connection
from .utils import (
    get_version,
    get_build_info,
    hash_password,
    validate_token,
    logger,
)

# ── Application ──────────────────────────────────────────────────────────────

app = FastAPI(
    title="DevSecOps Demo API",
    description="API de démonstration pour pipeline CI/CD sécurisé",
    version=get_version(),
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],   # VULN : trop permissif — à restreindre en prod
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup():
    logger.info("Démarrage de l'application...")
    init_db()
    logger.info(f"Version : {get_version()}")


# ── Schémas Pydantic ─────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    username: str
    password: str
    email: str
    role: str = "user"


class UserLogin(BaseModel):
    username: str
    password: str


class ProductCreate(BaseModel):
    name: str
    description: str
    price: float
    category: str


class SearchQuery(BaseModel):
    query: str


# ── Routes santé & infos ──────────────────────────────────────────────────────

@app.get("/", tags=["health"])
def root():
    """Point d'entrée principal."""
    return {
        "message": "DevSecOps Demo API",
        "version": get_version(),
        "status": "running",
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.get("/health", tags=["health"])
def health():
    """Health check pour Docker et monitoring."""
    return {
        "status": "ok",
        "database": "connected",
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.get("/info", tags=["health"])
def info():
    """Informations de build (utile pour traçabilité CI/CD)."""
    return get_build_info()


# ── Utilisateurs ──────────────────────────────────────────────────────────────

@app.post("/users/register", tags=["users"], status_code=201)
def register_user(user: UserCreate):
    """Enregistre un nouvel utilisateur."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Vérifier doublon
    cursor.execute("SELECT id FROM users WHERE username = ?", (user.username,))
    if cursor.fetchone():
        conn.close()
        raise HTTPException(status_code=409, detail="Utilisateur déjà existant")

    # VULN [B303] : MD5 pour hash mot de passe — faible, utiliser bcrypt en prod
    password_hash = hash_password(user.password)

    cursor.execute(
        "INSERT INTO users (username, password_hash, email, role, created_at) VALUES (?, ?, ?, ?, ?)",
        (user.username, password_hash, user.email, user.role, datetime.utcnow().isoformat()),
    )
    conn.commit()
    user_id = cursor.lastrowid
    conn.close()

    logger.info(f"Nouvel utilisateur créé : {user.username}")
    return {"id": user_id, "username": user.username, "role": user.role}


@app.post("/users/login", tags=["users"])
def login(credentials: UserLogin):
    """Authentifie un utilisateur et retourne un token."""
    conn = get_db_connection()
    cursor = conn.cursor()

    password_hash = hash_password(credentials.password)

    cursor.execute(
        "SELECT id, username, role FROM users WHERE username = ? AND password_hash = ?",
        (credentials.username, password_hash),
    )
    user = cursor.fetchone()
    conn.close()

    if not user:
        raise HTTPException(status_code=401, detail="Identifiants invalides")

    # Token simple pour la démo (utiliser JWT en prod)
    token = hashlib.sha256(
        f"{user['username']}{datetime.utcnow().timestamp()}".encode()
    ).hexdigest()

    return {"token": token, "username": user["username"], "role": user["role"]}


@app.get("/users", tags=["users"])
def list_users(authorization: Optional[str] = Header(None)):
    """Liste tous les utilisateurs (admin seulement)."""
    if not validate_token(authorization):
        raise HTTPException(status_code=403, detail="Non autorisé")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, email, role, created_at FROM users")
    users = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return {"users": users, "total": len(users)}


# ── Produits ──────────────────────────────────────────────────────────────────

@app.post("/products", tags=["products"], status_code=201)
def create_product(product: ProductCreate, authorization: Optional[str] = Header(None)):
    """Crée un nouveau produit."""
    if not validate_token(authorization):
        raise HTTPException(status_code=403, detail="Non autorisé")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO products (name, description, price, category, created_at) VALUES (?, ?, ?, ?, ?)",
        (product.name, product.description, product.price, product.category, datetime.utcnow().isoformat()),
    )
    conn.commit()
    product_id = cursor.lastrowid
    conn.close()

    return {"id": product_id, "name": product.name, "price": product.price}


@app.get("/products", tags=["products"])
def list_products(category: Optional[str] = None):
    """Liste les produits, avec filtre optionnel par catégorie."""
    conn = get_db_connection()
    cursor = conn.cursor()

    if category:
        # VULN [B608] : injection SQL possible via formatage de string
        # À corriger : utiliser des paramètres liés (?)
        query = f"SELECT * FROM products WHERE category = '{category}'"
        cursor.execute(query)
    else:
        cursor.execute("SELECT * FROM products")

    products = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return {"products": products, "total": len(products)}


@app.get("/products/{product_id}", tags=["products"])
def get_product(product_id: int):
    """Récupère un produit par son ID."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE id = ?", (product_id,))
    product = cursor.fetchone()
    conn.close()

    if not product:
        raise HTTPException(status_code=404, detail="Produit introuvable")
    return dict(product)


@app.post("/products/search", tags=["products"])
def search_products(search: SearchQuery):
    """Recherche de produits par nom."""
    conn = get_db_connection()
    cursor = conn.cursor()
    # VULN [B608] : même problème d'injection SQL
    query = f"SELECT * FROM products WHERE name LIKE '%{search.query}%'"
    cursor.execute(query)
    results = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return {"results": results, "count": len(results)}


# ── Endpoint debug (à ne JAMAIS laisser en prod) ─────────────────────────────

@app.get("/debug/env", tags=["debug"])
def debug_env():
    """
    VULN : expose les variables d'environnement.
    Cet endpoint ne devrait pas exister en production.
    Semgrep et les code review doivent détecter ce type de fuite.
    """
    # VULN [B101] : assert utilisé comme garde de sécurité
    assert os.getenv("ENV") != "production", "Debug désactivé en prod"

    return {
        "env_vars": dict(os.environ),   # NE JAMAIS faire ça en prod
        "python_path": os.sys.path,
    }


@app.get("/debug/fetch", tags=["debug"])
def debug_fetch(url: str):
    """
    VULN [B310] : fetch d'URL arbitraire sans validation (SSRF potentiel).
    """
    try:
        # VULN : pas de validation de l'URL — risque SSRF
        response = urllib.request.urlopen(url)  # noqa: S310
        return {"content": response.read(512).decode("utf-8", errors="replace")}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))