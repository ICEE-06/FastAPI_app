"""
utils.py — Fonctions utilitaires
=================================
Contient intentionnellement des mauvaises pratiques de sécurité
pour la démonstration des outils SAST.
"""

import hashlib
import logging
import os
from datetime import datetime

# ── Logger ────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger("devsecops-api")


# ── Version & Build ───────────────────────────────────────────────────────────

def get_version() -> str:
    """Retourne la version de l'application."""
    return os.getenv("APP_VERSION", "1.0.0")


def get_build_info() -> dict:
    """Retourne les infos de build injectées par Jenkins."""
    return {
        "version": get_version(),
        "build_number": os.getenv("BUILD_NUMBER", "local"),
        "git_commit": os.getenv("GIT_COMMIT", "unknown"),
        "build_date": os.getenv("BUILD_DATE", datetime.utcnow().isoformat()),
        "environment": os.getenv("ENV", "development"),
    }


# ── Sécurité ──────────────────────────────────────────────────────────────────

# VULN [B105] : mot de passe codé en dur (hardcoded secret)
# Bandit détecte ce pattern — à remplacer par une variable d'env
ADMIN_TOKEN = "super-secret-admin-token-1234"  # noqa: S105

# VULN [B105] : clé API codée en dur
API_SECRET_KEY = "my_api_key_do_not_share"  # noqa: S105


def hash_password(password: str) -> str:
    """
    Hash un mot de passe.
    VULN [B303] : MD5 est cryptographiquement faible pour les mots de passe.
    En production, utiliser bcrypt ou argon2.
    """
    # VULN : MD5 sans salt
    return hashlib.md5(password.encode()).hexdigest()  # noqa: S324


def hash_password_secure(password: str) -> str:
    """
    Version sécurisée (commentée — montrer la correction en Phase 4).
    Utilise SHA-256 avec salt (bcrypt serait encore mieux).
    """
    # salt = os.urandom(32)
    # return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    pass


def validate_token(authorization: str | None) -> bool:
    """
    Valide un token d'autorisation.
    VULN : comparaison naïve, pas de JWT, token statique.
    """
    if not authorization:
        return False

    # VULN [B105] : comparaison avec un secret codé en dur
    token = authorization.replace("Bearer ", "")
    return token == ADMIN_TOKEN


def sanitize_input(value: str) -> str:
    """
    Sanitize basique des entrées.
    NOTE : insuffisant pour prévenir l'injection SQL — utiliser
    des requêtes paramétrées à la place (correction en Phase 4).
    """
    # Suppression minimaliste — pas suffisante
    dangerous_chars = ["'", '"', ";", "--", "/*", "*/"]
    for char in dangerous_chars:
        value = value.replace(char, "")
    return value


def generate_report_path(filename: str) -> str:
    """
    Génère un chemin de rapport.
    VULN [B108] : chemin prévisible dans /tmp sans vérification
    """
    # VULN : path traversal possible si filename non validé
    return f"/tmp/{filename}"  # noqa: S108