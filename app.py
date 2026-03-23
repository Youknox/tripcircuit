import os
import glob
import uuid
import math
import random
import json
import hashlib
import logging
import re
import time
from functools import wraps
from datetime import datetime, timezone, timedelta
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature

import requests
from bs4 import BeautifulSoup
from flask import Flask, render_template, request, redirect, url_for, session, abort, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from authlib.integrations.flask_client import OAuth
from data import prochain_id
import anthropic
from pydantic import BaseModel
import openai

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "goandtrip-dev-secret-key")
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=30)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"]   = os.environ.get("RENDER", False)  # HTTPS only en prod


# ══════════════════════════════════════════════════════════
#  SÉCURITÉ — logging, rate-limiting, headers, OAuth
# ══════════════════════════════════════════════════════════

# ── 1. Logging structuré ──────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
security_logger = logging.getLogger("goandtrip.security")
api_logger      = logging.getLogger("goandtrip.api")


def _log_api_call(user_id: int, route: str, status: int, duration_ms: float, extra: str = "") -> None:
    """Log structuré pour chaque appel API."""
    api_logger.info(
        "user=%s route=%s status=%d duration_ms=%.0f ip=%s%s",
        user_id,
        route,
        status,
        duration_ms,
        request.remote_addr,
        f" {extra}" if extra else "",
    )


def _log_suspicious(reason: str) -> None:
    """Log une tentative suspecte."""
    security_logger.warning(
        "SUSPICIOUS reason=%s ip=%s user_agent=%s path=%s",
        reason,
        request.remote_addr,
        request.headers.get("User-Agent", "")[:120],
        request.path,
    )


# ── 2. Rate Limiter ───────────────────────────────────────

def _rate_limit_key() -> str:
    """Clé de rate-limit : user_id si connecté, sinon IP."""
    uid = session.get("user_id")
    return f"user:{uid}" if uid else f"ip:{get_remote_address()}"


limiter = Limiter(
    key_func=_rate_limit_key,
    app=app,
    default_limits=[],          # pas de limite globale — on cible les routes sensibles
    storage_uri="memory://",    # en prod : redis://localhost:6379
    strategy="fixed-window",
)


@app.errorhandler(429)
def handle_rate_limit(e):
    _log_suspicious(f"rate_limit_exceeded path={request.path}")
    if request.is_json or request.path.startswith("/api/"):
        return jsonify({
            "error": "Trop de requêtes. Attendez quelques instants avant de réessayer.",
            "retry_after": e.retry_after if hasattr(e, "retry_after") else 60,
        }), 429
    return render_template("429.html"), 429


# ── 3. Validation et sanitisation des inputs ─────────────

# Caractères autorisés pour un nom de ville (lettres, espaces, tirets, apostrophes, accents)
_VILLE_RE = re.compile(r"^[\w\s\-\'\,\.àâäéèêëîïôöùûüçœæÀÂÄÉÈÊËÎÏÔÖÙÛÜÇŒÆ]{1,100}$")

# Patterns d'injection connus
_INJECTION_PATTERNS = re.compile(
    r"(<script|javascript:|on\w+\s*=|select\s+.*from|drop\s+table|union\s+select|--|;--|/\*)",
    re.IGNORECASE,
)


def sanitize_ville(valeur: str) -> str | None:
    """
    Nettoie et valide un nom de ville.
    Retourne la valeur nettoyée ou None si invalide.
    """
    valeur = valeur.strip()
    if not valeur:
        return None
    if len(valeur) > 100:
        return None
    if _INJECTION_PATTERNS.search(valeur):
        _log_suspicious(f"injection_attempt input={valeur[:60]!r}")
        return None
    if not _VILLE_RE.match(valeur):
        return None
    return valeur


def sanitize_transport(valeur: str) -> str | None:
    """Valide le champ transport."""
    valeur = valeur.strip()
    if not valeur or len(valeur) > 60:
        return None
    if _INJECTION_PATTERNS.search(valeur):
        _log_suspicious(f"injection_attempt transport={valeur[:60]!r}")
        return None
    return valeur


# ── 4. En-têtes de sécurité HTTP ─────────────────────────

@app.after_request
def add_security_headers(response):
    # Empêche le sniffing MIME
    response.headers["X-Content-Type-Options"]  = "nosniff"
    # Refuse l'affichage dans un iframe (clickjacking)
    response.headers["X-Frame-Options"]          = "DENY"
    # Protection XSS navigateur (legacy, complète le CSP)
    response.headers["X-XSS-Protection"]         = "1; mode=block"
    # Politique de référant
    response.headers["Referrer-Policy"]           = "strict-origin-when-cross-origin"
    # Cache — ne pas mettre en cache les réponses authentifiées
    if "user_id" in session:
        response.headers["Cache-Control"] = "no-store, private"
    return response


# ── 5. Google OAuth ───────────────────────────────────────

oauth = OAuth(app)
oauth.register(
    name="google",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={"scope": "openid email profile"},
)


@app.route("/login/google")
def login_google():
    """Redirige vers Google pour l'authentification OAuth."""
    if not os.getenv("GOOGLE_CLIENT_ID"):
        # Google OAuth non configuré — redirige vers login classique
        return redirect("/login")
    redirect_uri = os.getenv(
        "GOOGLE_REDIRECT_URI",
        "http://localhost:5000/callback/google",
    )
    return oauth.google.authorize_redirect(redirect_uri)


@app.route("/callback/google")
def callback_google():
    """Reçoit le token Google et connecte (ou crée) l'utilisateur."""
    if not os.getenv("GOOGLE_CLIENT_ID"):
        return redirect("/login")

    try:
        token = oauth.google.authorize_access_token()
    except Exception as exc:
        security_logger.error("Google OAuth error: %s", exc)
        return redirect("/login?erreur=oauth")

    userinfo = token.get("userinfo", {})
    email    = userinfo.get("email", "").lower().strip()

    if not email or "@" not in email:
        return redirect("/login?erreur=oauth")

    users   = charger_users()
    existant = next((u for u in users if u["email"] == email), None)

    if existant:
        user_id = existant["id"]
    else:
        # Création automatique du compte Google
        user_id = max((u["id"] for u in users), default=0) + 1
        users.append({
            "id":     user_id,
            "email":  email,
            "mdp":    "",          # pas de mot de passe pour les comptes OAuth
            "oauth":  "google",
        })
        sauvegarder_users(users)
        security_logger.info("new_google_user email=%s id=%s", email, user_id)

    session.permanent  = True
    session["user_id"] = user_id
    session["email"]   = email
    return redirect("/organiser")   # après OAuth → directement sur le générateur


# ══════════════════════════════════════════════════════════
#  FIN SÉCURITÉ
# ══════════════════════════════════════════════════════════

# ── Client OpenAI ─────────────────────────────────────────
_openai_client: openai.OpenAI | None = None

def _get_openai_client() -> openai.OpenAI:
    """Instancie le client OpenAI une seule fois (lazy singleton)."""
    global _openai_client
    if _openai_client is None:
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise RuntimeError("OPENAI_API_KEY n'est pas définie dans les variables d'environnement.")
        _openai_client = openai.OpenAI(api_key=api_key, timeout=30.0)
    return _openai_client

# ══════════════════════════════════════════════════════════
#  STOCKAGE ISOLÉ PAR UTILISATEUR
#  Tous les fichiers sont dans le sous-dossier data/
#  pour éviter tout mélange de données entre utilisateurs.
# ══════════════════════════════════════════════════════════

DATA_DIR   = "data"
USERS_FILE = os.path.join(DATA_DIR, "users.json")

# Créer le dossier data/ au démarrage (silencieux si déjà existant)
try:
    os.makedirs(DATA_DIR, exist_ok=True)
except OSError:
    pass


def _migrer_fichiers_legacy() -> None:
    """
    Migration unique : copie les anciens fichiers de la racine vers data/.
    Robuste : jamais fatal — toute erreur est juste loggée.
    """
    import shutil
    candidates = (
        ["users.json", "data.json"]
        + glob.glob("data_*.json")
        + glob.glob("trips_*.json")
        + glob.glob("ai_trips_*.json")
    )
    for old_path in candidates:
        new_path = os.path.join(DATA_DIR, os.path.basename(old_path))
        try:
            if os.path.isfile(old_path) and not os.path.exists(new_path):
                shutil.copy2(old_path, new_path)   # copie d'abord
                os.remove(old_path)                # puis supprime l'original
                app.logger.info("migration legacy: %s → %s", old_path, new_path)
        except Exception as exc:
            # Ne jamais crasher au démarrage à cause de la migration
            app.logger.warning("migration legacy skipped %s: %s", old_path, exc)


# ── Gestion des utilisateurs ─────────────────────────────

def charger_users() -> list:
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def sauvegarder_users(users: list) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2, ensure_ascii=False)


def hash_mdp(mdp: str) -> str:
    return hashlib.sha256(mdp.encode()).hexdigest()


# ── Données par utilisateur ──────────────────────────────

def fichier_data(user_id: int) -> str:
    """Retourne le chemin du fichier d'activités d'un utilisateur."""
    return os.path.join(DATA_DIR, f"data_{user_id}.json")


def charger(user_id: int) -> list:
    """Charge les activités d'un utilisateur. Ne fonctionne JAMAIS sans user_id."""
    if not user_id:
        raise ValueError("charger() requiert un user_id valide — données isolées par utilisateur.")
    path = fichier_data(user_id)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def sauvegarder(activites: list, user_id: int) -> None:
    """Sauvegarde les activités d'un utilisateur. Ne fonctionne JAMAIS sans user_id."""
    if not user_id:
        raise ValueError("sauvegarder() requiert un user_id valide — données isolées par utilisateur.")
    os.makedirs(DATA_DIR, exist_ok=True)
    path = fichier_data(user_id)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(activites, f, indent=2, ensure_ascii=False)


# ── Gestion des voyages (trips) ───────────────────────────

def fichier_trips(user_id: int) -> str:
    """Retourne le chemin du fichier de voyages manuels d'un utilisateur."""
    return os.path.join(DATA_DIR, f"trips_{user_id}.json")


def charger_trips(user_id: int) -> list:
    try:
        fichier = fichier_trips(user_id)

        # Vérifie que le fichier existe
        if not os.path.exists(fichier):
            return []

        with open(fichier, "r", encoding="utf-8") as f:
            data = json.load(f)

    except Exception as e:
        print("Erreur charger_trips:", e)
        return []

    # Sécurise les données
    if not isinstance(data, list):
        return []

    return data


def sauvegarder_trips(trips: list, user_id: int) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(fichier_trips(user_id), "w", encoding="utf-8") as f:
        json.dump(trips, f, indent=2, ensure_ascii=False)


def prochain_trip_id(trips: list) -> int:
    return max((t["id"] for t in trips), default=0) + 1


def trouver_trip_par_slug(slug: str) -> dict | None:
    """
    Cherche un voyage par son slug public dans tous les fichiers trips_*.json.
    Retourne {"trip": ..., "owner_id": ...} ou None.
    """
    for path in glob.glob(os.path.join(DATA_DIR, "trips_*.json")):
        try:
            owner_id = int(os.path.basename(path).replace("trips_", "").replace(".json", ""))
        except ValueError:
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                trips = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            continue
        for t in trips:
            if t.get("slug") == slug:
                return {"trip": t, "owner_id": owner_id}
    return None


def trouver_trip_avec_acces(uid: int, trip_id: int) -> dict | None:
    """
    Retourne {"trip": ..., "owner_id": ..., "est_proprio": bool}
    si uid est propriétaire ou collaborateur du voyage trip_id.
    Retourne None si aucun accès.
    """
    # Propriétaire ?
    mes_trips = charger_trips(uid)
    own = next((t for t in mes_trips if t["id"] == trip_id), None)
    if own:
        return {"trip": own, "owner_id": uid, "est_proprio": True}

    # Collaborateur ? — scanner les fichiers des autres utilisateurs
    users = charger_users()
    users_par_id = {u["id"]: u for u in users}
    own_file = fichier_trips(uid)

    for path in glob.glob(os.path.join(DATA_DIR, "trips_*.json")):
        if path == own_file:
            continue
        try:
            owner_id = int(os.path.basename(path).replace("trips_", "").replace(".json", ""))
        except ValueError:
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                trips = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            continue
        for t in trips:
            if t["id"] == trip_id and uid in t.get("collaborateurs", []):
                enrichi = dict(t)
                enrichi["_owner_id"]    = owner_id
                enrichi["_owner_email"] = users_par_id.get(owner_id, {}).get("email", "?")
                return {"trip": enrichi, "owner_id": owner_id, "est_proprio": False}

    return None  # aucun accès


def charger_trips_partages(user_id: int) -> list:
    """
    Retourne tous les voyages d'autres utilisateurs où user_id est collaborateur.
    Chaque trip est enrichi avec _owner_id et _owner_email.
    """
    users = charger_users()
    users_par_id = {u["id"]: u for u in users}
    partages = []
    own_file = fichier_trips(user_id)

    for path in glob.glob(os.path.join(DATA_DIR, "trips_*.json")):
        if path == own_file:
            continue
        try:
            # Extraire l'owner_id depuis le nom du fichier trips_<uid>.json
            owner_id = int(os.path.basename(path).replace("trips_", "").replace(".json", ""))
        except ValueError:
            continue
        try:
            with open(path, "r", encoding="utf-8") as f:
                trips = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            continue
        for t in trips:
            if user_id in t.get("collaborateurs", []):
                enrichi = dict(t)
                enrichi["_owner_id"]    = owner_id
                enrichi["_owner_email"] = users_par_id.get(owner_id, {}).get("email", "?")
                partages.append(enrichi)
    return partages


# ── Décorateur login_required ────────────────────────────

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated

UPLOAD_FOLDER = os.path.join("static", "uploads")
EXTENSIONS_AUTORISEES = {"jpg", "jpeg", "png"}

LAT_DEFAUT = 48.8566   # Paris
LNG_DEFAUT = 2.3522

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


def extension_valide(nom_fichier: str) -> bool:
    """Vérifie que le fichier a une extension image autorisée."""
    return (
        "." in nom_fichier
        and nom_fichier.rsplit(".", 1)[1].lower() in EXTENSIONS_AUTORISEES
    )


def sauvegarder_image(fichier) -> str | None:
    """
    Valide, renomme et sauvegarde un fichier image uploadé.
    Retourne le nom du fichier sauvegardé, ou None si aucun fichier valide.
    """
    if not fichier or fichier.filename == "":
        return None

    if not extension_valide(fichier.filename):
        return None

    # Renommage automatique avec un UUID pour éviter les doublons
    extension = fichier.filename.rsplit(".", 1)[1].lower()
    nom_unique = f"{uuid.uuid4().hex}.{extension}"

    chemin = os.path.join(app.config["UPLOAD_FOLDER"], nom_unique)
    fichier.save(chemin)

    return nom_unique


def extraire_titre(url: str) -> str:
    """
    Tente d'extraire le titre d'une page web depuis son URL.
    Ordre de priorité : og:title → twitter:title → <title> → URL brute.
    Retourne toujours une chaîne non vide.
    """
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        reponse = requests.get(url, headers=headers, timeout=6)
        reponse.raise_for_status()

        soup = BeautifulSoup(reponse.text, "html.parser")

        og = soup.find("meta", property="og:title")
        if og and og.get("content", "").strip():
            return og["content"].strip()

        twitter = soup.find("meta", attrs={"name": "twitter:title"})
        if twitter and twitter.get("content", "").strip():
            return twitter["content"].strip()

        if soup.title and soup.title.string and soup.title.string.strip():
            return soup.title.string.strip()

    except Exception:
        pass

    return url


def geocoder(nom: str) -> tuple[float, float]:
    """
    Cherche les coordonnées GPS d'un lieu via OpenStreetMap Nominatim.
    Retourne (lat, lng) si trouvé, sinon les coordonnées de Paris par défaut.
    """
    try:
        reponse = requests.get(
            "https://nominatim.openstreetmap.org/search",
            params={"q": nom, "format": "json", "limit": 1},
            headers={"User-Agent": "GoAndTrip/1.0"},
            timeout=5
        )
        reponse.raise_for_status()
        resultats = reponse.json()

        if resultats:
            return float(resultats[0]["lat"]), float(resultats[0]["lon"])

    except Exception:
        pass

    return LAT_DEFAUT, LNG_DEFAUT


REGLES = [
    {
        "mots_cles": ["restaurant", "resto", "café", "cafe", "bar", "brasserie", "bistrot",
                      "bistro", "food", "eat", "dinner", "lunch", "breakfast", "pizza",
                      "sushi", "burger", "brunch", "cuisine", "gastronomie", "tapas"],
        "type":        "Restaurant",
        "categorie":   "food",
        "icone":       "🍽️",
        "description": "Adresse gastronomique à ne pas manquer",
    },
    {
        "mots_cles": ["museum", "musée", "musee", "gallery", "galerie", "art",
                      "exhibition", "expo", "louvre", "moma", "tate", "uffizi"],
        "type":        "Musée",
        "categorie":   "culture",
        "icone":       "🏛️",
        "description": "Lieu culturel incontournable",
    },
    {
        "mots_cles": ["monument", "chateau", "château", "palace", "palais", "cathedral",
                      "cathédrale", "church", "église", "eglise", "temple", "ruins",
                      "ruines", "castle", "fort", "basilique", "basilica"],
        "type":        "Monument",
        "categorie":   "culture",
        "icone":       "🏰",
        "description": "Site historique et patrimonial",
    },
    {
        "mots_cles": ["beach", "plage", "mer", "sea", "ocean", "côte", "cote",
                      "snorkel", "surf", "sable", "baignade"],
        "type":        "Plage",
        "categorie":   "nature",
        "icone":       "🏖️",
        "description": "Espace balnéaire et détente",
    },
    {
        "mots_cles": ["parc", "park", "garden", "jardin", "forêt", "foret", "forest",
                      "nature", "montagne", "mountain", "lac", "lake", "waterfall",
                      "cascade", "trail", "randonnée", "randonnee", "sentier"],
        "type":        "Nature",
        "categorie":   "nature",
        "icone":       "🌿",
        "description": "Espace naturel à explorer",
    },
    {
        "mots_cles": ["sport", "ski", "vélo", "velo", "bike", "hiking", "tennis",
                      "golf", "escalade", "climbing", "kayak", "plongée", "plongee",
                      "diving", "running", "natation", "yoga", "fitness"],
        "type":        "Sport",
        "categorie":   "sport",
        "icone":       "⚽",
        "description": "Activité sportive et aventure",
    },
    {
        "mots_cles": ["shop", "boutique", "market", "marché", "marche", "mall",
                      "store", "magasin", "shopping", "outlet", "souk", "bazaar"],
        "type":        "Shopping",
        "categorie":   "shopping",
        "icone":       "🛍️",
        "description": "Lieu idéal pour le shopping",
    },
    {
        "mots_cles": ["concert", "cinema", "théâtre", "theatre", "theater", "show",
                      "spectacle", "festival", "club", "nightlife", "music",
                      "musique", "opera", "opéra"],
        "type":        "Divertissement",
        "categorie":   "divertissement",
        "icone":       "🎭",
        "description": "Sorties et divertissements",
    },
    {
        "mots_cles": ["hotel", "hôtel", "hostel", "airbnb", "logement", "auberge",
                      "gite", "resort", "villa", "chambre"],
        "type":        "Hébergement",
        "categorie":   "hebergement",
        "icone":       "🏨",
        "description": "Lieu d'hébergement",
    },
    {
        "mots_cles": ["tour", "visite", "visit", "guided", "guidé", "panorama",
                      "viewpoint", "vue", "sight", "landmark", "quartier", "district"],
        "type":        "Visite",
        "categorie":   "visite",
        "icone":       "🗺️",
        "description": "À découvrir lors de votre visite",
    },
]

ANALYSE_DEFAUT = {
    "type":        "Activité",
    "categorie":   "autre",
    "icone":       "📌",
    "description": "Activité à découvrir",
}


def analyser_activite(nom: str, lien: str = "") -> dict:
    """
    Détermine le type, catégorie, icône et description d'une activité
    par correspondance de mots-clés dans son nom et son URL.
    Aucune API externe — traitement 100 % local.
    """
    texte = f"{nom} {lien}".lower()

    for regle in REGLES:
        if any(mot in texte for mot in regle["mots_cles"]):
            return {
                "type":        regle["type"],
                "categorie":   regle["categorie"],
                "icone":       regle["icone"],
                "description": regle["description"],
            }

    return dict(ANALYSE_DEFAUT)


class AnalyseIA(BaseModel):
    type: str
    categorie: str
    icone: str
    description: str
    suggestions: list[str]


_client_ia: anthropic.Anthropic | None = None


def _get_client_ia() -> anthropic.Anthropic:
    global _client_ia
    if _client_ia is None:
        _client_ia = anthropic.Anthropic()
    return _client_ia


def analyser_avec_ia(nom: str, lien: str = "") -> dict | None:
    """
    Utilise Claude (claude-opus-4-6) pour analyser une activité et retourner
    type, catégorie, icône, description et suggestions.
    Retourne None si l'API est indisponible ou la clé absente.
    """
    try:
        client = _get_client_ia()
        prompt = (
            f"Tu es un assistant de voyage. Analyse cette activité :\n"
            f"Nom : {nom}\n"
            f"Lien : {lien or 'aucun'}\n\n"
            f"Retourne :\n"
            f"- type : une courte étiquette (ex: Restaurant, Musée, Plage, Monument, Nature, Sport, Shopping, Divertissement, Hébergement, Visite)\n"
            f"- categorie : une parmi food / culture / nature / sport / shopping / divertissement / hebergement / visite / autre\n"
            f"- icone : un seul emoji représentatif\n"
            f"- description : une phrase accrocheuse (max 10 mots)\n"
            f"- suggestions : 3 noms d'activités similaires que l'on pourrait faire dans la même ville"
        )

        reponse = client.messages.parse(
            model="claude-opus-4-6",
            max_tokens=512,
            messages=[{"role": "user", "content": prompt}],
            output_format=AnalyseIA,
        )

        resultat = reponse.parsed_output
        if resultat is None:
            return None

        return {
            "type":        resultat.type,
            "categorie":   resultat.categorie,
            "icone":       resultat.icone,
            "description": resultat.description,
            "suggestions_ia": resultat.suggestions,
        }

    except Exception:
        return None


def suggerer(activite: dict, toutes: list, n: int = 3) -> list:
    """
    Retourne jusqu'à n activités similaires à celle donnée.
    Priorité : même catégorie → même type → autres activités.
    L'activité elle-même est toujours exclue.
    """
    cible_id  = activite["id"]
    categorie = activite.get("categorie", "")
    type_act  = activite.get("type", "")

    # 1. Même catégorie (ex: food → tous les restaurants)
    meme_categorie = [
        a for a in toutes
        if a["id"] != cible_id and a.get("categorie") == categorie
    ]

    # 2. Même type si pas assez dans la catégorie
    meme_type = [
        a for a in toutes
        if a["id"] != cible_id
        and a not in meme_categorie
        and a.get("type") == type_act
    ]

    # 3. Compléter avec n'importe quelle autre activité
    autres = [
        a for a in toutes
        if a["id"] != cible_id
        and a not in meme_categorie
        and a not in meme_type
    ]

    resultats = (meme_categorie + meme_type + autres)[:n]
    return resultats


# Catégories assignées à chaque créneau, par ordre de priorité
CRENEAUX_CATEGORIES = {
    "matin":      ["culture", "visite"],
    "midi":       ["food"],
    "apres_midi": ["nature", "sport", "shopping", "divertissement", "visite"],
    "soir":       ["divertissement", "food"],
}

# Suggestions génériques par créneau (utilisées quand le bucket est vide)
SUGGESTIONS_CRENEAU = {
    "matin": [
        "Visite du centre historique",
        "Promenade matinale en ville",
        "Tour à pied du quartier ancien",
        "Marché local du matin",
    ],
    "midi": [
        "Déjeuner dans un restaurant local",
        "Pique-nique en plein air",
        "Pause café et spécialités locales",
        "Dégustation gastronomique",
    ],
    "apres_midi": [
        "Balade dans les jardins publics",
        "Visite d'un monument emblématique",
        "Shopping en centre-ville",
        "Détente au bord de l'eau",
    ],
    "soir": [
        "Dîner dans un restaurant local",
        "Soirée dans le quartier animé",
        "Concert ou spectacle",
        "Terrasse avec vue sur la ville",
    ],
}

ICONES_CRENEAU = {
    "matin":      "☀️",
    "midi":       "🍽️",
    "apres_midi": "🌤️",
    "soir":       "🌙",
}


def haversine(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    """Retourne la distance en kilomètres entre deux points GPS."""
    R = 6371
    dlat = math.radians(lat2 - lat1)
    dlng = math.radians(lng2 - lng1)
    a = (math.sin(dlat / 2) ** 2
         + math.cos(math.radians(lat1))
         * math.cos(math.radians(lat2))
         * math.sin(dlng / 2) ** 2)
    return R * 2 * math.asin(math.sqrt(a))


def generer_planning_multi(nb_jours: int, activites: list) -> dict:
    """
    Génère un planning de nb_jours jours en répartissant les activités par ville.
    - Les activités sont groupées par leur champ "ville".
    - Chaque jour est assigné à la ville la plus fournie en activités.
    - Les créneaux vides sont complétés par des suggestions génériques.
    """
    # 1. Grouper les activités par ville
    par_ville: dict[str, list] = {}
    for a in activites:
        v = (a.get("ville") or "").strip() or "Autre"
        par_ville.setdefault(v, []).append(a)

    # 2. Trier les villes par nombre d'activités (desc)
    villes = sorted(par_ville, key=lambda v: len(par_ville[v]), reverse=True)

    # 3. Générer chaque jour
    jours = []
    for i in range(nb_jours):
        # Assigner une ville au jour (cycler si moins de villes que de jours)
        ville = villes[i % len(villes)] if villes else "Destination"
        pool  = list(par_ville.get(ville, []))
        random.shuffle(pool)

        # Buckets par catégorie pour ce jour
        buckets: dict[str, list] = {}
        for a in pool:
            cat = a.get("categorie", "autre")
            buckets.setdefault(cat, []).append(a)

        def piocher(categories: list) -> dict | None:
            for cat in categories:
                if buckets.get(cat):
                    return buckets[cat].pop(0)
            return None

        def creer_slot(moment: str, idx: int) -> dict:
            act = piocher(CRENEAUX_CATEGORIES[moment])
            if act:
                return {
                    "nom":    act["nom"],
                    "lien":   act.get("lien"),
                    "icone":  act.get("icone", "📌"),
                    "type":   act.get("type", "Activité"),
                    "source": "activite",
                    "lat":    act.get("lat"),
                    "lng":    act.get("lng"),
                }
            liste = SUGGESTIONS_CRENEAU[moment]
            return {
                "nom":    liste[idx % len(liste)],
                "lien":   None,
                "icone":  ICONES_CRENEAU[moment],
                "type":   "Suggestion",
                "source": "suggestion",
            }

        jours.append({
            "label":      f"Jour {i + 1}",
            "ville":      ville,
            "matin":      creer_slot("matin",      i),
            "midi":       creer_slot("midi",       i),
            "apres_midi": creer_slot("apres_midi", i),
            "soir":       creer_slot("soir",       i),
        })

    nb_avec_activites = sum(
        1 for j in jours if any(
            j[m]["source"] == "activite"
            for m in ("matin", "midi", "apres_midi", "soir")
        )
    )

    return {
        "jours":              jours,
        "nb_jours":           nb_jours,
        "nb_avec_activites":  nb_avec_activites,
        "villes":             villes,
    }


def generer_planning(ville: str, activites: list) -> dict:
    """
    Génère un planning de 3 jours pour une ville.
    - Géocode la ville
    - Sélectionne les activités dans un rayon de 100 km
    - Remplit les créneaux vides avec des suggestions génériques
    """
    lat_ville, lng_ville = geocoder(ville)

    # Activités dans un rayon de 100 km autour de la ville
    proches = [
        a for a in activites
        if a.get("lat") and a.get("lng")
        and haversine(lat_ville, lng_ville, a["lat"], a["lng"]) <= 100
    ]

    # Si aucune activité proche, on prend toutes les activités
    pool = list(proches) if proches else list(activites)
    random.shuffle(pool)

    # Répartir les activités en buckets par catégorie
    buckets: dict[str, list] = {}
    for a in pool:
        cat = a.get("categorie", "autre")
        buckets.setdefault(cat, []).append(a)

    def piocher(categories: list) -> dict | None:
        """Retire et retourne la première activité disponible parmi les catégories."""
        for cat in categories:
            if buckets.get(cat):
                return buckets[cat].pop(0)
        return None

    def creer_slot(moment: str, index: int) -> dict:
        """
        Retourne une activité réelle du bon type si disponible,
        sinon une suggestion générique pour ce créneau.
        """
        act = piocher(CRENEAUX_CATEGORIES[moment])
        if act:
            return {
                "nom":       act["nom"],
                "lien":      act.get("lien"),
                "icone":     act.get("icone", "📌"),
                "type":      act.get("type", "Activité"),
                "categorie": act.get("categorie", "autre"),
                "source":    "activite",
            }
        liste = SUGGESTIONS_CRENEAU[moment]
        return {
            "nom":       liste[index % len(liste)],
            "lien":      None,
            "icone":     ICONES_CRENEAU[moment],
            "type":      "Suggestion",
            "categorie": None,
            "source":    "suggestion",
        }

    jours = []
    for i in range(3):
        jours.append({
            "label":      f"Jour {i + 1}",
            "matin":      creer_slot("matin",      i),
            "midi":       creer_slot("midi",       i),
            "apres_midi": creer_slot("apres_midi", i),
            "soir":       creer_slot("soir",       i),
        })

    return {
        "ville":      ville,
        "jours":      jours,
        "nb_proches": len(proches),
        "nb_total":   len(activites),
    }


def parse_coord(valeur: str) -> float | None:
    """Convertit une chaîne en float (coordonnée GPS). Retourne None si invalide."""
    try:
        return float(valeur)
    except (ValueError, TypeError):
        return None


def supprimer_image(nom_fichier: str) -> None:
    """Supprime un fichier image du dossier uploads s'il existe."""
    if not nom_fichier:
        return
    chemin = os.path.join(app.config["UPLOAD_FOLDER"], nom_fichier)
    if os.path.isfile(chemin):
        os.remove(chemin)


@app.route("/")
def index():
    # ── Visiteur non connecté : landing page dédiée ───────
    if "user_id" not in session:
        return render_template("home.html")

    # ── Utilisateur connecté : page de gestion des activités ─
    uid       = session["user_id"]
    activites = charger(uid)
    trips     = charger_trips(uid)
    trips_par_id = {t["id"]: t for t in trips}

    # Filtre par voyage (ex: /?trip=2)
    trip_filter = request.args.get("trip", type=int)
    trip_actif  = None
    if trip_filter:
        trip_actif = next((t for t in trips if t["id"] == trip_filter), None)
        if trip_actif:
            activites = [a for a in activites if a.get("trip_id") == trip_filter]

    # Activité fraîchement ajoutée (ex: /?nouveau=5)
    nouvelle_id = request.args.get("nouveau", type=int)
    nouvelle    = next((a for a in activites if a["id"] == nouvelle_id), None) if nouvelle_id else None

    suggestions    = []
    suggestions_ia = []
    if nouvelle:
        suggestions_ia = nouvelle.get("suggestions_ia", [])

    return render_template("index.html",
                           activites=activites,
                           trips=trips,
                           trips_par_id=trips_par_id,
                           trip_actif=trip_actif,
                           nouvelle=nouvelle,
                           suggestions=suggestions,
                           suggestions_ia=suggestions_ia,
                           email=session.get("email"))


@app.route("/ajouter", methods=["POST"])
@login_required
def ajouter():
    uid = session["user_id"]
    activites = charger(uid)
    nom      = request.form["nom"].strip()
    lien     = request.form["lien"].strip()
    ville    = request.form.get("ville", "").strip()
    trip_id  = request.form.get("trip_id", type=int)

    nom_image = sauvegarder_image(request.files.get("image"))
    lat = parse_coord(request.form.get("lat", ""))
    lng = parse_coord(request.form.get("lng", ""))

    if lat is None or lng is None:
        lat, lng = geocoder(nom)

    analyse = analyser_avec_ia(nom, lien) or analyser_activite(nom, lien)
    new_id  = prochain_id(activites)

    activites.append({
        "id":             new_id,
        "nom":            nom,
        "ville":          ville,
        "trip_id":        trip_id,
        "lien":           lien,
        "image":          nom_image or "",
        "lat":            lat,
        "lng":            lng,
        "type":           analyse["type"],
        "categorie":      analyse["categorie"],
        "icone":          analyse["icone"],
        "description":    analyse["description"],
        "suggestions_ia": analyse.get("suggestions_ia", []),
    })

    sauvegarder(activites, uid)
    return redirect(f"/?nouveau={new_id}")


@app.route("/importer", methods=["POST"])
@login_required
def importer():
    uid = session["user_id"]
    activites = charger(uid)
    lien    = request.form["lien"].strip()
    ville   = request.form.get("ville", "").strip()
    trip_id = request.form.get("trip_id", type=int)

    titre    = extraire_titre(lien)
    lat, lng = geocoder(titre)
    analyse  = analyser_avec_ia(titre, lien) or analyser_activite(titre, lien)
    new_id   = prochain_id(activites)

    activites.append({
        "id":             new_id,
        "nom":            titre,
        "ville":          ville,
        "trip_id":        trip_id,
        "lien":           lien,
        "image":          "",
        "lat":            lat,
        "lng":            lng,
        "type":           analyse["type"],
        "categorie":      analyse["categorie"],
        "icone":          analyse["icone"],
        "description":    analyse["description"],
        "suggestions_ia": analyse.get("suggestions_ia", []),
    })

    sauvegarder(activites, uid)
    return redirect(f"/?nouveau={new_id}")


@app.route("/supprimer/<int:id>", methods=["POST"])
@login_required
def supprimer(id: int):
    uid = session["user_id"]
    activites = charger(uid)

    cible = next((a for a in activites if a["id"] == id), None)
    if cible:
        supprimer_image(cible.get("image", ""))

    activites = [a for a in activites if a["id"] != id]
    sauvegarder(activites, uid)
    return redirect("/")


@app.route("/organiser", methods=["GET", "POST"])
@login_required
def organiser():
    if request.method == "GET":
        return render_template("organiser.html")

    nb_jours = int(request.form.get("nb_jours", 3))
    nb_jours = max(2, min(nb_jours, 3))

    activites = charger(session["user_id"])
    planning  = generer_planning_multi(nb_jours, activites)
    return render_template("planning.html", **planning)


# ── Voyages (Trips) ──────────────────────────────────────

@app.route("/trips")
@login_required
def trips():
    uid = session["user_id"]
    mes_trips      = charger_trips(uid)
    trips_partages = charger_trips_partages(uid)
    activites      = charger(uid)

    # Compter les activités par trip (propres)
    compteurs = {}
    for a in activites:
        tid = a.get("trip_id")
        if tid:
            compteurs[tid] = compteurs.get(tid, 0) + 1

    # Pour afficher les emails des collaborateurs
    users = charger_users()
    users_par_id = {u["id"]: u for u in users}

    erreur         = request.args.get("erreur")
    trip_erreur_id = request.args.get("tid", type=int)
    trip_ok_id     = request.args.get("ok", type=int)

    return render_template("trips.html",
                           trips=mes_trips,
                           trips_partages=trips_partages,
                           compteurs=compteurs,
                           users_par_id=users_par_id,
                           erreur=erreur,
                           trip_erreur_id=trip_erreur_id,
                           trip_ok_id=trip_ok_id,
                           email=session.get("email"))


@app.route("/trips/creer", methods=["POST"])
@login_required
def creer_trip():
    uid   = session["user_id"]
    nom   = request.form.get("nom", "").strip()
    ville = request.form.get("ville", "").strip()
    try:
        jours = max(0, min(int(request.form.get("jours", 0) or 0), 30))
    except (ValueError, TypeError):
        jours = 0

    if not nom:
        return redirect("/trips")

    trips  = charger_trips(uid)
    new_id = prochain_trip_id(trips)
    trips.append({
        "id":             new_id,
        "nom":            nom,
        "ville":          ville,
        "jours":          jours,
        "collaborateurs": [],
        "slug":           uuid.uuid4().hex[:8],
    })
    sauvegarder_trips(trips, uid)
    return redirect("/trips")


@app.route("/api/create-trip", methods=["POST"])
@login_required
def api_create_trip():
    """Crée un voyage depuis le frontend (JSON). Retourne {trip_id, nom}."""
    uid  = session["user_id"]
    data = request.get_json(silent=True) or {}
    nom  = str(data.get("nom", "")).strip()
    if not nom:
        return jsonify({"error": "Nom du voyage requis."}), 400

    ville = str(data.get("ville", "")).strip()
    try:
        jours = max(0, min(int(data.get("jours", 0) or 0), 30))
    except (TypeError, ValueError):
        jours = 0

    trips  = charger_trips(uid)
    new_id = prochain_trip_id(trips)
    trips.append({
        "id":             new_id,
        "nom":            nom,
        "ville":          ville,
        "jours":          jours,
        "collaborateurs": [],
        "slug":           uuid.uuid4().hex[:8],
    })
    sauvegarder_trips(trips, uid)
    return jsonify({"trip_id": new_id, "nom": nom})


@app.route("/api/add-activity-to-trip", methods=["POST"])
@login_required
def api_add_activity_to_trip():
    """
    POST /api/add-activity-to-trip
    Body JSON : { "activity_id": int, "trip_id": int, "jour": int }
    Retourne  : { "ok": true, "trip_nom": str, "jour": int }
    """
    uid  = session["user_id"]
    data = request.get_json(silent=True) or {}
    try:
        act_id  = int(data["activity_id"])
        trip_id = int(data["trip_id"])
        jour    = max(1, int(data.get("jour", 1) or 1))
    except (KeyError, TypeError, ValueError):
        return jsonify({"error": "Paramètres invalides."}), 400

    # Vérifier que le trip appartient bien à cet utilisateur
    trips = charger_trips(uid)
    trip  = next((t for t in trips if t["id"] == trip_id), None)
    if not trip:
        return jsonify({"error": "Voyage introuvable."}), 404

    # Mettre à jour l'activité
    activites = charger(uid)
    act = next((a for a in activites if a["id"] == act_id), None)
    if not act:
        return jsonify({"error": "Activité introuvable."}), 404

    act["trip_id"] = trip_id
    act["jour"]    = jour
    sauvegarder(activites, uid)

    return jsonify({"ok": True, "trip_nom": trip["nom"], "jour": jour})


@app.route("/trips/<int:trip_id>/partager", methods=["POST"])
@login_required
def partager_trip(trip_id: int):
    uid   = session["user_id"]
    email = request.form.get("email", "").strip().lower()

    users = charger_users()
    cible = next((u for u in users if u["email"] == email), None)

    if not cible:
        return redirect(f"/trips?erreur=introuvable&tid={trip_id}")
    if cible["id"] == uid:
        return redirect(f"/trips?erreur=soi_meme&tid={trip_id}")

    trips = charger_trips(uid)
    trip  = next((t for t in trips if t["id"] == trip_id), None)
    if not trip:
        return redirect("/trips")

    trip.setdefault("collaborateurs", [])
    if cible["id"] not in trip["collaborateurs"]:
        trip["collaborateurs"].append(cible["id"])
        sauvegarder_trips(trips, uid)

    return redirect(f"/trips?ok={trip_id}")


@app.route("/trips/<int:trip_id>/retirer/<int:col_id>", methods=["POST"])
@login_required
def retirer_collaborateur(trip_id: int, col_id: int):
    uid   = session["user_id"]
    trips = charger_trips(uid)
    trip  = next((t for t in trips if t["id"] == trip_id), None)
    if trip:
        trip["collaborateurs"] = [c for c in trip.get("collaborateurs", []) if c != col_id]
        sauvegarder_trips(trips, uid)
    return redirect("/trips")


@app.route("/trips/<int:trip_id>/activer-lien", methods=["POST"])
@login_required
def activer_lien_public(trip_id: int):
    """Génère un slug public pour un voyage existant qui n'en a pas encore."""
    uid   = session["user_id"]
    trips = charger_trips(uid)
    trip  = next((t for t in trips if t["id"] == trip_id), None)
    if trip and not trip.get("slug"):
        trip["slug"] = uuid.uuid4().hex[:8]
        sauvegarder_trips(trips, uid)
    return redirect("/trips")


@app.route("/trip/<slug>")
def trip_public(slug: str):
    """Vue publique d'un voyage — accessible sans compte."""
    acces = trouver_trip_par_slug(slug)
    if acces is None:
        abort(404)
    trip     = acces["trip"]
    activites = [
        a for a in charger(acces["owner_id"])
        if a.get("trip_id") == trip["id"]
    ]
    return render_template("trip_public.html", trip=trip, activites=activites)


@app.route("/trips/<int:trip_id>/supprimer", methods=["POST"])
@login_required
def supprimer_trip(trip_id: int):
    uid = session["user_id"]
    trips = charger_trips(uid)
    trips = [t for t in trips if t["id"] != trip_id]
    sauvegarder_trips(trips, uid)

    # Dissocier les activités de ce trip (trip_id → None)
    activites = charger(uid)
    for a in activites:
        if a.get("trip_id") == trip_id:
            a["trip_id"] = None
    sauvegarder(activites, uid)

    return redirect("/trips")


# ══════════════════════════════════════════════════════════
#  SAUVEGARDE & PARTAGE DES PLANNINGS IA
# ══════════════════════════════════════════════════════════

# Stockage séparé des plannings générés par IA (ne touche pas aux trips manuels)

def _fichier_ai_trips(user_id: int) -> str:
    """Retourne le chemin du fichier de plannings IA d'un utilisateur."""
    return os.path.join(DATA_DIR, f"ai_trips_{user_id}.json")


def _charger_ai_trips(user_id: int) -> list:
    path = _fichier_ai_trips(user_id)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def _sauvegarder_ai_trips(trips: list, user_id: int) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(_fichier_ai_trips(user_id), "w", encoding="utf-8") as f:
        json.dump(trips, f, indent=2, ensure_ascii=False)


def _trouver_ai_trip(share_id: str) -> dict | None:
    """Cherche un planning IA par share_id dans tous les fichiers ai_trips_*.json."""
    for path in glob.glob(os.path.join(DATA_DIR, "ai_trips_*.json")):
        try:
            with open(path, "r", encoding="utf-8") as f:
                trips = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            continue
        for t in trips:
            if t.get("share_id") == share_id:
                return t
    return None


@app.route("/api/save-trip", methods=["POST"])
@login_required
@limiter.limit("20 per hour")
def api_save_trip():
    """
    POST /api/save-trip
    Body JSON : { "ville", "jours", "transport", "planning": [...] }
    Réponse   : { "share_id": "...", "share_url": "..." }
    """
    user_id = session["user_id"]
    data    = request.get_json(silent=True)

    if not data:
        return jsonify({"error": "Corps JSON manquant."}), 400

    ville     = sanitize_ville(str(data.get("ville", "")))
    planning  = data.get("planning")
    jours     = data.get("jours")
    transport = sanitize_transport(str(data.get("transport", "")))
    nom       = str(data.get("nom", "")).strip()[:80]

    if not ville:
        return jsonify({"error": "Champ 'ville' invalide."}), 400
    if transport is None:
        return jsonify({"error": "Champ 'transport' invalide."}), 400
    if not isinstance(planning, list) or len(planning) == 0:
        return jsonify({"error": "Planning vide ou invalide."}), 400
    try:
        jours = int(jours)
        if not (1 <= jours <= 30):
            raise ValueError
    except (TypeError, ValueError):
        return jsonify({"error": "Champ 'jours' invalide."}), 400

    # Limite à 30 voyages sauvegardés par utilisateur (anti-abus)
    ai_trips = _charger_ai_trips(user_id)
    if len(ai_trips) >= 30:
        ai_trips = ai_trips[-29:]   # garde les 29 plus récents, libère une place

    share_id = uuid.uuid4().hex
    base_url = request.host_url.rstrip("/")
    if not nom:
        nom = f"{ville.title()} · {jours} jour{'s' if jours > 1 else ''}"

    record = {
        "share_id":   share_id,
        "user_id":    user_id,
        "nom":        nom,
        "ville":      ville,
        "jours":      jours,
        "transport":  transport,
        "planning":   planning,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    ai_trips.append(record)
    _sauvegarder_ai_trips(ai_trips, user_id)

    api_logger.info(
        "trip_saved user=%s share_id=%s ville=%s jours=%s",
        user_id, share_id, ville, jours,
    )

    return jsonify({
        "share_id":  share_id,
        "share_url": f"{base_url}/share/{share_id}",
    }), 201


@app.route("/api/update-ai-trip", methods=["POST"])
@login_required
def api_update_ai_trip():
    """Remplace le planning d'un voyage IA existant (même share_id)."""
    user_id  = session["user_id"]
    data     = request.get_json(silent=True) or {}
    share_id = str(data.get("share_id", ""))
    planning = data.get("planning")

    if not re.fullmatch(r"[0-9a-f]{32}", share_id):
        return jsonify({"error": "share_id invalide."}), 400
    if not isinstance(planning, list) or len(planning) == 0:
        return jsonify({"error": "Planning invalide."}), 400

    ai_trips = _charger_ai_trips(user_id)
    trip     = next((t for t in ai_trips if t["share_id"] == share_id), None)
    if not trip:
        return jsonify({"error": "Voyage introuvable."}), 404

    trip["planning"]    = planning
    trip["jours"]       = len(planning)
    trip["updated_at"]  = datetime.now(timezone.utc).isoformat()
    _sauvegarder_ai_trips(ai_trips, user_id)

    return jsonify({
        "share_id":  share_id,
        "share_url": f"{request.host_url.rstrip('/')}/share/{share_id}",
    })


@app.route("/api/delete-ai-trip", methods=["POST"])
@login_required
def api_delete_ai_trip():
    """Supprime un voyage IA de l'espace personnel."""
    user_id  = session["user_id"]
    data     = request.get_json(silent=True) or {}
    share_id = str(data.get("share_id", ""))

    if not re.fullmatch(r"[0-9a-f]{32}", share_id):
        return jsonify({"error": "share_id invalide."}), 400

    ai_trips  = _charger_ai_trips(user_id)
    new_trips = [t for t in ai_trips if t["share_id"] != share_id]
    if len(new_trips) == len(ai_trips):
        return jsonify({"error": "Voyage introuvable."}), 404

    _sauvegarder_ai_trips(new_trips, user_id)
    return jsonify({"ok": True})


@app.route("/api/mes-voyages-list")
@login_required
def api_mes_voyages_list():
    """Retourne la liste des voyages IA de l'utilisateur (pour le dropdown)."""
    user_id  = session["user_id"]
    ai_trips = _charger_ai_trips(user_id)
    return jsonify([
        {
            "share_id":   t["share_id"],
            "nom":        t.get("nom", f"{t['ville']} · {t['jours']} jours"),
            "ville":      t["ville"],
            "jours":      t["jours"],
            "created_at": t.get("created_at", ""),
        }
        for t in reversed(ai_trips)
    ])


@app.route("/mes-voyages")
@login_required
def mes_voyages():
    """Page privée : liste des plannings IA sauvegardés."""
    user_id  = session["user_id"]
    ai_trips = list(reversed(_charger_ai_trips(user_id)))
    base_url = request.host_url.rstrip("/")
    return render_template(
        "mes_voyages.html",
        ai_trips=ai_trips,
        base_url=base_url,
        email=session.get("email"),
    )


@app.route("/share/<share_id>")
def trip_share(share_id: str):
    """Vue publique d'un planning IA — accessible sans compte."""
    # Validation légère du share_id (32 hex chars)
    if not re.fullmatch(r"[0-9a-f]{32}", share_id):
        abort(404)

    trip = _trouver_ai_trip(share_id)
    if trip is None:
        abort(404)

    return render_template("trip_share.html", trip=trip)


# ── Authentification ─────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect("/")
    if request.method == "GET":
        return render_template("login.html", erreur=None)

    email = request.form["email"].strip().lower()
    mdp   = request.form["mdp"].strip()
    users = charger_users()
    user  = next((u for u in users if u["email"] == email), None)

    if not user or user["mdp"] != hash_mdp(mdp):
        return render_template("login.html", erreur="Email ou mot de passe incorrect.")

    session.permanent  = True
    session["user_id"] = user["id"]
    session["email"]   = user["email"]
    return redirect("/organiser")   # après login → directement sur le générateur


@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect("/")
    if request.method == "GET":
        return render_template("register.html", erreur=None)

    email = request.form["email"].strip().lower()
    mdp   = request.form["mdp"].strip()
    users = charger_users()

    if len(mdp) < 6:
        return render_template("register.html", erreur="Mot de passe trop court (min. 6 caractères).")
    if any(u["email"] == email for u in users):
        return render_template("register.html", erreur="Cet email est déjà utilisé.")

    new_id = max((u["id"] for u in users), default=0) + 1
    users.append({"id": new_id, "email": email, "mdp": hash_mdp(mdp)})
    sauvegarder_users(users)

    session.permanent  = True
    session["user_id"] = new_id
    session["email"]   = email
    return redirect("/organiser")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


# ══════════════════════════════════════════════════════════
#  MOT DE PASSE OUBLIÉ
# ══════════════════════════════════════════════════════════

# ── Envoi d'email (SendGrid) ──────────────────────────────

def _send_reset_email(to_email: str, reset_url: str) -> bool:
    """
    Envoie le lien de réinitialisation via SendGrid.
    Retourne True si l'envoi a réussi, False sinon.
    Si SENDGRID_API_KEY n'est pas définie → retourne False (mode debug).
    """
    api_key = os.getenv("SENDGRID_API_KEY")
    if not api_key:
        return False   # pas de clé → mode debug, le lien sera affiché sur la page

    sender = os.getenv("MAIL_SENDER", "noreply@goandtrip.fr")
    html_body = f"""
    <div style="font-family:Inter,sans-serif;max-width:520px;margin:0 auto;color:#111827;">
      <div style="background:linear-gradient(135deg,#f97316,#ec4899 55%,#7c3aed);
                  padding:24px 32px;border-radius:14px 14px 0 0;text-align:center;">
        <h1 style="color:#fff;font-size:22px;margin:0;letter-spacing:-.5px;">GoAndTrip</h1>
      </div>
      <div style="background:#f8f9fc;padding:32px;border-radius:0 0 14px 14px;
                  border:1px solid #e5e7eb;border-top:none;">
        <h2 style="font-size:20px;font-weight:800;margin:0 0 12px;">
          Réinitialisation du mot de passe
        </h2>
        <p style="color:#6b7280;line-height:1.6;margin:0 0 24px;">
          Vous avez demandé à réinitialiser votre mot de passe GoAndTrip.<br>
          Cliquez sur le bouton ci-dessous. Le lien expire dans <strong>1 heure</strong>.
        </p>
        <a href="{reset_url}"
           style="display:inline-block;padding:14px 28px;border-radius:12px;
                  background:linear-gradient(135deg,#f97316,#ec4899 55%,#7c3aed);
                  color:#fff;font-weight:700;text-decoration:none;font-size:15px;">
          Réinitialiser mon mot de passe →
        </a>
        <p style="color:#9ca3af;font-size:12px;margin:24px 0 0;line-height:1.5;">
          Si vous n'avez pas fait cette demande, ignorez cet email.<br>
          Votre mot de passe reste inchangé.
        </p>
      </div>
    </div>
    """

    try:
        resp = requests.post(
            "https://api.sendgrid.com/v3/mail/send",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type":  "application/json",
            },
            json={
                "personalizations": [{"to": [{"email": to_email}]}],
                "from":    {"email": sender, "name": "GoAndTrip"},
                "subject": "Réinitialisation de votre mot de passe GoAndTrip",
                "content": [{"type": "text/html", "value": html_body}],
            },
            timeout=10,
        )
        if resp.status_code == 202:
            security_logger.info("reset_email_sent to=%s", to_email)
            return True
        security_logger.warning("sendgrid_error status=%s body=%s", resp.status_code, resp.text[:200])
        return False
    except Exception as exc:
        security_logger.error("sendgrid_exception: %s", exc)
        return False


_RESET_SALT = "goandtrip-password-reset"


def _gen_reset_token(email: str) -> str:
    """Génère un token signé contenant l'email, valide 1 heure."""
    s = URLSafeTimedSerializer(app.secret_key)
    return s.dumps(email.lower(), salt=_RESET_SALT)


def _verify_reset_token(token: str, max_age: int = 3600) -> str | None:
    """Retourne l'email si le token est valide et non expiré, None sinon."""
    s = URLSafeTimedSerializer(app.secret_key)
    try:
        email = s.loads(token, salt=_RESET_SALT, max_age=max_age)
        return email
    except (SignatureExpired, BadSignature):
        return None


@app.route("/forgot-password", methods=["GET", "POST"])
@limiter.limit("5 per hour")
def forgot_password():
    if request.method == "GET":
        return render_template("forgot_password.html", message=None, erreur=None)

    email = request.form.get("email", "").strip().lower()

    # Message identique qu'il existe ou non (ne pas révéler l'existence du compte)
    MSG_OK = "Si cet email est enregistré, un lien vient d'être envoyé. Vérifiez vos spams."

    if not email or "@" not in email or len(email) > 254:
        return render_template("forgot_password.html",
                               erreur="Adresse email invalide.", message=None)

    users  = charger_users()
    user   = next((u for u in users if u["email"] == email), None)

    debug_url = None  # lien visible sur la page uniquement si l'email n'est pas envoyé

    if user and user.get("mdp") is not None:
        # Uniquement pour les comptes avec mot de passe (pas OAuth uniquement)
        token     = _gen_reset_token(email)
        base_url  = request.url_root.rstrip("/")   # ex: https://goandtrip.com
        reset_url = f"{base_url}/reset-password/{token}"

        sent = _send_reset_email(email, reset_url)

        if not sent:
            # Pas de clé SendGrid configurée → mode debug : on affiche le lien
            debug_url = reset_url
            security_logger.warning(
                "reset_email_not_sent (no SENDGRID_API_KEY) email=%s ip=%s",
                email, request.remote_addr
            )

        security_logger.info(
            "password_reset_requested email=%s sent=%s ip=%s",
            email, sent, request.remote_addr
        )

    return render_template("forgot_password.html",
                           message=MSG_OK, erreur=None, debug_url=debug_url)


@app.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    email = _verify_reset_token(token)

    if email is None:
        return render_template(
            "reset_password.html",
            token=None,
            erreur="Ce lien est expiré ou invalide. Faites une nouvelle demande.",
            message=None,
        )

    if request.method == "GET":
        return render_template("reset_password.html",
                               token=token, erreur=None, message=None)

    # POST — changement effectif du mot de passe
    mdp         = request.form.get("mdp", "").strip()
    mdp_confirm = request.form.get("mdp_confirm", "").strip()

    if len(mdp) < 6:
        return render_template("reset_password.html", token=token,
                               erreur="Mot de passe trop court (min. 6 caractères).", message=None)
    if mdp != mdp_confirm:
        return render_template("reset_password.html", token=token,
                               erreur="Les mots de passe ne correspondent pas.", message=None)

    users = charger_users()
    user  = next((u for u in users if u["email"] == email), None)

    if not user:
        return render_template("reset_password.html", token=None,
                               erreur="Compte introuvable.", message=None)

    user["mdp"] = hash_mdp(mdp)
    sauvegarder_users(users)

    security_logger.info(
        "password_reset_success email=%s ip=%s", email, request.remote_addr
    )

    return render_template(
        "reset_password.html",
        token=None,
        erreur=None,
        message="Mot de passe mis à jour ! Vous pouvez maintenant vous connecter.",
    )


# ── Routes SEO — /quoi-faire-a-<ville> ───────────────────

# Textes intro statiques pour les villes les plus cherchées
# (chaque page a du contenu même sans activités utilisateur)
_SEO_INTROS: dict[str, str] = {
    "paris": (
        "Paris, la Ville Lumière, est l'une des destinations les plus visitées au monde. "
        "Entre les chefs-d'œuvre du Louvre, les promenades le long de la Seine, "
        "la gastronomie des bistrots et l'effervescence de Montmartre, "
        "chaque quartier réserve une surprise. GoAndTrip vous aide à construire "
        "l'itinéraire idéal selon vos envies et votre rythme."
    ),
    "rome": (
        "Rome, la Ville Éternelle, concentre plus de 2 700 ans d'histoire en quelques kilomètres. "
        "Le Colisée, le Vatican, la Fontaine de Trévi ou la Piazza Navona ne sont que quelques-uns "
        "des incontournables qui attendent les voyageurs. "
        "Laissez GoAndTrip organiser votre séjour pour ne rien manquer."
    ),
    "barcelone": (
        "Barcelone mêle architecture moderniste, plages méditerranéennes et gastronomie catalane. "
        "La Sagrada Família de Gaudí, le quartier gothique et Las Ramblas font de cette ville "
        "une destination unique en Europe. "
        "Planifiez votre visite avec GoAndTrip pour un itinéraire sur-mesure."
    ),
    "tokyo": (
        "Tokyo est une métropole fascinante où tradition millénaire et modernité futuriste se côtoient. "
        "Temples shinto, marchés de poissons, quartiers branchés de Shibuya et jardins impériaux "
        "offrent une expérience de voyage incomparable. "
        "GoAndTrip vous génère un planning adapté à votre durée de séjour."
    ),
    "amsterdam": (
        "Amsterdam, ville des canaux et des musées, séduit par son charme unique. "
        "Le Rijksmuseum, le musée Van Gogh, les maisons à pignons et les marchés flottants "
        "en font une destination incontournable des Pays-Bas. "
        "Organisez votre visite facilement avec GoAndTrip."
    ),
    "new-york": (
        "New York, la ville qui ne dort jamais, propose une diversité d'expériences sans égale. "
        "Central Park, Times Square, les musées de world-class et la street food de Brooklyn "
        "sont à portée de main. "
        "GoAndTrip vous aide à optimiser chaque journée dans la Big Apple."
    ),
    "kyoto": (
        "Kyoto est le cœur culturel du Japon, avec ses temples bouddhistes, "
        "ses jardins zen et ses geishas du quartier de Gion. "
        "La ville concentre un tiers des trésors nationaux du Japon. "
        "Laissez GoAndTrip planifier votre immersion dans le Japon traditionnel."
    ),
    "lisbonne": (
        "Lisbonne, posée sur ses sept collines, est l'une des capitales les plus authentiques d'Europe. "
        "Tramways historiques, azulejos colorés, pastéis de nata et fado "
        "composent le charme unique de la capitale portugaise. "
        "Planifiez votre séjour avec GoAndTrip."
    ),
    "berlin": (
        "Berlin est une ville de contrastes fascinants — histoire chargée, "
        "scène artistique avant-gardiste et vie nocturne légendaire. "
        "Murs, musées, galeries et marchés en font une destination culturelle majeure d'Europe. "
        "GoAndTrip vous construit l'itinéraire berlinois parfait."
    ),
    "prague": (
        "Prague, la Ville aux Cent Clochers, est l'une des plus belles capitales médiévales d'Europe. "
        "Le Château de Prague, le Pont Charles et la Vieille Ville attirent des millions de visiteurs. "
        "Organisez votre séjour en Bohême avec GoAndTrip."
    ),
}

# Durées populaires proposées en maillage interne
_DUREES_POPULAIRES = [1, 2, 3, 5, 7]

# Villes populaires pour le sitemap
_VILLES_SITEMAP = list(_SEO_INTROS.keys()) + [
    "madrid", "vienne", "budapest", "dubai", "singapour",
    "bangkok", "new-york", "los-angeles", "sydney", "marrakech",
]

def _activites_publiques_ville(ville: str) -> list:
    """Retourne toutes les activités issues de voyages publics pour une ville donnée."""
    ville_norm = ville.lower().strip()
    resultats = []
    seen_ids = set()

    # Parcourt tous les fichiers trips_*.json dans data/
    for fichier in glob.glob(os.path.join(DATA_DIR, "trips_*.json")):
        try:
            with open(fichier, "r", encoding="utf-8") as f:
                trips = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            continue

        # Extrait l'user_id depuis le nom du fichier (data/trips_1.json → 1)
        try:
            uid = int(os.path.basename(fichier).replace("trips_", "").replace(".json", ""))
        except ValueError:
            continue

        activites_user = charger(uid)

        for trip in trips:
            if not trip.get("lien_public"):
                continue
            for act_id in trip.get("activites", []):
                if act_id in seen_ids:
                    continue
                act = next((a for a in activites_user if a.get("id") == act_id), None)
                if act and act.get("ville", "").lower() == ville_norm:
                    resultats.append(act)
                    seen_ids.add(act_id)

    return resultats


def _slugifier(texte: str) -> str:
    """Convertit 'Île-de-France' → 'ile-de-france' pour les URLs."""
    import unicodedata
    texte = unicodedata.normalize("NFD", texte)
    texte = "".join(c for c in texte if unicodedata.category(c) != "Mn")
    return texte.lower().replace(" ", "-").replace("'", "-").replace("_", "-")


def _seo_context(ville_slug: str, jours: int | None) -> dict:
    """Construit le contexte commun pour les pages SEO ville."""
    ville_display = ville_slug.replace("-", " ").title()
    activites     = _activites_publiques_ville(ville_display)
    intro_text    = _SEO_INTROS.get(ville_slug.lower(), "")

    # Liens vers les autres durées de la même ville (maillage interne)
    durees_liens = [
        {
            "label": f"{d} jour{'s' if d > 1 else ''}",
            "url":   f"/quoi-faire-a-{ville_slug}-{d}-jours",
            "actif": d == jours,
        }
        for d in _DUREES_POPULAIRES
    ]

    if jours:
        title = f"Que faire à {ville_display} en {jours} jour{'s' if jours > 1 else ''} — GoAndTrip"
        meta_description = (
            f"Découvrez les meilleures activités à {ville_display} en {jours} jour{'s' if jours > 1 else ''} "
            f"avec un itinéraire optimisé par GoAndTrip. Réservez vos activités et hôtels facilement."
        )
        canonical = f"https://goandtrip.fr/quoi-faire-a-{ville_slug}-{jours}-jours"
    else:
        title = f"Que faire à {ville_display} — Activités & idées de sorties — GoAndTrip"
        meta_description = (
            f"Les meilleures activités à faire à {ville_display} : musées, restaurants, balades et bien plus. "
            f"Planifiez votre visite avec GoAndTrip, le planificateur de voyage IA."
        )
        canonical = f"https://goandtrip.fr/quoi-faire-a-{ville_slug}"

    return dict(
        ville=ville_display,
        ville_slug=ville_slug,
        jours=jours,
        activites=activites,
        intro_text=intro_text,
        durees_liens=durees_liens,
        title=title,
        meta_description=meta_description,
        canonical=canonical,
    )


@app.route("/quoi-faire-a-<ville>-<int:jours>-jours")
def seo_ville_jours(ville: str, jours: int):
    """Page SEO : que faire à <ville> en <jours> jours."""
    if jours < 1 or jours > 30:
        abort(404)
    return render_template("seo_ville.html", **_seo_context(ville, jours))


@app.route("/quoi-faire-a-<ville>")
def seo_ville(ville: str):
    """Page SEO : que faire à <ville>."""
    return render_template("seo_ville.html", **_seo_context(ville, None))


@app.route("/sw.js")
def service_worker():
    """Service worker servi depuis la racine (scope /)."""
    from flask import send_from_directory
    return send_from_directory("static", "sw.js",
                               mimetype="application/javascript")


@app.route("/sitemap.xml")
def sitemap():
    """Sitemap XML complet pour Google."""
    from datetime import date
    today = date.today().isoformat()

    BASE = "https://goandtrip.com"

    urls = [
        # Pages principales
        {"loc": f"{BASE}/",          "changefreq": "daily",  "priority": "1.0"},
        {"loc": f"{BASE}/organiser", "changefreq": "weekly", "priority": "0.9"},
        # Pages SEO villes
    ]

    for slug in _VILLES_SITEMAP:
        urls.append({
            "loc":        f"{BASE}/quoi-faire-a-{slug}",
            "changefreq": "weekly",
            "priority":   "0.8",
        })
        for d in _DUREES_POPULAIRES:
            urls.append({
                "loc":        f"{BASE}/quoi-faire-a-{slug}-{d}-jours",
                "changefreq": "monthly",
                "priority":   "0.7",
            })

    xml = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">',
    ]
    for u in urls:
        xml.append(
            f'  <url>'
            f'<loc>{u["loc"]}</loc>'
            f'<lastmod>{today}</lastmod>'
            f'<changefreq>{u["changefreq"]}</changefreq>'
            f'<priority>{u["priority"]}</priority>'
            f'</url>'
        )
    xml.append('</urlset>')

    return "\n".join(xml), 200, {"Content-Type": "application/xml; charset=utf-8"}


@app.route("/robots.txt")
def robots():
    """robots.txt — indique le sitemap aux moteurs de recherche."""
    content = (
        "User-agent: *\n"
        "Allow: /\n"
        "Disallow: /api/\n"
        "Disallow: /login\n"
        "Disallow: /register\n"
        "Disallow: /trips\n"
        "Disallow: /logout\n"
        "Disallow: /forgot-password\n"
        "Disallow: /reset-password/\n"
        "\n"
        "Sitemap: https://goandtrip.com/sitemap.xml\n"
    )
    return content, 200, {"Content-Type": "text/plain; charset=utf-8"}


# ── API OpenAI — génération d'itinéraire ─────────────────

_TRANSPORTS_VALIDES = {"voiture", "train", "avion", "vélo", "marche", "bus", "bateau"}

_PROMPT_SYSTEME = """\
Tu es un expert en planification de voyages.

RÈGLES ABSOLUES — à respecter sans exception :
1. Tu réponds UNIQUEMENT en JSON valide. Aucun texte avant ni après. Aucune balise markdown.
2. Chaque jour contient entre 3 et 5 activités, jamais moins, jamais plus.
3. Toutes les activités doivent être des lieux RÉELS et CONNUS : musées officiels, monuments historiques, \
restaurants réputés, marchés existants, parcs publics, quartiers célèbres, etc.
4. Tu n'inventes AUCUN lieu. Si tu n'es pas certain qu'un lieu existe, tu ne le mets pas.
5. Chaque activité est un objet avec deux champs :
   - "name"        : nom exact et complet du lieu (ex: "Musée du Louvre", "Tour Eiffel").
   - "description" : une phrase courte (20-40 mots) décrivant ce qu'on y fait ou ce qui le rend incontournable.
6. Le JSON est un tableau, un objet par jour, exactement ce format :
[{"day": 1, "title": "...", "activities": [{"name": "Lieu réel", "description": "Courte description."}, ...]}]
"""

def _construire_prompt(ville: str, jours: int, transport: str) -> str:
    return (
        f"Crée un itinéraire de {jours} jour{'s' if jours > 1 else ''} à {ville}. "
        f"Transport principal : {transport}.\n\n"
        f"Contraintes rappelées :\n"
        f"- Exactement {jours} objet(s) dans le tableau (un par jour).\n"
        f"- 3 à 5 activités par jour, pas plus, pas moins.\n"
        f"- Uniquement des lieux réels et vérifiables à {ville} ou ses alentours proches.\n"
        f"- Chaque activité = objet avec \"name\" (nom exact du lieu) et \"description\" (1 phrase, 20-40 mots).\n"
        f"- Aucune invention. Si un lieu n'est pas certain, il est exclu.\n\n"
        f"Retourne UNIQUEMENT le JSON, rien d'autre."
    )


@app.route("/api/generate-trip", methods=["POST"])
@login_required
@limiter.limit("5 per minute")
def api_generate_trip():
    """
    POST /api/generate-trip
    Body JSON : { "ville": "Paris", "jours": 3, "transport": "métro" }
    Réponse   : { "trip": [...] }
    """
    user_id = session.get("user_id")
    t_start = time.monotonic()

    # ── Validation de l'input ──────────────────────────────
    data = request.get_json(silent=True)
    if not data:
        _log_api_call(user_id, "/api/generate-trip", 400, 0, "missing JSON body")
        return jsonify({"error": "Corps JSON manquant ou Content-Type incorrect."}), 400

    ville     = sanitize_ville(str(data.get("ville", "")))
    jours_raw = data.get("jours")
    transport = sanitize_transport(str(data.get("transport", "")))

    if ville is None:
        _log_api_call(user_id, "/api/generate-trip", 400, 0, "invalid ville")
        return jsonify({"error": "Nom de ville invalide ou caractères non autorisés."}), 400

    if transport is None:
        _log_api_call(user_id, "/api/generate-trip", 400, 0, "invalid transport")
        return jsonify({"error": "Mode de transport invalide."}), 400

    try:
        jours = int(jours_raw)
        if not (1 <= jours <= 30):
            raise ValueError
    except (TypeError, ValueError):
        _log_api_call(user_id, "/api/generate-trip", 400, 0, f"invalid jours={jours_raw!r}")
        return jsonify({"error": "Le champ 'jours' doit être un entier entre 1 et 30."}), 400

    # ── Appel OpenAI ──────────────────────────────────────
    try:
        client = _get_openai_client()

        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": _PROMPT_SYSTEME},
                {"role": "user",   "content": _construire_prompt(ville, jours, transport)},
            ],
            temperature=0.7,
            max_tokens=2048,
            response_format={"type": "json_object"},
        )

        contenu_brut = response.choices[0].message.content.strip()

    except RuntimeError as exc:
        duration_ms = (time.monotonic() - t_start) * 1000
        app.logger.error("OpenAI config error: %s", exc)
        _log_api_call(user_id, "/api/generate-trip", 503, duration_ms, "OpenAI not configured")
        return jsonify({"error": "Service IA non configuré. Contactez l'administrateur."}), 503

    except openai.AuthenticationError:
        duration_ms = (time.monotonic() - t_start) * 1000
        app.logger.error("OpenAI AuthenticationError: clé API invalide.")
        _log_api_call(user_id, "/api/generate-trip", 503, duration_ms, "OpenAI auth error")
        return jsonify({"error": "Clé API invalide. Contactez l'administrateur."}), 503

    except openai.RateLimitError:
        duration_ms = (time.monotonic() - t_start) * 1000
        _log_api_call(user_id, "/api/generate-trip", 429, duration_ms, "OpenAI rate limit")
        return jsonify({"error": "Quota OpenAI dépassé. Réessayez dans quelques instants."}), 429

    except openai.APITimeoutError:
        duration_ms = (time.monotonic() - t_start) * 1000
        _log_api_call(user_id, "/api/generate-trip", 504, duration_ms, "OpenAI timeout")
        return jsonify({"error": "Le service IA a mis trop de temps à répondre. Réessayez."}), 504

    except openai.APIError as exc:
        duration_ms = (time.monotonic() - t_start) * 1000
        app.logger.error("OpenAI APIError: %s", exc)
        _log_api_call(user_id, "/api/generate-trip", 502, duration_ms, f"OpenAI error: {exc}")
        return jsonify({"error": "Erreur du service IA. Réessayez dans quelques instants."}), 502

    # ── Parsing JSON de la réponse ─────────────────────────
    # response_format=json_object garantit un objet JSON — on récupère la clé contenant le tableau
    try:
        parsed = json.loads(contenu_brut)
    except json.JSONDecodeError as exc:
        app.logger.error("OpenAI réponse non-JSON: %s | contenu: %.200s", exc, contenu_brut)
        return jsonify({"error": "La réponse de l'IA n'est pas un JSON valide."}), 502

    # Le modèle peut envelopper dans {"itinerary": [...]} ou {"trip": [...]} ou retourner directement [...]
    if isinstance(parsed, list):
        itineraire = parsed
    elif isinstance(parsed, dict):
        # Cherche la première valeur qui est une liste
        itineraire = next(
            (v for v in parsed.values() if isinstance(v, list)),
            None
        )
        if itineraire is None:
            app.logger.error("OpenAI JSON sans tableau: %s", parsed)
            return jsonify({"error": "Format de réponse IA inattendu."}), 502
    else:
        return jsonify({"error": "Format de réponse IA inattendu."}), 502

    # ── Validation structurelle ────────────────────────────
    jours_recus = len(itineraire)
    for i, jour in enumerate(itineraire):
        if not isinstance(jour, dict):
            return jsonify({"error": f"Format invalide pour le jour {i + 1}."}), 502

        acts = jour.get("activities")
        if not isinstance(acts, list):
            return jsonify({"error": f"Clé 'activities' manquante au jour {i + 1}."}), 502

        # Normalise les activités : accepte str (ancien format) ou dict {name, description}
        normalized = []
        for act in acts:
            if isinstance(act, str):
                normalized.append({"name": act, "description": ""})
            elif isinstance(act, dict):
                name = str(act.get("name", "")).strip()
                description = str(act.get("description", "")).strip()
                if not name:
                    continue                            # ignore les entrées sans nom
                normalized.append({"name": name, "description": description})
        jour["activities"] = normalized

        nb = len(normalized)
        if nb > 5:
            jour["activities"] = normalized[:5]        # tronqué silencieusement à 5
        elif nb < 3:
            app.logger.warning("Jour %d : seulement %d activité(s) reçue(s).", i + 1, nb)
            # Accepté quand même pour ne pas bloquer l'utilisateur

    duration_ms = (time.monotonic() - t_start) * 1000
    _log_api_call(user_id, "/api/generate-trip", 200, duration_ms,
                  f"ville={ville} jours={jours_recus} transport={transport}")

    return jsonify({
        "trip":  itineraire,
        "meta": {
            "ville":     ville,
            "jours":     jours_recus,
            "transport": transport,
            "model":     "gpt-4o-mini",
        }
    }), 200


# ── Migration des fichiers legacy au démarrage ────────────
try:
    with app.app_context():
        _migrer_fichiers_legacy()
except Exception:
    pass   # ne jamais empêcher gunicorn de démarrer


if __name__ == "__main__":
    app.run(debug=True)
