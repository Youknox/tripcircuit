import os
import glob
import uuid
import math
import random
import json
import hashlib
from functools import wraps
import requests
from bs4 import BeautifulSoup
from flask import Flask, render_template, request, redirect, session, abort
from data import prochain_id
import anthropic
from pydantic import BaseModel

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "tripcircuit-dev-secret-key")

USERS_FILE = "users.json"


# ── Gestion des utilisateurs ─────────────────────────────

def charger_users() -> list:
    try:
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def sauvegarder_users(users: list) -> None:
    with open(USERS_FILE, "w", encoding="utf-8") as f:
        json.dump(users, f, indent=2, ensure_ascii=False)


def hash_mdp(mdp: str) -> str:
    return hashlib.sha256(mdp.encode()).hexdigest()


# ── Données par utilisateur ──────────────────────────────

def fichier_data(user_id: int) -> str:
    return f"data_{user_id}.json"


def charger(user_id: int | None = None) -> list:
    path = fichier_data(user_id) if user_id else "data.json"
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def sauvegarder(activites: list, user_id: int | None = None) -> None:
    path = fichier_data(user_id) if user_id else "data.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(activites, f, indent=2, ensure_ascii=False)


# ── Gestion des voyages (trips) ───────────────────────────

def fichier_trips(user_id: int) -> str:
    return f"trips_{user_id}.json"


def charger_trips(user_id: int) -> list:
    try:
        with open(fichier_trips(user_id), "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def sauvegarder_trips(trips: list, user_id: int) -> None:
    with open(fichier_trips(user_id), "w", encoding="utf-8") as f:
        json.dump(trips, f, indent=2, ensure_ascii=False)


def prochain_trip_id(trips: list) -> int:
    return max((t["id"] for t in trips), default=0) + 1


def trouver_trip_par_slug(slug: str) -> dict | None:
    """
    Cherche un voyage par son slug public dans tous les fichiers trips_*.json.
    Retourne {"trip": ..., "owner_id": ...} ou None.
    """
    for path in glob.glob("trips_*.json"):
        try:
            owner_id = int(path.replace("trips_", "").replace(".json", ""))
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

    for path in glob.glob("trips_*.json"):
        if path == own_file:
            continue
        try:
            owner_id = int(path.replace("trips_", "").replace(".json", ""))
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

    for path in glob.glob("trips_*.json"):
        if path == own_file:
            continue
        try:
            # Extraire l'owner_id depuis le nom du fichier trips_<uid>.json
            owner_id = int(path.replace("trips_", "").replace(".json", ""))
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
            headers={"User-Agent": "TripCircuit/1.0"},
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
@login_required
def index():
    return render_template(
        "index.html",
        activites=[],
        trips=[]
    )

    # Filtre optionnel par voyage — avec contrôle d'accès strict
    trip_id_filtre = request.args.get("trip", type=int)
    trip_actif = None
    if trip_id_filtre:
        acces = trouver_trip_avec_acces(uid, trip_id_filtre)
        if acces is None:
            abort(403)  # ni propriétaire ni collaborateur
        trip_actif = acces["trip"]
        if acces["est_proprio"]:
            activites = [a for a in toutes_activites if a.get("trip_id") == trip_id_filtre]
        else:
            # Collaborateur → charger les activités du propriétaire
            activites_owner = charger(acces["owner_id"])
            activites = [a for a in activites_owner if a.get("trip_id") == trip_id_filtre]
    else:
        activites = toutes_activites

    nouvelle    = None
    suggestions = []

    nouveau_id = request.args.get("nouveau", type=int)
    if nouveau_id:
        nouvelle = next((a for a in toutes_activites if a["id"] == nouveau_id), None)
        if nouvelle:
            suggestions = suggerer(nouvelle, toutes_activites)

    suggestions_ia = nouvelle.get("suggestions_ia", []) if nouvelle else []

    # Index trips par id pour affichage dans les cartes
    trips_par_id = {t["id"]: t for t in tous_les_trips}

    return render_template("index.html",
                           activites=activites,
                           trips=tous_les_trips,
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
    uid  = session["user_id"]
    nom  = request.form.get("nom", "").strip()
    if not nom:
        return redirect("/trips")

    trips = charger_trips(uid)
    new_id = prochain_trip_id(trips)
    trips.append({"id": new_id, "nom": nom, "collaborateurs": [], "slug": uuid.uuid4().hex[:8]})
    sauvegarder_trips(trips, uid)
    return redirect("/trips")


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

    session["user_id"] = user["id"]
    session["email"]   = user["email"]
    return redirect("/")


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

    session["user_id"] = new_id
    session["email"]   = email
    return redirect("/")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")


if __name__ == "__main__":
    app.run(debug=True)
