import json

FICHIER = "data.json"


def charger() -> list:
    try:
        with open(FICHIER, "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return []


def sauvegarder(activites: list) -> None:
    with open(FICHIER, "w", encoding="utf-8") as f:
        json.dump(activites, f, indent=4, ensure_ascii=False)


def prochain_id(activites: list) -> int:
    """Retourne un ID unique même après des suppressions."""
    if not activites:
        return 1
    return max(a["id"] for a in activites) + 1
