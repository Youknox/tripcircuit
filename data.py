"""
data.py — utilitaires partagés (ne contient PAS de charger/sauvegarder globaux).
L'isolation par utilisateur est gérée dans app.py via charger(user_id) / sauvegarder(activites, user_id).
"""


def prochain_id(activites: list) -> int:
    """Retourne un ID unique même après des suppressions."""
    if not activites:
        return 1
    return max(a["id"] for a in activites) + 1
