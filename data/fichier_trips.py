import os

def fichier_trips(user_id: int) -> str:
    dossier = "data"

    # Crée le dossier si il n'existe pas
    if not os.path.exists(dossier):
        os.makedirs(dossier)

    return os.path.join(dossier, f"trips_{user_id}.json")