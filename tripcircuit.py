from data import charger, sauvegarder, prochain_id


def ajouter_activite(activites: list, nom: str, lien: str) -> None:
    activites.append({
        "id": prochain_id(activites),
        "nom": nom,
        "lien": lien
    })
    sauvegarder(activites)
    print("✅ Activité ajoutée")


def afficher_activites(activites: list) -> None:
    if not activites:
        print("Aucune activité")
        return
    for act in activites:
        print(f"{act['id']} - {act['nom']} ({act['lien']})")


def supprimer_activite(activites: list, id: int) -> list:
    nouveau = [a for a in activites if a["id"] != id]
    sauvegarder(nouveau)
    print("🗑️ Activité supprimée")
    return nouveau


def main() -> None:
    activites = charger()

    while True:
        print("\n--- TripCircuit ---")
        print("1. Ajouter activité")
        print("2. Voir activités")
        print("3. Supprimer activité")
        print("4. Quitter")

        choix = input("Choix : ")

        if choix == "1":
            nom = input("Nom : ").strip()
            lien = input("Lien : ").strip()
            ajouter_activite(activites, nom, lien)

        elif choix == "2":
            afficher_activites(activites)

        elif choix == "3":
            afficher_activites(activites)
            try:
                id = int(input("ID à supprimer : "))
                activites = supprimer_activite(activites, id)
            except ValueError:
                print("❌ Entrez un nombre valide")

        elif choix == "4":
            break


if __name__ == "__main__":
    main()
