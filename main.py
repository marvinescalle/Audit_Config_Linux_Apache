# main.py

from audit_system import audit_system
from audit_apache import audit_apache
from utils import setup_logger, log_info

def afficher_menu():
    print("\n=== MENU AUDIT DE SÉCURITÉ ===")
    print("1. Lancer l'audit système Linux")
    print("2. Lancer l'audit Apache")
    print("3. Lancer les deux audits")
    print("4. Quitter")

def main():
    setup_logger()
    log_info("=== Lancement du script principal ===")

    while True:
        afficher_menu()
        choix = input("Votre choix (1-4) : ").strip()

        if choix == "1":
            audit_system()
        elif choix == "2":
            audit_apache()
        elif choix == "3":
            audit_system()
            audit_apache()
        elif choix == "4":
            print("👋 Au revoir !")
            log_info("Fin du script principal.")
            break
        else:
            print("❌ Choix invalide. Veuillez réessayer.")

if __name__ == "__main__":
    main()
