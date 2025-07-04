from audit_system import run_linux_audit
from audit_apache import run_apache_audit
from utils import setup_logger, log_info
import logging

def afficher_menu():
    print("\n=== MENU AUDIT DE SÉCURITÉ ===")
    print("1. Lancer l'audit système Linux")
    print("2. Lancer l'audit Apache")
    print("3. Lancer les deux audits")
    print("4. Quitter")

def main():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - [%(levelname)s] - %(message)s',
        handlers=[
            logging.StreamHandler(), # Affiche les logs dans la console
            logging.FileHandler('audit.log') # Enregistre dans un fichier
        ]
    )
    test_logger = logging.getLogger()
    log_info("=== Lancement du script principal ===")

    while True:
        afficher_menu()
        choix = input("Votre choix (1-4) : ").strip()

        if choix == "1":
            run_linux_audit(test_logger)
        elif choix == "2":
            run_apache_audit(test_logger)
        elif choix == "3":
            run_linux_audit(test_logger)
            run_apache_audit(test_logger)
        elif choix == "4":
            log_info("Fin du script principal.")
            break
        else:
            print("Choix invalide. Veuillez réessayer.")

if __name__ == "__main__":
    main()
