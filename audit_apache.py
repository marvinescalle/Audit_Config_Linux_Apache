# audit_apache.py

import os
import subprocess
import json
from datetime import datetime
from utils import setup_logger, log_info, log_error

def run_command(command):
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        return result.strip()
    except subprocess.CalledProcessError as e:
        log_error(f"Erreur commande '{command}': {e.output.strip()}")
        return f"Erreur: {e.output.strip()}"

def audit_apache():
    setup_logger()
    log_info("Début de l'audit Apache")

    result = {}

    try:
        # 1. Version Apache
        result["apache_version"] = run_command("apache2 -v")

        # 2. Modules activés
        result["apache_modules"] = run_command("apache2ctl -M")

        # 3. Fichier de conf principal
        result["apache_conf_path"] = "/etc/apache2/apache2.conf"
        result["apache_conf_content"] = run_command("cat /etc/apache2/apache2.conf")

        # 4. Analyse directives dangereuses
        directives = ["Indexes", "FollowSymLinks", "AllowOverride", "ServerTokens", "ServerSignature"]
        found = {}
        for directive in directives:
            cmd = f"grep -i '{directive}' /etc/apache2/apache2.conf"
            found[directive] = run_command(cmd)
        result["directives_sensibles"] = found

        # 5. Droits sur fichiers de conf
        result["conf_permissions"] = run_command("ls -l /etc/apache2/apache2.conf")

        # 6. Racine du site web
        result["document_root"] = run_command("apache2ctl -S | grep 'Main DocumentRoot' || grep -i 'DocumentRoot' /etc/apache2/sites-enabled/*.conf")

    except Exception as e:
        log_error(f"Erreur durant l'audit Apache : {str(e)}")

    os.makedirs("audits", exist_ok=True)
    filename = f"audits/audit_apache_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(result, f, indent=4)

    log_info(f"Audit Apache terminé. Fichier généré : {filename}")
    print(f"✅ Audit Apache terminé. Résultats enregistrés dans {filename}")
    return filename
