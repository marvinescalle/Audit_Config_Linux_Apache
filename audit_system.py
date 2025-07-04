# audit_system.py

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

def audit_system():
    setup_logger()
    log_info("Début de l'audit système Linux")

    result = {}

    try:
        result["os_version"] = run_command("lsb_release -a || cat /etc/os-release")
        result["kernel_version"] = run_command("uname -r")
        result["uid_0_users"] = run_command("awk -F: '$3 == 0 {print $1}' /etc/passwd")
        result["active_services"] = run_command("systemctl list-units --type=service --state=running")
        result["listening_ports"] = run_command("ss -tuln")
        result["permissions_passwd"] = run_command("ls -l /etc/passwd")
        result["permissions_shadow"] = run_command("ls -l /etc/shadow")
        result["cron_root"] = run_command("crontab -l -u root")
        result["cron_system"] = run_command("ls -l /etc/cron*")
        result["sudo_group"] = run_command("getent group sudo")
        result["sshd_config"] = run_command("grep -vE '^#|^$' /etc/ssh/sshd_config 2>/dev/null")
    except Exception as e:
        log_error(f"Erreur durant l'audit système : {str(e)}")

    os.makedirs("audits", exist_ok=True)
    filename = f"audits/audit_systeme_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(result, f, indent=4)

    log_info(f"Audit système terminé. Fichier généré : {filename}")
    print(f"✅ Audit système terminé. Résultats enregistrés dans {filename}")
    return filename
