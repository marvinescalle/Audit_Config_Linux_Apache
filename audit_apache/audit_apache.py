# -*- coding: utf-8 -*-

"""
Module d'audit pour le serveur web Apache.

Ce module collecte des informations de configuration essentielles pour un audit de sécurité,
en se basant sur les commandes natives d'Apache et l'analyse des fichiers de configuration.
"""

import subprocess
import os
import re
import json
from datetime import datetime

# --- Fonctions de collecte d'informations ---

def _get_apache_version_and_paths(logger):
    """
    Exécute 'apache2ctl -V' pour obtenir la version, les chemins de configuration, etc.
    C'est le point de départ le plus fiable pour trouver les informations clés.
    
    Args:
        logger: L'objet logger pour enregistrer les événements.

    Returns:
        Un dictionnaire avec les informations de base d'Apache ou None si la commande échoue.
    """
    logger.info("Début de la collecte des informations de base d'Apache via 'apache2ctl -V'.")
    apache_info = {}
    try:
        # Utiliser 'apache2ctl' qui est le standard sur Debian/Ubuntu
        result = subprocess.run(
            ['apache2ctl', '-V'],
            capture_output=True,
            text=True,
            check=True,
            encoding='utf-8'
        )
        
        # Expressions régulières pour extraire les informations clés
        patterns = {
            'server_version': r"Server version: (.*)",
            'server_built': r"Server built:   (.*)",
            'server_mpm': r"Server MPM:     (.*)",
            'config_file': r"-D SERVER_CONFIG_FILE=\"(.*?)\""
        }
        
        for key, pattern in patterns.items():
            match = re.search(pattern, result.stdout)
            if match:
                apache_info[key] = match.group(1).strip()
        
        if not apache_info:
             logger.warning("Impossible d'extraire les informations de version depuis la sortie de 'apache2ctl -V'.")
             return None

        logger.info(f"Version Apache détectée : {apache_info.get('server_version')}")
        logger.info(f"Fichier de configuration principal : {apache_info.get('config_file')}")
        return apache_info

    except FileNotFoundError:
        logger.error("'apache2ctl' non trouvé. Apache est-il installé et dans le PATH ?")
        return None
    except subprocess.CalledProcessError as e:
        logger.error(f"Erreur lors de l'exécution de 'apache2ctl -V': {e.stderr}")
        return None


def _get_loaded_modules(logger):
    """
    Liste les modules chargés par Apache via 'apache2ctl -M'.
    
    Args:
        logger: L'objet logger.

    Returns:
        Une liste des modules chargés ou une liste vide en cas d'erreur.
    """
    logger.info("Récupération des modules Apache chargés via 'apache2ctl -M'.")
    modules = []
    try:
        result = subprocess.run(
            ['apache2ctl', '-M'],
            capture_output=True,
            text=True,
            check=True,
            encoding='utf-8'
        )
        # La sortie liste les modules avec "(static)" ou "(shared)"
        # On ne garde que le nom du module
        for line in result.stdout.splitlines():
            line = line.strip()
            if 'module' in line:
                module_name = line.split()[0]
                modules.append(module_name)
        
        logger.info(f"{len(modules)} modules Apache trouvés.")
        return sorted(modules)

    except (FileNotFoundError, subprocess.CalledProcessError) as e:
        logger.error(f"Impossible de lister les modules Apache : {e}")
        return []

def _parse_config_files(config_file_path, logger):
    """
    Analyse le fichier de configuration principal d'Apache et les fichiers inclus.
    Recherche des directives de sécurité importantes.
    
    Args:
        config_file_path: Chemin vers le fichier de configuration principal (ex: /etc/apache2/apache2.conf).
        logger: L'objet logger.

    Returns:
        Un dictionnaire contenant les directives de configuration trouvées.
    """
    if not config_file_path or not os.path.exists(config_file_path):
        logger.error(f"Le fichier de configuration principal '{config_file_path}' est introuvable.")
        return {}

    logger.info(f"Début de l'analyse des fichiers de configuration à partir de '{config_file_path}'.")
    
    # Directives de sécurité et de configuration critiques à rechercher
    directives_to_find = [
        'ServerTokens', 'ServerSignature', 'TraceEnable', 'KeepAlive', 'KeepAliveTimeout',
        'Timeout', 'MaxRequestWorkers', 'User', 'Group', 'Listen', 'LogLevel',
        'ErrorLog', 'CustomLog', 'SSLEngine', 'SSLProtocol', 'SSLCipherSuite',
        'Options', 'AllowOverride'
    ]
    
    found_directives = {key: "Non trouvé" for key in directives_to_find}
    processed_files = set()
    
    # file_paths_to_scan est une pile de chemins à analyser
    config_dir = os.path.dirname(config_file_path)
    file_paths_to_scan = [config_file_path]
    
    while file_paths_to_scan:
        current_path = file_paths_to_scan.pop(0)
        
        if current_path in processed_files:
            continue
        processed_files.add(current_path)
        
        if not os.path.exists(current_path):
            logger.warning(f"Fichier de configuration inclus '{current_path}' non trouvé, ignoré.")
            continue
            
        logger.info(f"Analyse de : {current_path}")
        try:
            with open(current_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    # Ignorer les commentaires et les lignes vides
                    if not line or line.startswith('#'):
                        continue
                    
                    # Chercher les directives d'inclusion pour les ajouter à la liste
                    if line.lower().startswith(('include ', 'includeoptional ')):
                        path_pattern = line.split(maxsplit=1)[1]
                        # Construire un chemin absolu si le chemin est relatif
                        if not os.path.isabs(path_pattern):
                            path_pattern = os.path.join(config_dir, path_pattern)
                        # Pour l'instant, on gère les inclusions simples. Le globbing pourrait être ajouté.
                        file_paths_to_scan.append(path_pattern)
                        continue

                    # Chercher les directives importantes
                    parts = line.split(maxsplit=1)
                    directive = parts[0]
                    
                    if directive in directives_to_find:
                        value = parts[1] if len(parts) > 1 else "Activé (sans valeur)"
                        # On stocke la dernière valeur trouvée, qui est souvent celle qui s'applique
                        found_directives[directive] = value

        except Exception as e:
            logger.error(f"Erreur lors de la lecture du fichier '{current_path}': {e}")
            
    logger.info("Analyse des fichiers de configuration terminée.")
    return found_directives


# --- Fonction principale du module ---

def run_apache_audit(logger):
    """
    Orchestre l'audit complet du serveur Apache.

    Args:
        logger: L'objet logger principal du script.

    Returns:
        Un dictionnaire contenant tous les résultats de l'audit Apache.
    """
    logger.info("="*20 + " DÉBUT DE L'AUDIT APACHE " + "="*20)
    
    audit_results = {
        "audit_metadata": {
            "date": datetime.now().isoformat(),
            "module": "audit_apache"
        },
        "server_info": {},
        "loaded_modules": [],
        "config_directives": {}
    }

    # 1. Obtenir la version et les informations de base
    server_info = _get_apache_version_and_paths(logger)
    if not server_info:
        logger.error("Audit Apache interrompu : impossible de récupérer les informations de base.")
        audit_results['error'] = "Impossible de communiquer avec Apache via 'apache2ctl'."
        return audit_results
    
    audit_results["server_info"] = server_info

    # 2. Lister les modules chargés
    audit_results["loaded_modules"] = _get_loaded_modules(logger)

    # 3. Analyser les fichiers de configuration
    main_config_file = "/etc/apache2/apache2.conf"  # Chemin par défaut pour Debian/Ubuntu
    audit_results["config_directives"] = _parse_config_files(main_config_file, logger)

    logger.info("="*20 + " FIN DE L'AUDIT APACHE " + "="*20)


    os.makedirs("audits", exist_ok=True)
    filename = f"audits/audit_apache_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(audit_results, f, indent=4)

    return filename