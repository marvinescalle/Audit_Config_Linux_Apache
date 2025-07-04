# -*- coding: utf-8 -*-

"""
Module for auditing a Linux system (specifically tailored for Debian/Ubuntu).

This module collects critical operating system information to identify potential
misconfigurations and security weaknesses. It uses native system commands and file parsing.
"""

import subprocess
import os
import re
import json
from datetime import datetime
import stat # Used for checking file permissions

# --- Helper Function for Running Commands ---

def _run_command(command, logger):
    """
    Executes a shell command and returns its output.
    
    Args:
        command (list): The command to execute as a list of strings.
        logger: The logger object for logging events.

    Returns:
        tuple: (stdout, stderr) of the command. Returns (None, error_message) on failure.
    """
    try:
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False, # We handle errors manually
            encoding='utf-8'
        )
        if process.returncode != 0:
            error_msg = process.stderr.strip()
            # Log non-critical errors as warnings (e.g., command not found)
            logger.warning(f"Command '{' '.join(command)}' failed with exit code {process.returncode}: {error_msg}")
            return (None, error_msg)
        return (process.stdout.strip(), None)
    except FileNotFoundError:
        error_msg = f"Command '{command[0]}' not found."
        logger.error(error_msg)
        return (None, error_msg)
    except Exception as e:
        error_msg = f"An unexpected error occurred with command '{' '.join(command)}': {e}"
        logger.error(error_msg)
        return (None, error_msg)


# --- Information Gathering Functions ---

def _get_os_info(logger):
    """Collects basic Operating System information."""
    logger.info("Collecting OS information.")
    os_info = {}
    
    # Kernel version
    stdout, _ = _run_command(['uname', '-a'], logger)
    if stdout:
        os_info['kernel_version'] = stdout
        
    # OS release information
    try:
        with open('/etc/os-release', 'r', encoding='utf-8') as f:
            for line in f:
                key, value = line.strip().split('=', 1)
                os_info[key.lower()] = value.strip('"')
    except FileNotFoundError:
        logger.warning("File /etc/os-release not found.")
        os_info['distribution'] = "Unknown"
        
    return os_info

def _get_user_info(logger):
    """Collects information about users and groups."""
    logger.info("Collecting user and group information.")
    user_info = {
        'login_users': [],
        'sudo_users': [],
        'users_with_no_password': [],
        'root_ssh_login': 'Not checked'
    }

    # Users with a login shell from /etc/passwd
    try:
        with open('/etc/passwd', 'r', encoding='utf-8') as f:
            for line in f:
                parts = line.strip().split(':')
                if len(parts) == 7:
                    username, shell = parts[0], parts[6]
                    if shell not in ['/sbin/nologin', '/bin/false', '/usr/sbin/nologin']:
                        user_info['login_users'].append(username)
    except FileNotFoundError:
        logger.error("File /etc/passwd not found.")
    
    # Users in the 'sudo' group from /etc/group
    try:
        with open('/etc/group', 'r', encoding='utf-8') as f:
            for line in f:
                if line.startswith('sudo:'):
                    parts = line.strip().split(':')
                    if len(parts) == 4 and parts[3]:
                        user_info['sudo_users'] = parts[3].split(',')
                    break
    except FileNotFoundError:
        logger.warning("File /etc/group not found.")

    # Check for users with no password in /etc/shadow (requires privileges)
    stdout, _ = _run_command(['sudo', 'cat', '/etc/shadow'], logger)
    if stdout:
        for line in stdout.splitlines():
            parts = line.strip().split(':')
            if len(parts) > 1:
                username, pass_hash = parts[0], parts[1]
                if not pass_hash:
                    user_info['users_with_no_password'].append(username)
    
    # Check if root SSH login is permitted
    try:
        with open('/etc/ssh/sshd_config', 'r', encoding='utf-8') as f:
            for line in f:
                if re.match(r'^\s*PermitRootLogin\s+yes', line, re.IGNORECASE):
                    user_info['root_ssh_login'] = 'Permitted'
                    break
            else:
                 user_info['root_ssh_login'] = 'Not Permitted or Default'
    except FileNotFoundError:
        logger.warning("File /etc/ssh/sshd_config not found.")
        user_info['root_ssh_login'] = 'Not Found'

    return user_info

def _get_network_info(logger):
    """Collects networking information like open ports and firewall status."""
    logger.info("Collecting network information.")
    network_info = {
        'listening_ports': 'Not checked',
        'firewall_status': 'Not checked'
    }
    
    # Use 'ss' (socket statistics) which is more modern than 'netstat'
    stdout, _ = _run_command(['ss', '-tuln'], logger)
    if stdout:
        network_info['listening_ports'] = stdout.splitlines()

    # Check for UFW (Uncomplicated Firewall), common on Ubuntu
    stdout, _ = _run_command(['sudo', 'ufw', 'status'], logger)
    if stdout:
         network_info['firewall_status'] = stdout
    else:
        # Fallback to check for iptables if ufw is not active/installed
        logger.info("UFW not active or installed, checking for iptables rules.")
        stdout, _ = _run_command(['sudo', 'iptables', '-L'], logger)
        if stdout:
            network_info['firewall_status'] = "Using iptables:\n" + stdout
        else:
            network_info['firewall_status'] = "No firewall tool (UFW/iptables) found or active."

    return network_info

def _check_sensitive_file_permissions(logger):
    """Checks permissions of critical system files."""
    logger.info("Checking permissions of sensitive files.")
    files_to_check = {
        '/etc/shadow': '640',
        '/etc/passwd': '644',
        '/etc/group': '644',
        '/etc/sudoers': '440',
    }
    permissions = {}

    for f_path, expected_perm_str in files_to_check.items():
        if os.path.exists(f_path):
            try:
                # Use 'sudo stat' because /etc/shadow and /etc/sudoers are not readable by normal users
                cmd = ['sudo', 'stat', '-c', '%a', f_path]
                stdout, stderr = _run_command(cmd, logger)
                
                if stdout:
                    current_perm = stdout.strip()
                    permissions[f_path] = {
                        'current': current_perm,
                        'recommended': expected_perm_str,
                        'is_secure': current_perm == expected_perm_str
                    }
                else:
                     permissions[f_path] = {'error': f'Could not stat file: {stderr}'}

            except Exception as e:
                permissions[f_path] = {'error': f'Could not check permissions: {e}'}
        else:
            permissions[f_path] = {'error': 'File not found'}

    return permissions

def _check_pending_updates(logger):
    """Checks for pending system updates on Ubuntu/Debian."""
    logger.info("Checking for pending system updates.")
    # This command is specific to Ubuntu/Debian and gives a summary
    # apt-get -s dist-upgrade will simulate an upgrade and show what would be installed
    stdout, stderr = _run_command(['apt-get', '-s', 'dist-upgrade'], logger)
    if stdout:
        upgraded = re.search(r'(\d+)\s+upgraded', stdout)
        newly_installed = re.search(r'(\d+)\s+newly installed', stdout)
        removed = re.search(r'(\d+)\s+to remove', stdout)
        
        return {
            "upgraded_packages": int(upgraded.group(1)) if upgraded else 0,
            "newly_installed": int(newly_installed.group(1)) if newly_installed else 0,
            "to_be_removed": int(removed.group(1)) if removed else 0
        }
    return {"error": f"Could not check for updates. Sudo rights might be needed. Error: {stderr}"}


# --- Main Module Function ---

def run_linux_audit(logger):
    """
    Orchestrates the full Linux system audit.

    Args:
        logger: The main logger object from the script.

    Returns:
        A dictionary containing all the collected audit results.
    """
    logger.info("="*20 + " STARTING LINUX SYSTEM AUDIT " + "="*20)

    audit_results = {
        "audit_metadata": {
            "date": datetime.now().isoformat(),
            "module": "audit_linux"
        },
        "os_info": {},
        "user_info": {},
        "network_info": {},
        "file_permissions": {},
        "pending_updates": {}
    }

    # Run each audit function and store the results
    audit_results["os_info"] = _get_os_info(logger)
    audit_results["user_info"] = _get_user_info(logger)
    audit_results["network_info"] = _get_network_info(logger)
    audit_results["file_permissions"] = _check_sensitive_file_permissions(logger)
    audit_results["pending_updates"] = _check_pending_updates(logger)
    
    os.makedirs("audits", exist_ok=True)
    filename = f"audits/audit_systeme_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(filename, "w") as f:
        json.dump(audit_results, f, indent=4)

    logger.info("="*20 + " LINUX SYSTEM AUDIT FINISHED " + "="*20)
    return filename