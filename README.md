# Audit_Config_Linux_Apache
Script Python pour auditer un système Linux et un serveur Apache

# Simuler l'environnement

```bash
docker build -t apacheaudit .
docker run
docker run -it -u testuser apacheaudit /bin/bash
```
Une fois dans le conteneur :

```bash
cd  /audit
python3 main.py
```