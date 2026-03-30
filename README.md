# 🔐 Security Audit - Python Flask Application

## Objectif
Réaliser un audit de sécurité sur une application Python/Flask via :
- Revue de code manuelle
- Analyse statique avec outils (Bandit)
- Documentation des vulnérabilités

## Application audité
- **Langage** : Python 3
- **Framework** : Flask
- **Fichier** : `app.py`

## Méthodologie

| Phase | Action |
|-------|--------|
| 1 | Analyse statique avec Bandit |
| 2 | Inspection manuelle du code |
| 3 | Identification des patterns OWASP |
| 4 | Rédaction du rapport |

## Résultats de l'audit

### Vue d'ensemble

| Sévérité | Nombre |
|----------|--------|
| 🔴 CRITICAL | 5 |
| 🟠 HIGH | 7 |
| 🟡 MEDIUM | 5 |
| 🔵 LOW | 2 |
| **TOTAL** | **19** |

### Vulnérabilités critiques identifiées

| ID | Vulnérabilité | Localisation | Impact |
|----|---------------|--------------|--------|
| VULN-06 | SQL Injection | L93, L200, L233 | Bypass auth, exfiltration |
| VULN-09 | Command Injection | L135 | RCE complète |
| VULN-08 | Pickle Deserialization | L124 | RCE via pickle |
| VULN-14 | YAML RCE | L211 | Exécution de code |
| VULN-07 | SSTI | L116 | RCE via template |

### Cartographie OWASP Top 10

| OWASP | Vulnérabilités concernées |
|-------|---------------------------|
| A01:2021 (Broken Access Control) | IDOR, VULN-12,13 |
| A02:2021 (Cryptographic Failures) | MD5, hardcoded secrets |
| A03:2021 (Injection) | SQLi, Command, SSTI, XXE |
| A05:2021 (Security Misconfiguration) | Debug mode, CORS, headers |

## Recommandations immédiates (0-48h)

1. ❌ **Désactiver debug mode** → `app.run(debug=False)`
2. ❌ **Corriger les SQL injections** → Requêtes paramétrées
3. ❌ **Remplacer pickle.loads()** → Utiliser JSON
4. ❌ **Remplacer yaml.load()** → `yaml.safe_load()`
5. ❌ **Restreindre JWT** → `algorithms=['HS256']` uniquement


