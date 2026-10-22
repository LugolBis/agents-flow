---
name: readme-writing
description: "Rédiger ou améliorer un README et la documentation d'un projet à partir de l'analyse réelle du code, sans rien inventer."
metadata:
  agents: "doc_writer"
  tools: "read_file, list_dir, search_in_files, scan_project, create_file, modify_file, check_file_modifiable"
---

# readme-writing

> Une Skill CrewAI est un ensemble d'**instructions** chargées dans le prompt de l'agent. Elle n'accorde **aucune permission** :
> les permissions viennent de `config/permissions.jsonc` et sont appliquées par le code des outils.

## Objectif
Une documentation exacte, vérifiable, sans secret.

## Préconditions
- Avoir exécuté `scan_project` et lu les fichiers cités dans le README.

## Paramètres / outils
Outils : read_file, list_dir, search_in_files, scan_project, create_file, modify_file, check_file_modifiable.
Voir safe-file-editing.

## Résultats
README créé (ou `README.proposed.md` si le README existant n'est pas modifiable) + liste « non vérifié ».

## Erreurs possibles
Voir safe-file-editing.

## Permissions
`fs.read`, `fs.write`.

## Limites de sécurité
- Ne jamais inventer fonctionnalités, commandes, dépendances ou résultats de tests : marquer « non vérifié ».
- Variables d'environnement : noms et rôle uniquement, jamais de valeur.

## Tests
tests/tools/test_file_tools.py

## Consignes
Sections selon le projet : présentation, fonctionnalités, architecture, prérequis, installation, configuration, variables d'environnement, utilisation, tests, structure, dépannage, limites, licence/contribution (si connues).
