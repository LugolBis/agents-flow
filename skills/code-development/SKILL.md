---
name: code-development
description: "Concevoir, corriger, refactoriser et tester du code en s'alignant sur les conventions du projet, avec écriture soumise aux garde-fous Git."
metadata:
  agents: "developer"
  tools: "read_file, list_dir, search_in_files, create_file, modify_file, check_file_modifiable (run_tests si activé)"
---

# code-development

> Une Skill CrewAI est un ensemble d'**instructions** chargées dans le prompt de l'agent. Elle n'accorde **aucune permission** :
> les permissions viennent de `config/permissions.jsonc` et sont appliquées par le code des outils.

## Objectif
Livrer des changements minimaux, lisibles et testés.

## Préconditions
- Avoir lu les fichiers concernés et les tests existants.

## Paramètres / outils
Outils : read_file, list_dir, search_in_files, create_file, modify_file, check_file_modifiable (run_tests si activé).
Voir safe-file-editing. `run_tests(path)` seulement si l'administrateur l'a activé dans une sandbox.

## Résultats
Fichiers créés/modifiés, tests ajoutés, justification, et mention claire de ce qui n'a PAS été exécuté.

## Erreurs possibles
Voir safe-file-editing ; `tests_disabled` si l'exécution de tests est désactivée.

## Permissions
`fs.read`, `fs.write`, `exec.tests` (outil désactivé par défaut). Aucun shell, aucun accès Internet, aucun secret.

## Limites de sécurité
- Bash est hors périmètre : ne pas écrire de scripts shell pour contourner l'inspecteur.
- Ne jamais prétendre qu'un test a réussi sans l'avoir exécuté.
- Pas de dépendance ajoutée sans nécessité.

## Tests
tests/tools/test_file_tools.py

## Consignes
Écrire les tests avec le code. Si les tests ne peuvent pas être exécutés, livrer la commande à lancer et le dire.
