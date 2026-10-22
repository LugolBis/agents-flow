---
name: safe-file-editing
description: "Créer et modifier des fichiers en respectant la règle Git : un fichier existant n'est modifiable que s'il est suivi, commité et propre."
metadata:
  agents: "file_editor, developer, doc_writer"
  tools: "read_file, list_dir, search_in_files, create_file, modify_file, check_file_modifiable"
---

# safe-file-editing

> Une Skill CrewAI est un ensemble d'**instructions** chargées dans le prompt de l'agent. Elle n'accorde **aucune permission** :
> les permissions viennent de `config/permissions.jsonc` et sont appliquées par le code des outils.

## Objectif
Écrire sans jamais écraser un travail non sauvegardé.

## Préconditions
- Lire le fichier avant de le modifier.
- `check_file_modifiable` peut être appelé avant `modify_file` pour connaître l'état.

## Paramètres / outils
Outils : read_file, list_dir, search_in_files, create_file, modify_file, check_file_modifiable.
create_file(path, content) ; modify_file(path, edits[{old,new}] | content) ; edits = tout-ou-rien, chaque `old` unique.

## Résultats
Chemin écrit + vérification (hash, diff --stat). Si la modification directe est interdite : le fichier d'origine reste INTACT et une version `<nom>.proposed<ext>` est écrite, avec l'explication.

## Erreurs possibles
`already_exists`, `edit_not_unique`, `outside_allowed_roots`, `path_traversal`, `symlink_in_path`, `denied_by_pattern`, `write_denied_by_pattern`, `secret_in_content`, `content_too_large`, `binary_file`.

## Permissions
`fs.read` (+ `fs.write` pour créer/modifier).

## Limites de sécurité
- Ne jamais tenter un autre chemin, un lien symbolique ou un autre outil après un refus.
- Les fichiers `.env`, clés, `.git/`, `.github/workflows/**`, `.gitattributes` sont hors d'atteinte en écriture.
- Un fichier créé mais non commité n'est plus modifiable directement : réussir en une fois, ou demander un commit.

## Tests
tests/tools/test_file_tools.py ; tests/security/test_git_guard.py

## Consignes
Préférer `edits` (changements minimaux) à `content`. Après une modification, rapporter le diff vérifié, pas le contenu supposé.
