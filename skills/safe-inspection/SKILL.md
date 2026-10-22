---
name: safe-inspection
description: "Inspecter un environnement via une liste blanche de commandes en lecture seule (pwd, ls, find, cat, head, tail, file, stat, git status/log/diff/ls-files)."
metadata:
  agents: "shell_inspector"
  tools: "shell_inspect"
---

# safe-inspection

> Une Skill CrewAI est un ensemble d'**instructions** chargées dans le prompt de l'agent. Elle n'accorde **aucune permission** :
> les permissions viennent de `config/permissions.jsonc` et sont appliquées par le code des outils.

## Objectif
Constater l'état d'un environnement sans pouvoir le modifier.

## Préconditions
- Une seule commande simple par appel.

## Paramètres / outils
Outils : shell_inspect.
shell_inspect(command, cwd).

## Résultats
Sortie plafonnée et expurgée des secrets.

## Erreurs possibles
`shell_metacharacters`, `forbidden_command`, `command_not_allowlisted`, `flag_not_allowed`, `outside_allowed_roots`, `not_regular_file`.

## Permissions
Capacité `shell.inspect` — indépendante de celle du développeur.

## Limites de sécurité
- Aucun shell : argv exécuté directement, chemin absolu de confiance, environnement vide, délai/CPU/mémoire/sortie bornés.
- `find -exec/-delete`, `tail -f`, `git -c`, `--output` refusés.
- Un refus n'est pas un obstacle à contourner.

## Tests
tests/security/test_commands.py

## Consignes
Pour chercher : `find . -name '*.py' -maxdepth 3` ; pour lire : `head -n 50 fichier`.
