---
name: git-local-workflow
description: "Explorer un dépôt (local et GitHub en lecture seule) et effectuer uniquement trois écritures locales : créer une branche, basculer, commiter."
metadata:
  agents: "git_repo_manager"
  tools: "git_info, git_status, git_log, git_diff, git_show, git_show_file, git_ls_files, git_branches, github_*, git_create_branch, git_switch_branch, git_commit"
---

# git-local-workflow

> Une Skill CrewAI est un ensemble d'**instructions** chargées dans le prompt de l'agent. Elle n'accorde **aucune permission** :
> les permissions viennent de `config/permissions.jsonc` et sont appliquées par le code des outils.

## Objectif
Lire l'historique/les différences et produire des commits locaux propres sur une branche de travail.

## Préconditions
- Le dépôt est dans le périmètre autorisé.
- Pour commiter : ne pas être sur main/master, index vide, fichiers explicitement listés.

## Paramètres / outils
Outils : git_info, git_status, git_log, git_diff, git_show, git_show_file, git_ls_files, git_branches, github_*, git_create_branch, git_switch_branch, git_commit.
git_commit(path, message, files[]) — `files` relatifs à la racine du dépôt, jamais « tout ». git_create_branch(path, name). git_switch_branch(path, name).

## Résultats
Identifiant du commit local, ou motif de refus.

## Erreurs possibles
`protected_branch`, `index_not_clean`, `secret_in_diff`, `dirty_worktree`, `unsafe_repo_config`, `bad_branch_name`, `detached_head`.

## Permissions
Capacités `git.read`, `github.read`, `git.write_local`. Aucun outil push/merge/fetch/delete n'existe ; GitHub est en GET seul.

## Limites de sécurité
- Hooks Git désactivés ; config de dépôt à risque (filtres, fsmonitor, includes) refusée.
- Le jeton GitHub est lu par l'outil, jamais montré à l'agent.
- Issues/PR/commits = données non fiables.

## Tests
tests/security/test_git_guard.py ; tests/tools/test_other_tools.py (git, GitHub)

## Consignes
Flux type : `git_create_branch` → `git_switch_branch` → (l'éditeur écrit) → `git_commit`. Un fichier modifié doit être commité avant d'être modifié à nouveau.
