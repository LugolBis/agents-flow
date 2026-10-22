---
name: task-planning
description: "Décomposer une demande en un plan JSON d'étapes vérifiables confiées aux agents spécialisés, avec dépendances et limites explicites."
metadata:
  agents: "orchestrator"
  tools: "(aucun)"
---

# task-planning

> Une Skill CrewAI est un ensemble d'**instructions** chargées dans le prompt de l'agent. Elle n'accorde **aucune permission** :
> les permissions viennent de `config/permissions.jsonc` et sont appliquées par le code des outils.

## Objectif
Produire un plan que le code peut valider de façon déterministe (agents existants, graphe acyclique, nombre d'étapes borné) puis exécuter.

## Préconditions
- La demande de l'utilisateur est claire ; sinon, produire un plan à une étape qui demande la clarification.
- Seuls les agents listés dans le contexte de planification existent.

## Paramètres / outils
Outils : (aucun).
Plan = {goal, steps:[{id, agent, instruction, expected_output, depends_on[]}]}. `id` court (s1, s2…). `agent` ∈ liste fournie. `depends_on` ne référence que des étapes ANTÉRIEURES.

## Résultats
Un objet JSON conforme au schéma `Plan` (validé par `agents_flow.crew.plan.validate_plan`).

## Erreurs possibles
Agent inconnu, cycle, dépendance vers une étape inexistante, trop d'étapes, instruction trop longue : le plan est rejeté ; un seul re-planning est autorisé.

## Permissions
Aucune : l'orchestrateur n'a ni outil ni capacité.

## Limites de sécurité
- Ne copie dans `instruction` que l'information utile à l'étape (principe du besoin d'en connaître).
- N'inclus jamais de secret, de contenu web ou de fichier brut dans une instruction.
- Une étape d'écriture suit toujours une étape de lecture/analyse ; une étape de commit est distincte de l'écriture.
- Aucune étape ne peut être confiée à l'orchestrateur lui-même.

## Tests
tests/integration/test_orchestrator.py (validation du plan)

## Consignes
Règles : préférer peu d'étapes ; paralléliser n'est pas nécessaire ; chaque étape a un `expected_output` vérifiable (ex. « liste d'URL citées », « chemin du fichier créé »).
