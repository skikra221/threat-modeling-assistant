# Rapport de Threat Modeling — {{ app.app_name }}

**Date de génération :** {{ generated_at }}

---

## 1. Résumé exécutif

Ce rapport présente une modélisation des menaces pour l’application **{{ app.app_name }}**.

L’analyse a identifié **{{ analysis.threats | length }} menace(s)**.

---

## 2. Description de l’application

**Nom :** {{ app.app_name }}

**Type :** {{ app.app_type }}

**Description :**  
{{ app.description }}

---

## 3. Assets critiques

{% for asset in analysis.assets %}
- {{ asset }}
{% endfor %}

---

## 4. Acteurs

{% for actor in analysis.actors %}
- {{ actor }}
{% endfor %}

---

## 5. Points d’entrée

{% for entry in analysis.entry_points %}
- {{ entry }}
{% endfor %}

---

## 6. Méthodologie

La méthodologie utilisée repose sur :

- STRIDE pour classer les menaces.
- OWASP MASVS pour structurer les exigences mobiles.
- Scoring : Impact × Probabilité × Exposition.

---

## 7. Risk register

| ID | Menace | STRIDE | Asset | Point d’entrée | Impact | Probabilité | Exposition | Score | Niveau | MASVS | Statut |
|---|---|---|---|---|---:|---:|---:|---:|---|---|---|
{% for t in analysis.threats %}
| {{ t.id }} | {{ t.threat }} | {{ t.stride }} | {{ t.asset }} | {{ t.entry_point }} | {{ t.impact }} | {{ t.probability }} | {{ t.exposure }} | {{ t.score }} | {{ t.level }} | {{ t.masvs }} | {{ t.status }} |
{% endfor %}

---

## 8. Recommandations

{% for t in analysis.threats %}
- **{{ t.id }} :** {{ t.mitigation }}
{% endfor %}

---

## 9. Questions manquantes

{% if analysis.missing_questions %}
{% for q in analysis.missing_questions %}
- {{ q }}
{% endfor %}
{% else %}
Aucune question manquante détectée.
{% endif %}

---

## 10. Limites

Ce rapport est généré à partir des informations déclarées. Il ne remplace pas un audit manuel, une revue de code ou un test d’intrusion.

---

## 11. Conclusion

L’outil permet d’automatiser une première analyse de menace mobile, de produire un registre de risques et de prioriser les mesures de sécurité.
