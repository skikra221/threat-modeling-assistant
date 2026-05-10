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

## 5bis. Architecture & Data Flow Diagram

{{ mermaid_diagram if mermaid_diagram else "_Diagram not available._" }}

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

## 8bis. Remediation Roadmap

| Priority | ID | Recommended Action | Current Score | Residual Score | Risk Reduction | Effort | Owner | MASVS |
|---|---|---|---:|---:|---:|---|---|---|
{% for a in analysis.roadmap %}
| {{ a.priority }} | {{ a.threat_id }} | {{ a.recommended_action }} | {{ a.current_score }} | {{ a.residual_score }} | -{{ a.risk_reduction }} | {{ a.effort }} | {{ a.owner }} | {{ a.masvs }} |
{% endfor %}

---

## 8ter. RAG-Based Threat Explanations

{% for t in analysis.threats %}
{% if t.rag_data %}
### Threat: {{ t.threat }} ({{ t.masvs }})

**Explanation:**
{{ t.rag_data.rag_explanation }}

**MASVS Rationale:**
{{ t.rag_data.masvs_rationale }}

**Suggested Verification Tests:**
{% for test in t.rag_data.verification_tests %}
- {{ test }}
{% endfor %}

**Missing Information (Requires Review):**
{% for mi in t.rag_data.missing_information %}
- {{ mi }}
{% endfor %}

**Sources:** {{ t.rag_data.rag_sources | join(', ') }}

---
{% endif %}
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

{% if app.app_type == "Android APK" %}
This APK-based analysis is limited to static metadata extraction. It does not replace manual code review, dynamic analysis, reverse engineering, runtime testing or penetration testing.
{% else %}
Ce rapport est généré à partir des informations déclarées. Il ne remplace pas un audit manuel, une revue de code ou un test d’intrusion.
{% endif %}

---

## 11. Conclusion

L’outil permet d’automatiser une première analyse de menace mobile, de produire un registre de risques et de prioriser les mesures de sécurité.
