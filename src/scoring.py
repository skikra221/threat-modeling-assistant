def classify_score(score):
    if score <= 25:
        return "Faible"
    if score <= 60:
        return "Moyen"
    if score <= 100:
        return "Élevé"
    return "Critique"

def score_threats(threats):
    for threat in threats:
        impact = int(threat.get("impact", 1))
        probability = int(threat.get("probability", 1))
        exposure = int(threat.get("exposure", 1))

        score = impact * probability * exposure

        threat["score"] = score
        threat["level"] = classify_score(score)

    return threats

def calculate_global_risk(threats):
    if not threats:
        return {
            "max_score": 0,
            "average_score": 0,
            "level": "Aucun risque"
        }

    scores = [t["score"] for t in threats]

    return {
        "max_score": max(scores),
        "average_score": round(sum(scores) / len(scores), 2),
        "level": classify_score(max(scores))
    }
