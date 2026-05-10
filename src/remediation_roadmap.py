def classify_priority(score):
    if score >= 101:
        return "P0 Critical"
    if score >= 61:
        return "P1 High"
    if score >= 26:
        return "P2 Medium"
    return "P3 Low"

def estimate_effort(threat):
    masvs = threat.get("masvs", "").upper()
    action = threat.get("mitigation", "").lower()
    
    if "mfa" in action or "redesign" in action or "architecture" in action:
        return "High"
    
    if "network" in masvs or "storage" in masvs or "auth" in masvs:
        return "Medium"
    
    if "https" in action or "tls" in action or "keystore" in action or "rate limiting" in action:
        return "Medium"
        
    if "log" in action or "debug" in action or "intent" in action or "exported component" in action:
        return "Low"
        
    return "Medium"

def estimate_owner(threat):
    masvs = threat.get("masvs", "").upper()
    
    if "NETWORK" in masvs:
        return "Backend / Mobile Team"
    if "STORAGE" in masvs:
        return "Mobile Team"
    if "AUTH" in masvs:
        return "Backend / Identity Team"
    if "PRIVACY" in masvs:
        return "Security / Privacy Team"
    if "PLATFORM" in masvs or "CODE" in masvs:
        return "Mobile Team"
        
    return "Security Team"

def estimate_residual_score(threat):
    impact = int(threat.get("impact", 1))
    probability = int(threat.get("probability", 1))
    exposure = int(threat.get("exposure", 1))
    
    # Automatically reduce probability by 2 (min 1) and exposure by 1 (min 1)
    reduced_prob = max(1, probability - 2)
    reduced_exp = max(1, exposure - 1)
    
    residual_score = impact * reduced_prob * reduced_exp
    return residual_score

def generate_remediation_roadmap(threats):
    roadmap = []
    
    for t in threats:
        current_score = t.get("score", 0)
        residual_score = estimate_residual_score(t)
        priority = classify_priority(current_score)
        
        action = {
            "threat_id": t.get("id"),
            "priority": priority,
            "risk_level": t.get("level"),
            "current_score": current_score,
            "residual_score": residual_score,
            "risk_reduction": current_score - residual_score,
            "recommended_action": t.get("mitigation", "").split('.')[0] if '.' in t.get("mitigation", "") else t.get("mitigation", ""),
            "related_threat": t.get("threat"),
            "asset": t.get("asset"),
            "entry_point": t.get("entry_point"),
            "effort": estimate_effort(t),
            "owner": estimate_owner(t),
            "masvs": t.get("masvs"),
            "status": "To Do"
        }
        roadmap.append(action)
        
    # Sort by risk reduction (descending) then current score
    return sorted(roadmap, key=lambda x: (x["risk_reduction"], x["current_score"]), reverse=True)

def calculate_roadmap_metrics(roadmap):
    total_actions = len(roadmap)
    high_priority = sum(1 for a in roadmap if a["priority"] in ["P0 Critical", "P1 High"])
    
    total_reduction = sum(a["risk_reduction"] for a in roadmap)
    avg_reduction = round(total_reduction / total_actions, 1) if total_actions > 0 else 0
    
    quick_wins = sum(1 for a in roadmap if a["effort"] == "Low" and a["risk_reduction"] >= 10)
    
    return {
        "total_actions": total_actions,
        "high_priority": high_priority,
        "avg_reduction": avg_reduction,
        "quick_wins": quick_wins
    }
