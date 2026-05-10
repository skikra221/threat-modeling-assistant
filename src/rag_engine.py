import os
import re

RAG_DOCS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rag_docs")

# Mapping MASVS categories to their respective markdown files
MASVS_MAPPING = {
    "V2": ["masvs_storage.md", "stride.md"],
    "V3": ["masvs_code.md", "stride.md"], # V3 is cryptography, mapped to code for now or could be separated.
    "V4": ["masvs_auth.md", "stride.md"],
    "V5": ["masvs_network.md", "stride.md"],
    "V6": ["masvs_platform.md", "stride.md"],
    "V7": ["masvs_code.md", "stride.md"],
}

def read_doc(filename):
    """Read a markdown document from the rag_docs directory."""
    filepath = os.path.join(RAG_DOCS_DIR, filename)
    if os.path.exists(filepath):
        with open(filepath, "r", encoding="utf-8") as f:
            return f.read()
    return ""

def retrieve_context_for_threat(threat):
    """
    Retrieve local knowledge documents based on the threat's MASVS category.
    FUTURE EXTENSION: This function can be replaced with a ChromaDB vector search
    querying `threat['description']` against embedded markdown chunks.
    """
    masvs_cat = str(threat.get("masvs", "")).split(".")[0] # e.g., 'V4' from 'V4.1'
    files_to_load = MASVS_MAPPING.get(masvs_cat, ["stride.md"])
    
    # If the threat mentions privacy or LINDDUN, add linddun.md
    if "privacy" in str(threat.get("threat", "")).lower() or "privacy" in str(threat.get("description", "")).lower():
        if "linddun.md" not in files_to_load:
            files_to_load.append("linddun.md")
            
    # Also add privacy doc if MASVS is privacy-related (custom mapping if needed)
    
    contexts = {}
    for filename in files_to_load:
        contexts[filename] = read_doc(filename)
        
    return contexts, files_to_load

def generate_rag_explanation(threat, app_data=None):
    """
    Generate a structured RAG explanation by combining deterministic rules
    with the retrieved local context.
    FUTURE EXTENSION: This can send `contexts` and `threat` to an LLM (OpenAI/Ollama)
    to generate dynamic natural language responses.
    """
    contexts, sources = retrieve_context_for_threat(threat)
    
    masvs_full = threat.get("masvs", "Unknown")
    masvs_cat = str(masvs_full).split(".")[0]
    
    # Base extraction of relevant snippets from the contexts
    verification_tests = []
    core_concepts = ""
    
    for filename, content in contexts.items():
        if not content: continue
        
        # Extract Verification Tests using simple Regex (looking for numbered lists under the header)
        if "Suggested Verification Tests" in content:
            tests_section = content.split("Suggested Verification Tests")[1]
            tests = re.findall(r'^\d+\.\s*(.+)', tests_section, re.MULTILINE)
            verification_tests.extend(tests)
            
        # Extract Core Concepts
        if "Core Concepts" in content:
            concept_section = content.split("Core Concepts")[1].split("##")[0].strip()
            if not core_concepts:
                core_concepts = concept_section
    
    # Fallback if parsing fails
    if not verification_tests:
        verification_tests = [
            f"Review the implementation against {masvs_full} requirements.",
            "Perform dynamic analysis to validate if the vulnerability is exploitable.",
            "Review the source code for hardcoded secrets or improper configurations."
        ]
        
    if not core_concepts:
        core_concepts = f"This threat relates to the {masvs_cat} category. It involves potential weaknesses in the application's design or implementation that could be exploited."

    # Construct the structured explanation
    rag_data = {
        "rag_explanation": f"{threat.get('threat', 'Security Risk')} was flagged by the automated engine. Based on our local knowledge base: {core_concepts}",
        "masvs_rationale": f"This maps to {masvs_full} because it violates the fundamental security requirements for this category. Attackers might exploit {threat.get('stride', 'this flaw')} to compromise the application.",
        "verification_tests": verification_tests[:4], # Limit to top 4 tests
        "missing_information": [
            "Is there a compensating control (e.g., WAF, API Gateway) mitigating this risk?",
            "How is the sensitive data encrypted at rest and in transit?",
            "What is the exact framework or library version used for this feature?"
        ],
        "rag_sources": sources
    }
    
    return rag_data

def enrich_threats_with_rag(threats, app_data=None):
    """
    Iterate over the deterministic threats and enrich them with RAG data.
    """
    enriched_threats = []
    for threat in threats:
        # Create a copy to avoid mutating the original prematurely if needed
        enriched_threat = dict(threat)
        enriched_threat["rag_data"] = generate_rag_explanation(threat, app_data)
        enriched_threats.append(enriched_threat)
        
    return enriched_threats

def get_rag_metrics(threats):
    """Calculate metrics for the UI based on the RAG enrichment."""
    total_enriched = len(threats)
    
    all_sources = set()
    total_missing_questions = 0
    masvs_areas = set()
    
    for t in threats:
        rag = t.get("rag_data", {})
        all_sources.update(rag.get("rag_sources", []))
        total_missing_questions += len(rag.get("missing_information", []))
        
        masvs_cat = str(t.get("masvs", "")).split(".")[0]
        if masvs_cat:
            masvs_areas.add(masvs_cat)
            
    return {
        "threats_enriched": total_enriched,
        "knowledge_sources_used": len(all_sources),
        "masvs_areas_covered": len(masvs_areas),
        "missing_questions_generated": total_missing_questions
    }
