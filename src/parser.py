import yaml

REQUIRED_FIELDS = [
    "app_name",
    "description",
    "app_type",
    "users",
    "sensitive_data",
    "permissions",
    "endpoints",
    "components",
    "authentication",
    "storage",
    "network_flows",
    "business_context",
]

def load_yaml(file):
    content = file.read().decode("utf-8")
    data = yaml.safe_load(content)

    if not isinstance(data, dict):
        raise ValueError("Le fichier YAML doit contenir un objet principal.")

    return data

def validate_app_data(data):
    missing = [field for field in REQUIRED_FIELDS if field not in data]

    if missing:
        raise ValueError(f"Champs manquants : {', '.join(missing)}")

    return True
