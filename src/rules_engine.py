def as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]

def text_blob(data):
    return str(data).lower()

def has_keyword(data, keywords):
    blob = text_blob(data)
    return any(k.lower() in blob for k in keywords)

def endpoint_url(endpoint):
    if isinstance(endpoint, dict):
        return endpoint.get("url", "")
    return str(endpoint)

def uses_http(app_data):
    for endpoint in as_list(app_data.get("endpoints")):
        if endpoint_url(endpoint).lower().startswith("http://"):
            return True
    return False

def has_api(app_data):
    return len(as_list(app_data.get("endpoints"))) > 0

def has_login(app_data):
    auth = app_data.get("authentication", {})
    return bool(auth.get("login")) or has_keyword(auth, ["login", "oauth", "jwt", "session"])

def stores_tokens(app_data):
    storage = app_data.get("storage", {})
    auth = app_data.get("authentication", {})

    return (
        bool(storage.get("stores_tokens"))
        or has_keyword(storage, ["token", "jwt", "sharedpreferences"])
        or has_keyword(auth, ["token", "jwt", "sharedpreferences"])
    )

def has_location_or_camera(app_data):
    return has_keyword(app_data.get("permissions", []), ["location", "camera"])

def has_personal_data(app_data):
    return has_keyword(
        app_data.get("sensitive_data", []),
        ["email", "nom", "santé", "health", "localisation", "adresse", "phone", "token"]
    )

def has_exported_component(app_data):
    for component in as_list(app_data.get("components")):
        if isinstance(component, dict) and component.get("exported") is True:
            return True
    return False

def logs_sensitive_data(app_data):
    storage = app_data.get("storage", {})
    return bool(storage.get("logs_sensitive_data")) or has_keyword(storage, ["logs", "logcat"])

def make_threat(number, threat, stride, asset, entry_point, impact, probability, exposure, mitigation, masvs):
    return {
        "id": f"T-{number:03d}",
        "threat": threat,
        "stride": stride,
        "asset": asset,
        "entry_point": entry_point,
        "impact": impact,
        "probability": probability,
        "exposure": exposure,
        "mitigation": mitigation,
        "masvs": masvs,
        "status": "À traiter"
    }

def identify_assets(app_data):
    assets = set()

    for item in as_list(app_data.get("sensitive_data")):
        assets.add(item)

    if has_login(app_data):
        assets.add("Identifiants utilisateur")
        assets.add("Session utilisateur")

    if stores_tokens(app_data):
        assets.add("Tokens d’authentification")

    if has_api(app_data):
        assets.add("API backend")

    if has_keyword(app_data, ["database", "room", "sqlite"]):
        assets.add("Base de données locale")

    return sorted(assets)

def identify_actors(app_data):
    actors = set(as_list(app_data.get("users")))

    actors.add("Attaquant externe")
    actors.add("Utilisateur malveillant")
    actors.add("Malware présent sur le terminal")
    actors.add("Administrateur backend")

    return sorted(actors)

def identify_entry_points(app_data):
    entry_points = set()

    if has_login(app_data):
        entry_points.add("Écran de connexion")

    for endpoint in as_list(app_data.get("endpoints")):
        if isinstance(endpoint, dict):
            entry_points.add(endpoint.get("name", endpoint.get("url", "Endpoint API")))
        else:
            entry_points.add(str(endpoint))

    for permission in as_list(app_data.get("permissions")):
        entry_points.add(f"Permission Android : {permission}")

    for component in as_list(app_data.get("components")):
        if isinstance(component, dict):
            name = component.get("name", "Composant Android")
            entry_points.add(f"Composant Android : {name}")

    return sorted(entry_points)

def generate_threats(app_data):
    threats = []
    counter = 1

    if has_login(app_data) and has_api(app_data):
        threats.append(make_threat(
            counter,
            "Un attaquant peut tenter de contourner l’authentification ou d’abuser de l’API de login.",
            "Spoofing",
            "Identifiants utilisateur",
            "Écran de connexion / API login",
            4,
            4,
            4,
            "Mettre en place MFA si nécessaire, rate limiting, verrouillage progressif et journalisation.",
            "MASVS-AUTH"
        ))
        counter += 1

    if stores_tokens(app_data):
        threats.append(make_threat(
            counter,
            "Des tokens peuvent être extraits si le stockage local n’est pas chiffré.",
            "Information Disclosure",
            "Tokens d’authentification",
            "Stockage local",
            5,
            4,
            4,
            "Utiliser Android Keystore ou EncryptedSharedPreferences et limiter la durée de vie des tokens.",
            "MASVS-STORAGE"
        ))
        counter += 1

    if has_location_or_camera(app_data):
        threats.append(make_threat(
            counter,
            "Les permissions sensibles peuvent entraîner une collecte excessive de données personnelles.",
            "Information Disclosure",
            "Données personnelles",
            "Permissions caméra/localisation",
            4,
            3,
            3,
            "Appliquer la minimisation des données et demander les permissions uniquement au moment utile.",
            "MASVS-PRIVACY"
        ))
        counter += 1

    if has_api(app_data):
        threats.append(make_threat(
            counter,
            "Un utilisateur peut abuser des endpoints API par énumération, rejeu ou appels automatisés.",
            "Tampering",
            "API backend",
            "Endpoints API",
            4,
            3,
            4,
            "Ajouter rate limiting, contrôle d’autorisation serveur et validation stricte des entrées.",
            "MASVS-NETWORK"
        ))
        counter += 1

    if has_personal_data(app_data):
        threats.append(make_threat(
            counter,
            "Une fuite de données personnelles peut entraîner un impact réglementaire et réputationnel.",
            "Information Disclosure",
            "Données personnelles",
            "Stockage / API / logs",
            5,
            3,
            4,
            "Chiffrer les données, limiter la collecte et documenter les finalités RGPD.",
            "MASVS-PRIVACY"
        ))
        counter += 1

    if uses_http(app_data):
        threats.append(make_threat(
            counter,
            "Le trafic HTTP non chiffré peut être intercepté ou modifié.",
            "Information Disclosure / Tampering",
            "Données en transit",
            "Flux réseau HTTP",
            5,
            4,
            5,
            "Utiliser HTTPS uniquement, désactiver le cleartext traffic et vérifier TLS.",
            "MASVS-NETWORK"
        ))
        counter += 1

    if has_exported_component(app_data):
        threats.append(make_threat(
            counter,
            "Un composant Android exporté peut être appelé par une application malveillante.",
            "Elevation of Privilege",
            "Composants Android",
            "Activity/Service/Receiver exporté",
            4,
            3,
            4,
            "Limiter android:exported, protéger par permission et valider les intents.",
            "MASVS-PLATFORM"
        ))
        counter += 1

    if logs_sensitive_data(app_data):
        threats.append(make_threat(
            counter,
            "Des informations sensibles peuvent apparaître dans les logs applicatifs.",
            "Information Disclosure",
            "Logs applicatifs",
            "Logcat / fichiers logs",
            3,
            4,
            3,
            "Supprimer les logs sensibles et désactiver les logs debug en production.",
            "MASVS-CODE"
        ))

    return threats

def generate_missing_questions(app_data):
    questions = []

    auth = app_data.get("authentication", {})
    storage = app_data.get("storage", {})

    if "mfa" not in auth:
        questions.append("L’application utilise-t-elle une authentification multifacteur ?")

    if "token_storage" not in auth:
        questions.append("Où les tokens sont-ils stockés ?")

    if "encrypted_storage" not in storage:
        questions.append("Le stockage local est-il chiffré ?")

    return questions

def analyze_application(app_data):
    return {
        "assets": identify_assets(app_data),
        "actors": identify_actors(app_data),
        "entry_points": identify_entry_points(app_data),
        "threats": generate_threats(app_data),
        "missing_questions": generate_missing_questions(app_data)
    }
