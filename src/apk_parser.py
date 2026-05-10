import tempfile
import os
import re
from androguard.core.apk import APK

def parse_apk_to_app_model(uploaded_apk_file):
    with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp_file:
        tmp_file.write(uploaded_apk_file.read())
        tmp_path = tmp_file.name

    try:
        apk = APK(tmp_path)
        
        # 1. Basic Metadata
        package_name = apk.get_package()
        app_name = apk.get_app_name() or package_name
        
        # 2. Permissions
        permissions = apk.get_permissions()
        
        # 3. Components
        components = []
        activities = apk.get_activities()
        services = apk.get_services()
        receivers = apk.get_receivers()
        providers = apk.get_providers()
        
        manifest = apk.get_android_manifest_xml()
        
        for act in activities:
            components.append({
                "name": act,
                "type": "Activity",
                "exported": True if is_exported(manifest, "activity", act) else False
            })
        for srv in services:
            components.append({
                "name": srv,
                "type": "Service",
                "exported": True if is_exported(manifest, "service", srv) else False
            })
        for rec in receivers:
            components.append({
                "name": rec,
                "type": "Receiver",
                "exported": True if is_exported(manifest, "receiver", rec) else False
            })
        for prv in providers:
            components.append({
                "name": prv,
                "type": "Provider",
                "exported": True if is_exported(manifest, "provider", prv) else False
            })
            
        # 4. Endpoints / URLs
        endpoints = []
        try:
            for dex_bytes in apk.get_all_dex():
                urls = set(re.findall(rb'https?://[a-zA-Z0-9.-]+(?:/[a-zA-Z0-9./_?=&-]*)?', dex_bytes))
                endpoints.extend([url.decode('utf-8', errors='ignore') for url in urls])
        except Exception:
            pass
        endpoints = list(set(endpoints))
            
        # 5. Application Flags
        app_element = manifest.find("application") if manifest is not None else None
        allow_backup = "Unknown"
        debuggable = "Unknown"
        if app_element is not None:
            ns = "{http://schemas.android.com/apk/res/android}"
            allow_backup_attr = app_element.get(f"{ns}allowBackup")
            if allow_backup_attr is not None:
                allow_backup = allow_backup_attr.lower() == "true"
            debuggable_attr = app_element.get(f"{ns}debuggable")
            if debuggable_attr is not None:
                debuggable = debuggable_attr.lower() == "true"
        
        min_sdk = apk.get_min_sdk_version() or "Unknown"
        target_sdk = apk.get_target_sdk_version() or "Unknown"

        app_data = {
            "app_name": app_name,
            "description": f"Static analysis generated from uploaded APK (Package: {package_name}). Min SDK: {min_sdk}, Target SDK: {target_sdk}.",
            "app_type": "Android APK",
            "users": ["Mobile user", "Attacker", "Backend administrator"],
            "sensitive_data": [],
            "permissions": permissions,
            "endpoints": endpoints[:50], # Limit to 50 URLs
            "components": components,
            "authentication": {
                "type": "Unknown",
                "login": False,
                "mfa": False,
                "token_storage": "Unknown"
            },
            "storage": {
                "local_database": "Unknown",
                "stores_tokens": False,
                "encrypted_storage": "Unknown",
                "logs_sensitive_data": "Unknown",
                "allowBackup": allow_backup
            },
            "network_flows": [
                "Mobile app -> External endpoints"
            ],
            "business_context": {
                "sector": "Unknown",
                "regulation": "Unknown",
                "criticality": "Medium"
            },
            "apk_metadata": {
                "debuggable": debuggable,
                "allowBackup": allow_backup,
                "minSdkVersion": min_sdk,
                "targetSdkVersion": target_sdk,
                "package_name": package_name
            }
        }
        
        return app_data
        
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except:
                pass

def is_exported(manifest, tag_name, name):
    if manifest is None:
        return False
    app = manifest.find("application")
    if app is None:
        return False
    ns = "{http://schemas.android.com/apk/res/android}"
    for elem in app.findall(tag_name):
        if elem.get(f"{ns}name") == name:
            exported = elem.get(f"{ns}exported")
            if exported is not None:
                return exported.lower() == "true"
            # If not explicitly set, depends on intent-filters (simplified)
            if len(elem.findall("intent-filter")) > 0:
                return True
    return False
