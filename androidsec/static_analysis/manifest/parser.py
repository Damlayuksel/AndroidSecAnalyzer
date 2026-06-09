"""
AndroidManifest.xml Parser
AndroidManifest.xml dosyasını parse eder(veriyi okur ve anlamlı hale getirir)
 ve analiz için hazırlar

AndroidManifest.xml nedir?
- Android uygulamasının "kimlik belgesi"
- Uygulama adı, versiyonu, izinleri, componentleri içerir
- APK'nın kök dizininde bulunur
"""

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Any, List, Optional

from androidsec.core.exceptions import StaticAnalysisError
from androidsec.utils.logger import get_logger

logger = get_logger(__name__)


class ManifestParser:
    """
    AndroidManifest.xml parser
    
    Kullanım:
        parser = ManifestParser()
        manifest_data = parser.parse("path/to/AndroidManifest.xml")
        
        print(manifest_data["package"])  # com.example.app
        print(manifest_data["permissions"])  # ['CAMERA', 'INTERNET', ...]
    """
    
    # Android namespace("Android'in resmi web sitesinde (schemas.android.com)
 #tanımlanan, APK kaynaklarına ait, Android attribute'ları"
    ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
    
    def __init__(self):
        """Initialize manifest parser"""
        logger.debug("ManifestParser initialized")
    
    def parse(self, manifest_path: str) -> Dict[str, Any]:
        """
        Parse AndroidManifest.xml file
        AndroidManifest.xml dosyasını parse et
        
        Args:
            manifest_path: AndroidManifest.xml dosyası yolu
        
        Returns:
            Manifest verisi: {
                "package": "com.example.app",
                "version_name": "1.0.0",
                "version_code": 1,
                "min_sdk": 21,
                "target_sdk": 30,
                "permissions": ["CAMERA", "INTERNET"],
                "activities": [...],
                "services": [...],
                "receivers": [...],
                "providers": [...],
                "is_debuggable": False,
                "allow_backup": True,
                "uses_cleartext_traffic": False
            }
        
        Raises:
            StaticAnalysisError: Parse başarısız olursa
        """
        logger.info(f"Parsing manifest: {manifest_path}")
        
        manifest_file = Path(manifest_path)
        
        if not manifest_file.exists():
            raise StaticAnalysisError(f"Manifest file not found: {manifest_path}")
        
        try:
            # XML'i parse et
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            # Manifest verisini çıkar
            manifest_data = {
                "package": self._get_package(root),
                "version_name": self._get_version_name(root),
                "version_code": self._get_version_code(root),
                "min_sdk": self._get_min_sdk(root),
                "target_sdk": self._get_target_sdk(root),
                "permissions": self._get_permissions(root),
                "activities": self._get_activities(root),
                "services": self._get_services(root),
                "receivers": self._get_receivers(root),
                "providers": self._get_providers(root),
                "is_debuggable": self._is_debuggable(root),
                "allow_backup": self._allow_backup(root),
                "uses_cleartext_traffic": self._uses_cleartext_traffic(root),
            }
            
            logger.info(f"Manifest parsed: package={manifest_data['package']}")
            return manifest_data
            
        except ET.ParseError as e:
            raise StaticAnalysisError(f"Failed to parse manifest XML: {e}")
        except Exception as e:
            raise StaticAnalysisError(f"Manifest parsing failed: {e}")
    
    def _get_package(self, root: ET.Element) -> str:
        """Get package name (com.example.app)"""
        return root.get("package", "unknown")
    
    def _get_version_name(self, root: ET.Element) -> str:
        """Get version name (1.0.0)"""
        return root.get(f"{self.ANDROID_NS}versionName", "unknown")
    
    def _get_version_code(self, root: ET.Element) -> int:
        """Get version code (1)"""
        version_code = root.get(f"{self.ANDROID_NS}versionCode", "0")
        try:
            return int(version_code)
        except ValueError:
            return 0
    
    def _get_min_sdk(self, root: ET.Element) -> int:
        """Get minimum SDK version"""
        uses_sdk = root.find("uses-sdk")
        if uses_sdk is not None:
            min_sdk = uses_sdk.get(f"{self.ANDROID_NS}minSdkVersion", "0")
            try:
                return int(min_sdk)
            except ValueError:
                return 0
        return 0
    
    def _get_target_sdk(self, root: ET.Element) -> int:
        """Get target SDK version"""
        uses_sdk = root.find("uses-sdk")
        if uses_sdk is not None:
            target_sdk = uses_sdk.get(f"{self.ANDROID_NS}targetSdkVersion", "0")
            try:
                return int(target_sdk)
            except ValueError:
                return 0
        return 0
    
    def _get_permissions(self, root: ET.Element) -> List[str]:
        """
        Get all permissions
        Tüm izinleri al
        
        Örnek:
            <uses-permission android:name="android.permission.CAMERA"/>
            → ["CAMERA"]
        """
        permissions = []
        
        for perm in root.findall("uses-permission"):
            perm_name = perm.get(f"{self.ANDROID_NS}name", "")
            if perm_name:
                # "android.permission.CAMERA" → "CAMERA"
                short_name = perm_name.split(".")[-1]
                permissions.append(short_name)
        
        logger.debug(f"Found {len(permissions)} permissions")
        return permissions
    
    def _get_activities(self, root: ET.Element) -> List[Dict[str, Any]]:
        """
        Get all activities
        Tüm activity'leri al
        """
        activities = []
        application = root.find("application")
        
        if application is not None:
            for activity in application.findall("activity"):
                activity_data = {
                    "name": activity.get(f"{self.ANDROID_NS}name", ""),
                    "exported": self._is_exported(activity),
                    "has_intent_filter": len(activity.findall("intent-filter")) > 0
                }
                activities.append(activity_data)
        
        logger.debug(f"Found {len(activities)} activities")
        return activities
    
    def _get_services(self, root: ET.Element) -> List[Dict[str, Any]]:
        """Get all services"""
        services = []
        application = root.find("application")
        
        if application is not None:
            for service in application.findall("service"):
                service_data = {
                    "name": service.get(f"{self.ANDROID_NS}name", ""),
                    "exported": self._is_exported(service),
                }
                services.append(service_data)
        
        logger.debug(f"Found {len(services)} services")
        return services
    
    def _get_receivers(self, root: ET.Element) -> List[Dict[str, Any]]:
        """Get all broadcast receivers"""
        receivers = []
        application = root.find("application")
        
        if application is not None:
            for receiver in application.findall("receiver"):
                receiver_data = {
                    "name": receiver.get(f"{self.ANDROID_NS}name", ""),
                    "exported": self._is_exported(receiver),
                }
                receivers.append(receiver_data)
        
        logger.debug(f"Found {len(receivers)} receivers")
        return receivers
    
    def _get_providers(self, root: ET.Element) -> List[Dict[str, Any]]:
        """Get all content providers"""
        providers = []
        application = root.find("application")
        
        if application is not None:
            for provider in application.findall("provider"):
                provider_data = {
                    "name": provider.get(f"{self.ANDROID_NS}name", ""),
                    "exported": self._is_exported(provider),
                    "authorities": provider.get(f"{self.ANDROID_NS}authorities", ""),
                }
                providers.append(provider_data)
        
        logger.debug(f"Found {len(providers)} providers")
        return providers
    
    def _is_debuggable(self, root: ET.Element) -> bool:
        """
        Check if app is debuggable
        Uygulama debuggable mı?
        
        <application android:debuggable="true"> → GÜVENLİK RİSKİ!
        """
        application = root.find("application")
        if application is not None:
            debuggable = application.get(f"{self.ANDROID_NS}debuggable", "false")
            return debuggable.lower() == "true"
        return False
    
    def _allow_backup(self, root: ET.Element) -> bool:
        """
        Check if backup is allowed
        Yedekleme izni var mı?
        
        <application android:allowBackup="true"> → Veri sızıntısı riski
        """
        application = root.find("application")
        if application is not None:
            allow_backup = application.get(f"{self.ANDROID_NS}allowBackup", "true")
            return allow_backup.lower() == "true"
        return True  # Default is true
    
    def _uses_cleartext_traffic(self, root: ET.Element) -> bool:
        """
        Check if cleartext (HTTP) traffic is allowed
        HTTP trafiği izinli mi?
        
        <application android:usesCleartextTraffic="true"> → HTTP kullanılabilir (GÜVENSİZ!)
        """
        application = root.find("application")
        if application is not None:
            cleartext = application.get(f"{self.ANDROID_NS}usesCleartextTraffic", "false")
            return cleartext.lower() == "true"
        return False
    
    def _is_exported(self, component: ET.Element) -> bool:
        """
        Check if component is exported
        Component dışa açık mı?
        
        exported="true" → Diğer uygulamalar erişebilir (güvenlik riski olabilir)
        """
        exported = component.get(f"{self.ANDROID_NS}exported", "false")
        
        # Eğer intent-filter varsa, default exported=true
        if component.find("intent-filter") is not None and exported == "false":
            return True
        
        return exported.lower() == "true"
    
    def __repr__(self) -> str:
        return "ManifestParser()"
