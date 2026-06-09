"""
Permission Analyzer
Android izinlerini güvenlik açısından analiz eder

Ne kontrol ediyoruz?
1. Tehlikeli izinler (CAMERA, READ_SMS, ACCESS_FINE_LOCATION vb.)
2. Gereksiz izin kullanımı
3. Custom izinlerin güvenliği (protectionLevel)
4. Normal vs Dangerous vs Signature izin ayrımı
"""

from typing import List, Dict, Any

from androidsec.core.constants import (
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO,
    DANGEROUS_PERMISSIONS,
)
from androidsec.utils.logger import get_logger

logger = get_logger(__name__)


# İzin Kategorileri

# Gizlilik odaklı (Privacy-sensitive) izinler
PRIVACY_PERMISSIONS = [
    "READ_SMS", "SEND_SMS", "RECEIVE_SMS", "READ_MMS",
    "READ_CONTACTS", "WRITE_CONTACTS",
    "READ_CALL_LOG", "WRITE_CALL_LOG",
    "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
    "ACCESS_BACKGROUND_LOCATION",
    "CAMERA", "RECORD_AUDIO",
    "READ_PHONE_STATE", "READ_PHONE_NUMBERS",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
    "READ_CALENDAR", "WRITE_CALENDAR",
    "BODY_SENSORS",
]

# Cihaz yönetimi izinleri (Device admin-level)
DEVICE_ADMIN_PERMISSIONS = [
    "BIND_DEVICE_ADMIN",
    "BIND_ACCESSIBILITY_SERVICE",
    "BIND_NOTIFICATION_LISTENER_SERVICE",
    "BIND_VPN_SERVICE",
    "SYSTEM_ALERT_WINDOW",
    "WRITE_SETTINGS",
    "REQUEST_INSTALL_PACKAGES",
    "REQUEST_DELETE_PACKAGES",
]

# Network ile ilgili izinler
NETWORK_PERMISSIONS = [
    "INTERNET",
    "ACCESS_NETWORK_STATE",
    "ACCESS_WIFI_STATE",
    "CHANGE_NETWORK_STATE",
    "CHANGE_WIFI_STATE",
    "NFC",
    "BLUETOOTH",
    "BLUETOOTH_ADMIN",
    "BLUETOOTH_CONNECT",
]

# Potansiyel kötüye kullanım izinleri
ABUSE_RISK_PERMISSIONS = [
    "RECEIVE_BOOT_COMPLETED",
    "FOREGROUND_SERVICE",
    "WAKE_LOCK",
    "DISABLE_KEYGUARD",
    "USE_BIOMETRIC",
    "USE_FINGERPRINT",
]


class PermissionAnalyzer:
    """
    Android izinlerini güvenlik açısından analiz eder

    Kullanım:
        analyzer = PermissionAnalyzer()
        findings = analyzer.analyze(permissions_list, manifest_data)

        for finding in findings:
            print(f"{finding['severity']}: {finding['title']}")
    """

    def __init__(self):
        """Initialize permission analyzer"""
        logger.debug("PermissionAnalyzer initialized")

    def analyze(
        self,
        permissions: List[str],
        manifest_data: Dict[str, Any] = None
    ) -> List[Dict[str, Any]]:
        """
        İzinleri analiz et ve güvenlik bulgularını döndür

        Args:
            permissions: İzin listesi (kısa adlar: ["CAMERA", "INTERNET", ...])
            manifest_data: Tam manifest verisi (isteğe bağlı, ek analiz için)

        Returns:
            Bulgular listesi
        """
        logger.info(f"Analyzing {len(permissions)} permissions...")

        findings = []

        # 1. Tehlikeli izinleri tespit et
        findings.extend(self._check_dangerous_permissions(permissions))

        # 2. Gizlilik riskli izinleri kontrol et
        findings.extend(self._check_privacy_permissions(permissions))

        # 3. Cihaz yönetimi izinlerini kontrol et
        findings.extend(self._check_device_admin_permissions(permissions))

        # 4. İzin kombinasyonlarını analiz et (birlikte kullanıldığında riskli)
        findings.extend(self._check_permission_combinations(permissions))

        # 5. İzin sayısı uyarısı
        findings.extend(self._check_permission_count(permissions))

        # 6. Custom izinleri kontrol et
        if manifest_data:
            findings.extend(self._check_custom_permissions(manifest_data))

        logger.info(f"Permission analysis complete: {len(findings)} findings")
        return findings

    def _check_dangerous_permissions(self, permissions: List[str]) -> List[Dict[str, Any]]:
        """
        Resmi Android 'dangerous' izinlerini tespit et

        Dangerous izinler nedir?
        - Kullanıcının açıkça onay vermesi gereken izinler
        - Runtime'da istenir (Install-time değil)
        - Gizlilik ve güvenlik açısından riskli
        """
        findings = []

        # DANGEROUS_PERMISSIONS listesi tam paket adı ile tanımlı:
        # "android.permission.READ_SMS" formatında
        # permissions listesi kısa adlarla gelir: "READ_SMS"

        dangerous_found = []

        for perm in permissions:
            full_perm = f"android.permission.{perm}"
            if full_perm in DANGEROUS_PERMISSIONS:
                dangerous_found.append(perm)

        if dangerous_found:
            findings.append({
                "category": "M1: Improper Platform Usage",
                "severity": SEVERITY_MEDIUM,
                "title": f"Dangerous Permissions ({len(dangerous_found)})",
                "description": (
                    f"Application uses {len(dangerous_found)} dangerous permission(s): "
                    f"{', '.join(dangerous_found)}. "
                    "These permissions require explicit user consent and can access "
                    "sensitive user data."
                ),
                "file": "AndroidManifest.xml",
                "details": dangerous_found,
                "recommendation": (
                    "Only request permissions that are essential for the app's "
                    "core functionality. Follow the principle of least privilege."
                )
            })

        return findings

    def _check_privacy_permissions(self, permissions: List[str]) -> List[Dict[str, Any]]:
        """
        Gizlilik açısından riskli izinleri kontrol et

        SMS okuma, konum erişimi, mikrofon, kamera vb.
        """
        findings = []

        privacy_found = [p for p in permissions if p in PRIVACY_PERMISSIONS]

        # SMS izinleri (çok yüksek risk)
        sms_perms = [p for p in privacy_found if "SMS" in p or "MMS" in p]
        if sms_perms:
            findings.append({
                "category": "M2: Insecure Data Storage",
                "severity": SEVERITY_HIGH,
                "title": "SMS/MMS Access Permissions",
                "description": (
                    f"Application can access SMS/MMS: {', '.join(sms_perms)}. "
                    "This is a high-risk capability often associated with malware."
                ),
                "file": "AndroidManifest.xml",
                "recommendation": (
                    "SMS permissions are restricted by Google Play policy. "
                    "Remove unless absolutely essential (e.g., SMS verification app)."
                )
            })

        # Konum izinleri
        location_perms = [p for p in privacy_found if "LOCATION" in p]
        if location_perms:
            severity = SEVERITY_HIGH if "ACCESS_BACKGROUND_LOCATION" in location_perms else SEVERITY_MEDIUM
            findings.append({
                "category": "M2: Insecure Data Storage",
                "severity": severity,
                "title": "Location Access Permissions",
                "description": (
                    f"Application accesses user location: {', '.join(location_perms)}. "
                    + ("Background location access detected - HIGH privacy risk!" if "ACCESS_BACKGROUND_LOCATION" in location_perms else "")
                ),
                "file": "AndroidManifest.xml",
                "recommendation": (
                    "Use coarse location instead of fine location when possible. "
                    "Avoid background location access unless absolutely necessary."
                )
            })

        # Kamera + Mikrofon birlikte
        if "CAMERA" in privacy_found and "RECORD_AUDIO" in privacy_found:
            findings.append({
                "category": "M2: Insecure Data Storage",
                "severity": SEVERITY_MEDIUM,
                "title": "Camera and Microphone Access",
                "description": (
                    "Application has access to both camera and microphone. "
                    "This combination can be used for surveillance."
                ),
                "file": "AndroidManifest.xml",
                "recommendation": (
                    "Ensure camera and microphone access are genuinely needed. "
                    "Inform users about why these permissions are required."
                )
            })

        return findings

    def _check_device_admin_permissions(self, permissions: List[str]) -> List[Dict[str, Any]]:
        """
        Cihaz yönetici düzeyinde izinleri kontrol et

        Bu izinler çok güçlü yetkiler verir:
        - Ekran kilidi, cihaz silme
        - VPN, erişilebilirlik servisleri
        - Uygulama yükleme/kaldırma
        """
        findings = []

        admin_found = [p for p in permissions if p in DEVICE_ADMIN_PERMISSIONS]

        if admin_found:
            findings.append({
                "category": "M1: Improper Platform Usage",
                "severity": SEVERITY_HIGH,
                "title": f"Device Admin Level Permissions ({len(admin_found)})",
                "description": (
                    f"Application requests device admin level permissions: "
                    f"{', '.join(admin_found)}. "
                    "These are powerful capabilities commonly abused by malware."
                ),
                "file": "AndroidManifest.xml",
                "details": admin_found,
                "recommendation": (
                    "Device admin permissions are heavily scrutinized by Google Play. "
                    "Remove unless the app is an enterprise MDM or accessibility tool."
                )
            })

        # Özellikle SYSTEM_ALERT_WINDOW (overlay attacks)
        if "SYSTEM_ALERT_WINDOW" in permissions:
            findings.append({
                "category": "M1: Improper Platform Usage",
                "severity": SEVERITY_HIGH,
                "title": "System Alert Window (Overlay) Permission",
                "description": (
                    "Application can draw over other apps. "
                    "This can be abused for clickjacking/tapjacking attacks."
                ),
                "file": "AndroidManifest.xml",
                "recommendation": (
                    "SYSTEM_ALERT_WINDOW enables overlay attacks. "
                    "Remove unless critical for the app's functionality."
                )
            })

        return findings

    def _check_permission_combinations(self, permissions: List[str]) -> List[Dict[str, Any]]:
        """
        Tehlikeli izin kombinasyonlarını kontrol et

        Bazı izinler tek başına zararsız ama birlikte kullanıldığında riskli
        """
        findings = []

        # INTERNET + READ_CONTACTS = Kişi bilgileri dışarı sızdırılabilir
        if "INTERNET" in permissions and "READ_CONTACTS" in permissions:
            findings.append({
                "category": "M2: Insecure Data Storage",
                "severity": SEVERITY_MEDIUM,
                "title": "Contact Data Exfiltration Risk",
                "description": (
                    "Application has both INTERNET and READ_CONTACTS permissions. "
                    "This combination allows contacts to be uploaded to a remote server."
                ),
                "file": "AndroidManifest.xml",
                "recommendation": (
                    "If contacts are sent to a server, ensure encryption and user consent."
                )
            })

        # INTERNET + READ_SMS = SMS verileri dışarı sızdırılabilir
        if "INTERNET" in permissions and ("READ_SMS" in permissions or "RECEIVE_SMS" in permissions):
            findings.append({
                "category": "M2: Insecure Data Storage",
                "severity": SEVERITY_HIGH,
                "title": "SMS Data Exfiltration Risk",
                "description": (
                    "Application has both INTERNET and SMS read permissions. "
                    "SMS data (including OTP codes) can be exfiltrated to a remote server."
                ),
                "file": "AndroidManifest.xml",
                "recommendation": (
                    "This is a common malware pattern. Review the necessity of SMS access."
                )
            })

        # RECEIVE_BOOT_COMPLETED + INTERNET = Cihaz açılışında arka planda çalışabilir
        if "RECEIVE_BOOT_COMPLETED" in permissions and "INTERNET" in permissions:
            findings.append({
                "category": "M10: Extraneous Functionality",
                "severity": SEVERITY_LOW,
                "title": "Auto-Start with Network Access",
                "description": (
                    "Application starts automatically on boot and has internet access. "
                    "This is a common pattern for persistent malware."
                ),
                "file": "AndroidManifest.xml",
                "recommendation": (
                    "Verify that auto-start is necessary for legitimate functionality."
                )
            })

        return findings

    def _check_permission_count(self, permissions: List[str]) -> List[Dict[str, Any]]:
        """
        Toplam izin sayısını kontrol et

        Çok fazla izin → Aşırı yetkilendirilmiş uygulama
        """
        findings = []

        count = len(permissions)

        if count > 20:
            findings.append({
                "category": "M1: Improper Platform Usage",
                "severity": SEVERITY_MEDIUM,
                "title": f"Excessive Permissions ({count})",
                "description": (
                    f"Application requests {count} permissions, which is unusually high. "
                    "Over-privileged apps increase the attack surface."
                ),
                "file": "AndroidManifest.xml",
                "recommendation": (
                    "Follow the principle of least privilege. "
                    "Only request permissions that are essential."
                )
            })
        elif count > 10:
            findings.append({
                "category": "M1: Improper Platform Usage",
                "severity": SEVERITY_INFO,
                "title": f"Permission Count: {count}",
                "description": (
                    f"Application requests {count} permissions. "
                    "Review whether all are necessary."
                ),
                "file": "AndroidManifest.xml",
                "recommendation": "Review and minimize permission usage."
            })

        return findings

    def _check_custom_permissions(self, manifest_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Custom (özel tanımlanmış) izinleri kontrol et

        Custom izinler manifest'te <permission> tag'i ile tanımlanır.
        protectionLevel doğru ayarlanmazsa diğer uygulamalar erişebilir.
        """
        findings = []

        # manifest_data'da raw XML bilgisi varsa kontrol et
        # Burada basit bir kontrol yapıyoruz
        # TODO: ManifestParser'dan custom permission bilgisi alınabilir

        return findings

    def get_risk_summary(self, permissions: List[str]) -> Dict[str, Any]:
        """
        İzin risk özetini döndür

        Returns:
            {
                "total": 15,
                "dangerous_count": 5,
                "privacy_count": 3,
                "admin_count": 1,
                "risk_level": "HIGH",
                "dangerous_permissions": [...],
                "privacy_permissions": [...],
            }
        """
        dangerous = [p for p in permissions if f"android.permission.{p}" in DANGEROUS_PERMISSIONS]
        privacy = [p for p in permissions if p in PRIVACY_PERMISSIONS]
        admin = [p for p in permissions if p in DEVICE_ADMIN_PERMISSIONS]

        # Risk seviyesi hesapla
        if admin or len(dangerous) > 10:
            risk_level = "CRITICAL"
        elif len(dangerous) > 5 or len(privacy) > 3:
            risk_level = "HIGH"
        elif len(dangerous) > 2:
            risk_level = "MEDIUM"
        elif len(dangerous) > 0:
            risk_level = "LOW"
        else:
            risk_level = "INFO"

        return {
            "total": len(permissions),
            "dangerous_count": len(dangerous),
            "privacy_count": len(privacy),
            "admin_count": len(admin),
            "risk_level": risk_level,
            "dangerous_permissions": dangerous,
            "privacy_permissions": privacy,
            "admin_permissions": admin,
        }

    def __repr__(self) -> str:
        return "PermissionAnalyzer()"
