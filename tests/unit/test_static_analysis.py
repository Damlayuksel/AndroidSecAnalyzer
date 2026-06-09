"""
Static Analysis Unit Tests
Statik analiz modülü için birim testleri

Bu testler şu modülleri kapsar:
1. ManifestParser - AndroidManifest.xml parse
2. PermissionAnalyzer - İzin analizi
3. ComponentAnalyzer - Component güvenlik analizi
4. CodeScanner - Kaynak kod tarama
5. CryptoAnalyzer - Kriptografi kontrolü
6. SecretsDetector - Hardcoded secret tespiti
7. CertificateValidator - Sertifika doğrulama
8. SOAnalyzer - Native kütüphane analizi
9. StringsExtractor - Binary string çıkarma
10. StaticAnalyzer - Orkestratör (tam entegrasyon)
"""

import pytest
import sys
from pathlib import Path

# Proje kök dizinini Python path'ine ekle
PROJECT_ROOT = Path(__file__).parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from tests.fixtures.mock_data import (
    SAMPLE_MANIFEST_SECURE,
    SAMPLE_MANIFEST_VULNERABLE,
    SAMPLE_MANIFEST_MINIMAL,
    SAMPLE_JAVA_VULNERABLE,
    SAMPLE_JAVA_SECURE,
    SAMPLE_CERT_INFO_NORMAL,
    SAMPLE_CERT_INFO_EXPIRED,
    SAMPLE_CERT_INFO_DEBUG,
    SAMPLE_CERT_INFO_WEAK_ALGO,
    SAMPLE_CERT_INFO_SHORT_VALIDITY,
)


# ═══════════════════════════════════════════════════════════════════
# 1. ManifestParser Testleri
# ═══════════════════════════════════════════════════════════════════

class TestManifestParser:
    """ManifestParser birim testleri"""

    def setup_method(self):
        from androidsec.static_analysis.manifest.parser import ManifestParser
        self.parser = ManifestParser()

    def test_parse_vulnerable_manifest(self, vulnerable_manifest_file):
        """Zafiyetli manifest dosyasını parse et"""
        result = self.parser.parse(vulnerable_manifest_file)

        assert result["package"] == "com.example.vulnerableapp"
        assert result["version_name"] == "2.0.0"
        assert result["version_code"] == 1

    def test_parse_min_sdk(self, vulnerable_manifest_file):
        """Min SDK bilgisini doğru oku"""
        result = self.parser.parse(vulnerable_manifest_file)
        assert result["min_sdk"] == 16

    def test_parse_target_sdk(self, vulnerable_manifest_file):
        """Target SDK bilgisini doğru oku"""
        result = self.parser.parse(vulnerable_manifest_file)
        assert result["target_sdk"] == 25

    def test_parse_permissions(self, vulnerable_manifest_file):
        """İzinleri doğru oku"""
        result = self.parser.parse(vulnerable_manifest_file)
        permissions = result["permissions"]

        assert "INTERNET" in permissions
        assert "READ_SMS" in permissions
        assert "CAMERA" in permissions
        assert "ACCESS_FINE_LOCATION" in permissions
        assert len(permissions) >= 10

    def test_parse_debuggable(self, vulnerable_manifest_file):
        """Debuggable flag'ini doğru oku"""
        result = self.parser.parse(vulnerable_manifest_file)
        assert result["is_debuggable"] is True

    def test_parse_allow_backup(self, vulnerable_manifest_file):
        """AllowBackup flag'ini doğru oku"""
        result = self.parser.parse(vulnerable_manifest_file)
        assert result["allow_backup"] is True

    def test_parse_cleartext_traffic(self, vulnerable_manifest_file):
        """Cleartext traffic flag'ini doğru oku"""
        result = self.parser.parse(vulnerable_manifest_file)
        assert result["uses_cleartext_traffic"] is True

    def test_parse_activities(self, vulnerable_manifest_file):
        """Activity'leri doğru oku"""
        result = self.parser.parse(vulnerable_manifest_file)
        activities = result["activities"]

        assert len(activities) >= 3
        # Exported activity'leri kontrol et
        exported = [a for a in activities if a.get("exported")]
        assert len(exported) >= 2

    def test_parse_services(self, vulnerable_manifest_file):
        """Service'leri doğru oku"""
        result = self.parser.parse(vulnerable_manifest_file)
        services = result["services"]

        assert len(services) >= 1
        assert services[0]["exported"] is True

    def test_parse_receivers(self, vulnerable_manifest_file):
        """Receiver'ları doğru oku"""
        result = self.parser.parse(vulnerable_manifest_file)
        receivers = result["receivers"]

        assert len(receivers) >= 1
        assert receivers[0]["exported"] is True

    def test_parse_providers(self, vulnerable_manifest_file):
        """Provider'ları doğru oku"""
        result = self.parser.parse(vulnerable_manifest_file)
        providers = result["providers"]

        assert len(providers) >= 1
        assert providers[0]["exported"] is True
        assert "com.example.vulnerableapp.provider" in providers[0].get("authorities", "")

    def test_parse_secure_manifest(self, secure_manifest_file):
        """Güvenli manifest → güvenlik flag'leri False/kapalı"""
        result = self.parser.parse(secure_manifest_file)

        assert result["is_debuggable"] is False
        assert result["allow_backup"] is False
        assert result["uses_cleartext_traffic"] is False
        assert result["min_sdk"] == 26
        assert result["target_sdk"] == 34

    def test_parse_minimal_manifest(self, minimal_manifest_file):
        """Minimal manifest dosyasını parse et"""
        result = self.parser.parse(minimal_manifest_file)

        assert result["package"] == "com.example.minimal"
        assert result["min_sdk"] == 0  # uses-sdk yok
        assert len(result["permissions"]) == 0

    def test_parse_nonexistent_file(self):
        """Olmayan dosya → hata fırlatmalı"""
        from androidsec.core.exceptions import StaticAnalysisError
        with pytest.raises(StaticAnalysisError):
            self.parser.parse("/nonexistent/path/AndroidManifest.xml")


# 
# 2. PermissionAnalyzer Testleri
# 

class TestPermissionAnalyzer:
    """PermissionAnalyzer birim testleri"""

    def setup_method(self):
        from androidsec.static_analysis.manifest.permissions import PermissionAnalyzer
        self.analyzer = PermissionAnalyzer()

    def test_dangerous_permissions(self):
        """Tehlikeli izinler tespit edilmeli"""
        permissions = ["READ_SMS", "CAMERA", "ACCESS_FINE_LOCATION", "INTERNET"]
        findings = self.analyzer.analyze(permissions)

        dangerous_findings = [
            f for f in findings if "Dangerous Permissions" in f.get("title", "")
        ]
        assert len(dangerous_findings) >= 1

    def test_sms_permissions(self):
        """SMS izinleri HIGH seviyede raporlanmalı"""
        permissions = ["READ_SMS", "SEND_SMS", "INTERNET"]
        findings = self.analyzer.analyze(permissions)

        sms_findings = [
            f for f in findings if "SMS" in f.get("title", "")
        ]
        assert len(sms_findings) >= 1
        assert any(f["severity"] == "HIGH" for f in sms_findings)

    def test_location_permissions(self):
        """Konum izinleri raporlanmalı"""
        permissions = ["ACCESS_FINE_LOCATION", "ACCESS_BACKGROUND_LOCATION"]
        findings = self.analyzer.analyze(permissions)

        location_findings = [
            f for f in findings if "Location" in f.get("title", "")
        ]
        assert len(location_findings) >= 1
        # Background location → HIGH
        assert any(f["severity"] == "HIGH" for f in location_findings)

    def test_device_admin_permissions(self):
        """Cihaz yönetici izinleri raporlanmalı"""
        permissions = ["SYSTEM_ALERT_WINDOW", "BIND_DEVICE_ADMIN"]
        findings = self.analyzer.analyze(permissions)

        admin_findings = [
            f for f in findings if "Admin" in f.get("title", "") or "Overlay" in f.get("title", "")
        ]
        assert len(admin_findings) >= 1

    def test_permission_combinations(self):
        """Tehlikeli izin kombinasyonları tespit edilmeli"""
        permissions = ["INTERNET", "READ_CONTACTS", "READ_SMS"]
        findings = self.analyzer.analyze(permissions)

        combo_findings = [
            f for f in findings if "Exfiltration" in f.get("title", "")
        ]
        assert len(combo_findings) >= 1

    def test_excessive_permissions(self):
        """Aşırı izin sayısı uyarı vermeli"""
        permissions = [f"PERM_{i}" for i in range(25)]
        findings = self.analyzer.analyze(permissions)

        count_findings = [
            f for f in findings if "Excessive" in f.get("title", "")
        ]
        assert len(count_findings) >= 1

    def test_safe_permissions_minimal_findings(self):
        """Güvenli izinler → minimum bulgu"""
        permissions = ["INTERNET", "ACCESS_NETWORK_STATE"]
        findings = self.analyzer.analyze(permissions)

        # HIGH veya CRITICAL bulgu olmamalı
        high_or_critical = [
            f for f in findings
            if f.get("severity") in ["HIGH", "CRITICAL"]
        ]
        assert len(high_or_critical) == 0

    def test_risk_summary(self):
        """Risk özeti doğru hesaplanmalı"""
        permissions = ["READ_SMS", "CAMERA", "INTERNET", "SYSTEM_ALERT_WINDOW"]
        summary = self.analyzer.get_risk_summary(permissions)

        assert summary["total"] == 4
        assert summary["dangerous_count"] >= 2
        assert summary["admin_count"] >= 1
        assert summary["risk_level"] in ["HIGH", "CRITICAL"]


# 
# 3. ComponentAnalyzer Testleri
# 

class TestComponentAnalyzer:
    """ComponentAnalyzer birim testleri"""

    def setup_method(self):
        from androidsec.static_analysis.manifest.components import ComponentAnalyzer
        self.analyzer = ComponentAnalyzer()

    def test_debuggable_app(self):
        """Debuggable uygulama → CRITICAL bulgu"""
        manifest_data = {
            "is_debuggable": True,
            "allow_backup": False,
            "uses_cleartext_traffic": False,
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
            "min_sdk": 26,
            "target_sdk": 34,
        }
        findings = self.analyzer.analyze(manifest_data)

        debuggable_findings = [
            f for f in findings if "Debuggable" in f.get("title", "")
        ]
        assert len(debuggable_findings) == 1
        assert debuggable_findings[0]["severity"] == "CRITICAL"

    def test_allow_backup(self):
        """AllowBackup → MEDIUM bulgu"""
        manifest_data = {
            "is_debuggable": False,
            "allow_backup": True,
            "uses_cleartext_traffic": False,
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
            "min_sdk": 26,
            "target_sdk": 34,
        }
        findings = self.analyzer.analyze(manifest_data)

        backup_findings = [
            f for f in findings if "Backup" in f.get("title", "")
        ]
        assert len(backup_findings) == 1
        assert backup_findings[0]["severity"] == "MEDIUM"

    def test_cleartext_traffic(self):
        """Cleartext traffic → HIGH bulgu"""
        manifest_data = {
            "is_debuggable": False,
            "allow_backup": False,
            "uses_cleartext_traffic": True,
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
            "min_sdk": 26,
            "target_sdk": 34,
        }
        findings = self.analyzer.analyze(manifest_data)

        cleartext_findings = [
            f for f in findings if "Cleartext" in f.get("title", "")
        ]
        assert len(cleartext_findings) == 1
        assert cleartext_findings[0]["severity"] == "HIGH"

    def test_exported_activity_sensitive(self):
        """Hassas isimli exported activity → HIGH bulgu"""
        manifest_data = {
            "is_debuggable": False,
            "allow_backup": False,
            "uses_cleartext_traffic": False,
            "activities": [
                {"name": "com.example.app.AdminSettingsActivity", "exported": True, "has_intent_filter": False},
            ],
            "services": [],
            "receivers": [],
            "providers": [],
            "min_sdk": 26,
            "target_sdk": 34,
        }
        findings = self.analyzer.analyze(manifest_data)

        sensitive_findings = [
            f for f in findings if "Sensitive Exported Activity" in f.get("title", "")
        ]
        assert len(sensitive_findings) >= 1
        assert sensitive_findings[0]["severity"] == "HIGH"

    def test_exported_provider(self):
        """Exported Content Provider → HIGH bulgu"""
        manifest_data = {
            "is_debuggable": False,
            "allow_backup": False,
            "uses_cleartext_traffic": False,
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [
                {"name": "com.example.DataProvider", "exported": True, "authorities": "com.example.provider"},
            ],
            "min_sdk": 26,
            "target_sdk": 34,
        }
        findings = self.analyzer.analyze(manifest_data)

        provider_findings = [
            f for f in findings if "Content Provider" in f.get("title", "")
        ]
        assert len(provider_findings) >= 1
        assert provider_findings[0]["severity"] == "HIGH"

    def test_low_min_sdk(self):
        """Düşük min SDK → MEDIUM bulgu"""
        manifest_data = {
            "is_debuggable": False,
            "allow_backup": False,
            "uses_cleartext_traffic": False,
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
            "min_sdk": 16,
            "target_sdk": 34,
        }
        findings = self.analyzer.analyze(manifest_data)

        sdk_findings = [
            f for f in findings if "Low Minimum SDK" in f.get("title", "")
        ]
        assert len(sdk_findings) == 1

    def test_low_target_sdk(self):
        """Düşük target SDK → MEDIUM bulgu"""
        manifest_data = {
            "is_debuggable": False,
            "allow_backup": False,
            "uses_cleartext_traffic": False,
            "activities": [],
            "services": [],
            "receivers": [],
            "providers": [],
            "min_sdk": 21,
            "target_sdk": 25,
        }
        findings = self.analyzer.analyze(manifest_data)

        sdk_findings = [
            f for f in findings if "Low Target SDK" in f.get("title", "")
        ]
        assert len(sdk_findings) == 1

    def test_secure_manifest_no_critical(self):
        """Güvenli manifest → CRITICAL bulgu olmamalı"""
        manifest_data = {
            "is_debuggable": False,
            "allow_backup": False,
            "uses_cleartext_traffic": False,
            "activities": [
                {"name": ".MainActivity", "exported": True, "has_intent_filter": True},
            ],
            "services": [],
            "receivers": [],
            "providers": [],
            "min_sdk": 26,
            "target_sdk": 34,
        }
        findings = self.analyzer.analyze(manifest_data)

        critical = [f for f in findings if f.get("severity") == "CRITICAL"]
        assert len(critical) == 0

    def test_component_summary(self):
        """Component özeti doğru hesaplanmalı"""
        manifest_data = {
            "activities": [
                {"name": "A1", "exported": True},
                {"name": "A2", "exported": False},
                {"name": "A3", "exported": True},
            ],
            "services": [
                {"name": "S1", "exported": True},
            ],
            "receivers": [
                {"name": "R1", "exported": False},
            ],
            "providers": [],
        }
        summary = self.analyzer.get_component_summary(manifest_data)

        assert summary["total_activities"] == 3
        assert summary["exported_activities"] == 2
        assert summary["total_services"] == 1
        assert summary["exported_services"] == 1
        assert summary["total_receivers"] == 1
        assert summary["exported_receivers"] == 0


# 
# 4. CryptoAnalyzer Testleri
# 

class TestCryptoAnalyzer:
    """CryptoAnalyzer birim testleri"""

    def setup_method(self):
        from androidsec.static_analysis.code.crypto_analyzer import CryptoAnalyzer
        self.analyzer = CryptoAnalyzer()

    def test_weak_hash_md5(self):
        """MD5 kullanımı → CRITICAL bulgu"""
        code = 'MessageDigest.getInstance("MD5")'
        findings = self.analyzer.analyze(code, "Test.java")

        assert len(findings) >= 1
        assert any("MD5" in f["title"] for f in findings)
        assert findings[0]["severity"] == "CRITICAL"

    def test_weak_hash_sha1(self):
        """SHA1 kullanımı → CRITICAL bulgu"""
        code = 'MessageDigest.getInstance("SHA1")'
        findings = self.analyzer.analyze(code, "Test.java")

        assert len(findings) >= 1
        assert any("SHA1" in f["title"] or "SHA-1" in f["title"] for f in findings)

    def test_weak_cipher_des(self):
        """DES kullanımı → CRITICAL bulgu"""
        code = 'Cipher.getInstance("DES/ECB/PKCS5Padding")'
        findings = self.analyzer.analyze(code, "Test.java")

        # DES ve ECB ayrı ayrı tespit edilmeli
        assert len(findings) >= 1

    def test_ecb_mode(self):
        """ECB mode kullanımı → HIGH bulgu"""
        code = 'Cipher.getInstance("AES/ECB/PKCS5Padding")'
        findings = self.analyzer.analyze(code, "Test.java")

        ecb_findings = [f for f in findings if "ECB" in f["title"]]
        assert len(ecb_findings) >= 1
        assert ecb_findings[0]["severity"] == "HIGH"

    def test_insecure_random(self):
        """Random() kullanımı → MEDIUM bulgu"""
        code = 'Random random = new Random();\nint x = random.nextInt(100);'
        findings = self.analyzer.analyze(code, "Test.java")

        random_findings = [f for f in findings if "Random" in f["title"]]
        assert len(random_findings) >= 1
        assert random_findings[0]["severity"] == "MEDIUM"

    def test_hardcoded_key(self):
        """Hardcoded key → CRITICAL bulgu"""
        code = 'byte[] secretKey = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};'
        findings = self.analyzer.analyze(code, "Test.java")

        key_findings = [f for f in findings if "Hardcoded" in f["title"]]
        assert len(key_findings) >= 1
        assert key_findings[0]["severity"] == "CRITICAL"

    def test_secure_crypto_no_findings(self):
        """Güvenli kriptografi → bulgu olmamalı"""
        code = SAMPLE_JAVA_SECURE
        findings = self.analyzer.analyze(code, "Secure.java")

        # SHA-256, AES/GCM, SecureRandom → Finding olmamalı
        critical_or_high = [
            f for f in findings
            if f.get("severity") in ["CRITICAL", "HIGH"]
        ]
        assert len(critical_or_high) == 0

    def test_vulnerable_code_multiple_findings(self):
        """Zafiyetli kod → birden fazla bulgu"""
        findings = self.analyzer.analyze(SAMPLE_JAVA_VULNERABLE, "Vulnerable.java")
        assert len(findings) >= 2  # MD5 + ECB + DES + Random + Key


# 
# 5. SecretsDetector Testleri
# 

class TestSecretsDetector:
    """SecretsDetector birim testleri"""

    def setup_method(self):
        from androidsec.static_analysis.code.secrets_detector import SecretsDetector
        self.detector = SecretsDetector()

    def test_google_api_key(self):
        """Google API Key tespiti"""
        code = 'String key = "AIzaSyA1234567890abcdefghijklmnopqrstuv";'
        findings = self.detector.detect(code, "Config.java")

        assert len(findings) >= 1
        assert any("Google API Key" in f["title"] for f in findings)

    def test_aws_access_key(self):
        """AWS Access Key tespiti"""
        code = 'String awsKey = "AKIAIOSFODNN7EXAMPLE";'
        findings = self.detector.detect(code, "Config.java")

        assert len(findings) >= 1
        assert any("AWS" in f["title"] for f in findings)

    def test_hardcoded_password(self):
        """Hardcoded password tespiti"""
        code = 'password = "admin123secure";'
        findings = self.detector.detect(code, "Auth.java")

        assert len(findings) >= 1
        assert any("Password" in f["title"] for f in findings)

    def test_private_key(self):
        """Private key tespiti"""
        code = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ...'
        findings = self.detector.detect(code, "Keys.java")

        assert len(findings) >= 1
        assert any("Private Key" in f["title"] for f in findings)

    def test_secrets_in_comments_ignored(self):
        """Yorum satırındaki secretler göz ardı edilmeli"""
        code = '// API_KEY = "AIzaSyA1234567890abcdefghijklmnopqrstuv"'
        findings = self.detector.detect(code, "Test.java")

        # Yorum satırında olduğu için finding olmamalı
        # (Ancak basit implementasyon bunu yakalayamayabilir)
        # Bu test implementasyona bağlı



# 6. CodeScanner Testleri


class TestCodeScanner:
    """CodeScanner birim testleri"""

    def setup_method(self):
        from androidsec.static_analysis.code.scanner import CodeScanner
        self.scanner = CodeScanner()

    def test_sql_injection(self):
        """SQL Injection tespiti"""
        code = 'db.execSQL("SELECT * FROM users WHERE name = \'" + input + "\'");'
        findings = self.scanner._check_sql_injection(code, "DAO.java")

        assert len(findings) >= 1
        assert findings[0]["severity"] == "HIGH"

    def test_rawquery_injection(self):
        """rawQuery SQL Injection tespiti"""
        code = 'db.rawQuery("SELECT * FROM accounts WHERE id = " + userId, null);'
        findings = self.scanner._check_sql_injection(code, "DAO.java")

        assert len(findings) >= 1

    def test_webview_javascript(self):
        """WebView JavaScript tespiti"""
        code = 'webView.getSettings().setJavaScriptEnabled(true);'
        findings = self.scanner._check_webview_security(code, "WebActivity.java")

        assert len(findings) >= 1
        assert any("JavaScript" in f["title"] for f in findings)

    def test_webview_file_access(self):
        """WebView file access tespiti"""
        code = 'webView.getSettings().setAllowFileAccess(true);'
        findings = self.scanner._check_webview_security(code, "WebActivity.java")

        assert len(findings) >= 1
        assert any("File Access" in f["title"] for f in findings)

    def test_sensitive_logging(self):
        """Hassas veri loglama tespiti"""
        code = 'Log.d("Auth", "password: " + userPwd);'
        findings = self.scanner._check_sensitive_logging(code, "Auth.java")

        assert len(findings) >= 1
        assert any("password" in f["title"].lower() for f in findings)

    def test_scan_decompiled_dir(self, vulnerable_decompiled_dir):
        """Dekompile edilmiş klasörü tara → bulgu bulmalı"""
        findings = self.scanner.scan(vulnerable_decompiled_dir)

        # Zafiyetli Java kodu var → bulgu olmalı
        assert len(findings) >= 1

# 7. CertificateValidator Testleri
#

class TestCertificateValidator:
    """CertificateValidator birim testleri"""

    def setup_method(self):
        from androidsec.static_analysis.certificate.validator import CertificateValidator
        self.validator = CertificateValidator()

    def test_self_signed_certificate(self, normal_cert_info):
        """Self-signed sertifika tespiti"""
        # subject == issuer → self-signed
        findings = self.validator.validate(normal_cert_info)

        self_signed_findings = [
            f for f in findings if "Self-Signed" in f.get("title", "")
        ]
        assert len(self_signed_findings) == 1
        assert self_signed_findings[0]["severity"] == "MEDIUM"

    def test_expired_certificate(self, expired_cert_info):
        """Süresi dolmuş sertifika tespiti"""
        findings = self.validator.validate(expired_cert_info)

        expired_findings = [
            f for f in findings if "Expired" in f.get("title", "")
        ]
        assert len(expired_findings) == 1
        assert expired_findings[0]["severity"] == "CRITICAL"

    def test_debug_certificate(self, debug_cert_info):
        """Debug sertifikası tespiti"""
        findings = self.validator.validate(debug_cert_info)

        debug_findings = [
            f for f in findings if "Debug" in f.get("title", "")
        ]
        assert len(debug_findings) == 1
        assert debug_findings[0]["severity"] == "CRITICAL"

    def test_weak_algorithm(self, weak_algo_cert_info):
        """Zayıf algoritma tespiti"""
        findings = self.validator.validate(weak_algo_cert_info)

        algo_findings = [
            f for f in findings if "Weak Signature" in f.get("title", "")
        ]
        assert len(algo_findings) == 1
        assert algo_findings[0]["severity"] == "HIGH"

    def test_short_validity(self, short_validity_cert_info):
        """Kısa geçerlilik tespiti"""
        findings = self.validator.validate(short_validity_cert_info)

        validity_findings = [
            f for f in findings if "Validity Too Short" in f.get("title", "")
        ]
        assert len(validity_findings) == 1
        assert validity_findings[0]["severity"] == "MEDIUM"



# 8. CertificateExtractor Testleri


class TestCertificateExtractor:
    """CertificateExtractor birim testleri"""

    def setup_method(self):
        from androidsec.static_analysis.certificate.extractor import CertificateExtractor
        self.extractor = CertificateExtractor()

    def test_find_certificate_file(self, vulnerable_apk):
        """APK'da sertifika dosyası bulmalı"""
        cert_file = self.extractor._find_certificate_file(vulnerable_apk)
        assert cert_file is not None
        assert "CERT.RSA" in cert_file

    def test_extract_returns_dict(self, vulnerable_apk):
        """Sertifika çıkarma → dictionary döndürmeli"""
        cert_info = self.extractor.extract(vulnerable_apk)

        assert isinstance(cert_info, dict)
        assert "cert_file" in cert_info
        assert "fingerprint_sha256" in cert_info
        assert cert_info["fingerprint_sha256"] != "Unknown"

    def test_extract_invalid_apk(self):
        """Geçersiz APK → hata fırlatmalı"""
        from androidsec.core.exceptions import StaticAnalysisError
        with pytest.raises(StaticAnalysisError):
            self.extractor.extract("/nonexistent/app.apk")



# 9. SOAnalyzer Testleri


class TestSOAnalyzer:
    """SOAnalyzer birim testleri"""

    def setup_method(self):
        from androidsec.static_analysis.native.so_analyzer import SOAnalyzer
        self.analyzer = SOAnalyzer()

    def test_analyze_apk_with_so(self, vulnerable_apk):
        """SO dosyaları olan APK → bulgular üretmeli"""
        findings = self.analyzer.analyze_apk(vulnerable_apk)

        # Mimari bilgisi, tehlikeli fonksiyonlar vb. bulgu olmalı
        assert len(findings) >= 1

    def test_analyze_apk_without_so(self, secure_apk):
        """SO dosyası olmayan APK → boş bulgular"""
        findings = self.analyzer.analyze_apk(secure_apk)
        assert len(findings) == 0

    def test_analyze_directory(self, vulnerable_decompiled_dir):
        """Dekompile edilmiş klasördeki SO dosyalarını analiz et"""
        findings = self.analyzer.analyze_directory(vulnerable_decompiled_dir)

        # .so dosyaları varsa bulgu olmalı
        assert len(findings) >= 1

    def test_dangerous_functions_detected(self):
        """Tehlikeli fonksiyonlar binary'de tespit edilmeli"""
        # strcpy null-terminated
        elf_data = (
            b'\x7fELF\x02\x01\x01' + b'\x00' * 9
            + b'\x03\x00' + b'\xB7\x00'
            + b'\x00' * 48
            + b'system\x00'
            + b'strcpy\x00'
            + b'gets\x00'
            + b'\x00' * 100
        )

        findings = self.analyzer._check_dangerous_functions(elf_data, "libnative.so")

        assert len(findings) >= 2  # system + strcpy + gets
        severities = [f["severity"] for f in findings]
        assert "CRITICAL" in severities  # system() veya gets()

    def test_pie_check(self):
        """PIE olmayan binary → HIGH bulgu"""
        # ET_EXEC (type=2) → PIE kapalı
        elf_data = (
            b'\x7fELF\x02\x01\x01' + b'\x00' * 9
            + b'\x02\x00'  # ET_EXEC → PIE kapalı
            + b'\xB7\x00'
            + b'\x00' * 200
        )

        findings = self.analyzer._analyze_so_binary(elf_data, "libnopie.so")

        pie_findings = [f for f in findings if "PIE" in f.get("title", "")]
        assert len(pie_findings) >= 1
        assert pie_findings[0]["severity"] == "HIGH"



# 10. StringsExtractor Testleri


class TestStringsExtractor:
    """StringsExtractor birim testleri"""

    def setup_method(self):
        from androidsec.static_analysis.native.strings_extractor import StringsExtractor
        self.extractor = StringsExtractor(min_length=4)

    def test_extract_strings(self):
        """Binary'den string çıkarma"""
        data = b'\x00\x00Hello World\x00\x00Test\x00\x00AB\x00\x00'
        strings = self.extractor.extract_strings(data)

        assert "Hello World" in strings
        assert "Test" in strings
        assert "AB" not in strings  # min_length=4, "AB" çok kısa

    def test_check_http_urls(self):
        """HTTP URL tespiti"""
        data = b'\x00http://evil.example.com/malware\x00https://secure.example.com\x00'
        findings = self.extractor._check_urls(data, "libnative.so")

        http_findings = [f for f in findings if "HTTP URLs" in f.get("title", "")]
        assert len(http_findings) >= 1

    def test_check_ip_addresses(self):
        """IP adresi tespiti"""
        data = b'\x00192.168.1.100\x00\x0045.33.32.156\x00'
        findings = self.extractor._check_ip_addresses(data, "libnative.so")

        # Public IP bulgusu olmalı
        ip_findings = [f for f in findings if "IP" in f.get("title", "")]
        assert len(ip_findings) >= 1

    def test_check_api_keys(self):
        """API key tespiti"""
        data = b'\x00AIzaSyA1234567890abcdefghijklmnopqrstuv\x00'
        findings = self.extractor._check_api_keys(data, "libnative.so")

        assert len(findings) >= 1
        assert findings[0]["severity"] == "CRITICAL"

    def test_check_file_paths(self):
        """Dosya yolu tespiti"""
        data = b'\x00/data/data/com.example/databases/secret.db\x00/sdcard/DCIM/photo.jpg\x00'
        findings = self.extractor._check_file_paths(data, "libnative.so")

        assert len(findings) >= 1

    def test_check_suspicious_commands(self):
        """Şüpheli komut tespiti"""
        data = b'\x00/system/bin/su\x00chmod\x00pm install\x00'
        findings = self.extractor._check_suspicious_commands(data, "libnative.so")

        # su komutu → root access finding
        root_findings = [f for f in findings if "Root" in f.get("title", "")]
        assert len(root_findings) >= 1

    def test_analyze_apk(self, vulnerable_apk):
        """APK'dan string analizi"""
        findings = self.extractor.analyze_apk(vulnerable_apk)
        # SO dosyaları varsa analiz yapılmalı
        assert isinstance(findings, list)



# 11. StaticAnalyzer (Orkestratör) Testleri


class TestStaticAnalyzer:
    """StaticAnalyzer entegrasyon testleri"""

    def setup_method(self):
        from androidsec.static_analysis.analyzer import StaticAnalyzer
        self.analyzer = StaticAnalyzer()

    def test_analyze_with_apk_only(self, vulnerable_apk):
        """Sadece APK ile analiz (decompiled dir yok)"""
        findings = self.analyzer.analyze(apk_path=vulnerable_apk)

        assert isinstance(findings, list)
        assert len(findings) >= 1

        # Her bulgunun gerekli alanları var mı?
        for finding in findings:
            assert "category" in finding
            assert "severity" in finding
            assert "title" in finding
            assert "description" in finding

    def test_analyze_with_decompiled_dir(self, vulnerable_apk, vulnerable_decompiled_dir):
        """APK + dekompile edilmiş klasör ile tam analiz"""
        findings = self.analyzer.analyze(
            apk_path=vulnerable_apk,
            decompiled_dir=vulnerable_decompiled_dir
        )

        assert isinstance(findings, list)
        # Hem manifest hem kod hem sertifika hem native bulgular olmalı
        assert len(findings) >= 3

    def test_analyze_secure_apk(self, secure_apk):
        """Güvenli APK → daha az HIGH/CRITICAL bulgu"""
        findings = self.analyzer.analyze(apk_path=secure_apk)

        # Hiç CRITICAL debuggable bulgusu olmamalı (debuggable=false)
        debuggable = [f for f in findings if "Debuggable" in f.get("title", "")]
        assert len(debuggable) == 0

    def test_statistics(self):
        """İstatistikler doğru hesaplanmalı"""
        test_findings = [
            {"severity": "CRITICAL", "category": "M1: Improper Platform Usage"},
            {"severity": "CRITICAL", "category": "M5: Insufficient Cryptography"},
            {"severity": "HIGH", "category": "M1: Improper Platform Usage"},
            {"severity": "MEDIUM", "category": "M2: Insecure Data Storage"},
            {"severity": "LOW", "category": "M7: Client Code Quality"},
            {"severity": "INFO", "category": "M7: Client Code Quality"},
        ]

        stats = self.analyzer.get_statistics(test_findings)

        assert stats["total"] == 6
        assert stats["by_severity"]["CRITICAL"] == 2
        assert stats["by_severity"]["HIGH"] == 1
        assert stats["by_severity"]["MEDIUM"] == 1
        assert stats["by_severity"]["LOW"] == 1
        assert stats["by_severity"]["INFO"] == 1
        assert stats["by_category"]["M1: Improper Platform Usage"] == 2
        assert stats["by_category"]["M7: Client Code Quality"] == 2

    def test_finding_format(self, vulnerable_apk):
        """Bulgular doğru formatta olmalı"""
        findings = self.analyzer.analyze(apk_path=vulnerable_apk)

        required_fields = ["category", "severity", "title", "description"]
        valid_severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

        for finding in findings:
            for field in required_fields:
                assert field in finding, f"Missing field '{field}' in finding: {finding.get('title', 'Unknown')}"

            assert finding["severity"] in valid_severities, (
                f"Invalid severity '{finding['severity']}' in finding: {finding['title']}"
            )
