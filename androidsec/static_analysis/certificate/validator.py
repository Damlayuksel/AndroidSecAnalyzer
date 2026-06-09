"""
Certificate Validator
Sertifika güvenlik kontrolü yapar

Ne kontrol ediyoruz?
1. Self-signed mı? (Kendi kendine imzalanmış)
2. Süresi dolmuş mu?
3. Zayıf algoritma mı? (MD5, SHA1)
4. Debug sertifikası mı?
5. Geçerlilik süresi çok kısa mı?
"""

from datetime import datetime, timedelta
from typing import List, Dict, Any

from androidsec.core.constants import SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO
from androidsec.utils.logger import get_logger

logger = get_logger(__name__)


class CertificateValidator:
    """
    Sertifika güvenlik kontrolü yapar
    
    Kullanım:
        validator = CertificateValidator()
        findings = validator.validate(cert_info)
        
        for finding in findings:
            print(f"{finding['severity']}: {finding['title']}")
    """
    
    # Debug sertifikası bilgileri (Android Studio default)
    DEBUG_CERT_SUBJECT = "CN=Android Debug"
    DEBUG_CERT_FINGERPRINT = "38:A8:62:A6:F9:EC:3B:32:BD:64:40:00:6F:5D:AF:01:FA:BF:46:B8:B5:41:94:FB:EF:61:BF:AD:0B:E5:A6:8D"
    
    # Zayıf hash algoritmaları
    WEAK_ALGORITHMS = ["MD5", "SHA1", "MD5withRSA", "SHA1withRSA"]
    
    # Minimum geçerlilik süresi (yıl)
    MIN_VALIDITY_YEARS = 25
    
    def __init__(self):
        """Initialize certificate validator"""
        logger.debug("CertificateValidator initialized")
    
    def validate(self, cert_info: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Sertifikayı doğrula ve güvenlik bulgularını döndür
        
        Args:
            cert_info: CertificateExtractor.extract() tarafından döndürülen sertifika bilgisi
        
        Returns:
            Bulgular listesi: [
                {
                    "category": "M8: Code Tampering",
                    "severity": "MEDIUM",
                    "title": "Self-Signed Certificate",
                    "description": "...",
                    "recommendation": "..."
                },
                ...
            ]
        """
        logger.info("Validating certificate...")
        
        findings = []
        
        # 1. Self-signed kontrolü
        if self._is_self_signed(cert_info):
            findings.append(self._create_self_signed_finding(cert_info))
        
        # 2. Süre dolmuş mu?
        if self._is_expired(cert_info):
            findings.append(self._create_expired_finding(cert_info))
        
        # 3. Zayıf algoritma mı?
        if self._has_weak_algorithm(cert_info):
            findings.append(self._create_weak_algorithm_finding(cert_info))
        
        # 4. Debug sertifikası mı?
        if self._is_debug_certificate(cert_info):
            findings.append(self._create_debug_cert_finding(cert_info))
        
        # 5. Geçerlilik süresi çok kısa mı?
        if self._has_short_validity(cert_info):
            findings.append(self._create_short_validity_finding(cert_info))
        
        logger.info(f"Certificate validation complete: {len(findings)} findings")
        return findings
    
    def _is_self_signed(self, cert_info: Dict[str, Any]) -> bool:
        """
        Self-signed (kendi kendine imzalanmış) mı?
        
        Self-signed nedir?
        - Sertifikayı veren (issuer) = Sertifika sahibi (subject)
        - Güvenilir bir CA (Certificate Authority) tarafından imzalanmamış
        - Production uygulamalarda riskli
        
        Örnek:
            subject: "CN=MyCompany"
            issuer:  "CN=MyCompany"  ← Aynı! Self-signed
        """
        subject = cert_info.get("subject", "")
        issuer = cert_info.get("issuer", "")
        
        return subject == issuer
    
    def _is_expired(self, cert_info: Dict[str, Any]) -> bool:
        """
        Sertifika süresi dolmuş mu?
        
        valid_to tarihini kontrol eder
        """
        valid_to_str = cert_info.get("valid_to", "")
        
        try:
            # String'i datetime'a çevir
            valid_to = datetime.strptime(valid_to_str, "%Y-%m-%d %H:%M:%S")
            
            # Şu anki tarihle karşılaştır
            now = datetime.now()
            
            return now > valid_to
            
        except (ValueError, TypeError):
            logger.warning(f"Invalid date format: {valid_to_str}")
            return False
    
    def _has_weak_algorithm(self, cert_info: Dict[str, Any]) -> bool:
        """
        Zayıf hash algoritması mı?
        
        MD5 ve SHA1 artık güvenli değil!
        - MD5: 1996'dan beri kırılmış
        - SHA1: 2017'den beri kırılmış
        
        Güvenli: SHA256, SHA384, SHA512
        """
        algorithm = cert_info.get("signature_algorithm", "")
        
        for weak_algo in self.WEAK_ALGORITHMS:
            if weak_algo.upper() in algorithm.upper():
                return True
        
        return False
    
    def _is_debug_certificate(self, cert_info: Dict[str, Any]) -> bool:
        """
        Android Debug sertifikası mı?
        
        Android Studio otomatik debug sertifikası oluşturur:
        - Subject: "CN=Android Debug, O=Android, C=US"
        - Fingerprint: 38:A8:62:A6:...
        
        Production APK'da debug sertifikası OLMAMALI!
        """
        subject = cert_info.get("subject", "")
        fingerprint = cert_info.get("fingerprint_sha256", "")
        
        # Subject kontrolü
        if self.DEBUG_CERT_SUBJECT in subject:
            return True
        
        # Fingerprint kontrolü
        if self.DEBUG_CERT_FINGERPRINT in fingerprint:
            return True
        
        return False
    
    def _has_short_validity(self, cert_info: Dict[str, Any]) -> bool:
        """
        Geçerlilik süresi çok kısa mı?
        
        Google Play Store kuralı:
        - Sertifika en az 25 yıl geçerli olmalı
        - 2033'ten sonra bitmeligerekir
        """
        valid_from_str = cert_info.get("valid_from", "")
        valid_to_str = cert_info.get("valid_to", "")
        
        try:
            valid_from = datetime.strptime(valid_from_str, "%Y-%m-%d %H:%M:%S")
            valid_to = datetime.strptime(valid_to_str, "%Y-%m-%d %H:%M:%S")
            
            # Geçerlilik süresi (yıl)
            validity_years = (valid_to - valid_from).days / 365.25
            
            return validity_years < self.MIN_VALIDITY_YEARS
            
        except (ValueError, TypeError):
            return False
    
    def _create_self_signed_finding(self, cert_info: Dict[str, Any]) -> Dict[str, Any]:
        """Self-signed bulgusu oluştur"""
        return {
            "category": "M8: Code Tampering",
            "severity": SEVERITY_MEDIUM,
            "title": "Self-Signed Certificate",
            "description": (
                f"APK is signed with a self-signed certificate. "
                f"Subject: {cert_info.get('subject', 'Unknown')}"
            ),
            "file": cert_info.get("cert_file", "META-INF/CERT.RSA"),
            "recommendation": (
                "For production apps, use a certificate from a trusted "
                "Certificate Authority (CA)."
            )
        }
    
    def _create_expired_finding(self, cert_info: Dict[str, Any]) -> Dict[str, Any]:
        """Süresi dolmuş bulgusu"""
        return {
            "category": "M8: Code Tampering",
            "severity": SEVERITY_CRITICAL,
            "title": "Expired Certificate",
            "description": (
                f"Certificate has expired! "
                f"Valid until: {cert_info.get('valid_to', 'Unknown')}"
            ),
            "file": cert_info.get("cert_file", "META-INF/CERT.RSA"),
            "recommendation": "Renew the certificate immediately."
        }
    
    def _create_weak_algorithm_finding(self, cert_info: Dict[str, Any]) -> Dict[str, Any]:
        """Zayıf algoritma bulgusu"""
        algorithm = cert_info.get("signature_algorithm", "Unknown")
        
        return {
            "category": "M5: Insufficient Cryptography",
            "severity": SEVERITY_HIGH,
            "title": f"Weak Signature Algorithm: {algorithm}",
            "description": (
                f"Certificate uses weak signature algorithm: {algorithm}. "
                f"MD5 and SHA1 are cryptographically broken."
            ),
            "file": cert_info.get("cert_file", "META-INF/CERT.RSA"),
            "recommendation": "Use SHA256withRSA or stronger algorithm."
        }
    
    def _create_debug_cert_finding(self, cert_info: Dict[str, Any]) -> Dict[str, Any]:
        """Debug sertifikası bulgusu"""
        return {
            "category": "M8: Code Tampering",
            "severity": SEVERITY_CRITICAL,
            "title": "Debug Certificate in Production",
            "description": (
                "APK is signed with Android Debug certificate! "
                "This is extremely dangerous for production apps."
            ),
            "file": cert_info.get("cert_file", "META-INF/CERT.RSA"),
            "recommendation": (
                "NEVER release apps with debug certificate. "
                "Create a proper release certificate."
            )
        }
    
    def _create_short_validity_finding(self, cert_info: Dict[str, Any]) -> Dict[str, Any]:
        """Kısa geçerlilik bulgusu"""
        return {
            "category": "M8: Code Tampering",
            "severity": SEVERITY_MEDIUM,
            "title": "Certificate Validity Too Short",
            "description": (
                f"Certificate validity period is less than {self.MIN_VALIDITY_YEARS} years. "
                f"Valid from {cert_info.get('valid_from')} to {cert_info.get('valid_to')}."
            ),
            "file": cert_info.get("cert_file", "META-INF/CERT.RSA"),
            "recommendation": (
                f"Google Play requires certificates to be valid for at least "
                f"{self.MIN_VALIDITY_YEARS} years."
            )
        }
    
    def __repr__(self) -> str:
        return "CertificateValidator()"
