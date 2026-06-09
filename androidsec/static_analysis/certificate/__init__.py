"""
Certificate Analysis Module
Sertifika Analiz Modülü

APK sertifikası (imza) nedir?
- APK'nın kim tarafından imzalandığını gösterir
- APK'nın değiştirilip değiştirilmediğini kontrol eder
- Google Play Store için gereklidir

Bu modül:
1. APK'dan sertifikayı çıkarır (META-INF/CERT.RSA)
2. Sertifika bilgilerini parse eder (kim imzaladı, ne zaman, vb.)
3. Güvenlik kontrolü yapar (self-signed mı, süresi dolmuş mu, vb.)

IMPORT: extractor.py'den CertificateExtractor'ı al
IMPORT: validator.py'den CertificateValidator'ı al
EXPORT: Bu 2'sini dışarıya aç (__all__)
"""

from androidsec.static_analysis.certificate.extractor import CertificateExtractor
from androidsec.static_analysis.certificate.validator import CertificateValidator

__all__ = [
    "CertificateExtractor",
    "CertificateValidator",
]
