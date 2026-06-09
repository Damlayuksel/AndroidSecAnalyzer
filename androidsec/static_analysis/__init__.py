"""
Static Analysis Module
Statik Analiz Modülü - APK'yı çalıştırmadan kod analizi yapar

Bu modül şunları yapar:
1. AndroidManifest.xml analizi (izinler, componentler, güvenlik bayrakları)
2. Kaynak kod analizi (zayıf kriptografi, hardcoded secrets, SQL injection)
3. Sertifika analizi (imza doğrulama, geçerlilik, zayıf algoritma)
4. Native kod analizi (.so dosyaları, tehlikeli fonksiyonlar, stringler)
"""

from androidsec.static_analysis.analyzer import StaticAnalyzer

__all__ = [
    "StaticAnalyzer",
]
