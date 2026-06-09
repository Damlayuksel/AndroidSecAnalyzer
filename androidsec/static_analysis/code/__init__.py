"""
Code Analysis Module
Kod Analiz Modülü - Kaynak kodu güvenlik açıkları için tarar

Bu modül ne yapar?
1. Java/Kotlin kaynak kodunu tarar
2. Güvenlik açıklarını tespit eder:
   - Zayıf kriptografi (MD5, DES, vb.)
   - Hardcoded secrets (API keys, passwords)
   - SQL Injection
   - Path Traversal
   - Insecure Random
   - WebView güvenlik sorunları

IMPORT: scanner.py'den CodeScanner'ı al
IMPORT: crypto_analyzer.py'den CryptoAnalyzer'ı al
IMPORT: secrets_detector.py'den SecretsDetector'ı al
EXPORT: Bu 3'ünü dışarıya aç (__all__)
"""

from androidsec.static_analysis.code.scanner import CodeScanner
from androidsec.static_analysis.code.crypto_analyzer import CryptoAnalyzer
from androidsec.static_analysis.code.secrets_detector import SecretsDetector

__all__ = [
    "CodeScanner",
    "CryptoAnalyzer",
    "SecretsDetector",
]
