"""
Native Code Analysis Module
Native kod analiz modülü - .so dosyalarını güvenlik açısından analiz eder

Bu modül:
1. APK içindeki .so (shared library) dosyalarını bulur ve analiz eder
2. Binary dosyalardan string çıkarır (URL, IP, anahtar vb.)
3. Güvenlik kontrollerini kontrol eder (PIE, RELRO, Stack Canary vb.)

IMPORT: so_analyzer.py'den SOAnalyzer'ı al
IMPORT: strings_extractor.py'den StringsExtractor'ı al
EXPORT: Bu 2'sini dışarıya aç (__all__)
"""

from androidsec.static_analysis.native.so_analyzer import SOAnalyzer
from androidsec.static_analysis.native.strings_extractor import StringsExtractor

__all__ = [
    "SOAnalyzer",
    "StringsExtractor",
]
