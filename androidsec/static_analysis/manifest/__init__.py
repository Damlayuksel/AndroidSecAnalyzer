"""
Manifest Analysis Module
AndroidManifest.xml analiz modülü

Bu modül:
1. AndroidManifest.xml'i parse eder
2. İzinleri (permissions) analiz eder
3. Componentleri (Activity, Service, Receiver, Provider) analiz eder
4. Güvenlik açıklarını tespit eder

IMPORT: parser.py'den ManifestParser'ı al
IMPORT: permissions.py'den PermissionAnalyzer'ı al
IMPORT: components.py'den ComponentAnalyzer'ı al
EXPORT: Bu 3'ünü dışarıya aç (__all__)


"""

from androidsec.static_analysis.manifest.parser import ManifestParser
from androidsec.static_analysis.manifest.permissions import PermissionAnalyzer
from androidsec.static_analysis.manifest.components import ComponentAnalyzer

__all__ = [
    "ManifestParser",
    "PermissionAnalyzer",
    "ComponentAnalyzer",
]
