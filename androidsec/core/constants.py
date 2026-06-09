"""
Project-wide constants
Tüm projede kullanılacak sabit değerler
"""

# Severity Levels (Zafiyet Seviyeleri)
SEVERITY_CRITICAL = "CRITICAL"
SEVERITY_HIGH = "HIGH"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_LOW = "LOW"
SEVERITY_INFO = "INFO"

SEVERITY_LEVELS = [
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO,
]

# Risk Score Weights (Risk Skoru Ağırlıkları)
RISK_WEIGHTS = {
    SEVERITY_CRITICAL: 10.0,
    SEVERITY_HIGH: 7.5,
    SEVERITY_MEDIUM: 5.0,
    SEVERITY_LOW: 2.5,
    SEVERITY_INFO: 1.0,
}

# Analysis Types (Analiz Tipleri)
ANALYSIS_STATIC = "static"
ANALYSIS_DYNAMIC = "dynamic"
ANALYSIS_FULL = "full"

# File Extensions (Dosya Uzantıları)
APK_EXTENSION = ".apk"
DEX_EXTENSION = ".dex"
SO_EXTENSION = ".so"
JAR_EXTENSION = ".jar"

# Android Manifest
MANIFEST_FILE = "AndroidManifest.xml"

# Dangerous Permissions (Tehlikeli İzinler)
DANGEROUS_PERMISSIONS = [
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
]

# Report Formats (Rapor Formatları)
REPORT_FORMAT_HTML = "html"
REPORT_FORMAT_JSON = "json"

REPORT_FORMATS = [REPORT_FORMAT_HTML, REPORT_FORMAT_JSON]

# Default Timeouts (Varsayılan Zaman Aşımları)
DEFAULT_ANALYSIS_TIMEOUT = 3600  # 1 hour in seconds
DEFAULT_ADB_TIMEOUT = 30  # 30 seconds
DEFAULT_FRIDA_TIMEOUT = 300  # 5 minutes

# Database
DEFAULT_DB_NAME = "androidsec.db"

# Directories (Klasörler)
OUTPUT_DIR = "output"
REPORTS_DIR = "output/reports"
ARTIFACTS_DIR = "output/artifacts"
DECOMPILED_DIR = "output/decompiled"
LOGS_DIR = "output/logs"
CACHE_DIR = "output/cache"

# OWASP Mobile Top 10 Categories
OWASP_M1 = "M1: Improper Platform Usage"
OWASP_M2 = "M2: Insecure Data Storage"
OWASP_M3 = "M3: Insecure Communication"
OWASP_M4 = "M4: Insecure Authentication"
OWASP_M5 = "M5: Insufficient Cryptography"
OWASP_M6 = "M6: Insecure Authorization"
OWASP_M7 = "M7: Client Code Quality"
OWASP_M8 = "M8: Code Tampering"
OWASP_M9 = "M9: Reverse Engineering"
OWASP_M10 = "M10: Extraneous Functionality"

OWASP_CATEGORIES = [
    OWASP_M1, OWASP_M2, OWASP_M3, OWASP_M4, OWASP_M5,
    OWASP_M6, OWASP_M7, OWASP_M8, OWASP_M9, OWASP_M10,
]
