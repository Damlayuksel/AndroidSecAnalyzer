"""
Code Scanner
Kaynak kodu güvenlik açıkları için tarar

Ne tarar?
1. Zayıf kriptografi (MD5, DES, ECB mode)
2. Hardcoded secrets (API keys, passwords, tokens)
3. SQL Injection riski
4. Path Traversal
5. Insecure Random
6. WebView güvenlik sorunları
7. Logging sensitive data
"""

from pathlib import Path
from typing import List, Dict, Any
import re

from androidsec.core.constants import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
)
from androidsec.utils.logger import get_logger
from androidsec.static_analysis.code.crypto_analyzer import CryptoAnalyzer
from androidsec.static_analysis.code.secrets_detector import SecretsDetector

logger = get_logger(__name__)


class CodeScanner:
    """
    Kaynak kodu güvenlik açıkları için tarar
    
    Kullanım:
        scanner = CodeScanner()
        findings = scanner.scan("decompiled/")
        
        for finding in findings:
            print(f"{finding['severity']}: {finding['title']}")
    """
    
    def __init__(self):
        """Initialize code scanner"""
        logger.debug("CodeScanner initialized")
        
        # Alt analizörler
        self.crypto_analyzer = CryptoAnalyzer()
        self.secrets_detector = SecretsDetector()
    
    def scan(self, decompiled_dir: str) -> List[Dict[str, Any]]:
        """
        Dekompile edilmiş klasörü tara
        
        Args:
            decompiled_dir: Dekompile edilmiş APK klasörü
        
        Returns:
            Bulgular listesi
        """
        logger.info(f"Scanning code in: {decompiled_dir}")
        
        findings = []
        
        # Java/Kotlin dosyalarını bul
        java_files = self._find_source_files(decompiled_dir)
        logger.info(f"Found {len(java_files)} source files")
        
        # Her dosyayı tara
        for java_file in java_files:
            logger.debug(f"Scanning: {java_file}")
            
            # Dosyayı oku
            code = self._read_file(java_file)
            
            # 1. Kriptografi analizi
            crypto_findings = self.crypto_analyzer.analyze(code, str(java_file))
            findings.extend(crypto_findings)
            
            # 2. Hardcoded secrets
            secret_findings = self.secrets_detector.detect(code, str(java_file))
            findings.extend(secret_findings)
            
            # 3. SQL Injection
            sql_findings = self._check_sql_injection(code, str(java_file))
            findings.extend(sql_findings)
            
            # 4. WebView güvenlik
            webview_findings = self._check_webview_security(code, str(java_file))
            findings.extend(webview_findings)
            
            # 5. Logging sensitive data
            logging_findings = self._check_sensitive_logging(code, str(java_file))
            findings.extend(logging_findings)
        
        logger.info(f"Code scan complete: {len(findings)} findings")
        return findings
    
    # Taranmayacak üçüncü parti kütüphane paketleri
    THIRD_PARTY_PREFIXES = (
        "com/google/",
        "android/support/",
        "androidx/",
        "com/squareup/",
        "okhttp3/",
        "retrofit2/",
        "io/reactivex/",
        "kotlin/",
        "kotlinx/",
        "org/apache/",
        "org/bouncycastle/",
        "com/facebook/",
        "com/twitter/",
    )

    def _find_source_files(self, decompiled_dir: str) -> List[Path]:
        """
        Java/Kotlin kaynak dosyalarını bul, üçüncü parti kütüphaneleri atla

        Returns:
            Dosya yolları listesi
        """
        source_dir = Path(decompiled_dir)

        java_files  = list(source_dir.rglob("*.java"))
        kotlin_files = list(source_dir.rglob("*.kt"))

        all_files = java_files + kotlin_files

        # Üçüncü parti kütüphaneleri filtrele
        filtered = []
        for f in all_files:
            rel = f.as_posix()
            if not any(prefix in rel for prefix in self.THIRD_PARTY_PREFIXES):
                filtered.append(f)

        logger.debug(
            f"Found {len(all_files)} total, {len(filtered)} after filtering third-party libs"
        )
        return filtered
    
    def _read_file(self, file_path: Path) -> str:
        """
        Dosyayı oku
        
        Returns:
            Dosya içeriği (string)
        """
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
        except Exception as e:
            logger.warning(f"Failed to read {file_path}: {e}")
            return ""
    
    def _check_sql_injection(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """
        SQL Injection riski kontrol et
        
        Tehlikeli pattern:
        - execSQL() ile string concatenation
        - rawQuery() ile string concatenation
        """
        findings = []
        
        # Pattern: execSQL("... + variable + ...")
        sql_patterns = [
            r'execSQL\s*\([^)]*\+[^)]*\)',
            r'rawQuery\s*\([^)]*\+[^)]*\)',
        ]
        
        for pattern in sql_patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                # Satır numarasını bul
                line_num = code[:match.start()].count('\n') + 1
                
                findings.append({
                    "category": "M7: Client Code Quality",
                    "severity": SEVERITY_HIGH,
                    "title": "Potential SQL Injection",
                    "description": (
                        "SQL query uses string concatenation which may lead to SQL injection. "
                        f"Found: {match.group()}"
                    ),
                    "file": file_path,
                    "line": line_num,
                    "code_snippet": match.group(),
                    "recommendation": "Use parameterized queries instead of string concatenation"
                })
        
        return findings
    
    def _check_webview_security(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """
        WebView güvenlik sorunlarını kontrol et
        
        Tehlikeli:
        - setJavaScriptEnabled(true)
        - setAllowFileAccess(true)
        - setAllowUniversalAccessFromFileURLs(true)
        """
        findings = []
        
        # JavaScript enabled
        if 'setJavaScriptEnabled(true)' in code:
            line_num = code[:code.find('setJavaScriptEnabled(true)')].count('\n') + 1

            # loadData / loadUrl ile kullanıcı girdisi yükleniyorsa → CRITICAL XSS
            if re.search(r'loadData\s*\(|loadUrl\s*\(', code):
                findings.append({
                    "category": "M7: Client Code Quality",
                    "severity": SEVERITY_CRITICAL,
                    "title": "XSS: WebView Kullanıcı Girdisini HTML Olarak Yüklüyor",
                    "description": (
                        "WebView JavaScript etkin ve kullanıcı girdisi doğrudan HTML "
                        "olarak yükleniyor. Bu durum XSS (Cross-Site Scripting) saldırısına "
                        "neden olabilir. Saldırgan script enjekte edebilir."
                    ),
                    "file": file_path,
                    "line": line_num,
                    "recommendation": (
                        "Kullanıcı girdisini HTML encode edin veya JavaScript'i devre dışı bırakın."
                    )
                })
            else:
                findings.append({
                    "category": "M1: Improper Platform Usage",
                    "severity": SEVERITY_HIGH,
                    "title": "XSS Riski: WebView JavaScript Etkin",
                    "description": (
                        "WebView'de JavaScript etkinleştirilmiş. "
                        "Güvenilmeyen içerik yüklenirse XSS saldırısına açık hale gelir."
                    ),
                    "file": file_path,
                    "line": line_num,
                    "recommendation": "JavaScript'i sadece zorunlu durumlarda etkinleştirin, tüm içeriği doğrulayın."
                })
        
        # File access
        if 'setAllowFileAccess(true)' in code:
            line_num = code[:code.find('setAllowFileAccess(true)')].count('\n') + 1
            
            findings.append({
                "category": "M1: Improper Platform Usage",
                "severity": SEVERITY_HIGH,
                "title": "WebView File Access Enabled",
                "description": (
                    "WebView allows file access which may expose sensitive files"
                ),
                "file": file_path,
                "line": line_num,
                "recommendation": "Disable file access unless required"
            })
        
        return findings
    
    def _check_sensitive_logging(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """
        Hassas veri loglama kontrolü
        
        Tehlikeli:
        - Log.d("password: " + password)
        - Log.d("token: " + token)
        """
        findings = []
        
        # Hassas kelimeler
        sensitive_keywords = [
            'password', 'passwd', 'pwd',
            'token', 'api_key', 'apikey',
            'secret', 'private_key', 'privatekey',
            'credit_card', 'creditcard', 'ssn'
        ]
        
        # Log pattern
        log_pattern = r'Log\.[dviwe]\s*\([^)]*\)'
        
        for match in re.finditer(log_pattern, code, re.IGNORECASE):
            log_statement = match.group().lower()
            
            # Hassas kelime var mı?
            for keyword in sensitive_keywords:
                if keyword in log_statement:
                    line_num = code[:match.start()].count('\n') + 1
                    
                    findings.append({
                        "category": "M2: Insecure Data Storage",
                        "severity": SEVERITY_MEDIUM,
                        "title": f"Logging Sensitive Data: {keyword}",
                        "description": (
                            f"Application logs sensitive data ({keyword}) which may be "
                            "accessible to other apps or via ADB"
                        ),
                        "file": file_path,
                        "line": line_num,
                        "code_snippet": match.group(),
                        "recommendation": "Remove sensitive data from logs in production builds"
                    })
                    break  # Bir bulgu yeter
        
        return findings
    
    def __repr__(self) -> str:
        return "CodeScanner()"
