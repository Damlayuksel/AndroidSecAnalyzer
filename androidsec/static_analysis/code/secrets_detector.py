"""
Secrets Detector
Hardcoded secrets (API keys, passwords, tokens) tespit eder

Ne tespit eder?
1. API keys (AWS, Google, Firebase, vb.)
2. Passwords (hardcoded şifreler)
3. Tokens (OAuth, JWT, vb.)
4. Private keys
5. Database credentials
"""

import re
from typing import List, Dict, Any

from androidsec.core.constants import SEVERITY_CRITICAL, SEVERITY_HIGH
from androidsec.utils.logger import get_logger

logger = get_logger(__name__)


class SecretsDetector:
    """
    Hardcoded secrets tespit eder
    
    Kullanım:
        detector = SecretsDetector()
        findings = detector.detect(code, "MainActivity.java")
    """
    
    def __init__(self):
        """Initialize secrets detector"""
        logger.debug("SecretsDetector initialized")
        
        # Secret patterns (regex)
        self.patterns = {
            # AWS Keys
            "AWS Access Key": r'AKIA[0-9A-Z]{16}',
            "AWS Secret Key": r'aws_secret_access_key\s*=\s*["\']([^"\']{40})["\']',
            
            # Google API Key
            "Google API Key": r'AIza[0-9A-Za-z\-_]{35}',
            
            # Firebase
            "Firebase URL": r'https://[a-z0-9-]+\.firebaseio\.com',
            
            # Generic API Key patterns
            "API Key": r'[aA][pP][iI]_?[kK][eE][yY]\s*[=:]\s*["\']([^"\']{20,})["\']',
            "API Secret": r'[aA][pP][iI]_?[sS][eE][cC][rR][eE][tT]\s*[=:]\s*["\']([^"\']{20,})["\']',
            
            # OAuth Token
            "OAuth Token": r'["\']([a-zA-Z0-9\-_]{40,})["\']',
            
            # Password patterns
            "Password": r'[pP][aA][sS][sS][wW][oO][rR][dD]\s*[=:]\s*["\']([^"\']{4,})["\']',
            
            # Private Key
            "Private Key": r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
            
            # Database credentials
            "Database URL": r'jdbc:[a-z]+://[^"\']+',
        }
    
    def detect(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """
        Kodda hardcoded secrets ara
        
        Args:
            code: Kaynak kod
            file_path: Dosya yolu
        
        Returns:
            Bulgular listesi
        """
        findings = []
        
        for secret_type, pattern in self.patterns.items():
            matches = re.finditer(pattern, code)
            
            for match in matches:
                # Yorum satırında mı? (Örnek kod olabilir)
                if self._is_in_comment(code, match.start()):
                    continue
                
                # Satır numarası
                line_num = code[:match.start()].count('\n') + 1
                
                # Secret değerini gizle (ilk 10 karakter)
                secret_value = match.group()
                masked_value = secret_value[:10] + "***" if len(secret_value) > 10 else "***"
                
                findings.append({
                    "category": "M9: Reverse Engineering",
                    "severity": SEVERITY_CRITICAL if "Key" in secret_type or "Password" in secret_type else SEVERITY_HIGH,
                    "title": f"Hardcoded {secret_type}",
                    "description": (
                        f"Found hardcoded {secret_type} in source code. "
                        f"Value: {masked_value}"
                    ),
                    "file": file_path,
                    "line": line_num,
                    "code_snippet": self._get_code_snippet(code, match.start(), match.end()),
                    "recommendation": (
                        f"Never hardcode {secret_type} in source code. "
                        "Use environment variables or secure storage (Android Keystore)."
                    )
                })
        
        return findings
    
    def _is_in_comment(self, code: str, position: int) -> bool:
        """
        Verilen pozisyon yorum satırında mı?
        
        Args:
            code: Kaynak kod
            position: Kontrol edilecek pozisyon
        
        Returns:
            True ise yorum satırında
        """
        # Pozisyondan önceki satırı al
        line_start = code.rfind('\n', 0, position) + 1
        line_content = code[line_start:position]
        
        # // ile başlıyor mu?
        if '//' in line_content:
            return True
        
        # /* ... */ içinde mi?
        # (Basit kontrol - tam doğru olmayabilir)
        before_position = code[:position]
        comment_start = before_position.rfind('/*')
        comment_end = before_position.rfind('*/')
        
        if comment_start > comment_end:
            return True  # /* açılmış ama */ kapanmamış
        
        return False
    
    def _get_code_snippet(self, code: str, start: int, end: int) -> str:
        """
        Kod snippet'i al (gizlenmiş)
        
        Args:
            code: Kaynak kod
            start: Başlangıç pozisyonu
            end: Bitiş pozisyonu
        
        Returns:
            Gizlenmiş kod snippet'i
        """
        snippet = code[start:end]
        
        # Çok uzunsa kısalt
        if len(snippet) > 50:
            snippet = snippet[:20] + "***" + snippet[-10:]
        else:
            # Ortasını gizle
            if len(snippet) > 10:
                snippet = snippet[:5] + "***" + snippet[-5:]
        
        return snippet
    
    def __repr__(self) -> str:
        return "SecretsDetector()"
