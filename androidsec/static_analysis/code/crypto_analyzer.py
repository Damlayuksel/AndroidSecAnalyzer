"""
Crypto Analyzer
Kriptografi güvenlik açıklarını tespit eder

Ne kontrol eder?
1. Zayıf hash algoritmaları (MD5, SHA1)
2. Zayıf şifreleme (DES, RC4)
3. Güvensiz modlar (ECB mode)
4. Insecure Random (Random yerine SecureRandom kullanılmalı)
5. Hardcoded encryption keys
"""

import re
from typing import List, Dict, Any

from androidsec.core.constants import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
)
from androidsec.utils.logger import get_logger

logger = get_logger(__name__)


class CryptoAnalyzer:
    """
    Kriptografi güvenlik analizi
    
    Kullanım:
        analyzer = CryptoAnalyzer()
        findings = analyzer.analyze(code, "MainActivity.java")
    """
    
    # Zayıf hash algoritmaları
    WEAK_HASH_ALGORITHMS = ["MD5", "SHA1", "SHA-1"]
    
    # Zayıf şifreleme algoritmaları
    WEAK_CIPHER_ALGORITHMS = ["DES", "RC4", "RC2", "Blowfish"]
    
    # Güvensiz modlar
    INSECURE_MODES = ["ECB"]
    
    def __init__(self):
        """Initialize crypto analyzer"""
        logger.debug("CryptoAnalyzer initialized")
    
    def analyze(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """
        Kodu kriptografi açıkları için analiz et
        
        Args:
            code: Kaynak kod
            file_path: Dosya yolu
        
        Returns:
            Bulgular listesi
        """
        findings = []
        
        # Bu kodun görevi: 
        # Her bir güvenlik kontrolünü çalıştırıp sonuçları findings listesinde toplamak:
        # 1. Zayıf hash algoritmaları
        findings.extend(self._check_weak_hash(code, file_path))
        
        # 2. Zayıf şifreleme
        findings.extend(self._check_weak_cipher(code, file_path))
        
        # 3. ECB mode
        findings.extend(self._check_ecb_mode(code, file_path))
        
        # 4. Insecure Random
        findings.extend(self._check_insecure_random(code, file_path))
        
        # 5. Hardcoded keys
        findings.extend(self._check_hardcoded_keys(code, file_path))
        
        return findings
    
    def _check_weak_hash(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """
        Zayıf hash algoritmaları kontrol et
        
        Örnek:
            MessageDigest.getInstance("MD5")  ← Zayıf!
            MessageDigest.getInstance("SHA1") ← Zayıf!
        """
        findings = []
        
        for algorithm in self.WEAK_HASH_ALGORITHMS:
            # Pattern: MessageDigest.getInstance("MD5")
            pattern = rf'MessageDigest\.getInstance\s*\(\s*["\']({algorithm})["\']'
            
            for match in re.finditer(pattern, code, re.IGNORECASE):
                line_num = code[:match.start()].count('\n') + 1
                
                findings.append({
                    "category": "M5: Insufficient Cryptography",
                    "severity": SEVERITY_CRITICAL,
                    "title": f"Weak Hash Algorithm: {algorithm}",
                    "description": (
                        f"{algorithm} hash algorithm is cryptographically broken and "
                        "should not be used for security purposes."
                    ),
                    "file": file_path,
                    "line": line_num,
                    "code_snippet": match.group(),
                    "recommendation": f"Use SHA-256 or SHA-3 instead of {algorithm}"
                })
        
        return findings
    
    def _check_weak_cipher(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """
        Zayıf şifreleme algoritmaları kontrol et
        
        Örnek:
            Cipher.getInstance("DES")  ← Zayıf!
            Cipher.getInstance("RC4")  ← Zayıf!
        """
        findings = []
        
        for algorithm in self.WEAK_CIPHER_ALGORITHMS:
            # Pattern: Cipher.getInstance("DES/...")
            pattern = rf'Cipher\.getInstance\s*\(\s*["\']({algorithm})[/"\']'
            
            for match in re.finditer(pattern, code, re.IGNORECASE):
                line_num = code[:match.start()].count('\n') + 1
                
                findings.append({
                    "category": "M5: Insufficient Cryptography",
                    "severity": SEVERITY_CRITICAL,
                    "title": f"Weak Encryption Algorithm: {algorithm}",
                    "description": (
                        f"{algorithm} encryption algorithm is weak and can be easily broken."
                    ),
                    "file": file_path,
                    "line": line_num,
                    "code_snippet": match.group(),
                    "recommendation": f"Use AES-256 instead of {algorithm}"
                })
        
        return findings
    
    def _check_ecb_mode(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """
        ECB mode kontrolü
        
        ECB (Electronic Codebook) mode güvensizdir!
        - Aynı plaintext → Aynı ciphertext
        - Pattern'ler görünür
        
        Örnek:
            Cipher.getInstance("AES/ECB/PKCS5Padding")  ← Güvensiz!
        """
        findings = []
        
        # Pattern: Cipher.getInstance("AES/ECB/...")
        pattern = r'Cipher\.getInstance\s*\(\s*["\'][^"\']*ECB[^"\']*["\']'
        
        for match in re.finditer(pattern, code, re.IGNORECASE):
            line_num = code[:match.start()].count('\n') + 1
            
            findings.append({
                "category": "M5: Insufficient Cryptography",
                "severity": SEVERITY_HIGH,
                "title": "Insecure Cipher Mode: ECB",
                "description": (
                    "ECB (Electronic Codebook) mode is insecure. "
                    "It produces the same ciphertext for identical plaintext blocks, "
                    "revealing patterns in the encrypted data."
                ),
                "file": file_path,
                "line": line_num,
                "code_snippet": match.group(),
                "recommendation": "Use CBC or GCM mode instead of ECB"
            })
        
        return findings
    
    def _check_insecure_random(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """
        Insecure Random kontrolü
        
        java.util.Random güvenli değil!
        → Tahmin edilebilir
        
        Güvenli: java.security.SecureRandom
        """
        findings = []
        
        # Pattern: new Random()
        pattern = r'new\s+Random\s*\('
        
        for match in re.finditer(pattern, code):
            # SecureRandom değil mi?
            if 'SecureRandom' not in code[max(0, match.start()-50):match.end()+50]:
                line_num = code[:match.start()].count('\n') + 1
                
                findings.append({
                    "category": "M5: Insufficient Cryptography",
                    "severity": SEVERITY_MEDIUM,
                    "title": "Insecure Random Number Generator",
                    "description": (
                        "java.util.Random is not cryptographically secure. "
                        "Its output is predictable."
                    ),
                    "file": file_path,
                    "line": line_num,
                    "code_snippet": match.group(),
                    "recommendation": "Use java.security.SecureRandom for security-sensitive operations"
                })
        
        return findings
    
    def _check_hardcoded_keys(self, code: str, file_path: str) -> List[Dict[str, Any]]:
        """
        Hardcoded encryption keys kontrolü
        
        Örnek:
            byte[] key = {0x01, 0x02, 0x03, ...}  ← Hardcoded!
            String key = "mySecretKey123"         ← Hardcoded!
        """
        findings = []
        
        # Pattern: byte[] key = {...}
        pattern = r'byte\[\]\s+\w*[Kk]ey\w*\s*=\s*\{[^}]+\}'
        
        for match in re.finditer(pattern, code):
            line_num = code[:match.start()].count('\n') + 1
            
            findings.append({
                "category": "M5: Insufficient Cryptography",
                "severity": SEVERITY_CRITICAL,
                "title": "Hardcoded Encryption Key",
                "description": (
                    "Encryption key is hardcoded in the source code. "
                    "Anyone with access to the APK can extract it."
                ),
                "file": file_path,
                "line": line_num,
                "code_snippet": match.group()[:100],  # İlk 100 karakter
                "recommendation": (
                    "Never hardcode encryption keys. "
                    "Use Android Keystore or derive keys from user input."
                )
            })
        
        return findings
    
    def __repr__(self) -> str:
        return "CryptoAnalyzer()"
