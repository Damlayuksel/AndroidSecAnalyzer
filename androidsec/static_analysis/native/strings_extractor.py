"""
Strings Extractor
Binary (.so) dosyalardan okunabilir stringleri çıkarır ve güvenlik açısından analiz eder

Neden binary'den string çıkarıyoruz?
- Hardcoded URL'ler (HTTP → güvensiz, C&C sunucu adresleri)
- IP adresleri (arka kapı bağlantıları)
- Dosya yolları (hassas veri erişimi)
- API anahtarları, tokenlar
- SQL sorguları
- Şifreleme anahtarları

Not: Bu, Linux 'strings' komutu gibi çalışır ama Python ile.
"""

import re
import zipfile
from pathlib import Path
from typing import List, Dict, Any, Set

from androidsec.core.constants import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO,
)
from androidsec.utils.logger import get_logger

logger = get_logger(__name__)


# Şüpheli String Pattern'leri

# URL pattern'leri
URL_PATTERN = re.compile(
    rb'https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]{5,200}'
)

# IP adresi pattern'i
IP_PATTERN = re.compile(
    rb'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b'
)

# API Key pattern'leri
API_KEY_PATTERNS = {
    "AWS Access Key": re.compile(rb'AKIA[0-9A-Z]{16}'),
    "Google API Key": re.compile(rb'AIza[0-9A-Za-z\-_]{35}'),
    "Generic API Key": re.compile(rb'api[_-]?key["\s:=]+["\']?([a-zA-Z0-9_\-]{20,})', re.IGNORECASE),
    "Generic Secret": re.compile(rb'secret["\s:=]+["\']?([a-zA-Z0-9_\-]{20,})', re.IGNORECASE),
    "Generic Token": re.compile(rb'token["\s:=]+["\']?([a-zA-Z0-9_\-]{20,})', re.IGNORECASE),
}

# Dosya yolu pattern'leri (Android'e özel)
FILE_PATH_PATTERNS = {
    "SD Card Access": re.compile(rb'/sdcard/[^\x00\s]{3,100}'),
    "Data Directory": re.compile(rb'/data/data/[^\x00\s]{3,100}'),
    "System Path": re.compile(rb'/system/[^\x00\s]{3,100}'),
    "Proc Access": re.compile(rb'/proc/[^\x00\s]{3,100}'),
    "Dev Access": re.compile(rb'/dev/[^\x00\s]{3,100}'),
}

# Şüpheli komutlar
SUSPICIOUS_COMMANDS = [
    b'su', b'/system/bin/su', b'/system/xbin/su',
    b'chmod', b'chown', b'mount',
    b'pm install', b'pm uninstall',
    b'am start', b'am broadcast',
    b'getprop', b'setprop',
    b'dalvikvm', b'app_process',
    b'runtime.exec',
]


class StringsExtractor:
    """
    Binary dosyalardan okunabilir stringleri çıkarır ve güvenlik analizi yapar

    Kullanım:
        extractor = StringsExtractor()

        # APK'dan analiz
        findings = extractor.analyze_apk("app.apk")

        # Tek bir .so dosyasından
        findings = extractor.analyze_file("lib/arm64-v8a/libnative.so")
    """

    def __init__(self, min_length: int = 6):
        """
        Initialize strings extractor

        Args:
            min_length: Minimum string uzunluğu (daha kısa olanlar göz ardı edilir)
        """
        self.min_length = min_length
        logger.debug(f"StringsExtractor initialized (min_length={min_length})")

    def analyze_apk(self, apk_path: str) -> List[Dict[str, Any]]:
        """
        APK içindeki .so dosyalarından string çıkar ve analiz et

        Args:
            apk_path: APK dosyası yolu

        Returns:
            Bulgular listesi
        """
        logger.info(f"Extracting strings from native libraries in: {apk_path}")

        findings = []

        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                so_files = [
                    f for f in apk_zip.namelist()
                    if f.endswith('.so') and f.startswith('lib/')
                ]

                for so_file in so_files:
                    try:
                        data = apk_zip.read(so_file)
                        findings.extend(self._analyze_binary_strings(data, so_file))
                    except Exception as e:
                        logger.warning(f"Failed to extract strings from {so_file}: {e}")

        except zipfile.BadZipFile:
            logger.error(f"Invalid APK file: {apk_path}")
        except Exception as e:
            logger.error(f"String extraction failed: {e}")

        return findings

    def analyze_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Tek bir binary dosyadan string çıkar ve analiz et

        Args:
            file_path: Binary dosya yolu

        Returns:
            Bulgular listesi
        """
        logger.info(f"Extracting strings from: {file_path}")

        try:
            data = Path(file_path).read_bytes()
            return self._analyze_binary_strings(data, file_path)
        except Exception as e:
            logger.error(f"Failed to analyze {file_path}: {e}")
            return []

    def analyze_directory(self, decompiled_dir: str) -> List[Dict[str, Any]]:
        """
        Dekompile edilmiş klasördeki .so dosyalarından string çıkar

        Args:
            decompiled_dir: Dekompile edilmiş APK klasörü

        Returns:
            Bulgular listesi
        """
        logger.info(f"Extracting strings from native libraries in: {decompiled_dir}")

        findings = []
        decompiled_path = Path(decompiled_dir)

        so_files = list(decompiled_path.rglob("*.so"))

        for so_file in so_files:
            try:
                data = so_file.read_bytes()
                rel_path = str(so_file.relative_to(decompiled_path))
                findings.extend(self._analyze_binary_strings(data, rel_path))
            except Exception as e:
                logger.warning(f"Failed to extract strings from {so_file}: {e}")

        return findings


    def extract_strings(self, data: bytes) -> List[str]:
        """
        Binary veriden okunabilir ASCII stringleri çıkar

        Linux 'strings' komutu gibi çalışır:
        - ASCII yazdırılabilir karakterlerin (32-126) ardışık dizileri
        - Minimum uzunluk kontrolü

        Args:
            data: Binary veri

        Returns:
            String listesi
        """
        strings = []
        current_string = bytearray()

        for byte in data:
            # Yazdırılabilir ASCII karakter mi?
            if 32 <= byte <= 126:
                current_string.append(byte)
            else:
                # Karakter değilse, biriken stringi kaydet
                if len(current_string) >= self.min_length:
                    try:
                        strings.append(current_string.decode('ascii'))
                    except (UnicodeDecodeError, ValueError):
                        pass
                current_string = bytearray()

        # Son stringi de kontrol et
        if len(current_string) >= self.min_length:
            try:
                strings.append(current_string.decode('ascii'))
            except (UnicodeDecodeError, ValueError):
                pass

        return strings


    def _analyze_binary_strings(self, data: bytes, file_path: str) -> List[Dict[str, Any]]:
        """
        Binary veriden çıkarılan stringleri güvenlik açısından analiz et

        Args:
            data: Binary veri
            file_path: Dosya yolu

        Returns:
            Bulgular listesi
        """
        findings = []

        # 1. URL'leri kontrol et
        findings.extend(self._check_urls(data, file_path))

        # 2. IP adreslerini kontrol et
        findings.extend(self._check_ip_addresses(data, file_path))

        # 3. API anahtarlarını kontrol et
        findings.extend(self._check_api_keys(data, file_path))

        # 4. Dosya yollarını kontrol et
        findings.extend(self._check_file_paths(data, file_path))

        # 5. Şüpheli komutları kontrol et
        findings.extend(self._check_suspicious_commands(data, file_path))

        return findings

    def _check_urls(self, data: bytes, file_path: str) -> List[Dict[str, Any]]:
        """
        Binary'deki URL'leri kontrol et

        HTTP URL'ler → Güvensiz iletişim
        Şüpheli domain'ler → C&C sunucu olabilir
        """
        findings = []

        urls = URL_PATTERN.findall(data)
        if not urls:
            return findings

        # URL'leri decode et ve unique yap
        decoded_urls: Set[str] = set()
        for url in urls:
            try:
                decoded_urls.add(url.decode('ascii', errors='ignore'))
            except (UnicodeDecodeError, ValueError):
                pass

        # HTTP URL'leri (şifrelenmemiş)
        http_urls = [u for u in decoded_urls if u.startswith('http://')]
        https_urls = [u for u in decoded_urls if u.startswith('https://')]

        if http_urls:
            findings.append({
                "category": "M3: Insecure Communication",
                "severity": SEVERITY_HIGH,
                "title": f"HTTP URLs in Native Code ({len(http_urls)})",
                "description": (
                    f"Found {len(http_urls)} unencrypted HTTP URL(s) in native library '{file_path}'. "
                    "HTTP traffic can be intercepted (MITM attack).\n"
                    f"URLs: {', '.join(http_urls[:5])}"
                    + (f" (and {len(http_urls) - 5} more)" if len(http_urls) > 5 else "")
                ),
                "file": file_path,
                "recommendation": "Use HTTPS instead of HTTP for all network communication."
            })

        # Toplam URL raporu
        if decoded_urls:
            findings.append({
                "category": "M9: Reverse Engineering",
                "severity": SEVERITY_INFO,
                "title": f"URLs in Native Code ({len(decoded_urls)})",
                "description": (
                    f"Found {len(decoded_urls)} URL(s) in native library '{file_path}'. "
                    f"({len(http_urls)} HTTP, {len(https_urls)} HTTPS). "
                    "These endpoints may reveal server infrastructure."
                ),
                "file": file_path,
                "details": list(decoded_urls)[:20],
                "recommendation": "Review embedded URLs for sensitive endpoints."
            })

        return findings

    def _check_ip_addresses(self, data: bytes, file_path: str) -> List[Dict[str, Any]]:
        """
        Binary'deki IP adreslerini kontrol et

        Hardcoded IP → Şüpheli bağlantı
        """
        findings = []

        ips = IP_PATTERN.findall(data)
        if not ips:
            return findings

        # IP'leri decode et ve unique yap
        unique_ips: Set[str] = set()
        for ip in ips:
            try:
                decoded_ip = ip.decode('ascii')
                # Geçerli IP olup olmadığını kontrol et
                parts = decoded_ip.split('.')
                if all(0 <= int(p) <= 255 for p in parts):
                    # Yaygın false positive'leri filtrele
                    if decoded_ip not in ('0.0.0.0', '127.0.0.1', '255.255.255.255',
                                          '255.255.255.0', '10.0.0.0', '192.168.0.0'):
                        unique_ips.add(decoded_ip)
            except (UnicodeDecodeError, ValueError):
                pass

        if unique_ips:
            # Özel IP adresleri vs Genel IP adresleri ayır
            private_ips = [
                ip for ip in unique_ips
                if ip.startswith('10.') or ip.startswith('192.168.')
                or ip.startswith('172.')
            ]
            public_ips = [ip for ip in unique_ips if ip not in private_ips]

            if public_ips:
                findings.append({
                    "category": "M3: Insecure Communication",
                    "severity": SEVERITY_MEDIUM,
                    "title": f"Hardcoded Public IP Addresses ({len(public_ips)})",
                    "description": (
                        f"Found {len(public_ips)} public IP address(es) in native code: "
                        f"{', '.join(public_ips[:5])}"
                        + (f" (and {len(public_ips) - 5} more)" if len(public_ips) > 5 else "")
                        + ". Hardcoded IPs may indicate C&C server communication."
                    ),
                    "file": file_path,
                    "recommendation": (
                        "Use domain names instead of hardcoded IPs. "
                        "Review the purpose of these IP addresses."
                    )
                })

        return findings

    def _check_api_keys(self, data: bytes, file_path: str) -> List[Dict[str, Any]]:
        """
        Binary'deki API anahtarlarını kontrol et
        """
        findings = []

        for key_type, pattern in API_KEY_PATTERNS.items():
            matches = pattern.findall(data)
            if matches:
                # İlk eşleşmeyi göster (gizlenmiş)
                sample = matches[0]
                if isinstance(sample, bytes):
                    try:
                        sample_str = sample.decode('ascii', errors='ignore')
                    except (UnicodeDecodeError, ValueError):
                        sample_str = str(sample)
                else:
                    sample_str = str(sample)

                masked = sample_str[:8] + "***" if len(sample_str) > 8 else "***"

                findings.append({
                    "category": "M9: Reverse Engineering",
                    "severity": SEVERITY_CRITICAL,
                    "title": f"Hardcoded {key_type} in Native Code",
                    "description": (
                        f"Found potential {key_type} in native library '{file_path}'. "
                        f"Value: {masked}. "
                        "Secrets in native code can be extracted with 'strings' command."
                    ),
                    "file": file_path,
                    "recommendation": (
                        "Never embed API keys in native code. "
                        "Use server-side key management or Android Keystore."
                    )
                })

        return findings

    def _check_file_paths(self, data: bytes, file_path: str) -> List[Dict[str, Any]]:
        """
        Binary'deki dosya yollarını kontrol et

        /data/data/ → Uygulama veri dizini
        /sdcard/ → SD kart erişimi
        /proc/ → Sistem bilgisi erişimi (anti-debug, anti-emulator)
        """
        findings = []

        for path_type, pattern in FILE_PATH_PATTERNS.items():
            matches = pattern.findall(data)
            if matches:
                decoded_paths = []
                for m in matches[:5]:
                    try:
                        decoded_paths.append(m.decode('ascii', errors='ignore'))
                    except (UnicodeDecodeError, ValueError):
                        pass

                if decoded_paths:
                    severity = SEVERITY_MEDIUM if "proc" in path_type.lower() else SEVERITY_LOW

                    findings.append({
                        "category": "M2: Insecure Data Storage",
                        "severity": severity,
                        "title": f"{path_type} in Native Code",
                        "description": (
                            f"Native library accesses {path_type.lower()} paths: "
                            f"{', '.join(decoded_paths[:3])}"
                            + (f" (and {len(decoded_paths) - 3} more)" if len(decoded_paths) > 3 else "")
                        ),
                        "file": file_path,
                        "recommendation": (
                            f"Review {path_type.lower()} access for data security."
                        )
                    })

        return findings

    def _check_suspicious_commands(self, data: bytes, file_path: str) -> List[Dict[str, Any]]:
        """
        Binary'deki şüpheli komutları kontrol et

        su, chmod, exec vb. → Root erişimi, komut yürütme
        """
        findings = []
        found_commands = []

        for cmd in SUSPICIOUS_COMMANDS:
            # Null-terminated string olarak ara
            if cmd + b'\x00' in data or b'\x00' + cmd in data:
                try:
                    found_commands.append(cmd.decode('ascii'))
                except (UnicodeDecodeError, ValueError):
                    pass

        if found_commands:
            # su komutu özellikle önemli
            if any('su' == cmd or '/su' in cmd for cmd in found_commands):
                findings.append({
                    "category": "M8: Code Tampering",
                    "severity": SEVERITY_HIGH,
                    "title": f"Root Access Attempt in Native Code",
                    "description": (
                        f"Native library '{file_path}' contains references to 'su' command. "
                        "This may indicate root detection or root exploitation."
                    ),
                    "file": file_path,
                    "recommendation": (
                        "If root detection is intended, document it clearly. "
                        "Root access should not be required for normal operation."
                    )
                })

            # Diğer şüpheli komutlar
            other_cmds = [c for c in found_commands if 'su' not in c]
            if other_cmds:
                findings.append({
                    "category": "M10: Extraneous Functionality",
                    "severity": SEVERITY_MEDIUM,
                    "title": f"Suspicious Commands in Native Code ({len(other_cmds)})",
                    "description": (
                        f"Found system commands in native code: {', '.join(other_cmds[:5])}. "
                        "These commands suggest the app interacts with the OS at a low level."
                    ),
                    "file": file_path,
                    "recommendation": "Review command usage for security implications."
                })

        return findings

    def __repr__(self) -> str:
        return f"StringsExtractor(min_length={self.min_length})"
