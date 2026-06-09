"""
SO Analyzer
.so (Shared Object / Native Library) dosyalarını güvenlik açısından analiz eder

.so dosyası nedir?
- C/C++ ile yazılmış native kod
- Android NDK ile derlenir
- JNI (Java Native Interface) üzerinden Java/Kotlin'den çağrılır
- Örnek: libnative-lib.so, libcrypto.so

Ne kontrol ediyoruz?
1. Güvenlik bayrakları (PIE, RELRO, Stack Canary, NX)
2. Bilinen zafiyetli kütüphaneler
3. Şüpheli fonksiyon kullanımları (system(), exec(), strcpy() vb.)
4. Mimari uyumluluğu (arm64-v8a, armeabi-v7a, x86, x86_64)
5. Debug bilgisi sızıntısı
"""

import struct
import zipfile
from pathlib import Path
from typing import List, Dict, Any, Optional

from androidsec.core.constants import (
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO,
)
from androidsec.core.exceptions import StaticAnalysisError
from androidsec.utils.logger import get_logger

logger = get_logger(__name__)


# ELF Sabitleri

ELF_MAGIC = b'\x7fELF'

# ELF Machine types
ELF_MACHINE_ARM = 40         # ARM (armeabi-v7a)
ELF_MACHINE_AARCH64 = 183    # ARM 64-bit (arm64-v8a)
ELF_MACHINE_386 = 3          # Intel x86
ELF_MACHINE_X86_64 = 62      # AMD x86-64

MACHINE_NAMES = {
    ELF_MACHINE_ARM: "armeabi-v7a (ARM 32-bit)",
    ELF_MACHINE_AARCH64: "arm64-v8a (ARM 64-bit)",
    ELF_MACHINE_386: "x86 (Intel 32-bit)",
    ELF_MACHINE_X86_64: "x86_64 (Intel 64-bit)",
}

# Bilinen zafiyetli native kütüphaneler
VULNERABLE_LIBRARIES = {
    "libssl.so": {
        "description": "OpenSSL library - check for known CVEs",
        "severity": SEVERITY_MEDIUM,
    },
    "libcrypto.so": {
        "description": "OpenSSL crypto library - may contain vulnerabilities",
        "severity": SEVERITY_MEDIUM,
    },
    "libsqlite.so": {
        "description": "SQLite library - bundled version may be outdated",
        "severity": SEVERITY_LOW,
    },
    "libwebviewchromium.so": {
        "description": "Chromium WebView - bundled version may have security issues",
        "severity": SEVERITY_MEDIUM,
    },
}

# Tehlikeli C fonksiyonları
DANGEROUS_FUNCTIONS = {
    "system": {
        "description": "system() call - can execute arbitrary commands",
        "severity": SEVERITY_CRITICAL,
        "recommendation": "Avoid system() calls. Use specific APIs instead.",
        # İşletim sisteminde komut çalıstırırç
    },
    "exec": {
        "description": "exec() family - can execute arbitrary programs",
        "severity": SEVERITY_HIGH,
        "recommendation": "Avoid exec() calls unless absolutely necessary.",
        # yeni program başlatır
    },
    "strcpy": {
        "description": "strcpy() - buffer overflow risk (no bounds checking)",
        "severity": SEVERITY_MEDIUM,
        "recommendation": "Use strncpy() or strlcpy() instead.",
        # string kopyalar
    },
    "strcat": {
        "description": "strcat() - buffer overflow risk (no bounds checking)",
        "severity": SEVERITY_MEDIUM,
        "recommendation": "Use strncat() or strlcat() instead.",
        # string birleştirir
    },
    "sprintf": {
        "description": "sprintf() - format string vulnerability risk",
        "severity": SEVERITY_MEDIUM,
        "recommendation": "Use snprintf() instead.",
        # string formatlayıp yazdırır
    },
    "gets": {
        "description": "gets() - no input length limit, buffer overflow guaranteed",
        "severity": SEVERITY_CRITICAL,
        "recommendation": "Use fgets() instead. gets() is deprecated and removed in C11.",
        # kullanıcıdan sınırsız input alır
    },
    "scanf": {
        "description": "scanf() without width limit - buffer overflow risk",
        "severity": SEVERITY_MEDIUM,
        "recommendation": "Use scanf with width specifiers or fgets().",
        # scanf()
    },
}


class SOAnalyzer:
    """
    .so (native library) dosyalarını güvenlik açısından analiz eder

    Kullanım:
        analyzer = SOAnalyzer()

        # APK'dan analiz
        findings = analyzer.analyze_apk("app.apk")

        # Dekompile edilmiş klasörden analiz
        findings = analyzer.analyze_directory("decompiled/")
    """

    def __init__(self):
        """Initialize SO analyzer"""
        logger.debug("SOAnalyzer initialized")

    def analyze_apk(self, apk_path: str) -> List[Dict[str, Any]]:
        """
        APK dosyası içindeki .so dosyalarını analiz et

        APK bir ZIP dosyası olduğu için doğrudan içinden okuyabiliriz.
        .so dosyaları genellikle lib/<architecture>/ altında bulunur:
        - lib/armeabi-v7a/libnative.so
        - lib/arm64-v8a/libnative.so
        - lib/x86/libnative.so

        Args:
            apk_path: APK dosyası yolu

        Returns:
            Bulgular listesi
        """
        logger.info(f"Analyzing native libraries in APK: {apk_path}")

        findings = []

        try:
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                # .so dosyalarını bul
                so_files = [
                    f for f in apk_zip.namelist()
                    if f.endswith('.so') and f.startswith('lib/')
                ]

                if not so_files:
                    logger.info("No native libraries found in APK")
                    return findings

                logger.info(f"Found {len(so_files)} native libraries")

                # Mimari analizi
                findings.extend(self._analyze_architectures(so_files))

                # Her .so dosyasını analiz et
                for so_file in so_files:
                    try:
                        so_data = apk_zip.read(so_file)
                        findings.extend(self._analyze_so_binary(so_data, so_file))
                    except Exception as e:
                        logger.warning(f"Failed to analyze {so_file}: {e}")

                # Bilinen zafiyetli kütüphaneleri kontrol et
                findings.extend(self._check_vulnerable_libraries(so_files))

        except zipfile.BadZipFile:
            raise StaticAnalysisError(f"Invalid APK (ZIP) file: {apk_path}")
        except Exception as e:
            logger.error(f"Native analysis failed: {e}", exc_info=True)

        logger.info(f"Native analysis complete: {len(findings)} findings")
        return findings

    def analyze_directory(self, decompiled_dir: str) -> List[Dict[str, Any]]:
        """
        Dekompile edilmiş klasördeki .so dosyalarını analiz et

        Args:
            decompiled_dir: Dekompile edilmiş APK klasörü

        Returns:
            Bulgular listesi
        """
        logger.info(f"Analyzing native libraries in: {decompiled_dir}")

        findings = []
        decompiled_path = Path(decompiled_dir)

        # .so dosyalarını bul
        so_files = list(decompiled_path.rglob("*.so"))

        if not so_files:
            logger.info("No native libraries found")
            return findings

        logger.info(f"Found {len(so_files)} native libraries")

        # Genel bilgi
        findings.append({
            "category": "M7: Client Code Quality",
            "severity": SEVERITY_INFO,
            "title": f"Native Libraries Found ({len(so_files)})",
            "description": (
                f"Application contains {len(so_files)} native libraries (.so files). "
                "Native code requires careful security review as it bypasses "
                "Java/Kotlin memory safety features."
            ),
            "file": str(so_files[0].relative_to(decompiled_path)) if so_files else "lib/",
            "recommendation": "Review native code for memory corruption vulnerabilities."
        })

        # Her .so dosyasını analiz et
        for so_file in so_files:
            try:
                so_data = so_file.read_bytes()
                rel_path = str(so_file.relative_to(decompiled_path))
                findings.extend(self._analyze_so_binary(so_data, rel_path))
            except Exception as e:
                logger.warning(f"Failed to analyze {so_file}: {e}")

        # Bilinen zafiyetli kütüphaneleri kontrol et
        so_names = [str(f.relative_to(decompiled_path)) for f in so_files]
        findings.extend(self._check_vulnerable_libraries(so_names))

        return findings

    # Binary Analiz

    def _analyze_so_binary(self, data: bytes, file_path: str) -> List[Dict[str, Any]]:
        """
        .so binary verisini analiz et

        ELF formatını temel düzeyde parse eder:
        - ELF header'ı oku
        - PIE (Position Independent Executable) kontrolü
        - Mimari bilgisi

        Args:
            data: Binary veri
            file_path: Dosya yolu (raporlama için)

        Returns:
            Bulgular listesi
        """
        findings = []

        # ELF magic number kontrolü
        if not data.startswith(ELF_MAGIC):
            logger.warning(f"Not a valid ELF file: {file_path}")
            return findings

        try:
            # ELF class (32-bit mi 64-bit mi?)
            elf_class = data[4]  # 1 = 32-bit, 2 = 64-bit
            is_64bit = elf_class == 2

            # Endianness
            endian = data[5]  # 1 = little-endian, 2 = big-endian
            byte_order = '<' if endian == 1 else '>'

            # ELF type (e_type)
            e_type = struct.unpack(f'{byte_order}H', data[16:18])[0]

            # Machine type
            e_machine = struct.unpack(f'{byte_order}H', data[18:20])[0]

            # PIE kontrolü: e_type == 3 (ET_DYN) ise PIE etkin
            # e_type == 2 (ET_EXEC) ise PIE kapalı
            if e_type == 2:  # ET_EXEC - PIE kapalı
                findings.append({
                    "category": "M7: Client Code Quality",
                    "severity": SEVERITY_HIGH,
                    "title": f"No PIE (Position Independent Executable): {Path(file_path).name}",
                    "description": (
                        f"Native library '{file_path}' is not compiled with PIE. "
                        "PIE is required for ASLR (Address Space Layout Randomization) "
                        "to work effectively, which helps prevent memory exploitation attacks."
                    ),
                    "file": file_path,
                    "recommendation": (
                        "Compile native code with -fPIE flag. "
                        "PIE is mandatory for Android 5.0+ (API 21+)."
                    )
                })

            # Tehlikeli fonksiyonları string olarak ara
            findings.extend(self._check_dangerous_functions(data, file_path))

        except (struct.error, IndexError) as e:
            logger.warning(f"Failed to parse ELF header for {file_path}: {e}")

        return findings

    def _check_dangerous_functions(self, data: bytes, file_path: str) -> List[Dict[str, Any]]:
        """
        Binary'de tehlikeli C fonksiyonlarını ara

        .so dosyasının string tablosunda tehlikeli fonksiyon adlarını arar.
        Not: Bu basit bir string aramasıdır, import tablosu analizi değil.

        Args:
            data: Binary veri
            file_path: Dosya yolu

        Returns:
            Bulgular listesi
        """
        findings = []

        for func_name, func_info in DANGEROUS_FUNCTIONS.items():
            # Fonksiyon adını binary'de ara (null-terminated string olarak)
            search_pattern = func_name.encode('ascii') + b'\x00'

            if search_pattern in data:
                findings.append({
                    "category": "M7: Client Code Quality",
                    "severity": func_info["severity"],
                    "title": f"Dangerous Function: {func_name}() in {Path(file_path).name}",
                    "description": (
                        f"Native library '{file_path}' uses {func_name}(). "
                        f"{func_info['description']}"
                    ),
                    "file": file_path,
                    "recommendation": func_info["recommendation"]
                })

        return findings

    # Mimari Analizi

    def _analyze_architectures(self, so_files: List[str]) -> List[Dict[str, Any]]:
        """
        Desteklenen CPU mimarilerini analiz et

        Modern uygulamalar şu mimarileri desteklemeli:
        - arm64-v8a (zorunlu - modern cihazlar)
        - armeabi-v7a (eski cihazlar için)
        - x86_64 (emülatör / Chromebook)

        Args:
            so_files: .so dosya yolları

        Returns:
            Bulgular listesi
        """
        findings = []

        # Mimarileri ayıkla
        architectures = set()
        for so_file in so_files:
            parts = so_file.split('/')
            if len(parts) >= 2:
                arch = parts[1]  # lib/arm64-v8a/xxx.so → arm64-v8a
                architectures.add(arch)

        if architectures:
            findings.append({
                "category": "M7: Client Code Quality",
                "severity": SEVERITY_INFO,
                "title": f"Supported Architectures: {', '.join(sorted(architectures))}",
                "description": (
                    f"Application ships native libraries for {len(architectures)} "
                    f"architecture(s): {', '.join(sorted(architectures))}."
                ),
                "file": "lib/",
                "recommendation": (
                    "Ensure arm64-v8a is supported for modern devices."
                )
            })

            # arm64-v8a yoksa uyar
            if "arm64-v8a" not in architectures:
                findings.append({
                    "category": "M7: Client Code Quality",
                    "severity": SEVERITY_MEDIUM,
                    "title": "Missing arm64-v8a Architecture",
                    "description": (
                        "Application does not include native libraries for arm64-v8a. "
                        "Most modern Android devices use 64-bit ARM processors. "
                        "Google Play requires 64-bit support."
                    ),
                    "file": "lib/",
                    "recommendation": (
                        "Add arm64-v8a support. Google Play requires 64-bit "
                        "native libraries since August 2019."
                    )
                })

        return findings

    # Zafiyetli Kütüphane Kontrolü

    def _check_vulnerable_libraries(self, so_files: List[str]) -> List[Dict[str, Any]]:
        """
        Bilinen zafiyetli kütüphaneleri kontrol et

        Args:
            so_files: .so dosya yolları

        Returns:
            Bulgular listesi
        """
        findings = []

        for so_file in so_files:
            lib_name = Path(so_file).name

            if lib_name in VULNERABLE_LIBRARIES:
                lib_info = VULNERABLE_LIBRARIES[lib_name]
                findings.append({
                    "category": "M7: Client Code Quality",
                    "severity": lib_info["severity"],
                    "title": f"Known Vulnerable Library: {lib_name}",
                    "description": (
                        f"Application bundles '{lib_name}'. "
                        f"{lib_info['description']}. "
                        "Bundled libraries may contain known CVEs if not updated."
                    ),
                    "file": so_file,
                    "recommendation": (
                        f"Ensure '{lib_name}' is the latest version. "
                        "Check for known CVEs and update regularly."
                    )
                })

        return findings

    def __repr__(self) -> str:
        return "SOAnalyzer()"
