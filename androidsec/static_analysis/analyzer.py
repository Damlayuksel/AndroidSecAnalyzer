"""
Statik Analiz Orkestratörü - Tüm statik analiz işlemlerini yönetir

Bu sınıf:
1. Manifest analizi yapar (izinler, componentler, güvenlik bayrakları)
2. Kod analizi yapar (zayıf kriptografi, hardcoded secrets, SQL injection)
3. Sertifika analizi yapar (imza doğrulama, geçerlilik)
4. Native kod analizi yapar (.so dosyaları, tehlikeli fonksiyonlar, stringler)
5. Tüm bulguları birleştirir ve istatistik üretir
"""

import zipfile
from pathlib import Path
from typing import List, Dict, Any, Optional

from androidsec.core.exceptions import StaticAnalysisError
from androidsec.utils.logger import get_logger

# Alt modüller
from androidsec.static_analysis.manifest.parser import ManifestParser
from androidsec.static_analysis.manifest.permissions import PermissionAnalyzer
from androidsec.static_analysis.manifest.components import ComponentAnalyzer
from androidsec.static_analysis.code.scanner import CodeScanner
from androidsec.static_analysis.certificate.extractor import CertificateExtractor
from androidsec.static_analysis.certificate.validator import CertificateValidator
from androidsec.static_analysis.native.so_analyzer import SOAnalyzer
from androidsec.static_analysis.native.strings_extractor import StringsExtractor

logger = get_logger(__name__)


class StaticAnalyzer:
    """
    
    Ana statik analiz orkestratörü

    Tüm alt modülleri (manifest, code, certificate, native) koordine eder
    ve birleşik bulgular listesi üretir.

    Kullanım:
        analyzer = StaticAnalyzer()

        # Sadece APK ile (dekompile olmadan)
        findings = analyzer.analyze(apk_path="app.apk")

        # Dekompile edilmiş klasörle birlikte (tam analiz)
        findings = analyzer.analyze(
            apk_path="app.apk",
            decompiled_dir="output/decompiled/app"
        )

        # İstatistikler
        stats = analyzer.get_statistics(findings)
        print(f"Toplam: {stats['total']}, Kritik: {stats['by_severity']['CRITICAL']}")
    """

    def __init__(self):
        """Initialize static analyzer with all sub-modules"""
        logger.info("StaticAnalyzer initialized")

        # Alt modüller - hepsi burada başlatılıyor
        self._manifest_parser = ManifestParser()
        self._permission_analyzer = PermissionAnalyzer()
        self._component_analyzer = ComponentAnalyzer()
        self._code_scanner = CodeScanner()
        self._cert_extractor = CertificateExtractor()
        self._cert_validator = CertificateValidator()
        self._so_analyzer = SOAnalyzer()
        self._strings_extractor = StringsExtractor()

    def analyze(
        self,
        apk_path: str,
        decompiled_dir: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
       
        APK üzerinde statik analiz yap

        Args:
            apk_path: APK dosyası yolu
            decompiled_dir: Dekompile edilmiş klasör yolu
                          (None ise sadece APK üzerinden analiz)

        Returns:
            List of findings (bulgular listesi)
            Her finding: {
                "category": "OWASP M2",
                "severity": "HIGH",
                "title": "Insecure Data Storage",
                "description": "...",
                "file": "MainActivity.java",
                "line": 42
            }

        Raises:
            StaticAnalysisError: Analiz başarısız olursa
        """
        logger.info(f"Starting static analysis: {apk_path}")

        findings = []

        try:
            # 1. Manifest Analizi
            logger.info("=" * 50)
            logger.info("PHASE 1: Manifest Analysis")
            logger.info("=" * 50)
            manifest_findings = self._analyze_manifest(apk_path, decompiled_dir)
            findings.extend(manifest_findings)
            logger.info(f"Manifest analysis: {len(manifest_findings)} findings")

            # 2. Kod Analizi (eğer decompiled_dir varsa)
            if decompiled_dir:
                logger.info("=" * 50)
                logger.info("PHASE 2: Code Analysis")
                logger.info("=" * 50)
                code_findings = self._analyze_code(decompiled_dir)
                findings.extend(code_findings)
                logger.info(f"Code analysis: {len(code_findings)} findings")

            # 3. Sertifika Analizi
            logger.info("=" * 50)
            logger.info("PHASE 3: Certificate Analysis")
            logger.info("=" * 50)
            cert_findings = self._analyze_certificate(apk_path)
            findings.extend(cert_findings)
            logger.info(f"Certificate analysis: {len(cert_findings)} findings")

            # 4. Native Kod Analizi
            logger.info("=" * 50)
            logger.info("PHASE 4: Native Code Analysis")
            logger.info("=" * 50)
            native_findings = self._analyze_native(apk_path, decompiled_dir)
            findings.extend(native_findings)
            logger.info(f"Native analysis: {len(native_findings)} findings")

            # Tekrar eden bulguları temizle (aynı title + file + line)
            findings = self._deduplicate(findings)

            logger.info("=" * 50)
            logger.info(f"Static analysis complete: {len(findings)} total findings")
            logger.info("=" * 50)
            return findings

        except StaticAnalysisError:
            raise
        except Exception as e:
            error_msg = f"Static analysis failed: {str(e)}"
            logger.error(error_msg, exc_info=True)
            raise StaticAnalysisError(error_msg) from e

    # Manifest Analizi

    def _analyze_manifest(
        self,
        apk_path: str,
        decompiled_dir: Optional[str]
    ) -> List[Dict[str, Any]]:
        """
        Analyze AndroidManifest.xml
        AndroidManifest.xml'i analiz et

        Adımlar:
        1. Manifest dosyasını bul (decompiled_dir veya APK içinde)
        2. ManifestParser ile parse et
        3. PermissionAnalyzer ile izinleri analiz et
        4. ComponentAnalyzer ile componentleri analiz et

        Returns:
            Manifest ile ilgili bulgular listesi
        """
        logger.info("Analyzing manifest...")

        findings = []

        # Manifest dosyasını bul
        manifest_path = self._find_manifest(apk_path, decompiled_dir)

        if not manifest_path:
            logger.warning("AndroidManifest.xml not found, skipping manifest analysis")
            findings.append({
                "category": "M1: Improper Platform Usage",
                "severity": "HIGH",
                "title": "AndroidManifest.xml Not Found",
                "description": (
                    "Could not locate AndroidManifest.xml. "
                    "This may indicate a corrupted APK or incomplete decompilation."
                ),
                "file": "AndroidManifest.xml",
                "recommendation": "Ensure the APK is valid and decompilation was successful."
            })
            return findings

        try:
            # 1. Manifest'i parse et
            manifest_data = self._manifest_parser.parse(manifest_path)

            # 2. İzin analizi
            permissions = manifest_data.get("permissions", [])
            permission_findings = self._permission_analyzer.analyze(permissions, manifest_data)
            findings.extend(permission_findings)
            logger.info(f"Permission analysis: {len(permission_findings)} findings")

            # 3. Component analizi
            component_findings = self._component_analyzer.analyze(manifest_data)
            findings.extend(component_findings)
            logger.info(f"Component analysis: {len(component_findings)} findings")

        except Exception as e:
            logger.error(f"Manifest analysis failed: {e}", exc_info=True)
            findings.append({
                "category": "M1: Improper Platform Usage",
                "severity": "MEDIUM",
                "title": "Manifest Analysis Error",
                "description": f"Failed to analyze AndroidManifest.xml: {str(e)}",
                "file": "AndroidManifest.xml",
                "recommendation": "Check the manifest file format."
            })

        return findings

    def _find_manifest(
        self,
        apk_path: str,
        decompiled_dir: Optional[str]
    ) -> Optional[str]:
        """
        AndroidManifest.xml dosyasını bul

        Arama sırası:
        1. Dekompile edilmiş klasörde (metin XML → parse edilebilir)
        2. APK içinde çıkarılabilir mi?

        Args:
            apk_path: APK dosyası yolu
            decompiled_dir: Dekompile edilmiş klasör yolu

        Returns:
            Manifest dosya yolu veya None
        """
        # 1. Dekompile edilmiş klasörde ara (JADX farklı alt dizinlere koyabilir)
        if decompiled_dir:
            candidates = [
                Path(decompiled_dir) / "AndroidManifest.xml",
                Path(decompiled_dir) / "app" / "src" / "main" / "AndroidManifest.xml",
                Path(decompiled_dir) / "src" / "main" / "AndroidManifest.xml",
            ]
            for candidate in candidates:
                if candidate.exists():
                    logger.debug(f"Found manifest in decompiled dir: {candidate}")
                    return str(candidate)
            # Bulunamazsa recursive ara
            found = list(Path(decompiled_dir).rglob("AndroidManifest.xml"))
            if found:
                logger.debug(f"Found manifest (recursive): {found[0]}")
                return str(found[0])

        # 2. APK içinde ara ve geçici dosyaya çıkar
        try:
            import tempfile
            with zipfile.ZipFile(apk_path, 'r') as apk_zip:
                if "AndroidManifest.xml" in apk_zip.namelist():
                    # Binary XML olabilir, APKTool ile dekompile gerekebilir
                    # Şu an sadece decompiled_dir'dan okunan metin XML'i destekliyoruz
                    logger.debug("Found binary AndroidManifest.xml in APK (not directly parseable)")
                    # Binary XML'i metin olarak okumaya çalış
                    try:
                        manifest_data = apk_zip.read("AndroidManifest.xml")
                        # XML header ile başlıyorsa metin XML'dir
                        if manifest_data.startswith(b'<?xml') or manifest_data.startswith(b'<manifest'):
                            # Geçici dosyaya yaz
                            tmp = tempfile.NamedTemporaryFile(
                                suffix='.xml', delete=False, mode='wb'
                            )
                            tmp.write(manifest_data)
                            tmp.close()
                            return tmp.name
                    except Exception:
                        pass
        except (zipfile.BadZipFile, Exception) as e:
            logger.warning(f"Failed to read APK: {e}")

        return None

    # Kod Analizi

    def _analyze_code(self, decompiled_dir: str) -> List[Dict[str, Any]]:
        """
         
        Kaynak kodu güvenlik açıkları için analiz et

        CodeScanner alt modülünü kullanır:
        - Kriptografi analizi (MD5, DES, ECB)
        - Hardcoded secrets (API keys, passwords)
        - SQL Injection
        - WebView güvenlik sorunları
        - Hassas veri loglama

    Args:
            decompiled_dir: Dekompile edilmiş klasör yolu

    Returns:
            Kod analizi bulguları
        """
        logger.info(f"Running code analysis on: {decompiled_dir}")

        try:
            findings = self._code_scanner.scan(decompiled_dir)
            return findings
        except Exception as e:
            logger.error(f"Code analysis failed: {e}", exc_info=True)
            return [{
                "category": "M7: Client Code Quality",
                "severity": "MEDIUM",
                "title": "Code Analysis Error",
                "description": f"Failed to analyze source code: {str(e)}",
                "file": decompiled_dir,
                "recommendation": "Ensure decompilation was successful."
            }]

    # Sertifika Analizi

    def _analyze_certificate(self, apk_path: str) -> List[Dict[str, Any]]:
        """
    
        APK sertifikası/imzasını analiz et

        Adımlar:
        1. CertificateExtractor ile sertifika bilgilerini çıkar
        2. CertificateValidator ile güvenlik kontrolleri yap

        Args:
            apk_path: APK dosyası yolu

        Returns:
            Sertifika bulguları
        """
        logger.info(f"Analyzing certificate: {apk_path}")

        findings = []

        try:
            # 1. Sertifika bilgilerini çıkar
            cert_info = self._cert_extractor.extract(apk_path)
            logger.info(f"Certificate subject: {cert_info.get('subject', 'Unknown')}")
            logger.info(f"Certificate algorithm: {cert_info.get('signature_algorithm', 'Unknown')}")
            logger.info(f"SHA256 fingerprint: {cert_info.get('fingerprint_sha256', 'Unknown')}")

            # 2. Sertifika bilgilerini bulgu olarak ekle (info seviyesinde)
            findings.append({
                "category": "M8: Code Tampering",
                "severity": "INFO",
                "title": "Certificate Information",
                "description": (
                    f"Subject: {cert_info.get('subject', 'Unknown')}\n"
                    f"Issuer: {cert_info.get('issuer', 'Unknown')}\n"
                    f"Valid: {cert_info.get('valid_from', '?')} to {cert_info.get('valid_to', '?')}\n"
                    f"Algorithm: {cert_info.get('signature_algorithm', 'Unknown')}\n"
                    f"SHA256: {cert_info.get('fingerprint_sha256', 'Unknown')}"
                ),
                "file": cert_info.get("cert_file", "META-INF/CERT.RSA"),
                "recommendation": "No action required - informational only."
            })

            # 3. Sertifika doğrulama (güvenlik kontrolleri)
            validation_findings = self._cert_validator.validate(cert_info)
            findings.extend(validation_findings)

        except Exception as e:
            logger.error(f"Certificate analysis failed: {e}", exc_info=True)
            findings.append({
                "category": "M8: Code Tampering",
                "severity": "MEDIUM",
                "title": "Certificate Analysis Error",
                "description": f"Failed to analyze APK certificate: {str(e)}",
                "file": "META-INF/",
                "recommendation": "Ensure the APK file is valid."
            })

        return findings

    # Native Kod Analizi

    def _analyze_native(
        self,
        apk_path: str,
        decompiled_dir: Optional[str]
    ) -> List[Dict[str, Any]]:
        """
    
        Native kütüphaneleri (.so dosyaları) analiz et

        İki aşamalı analiz:
        1. SOAnalyzer: ELF güvenlik bayrakları, tehlikeli fonksiyonlar, mimari
        2. StringsExtractor: URL, IP, API key, şüpheli komut arama

        Args:
            apk_path: APK dosyası yolu
            decompiled_dir: Dekompile edilmiş klasör yolu

        Returns:
            Native analiz bulguları
        """
        logger.info("Running native code analysis...")

        findings = []

        try:
            # Kaynak seçimi: decompiled_dir varsa oradan, yoksa APK'dan
            if decompiled_dir:
                # 1. SO analizi (dekompile klasöründen)
                so_findings = self._so_analyzer.analyze_directory(decompiled_dir)
                findings.extend(so_findings)

                # 2. String analizi (dekompile klasöründen)
                string_findings = self._strings_extractor.analyze_directory(decompiled_dir)
                findings.extend(string_findings)
            else:
                # 1. SO analizi (APK'dan doğrudan)
                so_findings = self._so_analyzer.analyze_apk(apk_path)
                findings.extend(so_findings)

                # 2. String analizi (APK'dan doğrudan)
                string_findings = self._strings_extractor.analyze_apk(apk_path)
                findings.extend(string_findings)

        except Exception as e:
            logger.error(f"Native analysis failed: {e}", exc_info=True)
            findings.append({
                "category": "M7: Client Code Quality",
                "severity": "LOW",
                "title": "Native Analysis Error",
                "description": f"Failed to analyze native libraries: {str(e)}",
                "file": "lib/",
                "recommendation": "Ensure the APK or decompiled directory is accessible."
            })

        return findings

    # İstatistikler

    def _deduplicate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Aynı başlığa sahip bulguları tekil hale getirir. Sondaki (N) sayıları normalize edilir."""
        import re
        seen = set()
        unique = []
        for f in findings:
            normalized = re.sub(r'\s*\(\d+\)\s*$', '', f.get("title", "")).strip()
            if normalized not in seen:
                seen.add(normalized)
                unique.append(f)
        removed = len(findings) - len(unique)
        if removed:
            logger.info(f"Deduplicated {removed} duplicate findings")
        return unique

    def get_statistics(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Get statistics from findings
        Bulgulardan istatistik çıkar

        Args:
            findings: Bulgular listesi

        Returns:
            İstatistikler: {
                "total": 10,
                "by_severity": {"CRITICAL": 2, "HIGH": 5, ...},
                "by_category": {"M1: Improper Platform Usage": 3, ...},
                "by_phase": {"manifest": 4, "code": 3, "certificate": 2, "native": 1}
            }
        """
        stats = {
            "total": len(findings),
            "by_severity": {},
            "by_category": {},
        }

        for finding in findings:
            # Severity istatistikleri
            severity = finding.get("severity", "UNKNOWN")
            stats["by_severity"][severity] = stats["by_severity"].get(severity, 0) + 1

            # Category istatistikleri
            category = finding.get("category", "UNKNOWN")
            stats["by_category"][category] = stats["by_category"].get(category, 0) + 1

        return stats

    def __repr__(self) -> str:
        return "StaticAnalyzer()"
