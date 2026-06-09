"""
Ana Analiz Motoru - Tüm analiz sürecini yönetir

Statik analiz, dinamik analiz, korelasyon ve raporlama
modüllerini orkestra eder.
"""

import time
from pathlib import Path
from typing import Dict, Any, Optional, List

from androidsec.core.config_manager import ConfigManager
from androidsec.core.constants import (
    ANALYSIS_STATIC,
    ANALYSIS_DYNAMIC,
    ANALYSIS_FULL,
)
from androidsec.core.exceptions import (
    AndroidSecError,
    InvalidAPKError,
    DynamicAnalysisError,
)
from androidsec.utils.logger import get_logger

logger = get_logger(__name__)


class AnalysisResult:
    """
    
    Analiz sonuçlarını tutan sınıftır
    """
    
    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self.apk_info: Dict[str, Any] = {}
        self.static_findings: List[Dict[str, Any]] = []
        self.dynamic_findings: List[Dict[str, Any]] = []
        self.correlated_findings: List[Dict[str, Any]] = []
        self.all_findings: List[Dict[str, Any]] = []
        self.by_owasp: Dict[str, List] = {}
        self.risk_score: float = 0.0
        self.risk_info: Dict[str, Any] = {}
        self.statistics: Dict[str, Any] = {}
        self.analysis_time: float = 0.0
        self.errors: List[str] = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary"""
        return {
            "apk_path": self.apk_path,
            "apk_info": self.apk_info,
            "static_findings": self.static_findings,
            "dynamic_findings": self.dynamic_findings,
            "correlated_findings": self.correlated_findings,
            "all_findings": self.all_findings,
            "by_owasp": self.by_owasp,
            "risk_score": self.risk_score,
            "risk_info": self.risk_info,
            "statistics": self.statistics,
            "analysis_time": self.analysis_time,
            "errors": self.errors,
        }
    
    def to_report_data(self) -> Dict[str, Any]:
        """ReportGenerator'a uygun format döndürür."""
        return {
            "apk_info": self.apk_info,
            "risk": self.risk_info,
            "statistics": self.statistics,
            "findings": self.all_findings,
            "by_owasp": self.by_owasp,
            "analysis_time": self.analysis_time,
        }
    
    def __repr__(self) -> str:
        return (
            f"AnalysisResult(apk={Path(self.apk_path).name}, "
            f"static={len(self.static_findings)}, "
            f"dynamic={len(self.dynamic_findings)}, "
            f"correlated={len(self.correlated_findings)}, "
            f"risk={self.risk_score:.2f})"
        )


class AndroidSecAnalyzer:
    """
    
    Ana analiz sınıfı - tüm analiz sürecini orkestra eder
    
    Kullanım:
        analyzer = AndroidSecAnalyzer()
        result = analyzer.analyze("app.apk", analysis_type="full")
        print(f"Risk Score: {result.risk_score}")
        analyzer.generate_report(result, format="html")
    """
    
    def __init__(self, config: Optional[ConfigManager] = None):
        """
        Initialize the analyzer
        
        Args:
            config: ConfigManager instance (None ise default config kullanılır)
        """
        self.config = config or ConfigManager()
        logger.info("AndroidSecAnalyzer initialized")
        
        # Modüller lazy loading ile yüklenecek (ihtiyaç olduğunda)
        self._static_analyzer = None
        self._dynamic_analyzer = None
        self._decompiler = None
        self._correlator = None
        self._risk_calculator = None
        self._report_generator = None
    
    def analyze(
        self,
        apk_path: str,
        analysis_type: str = ANALYSIS_FULL,
        output_dir: Optional[str] = None
    ) -> AnalysisResult:
        """
        
        APK dosyasını analiz eder
        
        Args:
            apk_path: APK dosyası yolu
            analysis_type: Analiz tipi ('static', 'dynamic', 'full')
            output_dir: Çıktı klasörü (None ise config'den alınır)
        
        Returns:
            AnalysisResult object
        
        Raises:
            InvalidAPKError: APK dosyası geçersizse
            AndroidSecError: Analiz sırasında hata oluşursa
        
        Örnek:
            analyzer = AndroidSecAnalyzer()
            result = analyzer.analyze("app.apk")
            print(f"Bulunan zafiyet sayısı: {len(result.all_findings)}")
        """
        start_time = time.time()
        
        logger.info(f"Starting analysis: {apk_path} (type: {analysis_type})")
        
        # APK dosyasını doğrula
        self._validate_apk(apk_path)
        
        # Result container oluştur
        result = AnalysisResult(apk_path)
        
        try:
            # 1. APK bilgilerini çıkar (temel bilgiler)
            logger.info("Extracting APK information...")
            result.apk_info = self._extract_apk_info(apk_path)
            
            # 2. Statik analiz
            if analysis_type in [ANALYSIS_STATIC, ANALYSIS_FULL]:
                logger.info("Running static analysis...")
                result.static_findings = self._run_static_analysis(apk_path)
                logger.info(f"Static analysis complete: {len(result.static_findings)} findings")
            
            # 3. Dinamik analiz
            if analysis_type in [ANALYSIS_DYNAMIC, ANALYSIS_FULL]:
                logger.info("Running dynamic analysis...")
                result.dynamic_findings = self._run_dynamic_analysis(apk_path)
                logger.info(f"Dynamic analysis complete: {len(result.dynamic_findings)} findings")
            
            # 4. Korelasyon ve risk skoru hesapla
            logger.info("Running correlation and risk calculation...")
            self._correlate_and_score(result)
            logger.info(f"Risk score: {result.risk_score:.2f}/10")
            
            # 5. Analiz süresini kaydet
            result.analysis_time = time.time() - start_time
            
            logger.info(f"Analysis completed in {result.analysis_time:.2f} seconds")
            
            return result
            
        except Exception as e:
            error_msg = f"Analysis failed: {str(e)}"
            logger.error(error_msg, exc_info=True)
            result.errors.append(error_msg)
            result.analysis_time = time.time() - start_time
            raise AndroidSecError(error_msg) from e
    
    def _validate_apk(self, apk_path: str) -> None:
        """
        
        APK dosyasını doğrula
        """
        apk_file = Path(apk_path)
        
        if not apk_file.exists():
            raise InvalidAPKError(f"APK file not found: {apk_path}")
        
        if not apk_file.is_file():
            raise InvalidAPKError(f"Not a file: {apk_path}")
        
        if apk_file.suffix.lower() != '.apk':
            raise InvalidAPKError(f"Not an APK file: {apk_path}")
        
        # Dosya boyutu kontrolü (çok büyükse uyar)
        max_size = self.config.get('analysis.max_file_size', 104857600)  # 100MB
        if apk_file.stat().st_size > max_size:
            logger.warning(f"APK file is large: {apk_file.stat().st_size / 1024 / 1024:.2f} MB")
    
    def _extract_apk_info(self, apk_path: str) -> Dict[str, Any]:
        """
        
        Temel APK bilgilerini çıkar
        """
        logger.debug("Extracting APK info")
        
        apk_file = Path(apk_path)
        
        info = {
            "file_name": apk_file.name,
            "file_size": apk_file.stat().st_size,
            "file_path": str(apk_file.absolute()),
            "package_name": "com.example.app",
            "version_name": "1.0.0",
            "version_code": 1,
        }

        # APK'dan paket bilgilerini çıkarmaya çalış
        try:
            import zipfile
            with zipfile.ZipFile(apk_path, 'r') as z:
                info["contents_count"] = len(z.namelist())
                # .dex dosyalarını say
                dex_files = [f for f in z.namelist() if f.endswith('.dex')]
                info["dex_count"] = len(dex_files)
                # .so dosyalarını say
                so_files = [f for f in z.namelist() if f.endswith('.so')]
                info["native_lib_count"] = len(so_files)
        except Exception:
            pass

        return info
    
    def _run_static_analysis(self, apk_path: str) -> List[Dict[str, Any]]:
        """

        Statik analiz yap

        StaticAnalyzer modülünü kullanarak APK üzerinde
        kapsamlı statik güvenlik analizi yapar.
        """
        logger.info("Running static analysis with StaticAnalyzer module")

        # StaticAnalyzer'ı lazy loading ile yükle
        if self._static_analyzer is None:
            from androidsec.static_analysis.analyzer import StaticAnalyzer
            self._static_analyzer = StaticAnalyzer()

        # Önce mevcut dekompile klasörünü ara
        decompiled_dir = self._find_decompiled_dir(apk_path)

        # Yoksa otomatik dekompile et
        if not decompiled_dir:
            decompiled_dir = self._decompile_apk(apk_path)

        # Statik analizi başlat
        findings = self._static_analyzer.analyze(
            apk_path=apk_path,
            decompiled_dir=decompiled_dir
        )

        return findings

    def _decompile_apk(self, apk_path: str) -> Optional[str]:
        """
        JADX ile APK'yı dekompile et, output/decompiled/<apk_name>/ klasörüne yaz.

        Returns:
            Dekompile klasör yolu (başarılıysa), None (başarısızsa)
        """
        from androidsec.decompiler.extractor import APKExtractor
        from androidsec.core.constants import DECOMPILED_DIR

        apk_name = Path(apk_path).stem
        output_dir = str(Path(DECOMPILED_DIR) / apk_name)

        logger.info(f"APK dekompile ediliyor: {apk_path} → {output_dir}")
        extractor = APKExtractor()

        if not extractor.is_any_available():
            logger.warning(
                "Decompiler bulunamadı (JADX yüklü değil). "
                "Sadece APK üzerinden analiz yapılacak."
            )
            return None

        result = extractor.extract(apk_path, output_dir)
        if result:
            logger.info(f"Dekompilasyon tamamlandı: {result}")
        else:
            logger.warning("Dekompilasyon başarısız, APK-only analize devam ediliyor.")
        return result

    def _find_decompiled_dir(self, apk_path: str) -> Optional[str]:
        """
        APK'ya karşılık gelen dekompile edilmiş klasörü bul

        Arama sırası:
        1. output/decompiled/<apk_name>/ klasörü
        2. APK ile aynı dizinde <apk_name>/ klasörü

        Returns:
            Dekompile edilmiş klasör yolu veya None
        """
        from androidsec.core.constants import DECOMPILED_DIR

        apk_name = Path(apk_path).stem  # "app.apk" → "app"

        # 1. output/decompiled/<apk_name>/
        decompiled_path = Path(DECOMPILED_DIR) / apk_name
        if decompiled_path.exists() and decompiled_path.is_dir():
            logger.info(f"Found decompiled directory: {decompiled_path}")
            return str(decompiled_path)

        # 2. APK dizininde <apk_name>/
        apk_parent = Path(apk_path).parent / apk_name
        if apk_parent.exists() and apk_parent.is_dir():
            logger.info(f"Found decompiled directory: {apk_parent}")
            return str(apk_parent)

        logger.info("No decompiled directory found, running APK-only analysis")
        return None
    
    def _run_dynamic_analysis(self, apk_path: str) -> List[Dict[str, Any]]:
        """
        Dinamik analiz yap.
        
        DynamicAnalyzer modülünü kullanarak cihaz üzerinde
        runtime güvenlik analizi yapar.
        
        Eğer cihaz bağlı değilse veya ADB bulunamazsa,
        hata loglanır ve boş liste döndürülür (analiz durdurmaz).
        """
        logger.info("Running dynamic analysis with DynamicAnalyzer module")

        try:
            from androidsec.dynamic_analysis.analyzer import DynamicAnalyzer
            from androidsec.dynamic_analysis.device.adb_wrapper import ADBWrapper, ADBError

            adb = ADBWrapper()

            # Cihaz bağlı mı kontrol et
            if not adb.is_device_connected():
                logger.warning(
                    "No Android device/emulator connected. "
                    "Skipping dynamic analysis."
                )
                return []

            # Paket adını al
            package_name = self._extract_package_name(apk_path)

            # DynamicAnalyzer'ı oluştur ve çalıştır
            analyzer = DynamicAnalyzer(
                adb=adb,
                log_duration_seconds=self.config.get(
                    "dynamic.log_duration", 30
                ),
            )

            result = analyzer.analyze(apk_path, package_name)
            return result.get("findings", [])

        except ImportError as e:
            logger.warning("Dynamic analysis module not available: %s", e)
            return []
        except Exception as e:
            logger.warning("Dynamic analysis failed (non-fatal): %s", e)
            return []

    def _extract_package_name(self, apk_path: str) -> str:
        """APK'dan paket adını çıkarmaya çalışır."""
        # 1. Option: Try using aapt
        try:
            import subprocess
            from pathlib import Path
            import os
            
            # Find aapt in Mac Android SDK
            aapt_path = os.path.expanduser("~/Library/Android/sdk/build-tools")
            if os.path.exists(aapt_path):
                # Get the highest version
                versions = sorted(os.listdir(aapt_path), reverse=True)
                for v in versions:
                    binary = os.path.join(aapt_path, v, "aapt")
                    if os.path.exists(binary) and os.access(binary, os.X_OK):
                        result = subprocess.run(
                            [binary, "dump", "badging", apk_path],
                            capture_output=True, text=True, timeout=5
                        )
                        for line in result.stdout.splitlines():
                            if line.startswith("package:"):
                                import re
                                match = re.search(r"name='([^']+)'", line)
                                if match:
                                    logger.info(f"Package name extracted via aapt: {match.group(1)}")
                                    return match.group(1)
        except Exception as e:
            logger.debug(f"AAPT package extraction failed: {e}")

        # 2. Fallback
        logger.warning("Using naive package name extraction fallback.")
        return Path(apk_path).stem.replace("-", ".").replace("_", ".")

    def _correlate_and_score(self, result: AnalysisResult) -> None:
        """
        Statik ve dinamik bulguları korelasyon yap ve risk skoru hesapla.
        """
        from androidsec.correlation.correlator import FindingCorrelator
        from androidsec.correlation.risk_calculator import RiskCalculator

        if self._correlator is None:
            self._correlator = FindingCorrelator()
        if self._risk_calculator is None:
            self._risk_calculator = RiskCalculator()

        # Korelasyon
        correlation_result = self._correlator.correlate(
            static_findings=result.static_findings,
            dynamic_findings=result.dynamic_findings,
        )

        result.correlated_findings = correlation_result.get("correlated_findings", [])
        result.all_findings = correlation_result.get("all_findings", [])
        result.by_owasp = correlation_result.get("by_owasp", {})
        result.statistics = correlation_result.get("statistics", {})

        # Risk skoru hesapla
        risk_result = self._risk_calculator.calculate(result.all_findings)
        result.risk_score = risk_result.get("score", 0.0)
        result.risk_info = risk_result
    
    def generate_report(
        self,
        result: AnalysisResult,
        format: str = "html",
        output_path: Optional[str] = None
    ) -> str:
        """
        Analiz raporu oluştur
        
        Args:
            result: AnalysisResult object
            format: Rapor formatı ('html', 'json')
            output_path: Rapor dosyası yolu (None ise otomatik oluşturulur)
        
        Returns:
            Oluşturulan rapor dosyasının yolu
        """
        logger.info(f"Generating {format} report...")

        if self._report_generator is None:
            from androidsec.reporting.generator import ReportGenerator
            self._report_generator = ReportGenerator()

        report_data = result.to_report_data()

        report_path = self._report_generator.generate(
            data=report_data,
            format=format,
            output_path=output_path,
        )

        logger.info(f"Report saved to: {report_path}")
        return report_path
    
    def __repr__(self) -> str:
        return f"AndroidSecAnalyzer(config={self.config})"
