"""
androidsec/reporting/generator.py

Analiz sonuçlarından rapor oluşturma orkestratörü.
HTML ve JSON formatlarını destekler.
"""

import logging
import time
from pathlib import Path
from typing import Dict, Any, Optional

from androidsec.core.constants import REPORTS_DIR, REPORT_FORMAT_HTML, REPORT_FORMAT_JSON
from androidsec.reporting.html_formatter import HTMLFormatter
from androidsec.reporting.json_formatter import JSONFormatter

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Rapor oluşturma orkestratörü.

    Kullanım:
        generator = ReportGenerator()
        path = generator.generate(result_data, format="html")
    """

    def __init__(self):
        self._html_formatter = HTMLFormatter()
        self._json_formatter = JSONFormatter()

    def generate(
        self,
        data: Dict[str, Any],
        format: str = REPORT_FORMAT_HTML,
        output_path: Optional[str] = None,
    ) -> str:
        """
        Analiz sonuçlarından rapor oluşturur.

        Args:
            data: Analiz sonuç verisi. Beklenen format:
                {
                    "apk_info": {...},
                    "risk": {"score": 7.5, "level": "HIGH", "label": "..."},
                    "statistics": {...},
                    "findings": [...],
                    "by_owasp": {...},
                    "analysis_time": 12.5
                }
            format: Rapor formatı ("html" veya "json")
            output_path: Çıktı dosyası yolu (None ise otomatik oluşturulur)

        Returns:
            Oluşturulan rapor dosyasının yolu
        """
        logger.info("Rapor oluşturuluyor: format=%s", format)

        # Otomatik dosya yolu oluştur
        if output_path is None:
            timestamp = int(time.time())
            apk_name = data.get("apk_info", {}).get("file_name", "unknown")
            stem = Path(apk_name).stem
            output_path = f"{REPORTS_DIR}/{stem}_report_{timestamp}.{format}"

        # Formatı seç ve oluştur
        if format == REPORT_FORMAT_HTML:
            return self._html_formatter.format(data, output_path)
        elif format == REPORT_FORMAT_JSON:
            return self._json_formatter.format(data, output_path)
        else:
            raise ValueError(f"Desteklenmeyen rapor formatı: {format}. "
                           f"Kullanılabilir: html, json")

    def generate_all(
        self,
        data: Dict[str, Any],
        formats: list = None,
    ) -> Dict[str, str]:
        """
        Birden fazla formatta rapor oluşturur.

        Args:
            data: Analiz sonuç verisi
            formats: Format listesi (None ise html + json)

        Returns:
            {"html": "/path/to/report.html", "json": "/path/to/report.json"}
        """
        if formats is None:
            formats = [REPORT_FORMAT_HTML, REPORT_FORMAT_JSON]

        results = {}
        for fmt in formats:
            try:
                path = self.generate(data, format=fmt)
                results[fmt] = path
                logger.info("%s raporu oluşturuldu: %s", fmt.upper(), path)
            except Exception as e:
                logger.error("%s raporu oluşturulamadı: %s", fmt.upper(), e)
                results[fmt] = f"ERROR: {str(e)}"

        return results
