"""
androidsec/reporting/json_formatter.py

Analiz sonuçlarını JSON formatında dışa aktarır.
"""

import json
import logging
from pathlib import Path
from typing import Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)


class JSONFormatter:
    """
    Analiz sonuçlarını JSON dosyasına yazar.

    Kullanım:
        formatter = JSONFormatter()
        path = formatter.format(result_data, "output/reports/report.json")
    """

    def format(self, data: Dict[str, Any], output_path: str) -> str:
        """
        Analiz verilerini JSON olarak dışa aktarır.

        Args:
            data: Analiz sonuç verisi
            output_path: Çıktı dosyası yolu

        Returns:
            Oluşturulan dosyanın yolu
        """
        logger.info("JSON raporu oluşturuluyor: %s", output_path)

        # Çıktı klasörünü oluştur
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        # Meta bilgi ekle
        report = {
            "meta": {
                "tool": "AndroidSecAnalyzer",
                "version": "1.0.0",
                "generated_at": datetime.now().isoformat(),
                "report_format": "json",
            },
            "apk_info": data.get("apk_info", {}),
            "risk": data.get("risk", {}),
            "statistics": data.get("statistics", {}),
            "findings": data.get("findings", []),
            "by_owasp": data.get("by_owasp", {}),
            "analysis_time": data.get("analysis_time", 0),
        }

        with open(path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False, default=str)

        logger.info("JSON raporu oluşturuldu: %s", path)
        return str(path)
