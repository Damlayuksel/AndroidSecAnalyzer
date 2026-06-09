"""
androidsec/correlation/correlator.py

Statik ve dinamik analiz bulgularını korelasyon yaparak
birleştirilmiş ve zenginleştirilmiş bulgular üretir.
"""

import logging
from typing import List, Dict, Any

from androidsec.core.constants import (
    OWASP_M1, OWASP_M2, OWASP_M3, OWASP_M4, OWASP_M5,
    OWASP_M6, OWASP_M7, OWASP_M8, OWASP_M9, OWASP_M10,
    OWASP_CATEGORIES,
)

logger = logging.getLogger(__name__)


# Korelasyon kuralları: statik bulgu title pattern -> dinamik bulgu title pattern
CORRELATION_RULES = [
    {
        "name": "HTTP Traffic Correlation",
        "static_pattern": "cleartext",
        "dynamic_pattern": "http",
        "owasp": OWASP_M3,
        "boost_severity": "CRITICAL",
        "description": (
            "Hem statik analizde hem dinamik analizde şifresiz HTTP trafiği tespit edildi. "
            "Bu, uygulamanın gerçekten şifresiz iletişim kurduğunu doğrulamaktadır."
        ),
    },
    {
        "name": "Weak Crypto Correlation",
        "static_pattern": "md5|des|rc4|ecb|sha1",
        "dynamic_pattern": "zayıf|md5|des|rc4|ecb|sha1",
        "owasp": OWASP_M5,
        "boost_severity": "CRITICAL",
        "description": (
            "Hem statik kod analizinde hem runtime'da zayıf kriptografi kullanımı tespit edildi. "
            "Bu, uygulamanın gerçekten güvensiz algoritmalar kullandığını doğrulamaktadır."
        ),
    },
    {
        "name": "Data Leakage Correlation",
        "static_pattern": "log|sensitive|password|token",
        "dynamic_pattern": "password|token|secret|api_key",
        "owasp": OWASP_M2,
        "boost_severity": "CRITICAL",
        "description": (
            "Statik analizde hassas veri loglama kodu, dinamik analizde ise "
            "gerçek hassas veri sızıntısı tespit edildi."
        ),
    },
    {
        "name": "SSL Bypass Correlation",
        "static_pattern": "ssl|certificate|trust",
        "dynamic_pattern": "ssl|sertifika|trust|hostname",
        "owasp": OWASP_M3,
        "boost_severity": "CRITICAL",
        "description": (
            "Hem statik hem dinamik analizde SSL/TLS doğrulama sorunları tespit edildi. "
            "MITM saldırılarına açık olma riski doğrulandı."
        ),
    },
]


class FindingCorrelator:
    """
    Statik ve dinamik bulguları korelasyon yaparak birleştirir.

    Korelasyon mantığı:
    1. Her iki analiz tipindeki bulgular karşılaştırılır
    2. Eşleşen bulgular "correlated" olarak işaretlenir ve severity yükseltilir
    3. OWASP kategorilerine göre gruplandırma yapılır
    4. Tüm benzersiz bulgular tek bir listede birleştirilir
    """

    def __init__(self):
        self.correlation_rules = CORRELATION_RULES

    def correlate(
        self,
        static_findings: List[Dict[str, Any]],
        dynamic_findings: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Statik ve dinamik bulguları korelasyon yapar.

        Args:
            static_findings: Statik analiz bulguları
            dynamic_findings: Dinamik analiz bulguları

        Returns:
            {
                "all_findings": [...],
                "correlated_findings": [...],
                "by_owasp": {"M1": [...], "M2": [...], ...},
                "statistics": {...}
            }
        """
        logger.info(
            "Korelasyon başlıyor: %d statik, %d dinamik bulgu",
            len(static_findings), len(dynamic_findings)
        )

        correlated = []
        matched_static = set()
        matched_dynamic = set()

        # Korelasyon kurallarını uygula
        import re

        for rule in self.correlation_rules:
            static_re = re.compile(rule["static_pattern"], re.IGNORECASE)
            dynamic_re = re.compile(rule["dynamic_pattern"], re.IGNORECASE)

            for si, sf in enumerate(static_findings):
                sf_text = f"{sf.get('title', '')} {sf.get('description', '')}"
                if not static_re.search(sf_text):
                    continue

                for di, df in enumerate(dynamic_findings):
                    df_text = f"{df.get('title', '')} {df.get('description', '')}"
                    if not dynamic_re.search(df_text):
                        continue

                    # Eşleşme bulundu
                    correlated.append({
                        "category": rule["owasp"],
                        "severity": rule["boost_severity"],
                        "title": f"[CORRELATED] {rule['name']}",
                        "description": rule["description"],
                        "static_finding": sf.get("title", ""),
                        "dynamic_finding": df.get("title", ""),
                        "correlated": True,
                        "recommendation": (
                            "Bu bulgu hem statik hem dinamik analizde doğrulandı. "
                            "Öncelikli olarak düzeltilmelidir."
                        ),
                    })
                    matched_static.add(si)
                    matched_dynamic.add(di)

        logger.info("Korelasyon tamamlandı. %d eşleşme bulundu.", len(correlated))

        # Tüm bulguları birleştir
        all_findings = list(correlated)

        for si, sf in enumerate(static_findings):
            finding = dict(sf)
            finding["source"] = "static"
            finding["correlated"] = si in matched_static
            all_findings.append(finding)

        for di, df in enumerate(dynamic_findings):
            finding = dict(df)
            finding["source"] = "dynamic"
            finding["correlated"] = di in matched_dynamic
            all_findings.append(finding)

        # OWASP kategorilerine göre grupla
        by_owasp = {}
        for cat in OWASP_CATEGORIES:
            by_owasp[cat] = []

        for finding in all_findings:
            category = finding.get("category", "")
            for owasp_cat in OWASP_CATEGORIES:
                if owasp_cat in category or category in owasp_cat:
                    by_owasp[owasp_cat].append(finding)
                    break

        # İstatistikler
        statistics = self._compute_statistics(all_findings, correlated)

        return {
            "all_findings": all_findings,
            "correlated_findings": correlated,
            "by_owasp": by_owasp,
            "statistics": statistics,
        }

    def _compute_statistics(
        self,
        all_findings: List[Dict],
        correlated: List[Dict],
    ) -> Dict[str, Any]:
        """Bulguların istatistiklerini hesaplar."""
        severity_counts = {}
        for f in all_findings:
            sev = f.get("severity", "UNKNOWN")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        category_counts = {}
        for f in all_findings:
            cat = f.get("category", "UNKNOWN")
            category_counts[cat] = category_counts.get(cat, 0) + 1

        return {
            "total_findings": len(all_findings),
            "correlated_count": len(correlated),
            "by_severity": severity_counts,
            "by_category": category_counts,
            "static_count": sum(1 for f in all_findings if f.get("source") == "static"),
            "dynamic_count": sum(1 for f in all_findings if f.get("source") == "dynamic"),
        }
