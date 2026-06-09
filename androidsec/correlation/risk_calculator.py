"""
androidsec/correlation/risk_calculator.py

Analiz bulgularından genel risk skoru hesaplar.
"""

import logging
from typing import List, Dict, Any

from androidsec.core.constants import RISK_WEIGHTS

logger = logging.getLogger(__name__)


class RiskCalculator:
    """
    Bulgulardan genel risk skoru hesaplar (0-10 arası).

    Hesaplama yöntemi:
    1. Her bulgunun severity'sine göre ağırlıklı puan verilir
    2. Korelasyon bulunan bulgulara ekstra ağırlık verilir
    3. OWASP kategori çeşitliliği dikkate alınır
    4. Sonuç 0-10 arası normalize edilir
    """

    # Korelasyon bulunan bulgulara ekstra çarpan
    CORRELATED_MULTIPLIER = 1.5

    # Kategori çeşitliliği bonusu (her farklı OWASP kategorisi için)
    CATEGORY_DIVERSITY_BONUS = 0.3

    def __init__(self):
        self.weights = RISK_WEIGHTS

    def calculate(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Risk skorunu hesaplar.

        Args:
            findings: Tüm bulgular listesi (correlated bilgisi dahil)

        Returns:
            {
                "score": 7.5,
                "level": "HIGH",
                "label": "Yüksek Risk",
                "breakdown": {...}
            }
        """
        if not findings:
            return {
                "score": 0.0,
                "level": "NONE",
                "label": "Risk Bulunamadı",
                "breakdown": {
                    "base_score": 0.0,
                    "correlation_bonus": 0.0,
                    "diversity_bonus": 0.0,
                    "total_findings": 0,
                },
            }

        # 1. Temel skor hesapla
        base_score = 0.0
        for finding in findings:
            severity = finding.get("severity", "INFO")
            weight = self.weights.get(severity, 1.0)

            # Korelasyon bulunan bulgulara ekstra ağırlık
            if finding.get("correlated", False):
                weight *= self.CORRELATED_MULTIPLIER

            base_score += weight

        # Bulgu sayısına göre normalize et (ortalama ağırlık)
        avg_weight = base_score / len(findings)

        # 2. Kategori çeşitliliği bonusu
        categories = set()
        for f in findings:
            cat = f.get("category", "")
            if cat:
                categories.add(cat)

        diversity_bonus = min(len(categories) * self.CATEGORY_DIVERSITY_BONUS, 2.0)

        # 3. Final skor (0-10 arası)
        raw_score = avg_weight + diversity_bonus

        # Bulgu sayısına göre ek artış (çok bulgu = daha riskli)
        finding_factor = min(len(findings) / 10.0, 1.5)
        raw_score *= (1 + finding_factor * 0.2)

        # 0-10 arası normalize
        final_score = min(round(raw_score, 2), 10.0)

        # Risk seviyesi belirle
        level, label = self._get_risk_level(final_score)

        logger.info(
            "Risk skoru hesaplandı: %.2f/10 (%s) — %d bulgu, %d kategori",
            final_score, level, len(findings), len(categories)
        )

        return {
            "score": final_score,
            "level": level,
            "label": label,
            "breakdown": {
                "base_score": round(avg_weight, 2),
                "correlation_bonus": round(
                    sum(
                        self.weights.get(f.get("severity", "INFO"), 1.0) *
                        (self.CORRELATED_MULTIPLIER - 1)
                        for f in findings if f.get("correlated", False)
                    ), 2
                ),
                "diversity_bonus": round(diversity_bonus, 2),
                "total_findings": len(findings),
                "unique_categories": len(categories),
            },
        }

    def _get_risk_level(self, score: float) -> tuple:
        """Risk skorundan seviye ve etiket döndürür."""
        if score >= 8.0:
            return "CRITICAL", "Kritik Risk"
        elif score >= 6.0:
            return "HIGH", "Yüksek Risk"
        elif score >= 4.0:
            return "MEDIUM", "Orta Risk"
        elif score >= 2.0:
            return "LOW", "Düşük Risk"
        elif score > 0:
            return "INFO", "Bilgi Seviyesi"
        else:
            return "NONE", "Risk Bulunamadı"
