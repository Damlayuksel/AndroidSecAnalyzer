"""
androidsec/correlation/__init__.py

Korelasyon modülü — statik/dinamik bulgu birleştirme ve risk hesaplama.
"""

from androidsec.correlation.correlator import FindingCorrelator
from androidsec.correlation.risk_calculator import RiskCalculator

__all__ = [
    "FindingCorrelator",
    "RiskCalculator",
]
