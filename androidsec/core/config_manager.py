"""
Configuration Manager for AndroidSecAnalyzer
YAML dosyalarından konfigürasyon okur ve yönetir
"""

import os
from pathlib import Path
from typing import Any, Dict, Optional

import yaml

from androidsec.core.exceptions import ConfigurationError
from androidsec.utils.logger import get_logger

logger = get_logger(__name__)


class ConfigManager:
    """
    Manages application configuration from YAML files
    YAML dosyalarından uygulama ayarlarını yönetir
    
    Örnek kullanım:
        config = ConfigManager()
        db_url = config.get('database.url')
        timeout = config.get('analysis.timeout', default=3600)
    """
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration manager
        
        Args:
            config_path: YAML config dosyası yolu
                        None ise default config kullanılır
        """
        self.config: Dict[str, Any] = {}
        self.config_path = config_path or self._get_default_config_path()
        
        logger.info(f"Loading configuration from: {self.config_path}")
        self._load_config()
    
    def _get_default_config_path(self) -> str:
        """
        Get default configuration file path
        Varsayılan config dosyası yolunu bul
        """
        # Proje kök dizinini bul
        current_file = Path(__file__).resolve()
        project_root = current_file.parent.parent.parent
        
        default_config = project_root / "config" / "default.yaml"
        
        if not default_config.exists():
            raise ConfigurationError(
                f"Default configuration file not found: {default_config}"
            )
        
        return str(default_config)
    
    def _load_config(self) -> None:
        """
        Load configuration from YAML file
        YAML dosyasından konfigürasyonu yükle
        """
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                self.config = yaml.safe_load(f) or {}
            
            logger.info(f"Configuration loaded successfully: {len(self.config)} sections")
            
        except FileNotFoundError:
            raise ConfigurationError(
                f"Configuration file not found: {self.config_path}"
            )
        except yaml.YAMLError as e:
            raise ConfigurationError(
                f"Invalid YAML in configuration file: {e}"
            )
        except Exception as e:
            raise ConfigurationError(
                f"Failed to load configuration: {e}"
            )
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value by key (supports nested keys with dot notation)
        Nokta notasyonu ile nested değerlere erişim
        
        Args:
            key: Config anahtarı (örn: 'database.url' veya 'analysis.timeout')
            default: Anahtar bulunamazsa döndürülecek değer
        
        Returns:
            Config değeri veya default
        
        Örnek:
            url = config.get('database.url')
            timeout = config.get('analysis.timeout', 3600)
        """
        keys = key.split('.')
        value = self.config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            logger.debug(f"Config key not found: {key}, using default: {default}")
            return default
    
    def set(self, key: str, value: Any) -> None:
        """
        Set configuration value (supports nested keys with dot notation)
        Runtime'da config değeri değiştir
        
        Args:
            key: Config anahtarı
            value: Yeni değer
        
        Örnek:
            config.set('analysis.timeout', 7200)
        """
        keys = key.split('.')
        config_dict = self.config
        
        # Son key hariç tüm nested dict'leri oluştur
        for k in keys[:-1]:
            if k not in config_dict or not isinstance(config_dict[k], dict):
                config_dict[k] = {}
            config_dict = config_dict[k]
        
        # Son key'e değeri ata
        config_dict[keys[-1]] = value
        logger.debug(f"Config updated: {key} = {value}")
    
    def get_all(self) -> Dict[str, Any]:
        """
        Get all configuration as dictionary
        Tüm konfigürasyonu dict olarak al
        """
        return self.config.copy()
    
    def reload(self) -> None:
        """
        Reload configuration from file
        Config dosyasını yeniden yükle
        """
        logger.info("Reloading configuration...")
        self._load_config()
    
    def __repr__(self) -> str:
        return f"ConfigManager(config_path='{self.config_path}')"
