
import xml.etree.ElementTree as ET
from pathlib import Path

class ConfigReader:
    _instance = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(ConfigReader, cls).__new__(cls)
            cls._instance._load_config()
        return cls._instance
    
    def _load_config(self):
        try:
            config_path = Path(__file__).parent / "Web.config"
            
            if not config_path.exists():
                raise FileNotFoundError(f"Configuration file not found at {config_path}")
            
            tree = ET.parse(config_path)
            root = tree.getroot()
            
            # Database configurations
            self.USER_DATABASE_URL = self._get_config_value(root, "USER_DATABASE_URL")
            self.ADMIN_DATABASE_URL = self._get_config_value(root, "ADMIN_DATABASE_URL")
            self.QUEUE_DATABASE_URL = self._get_config_value(root, "QUEUE_DATABASE_URL")
            self.VACCINE_DATABASE_URL = self._get_config_value(root, "VACCINE_DATABASE_URL")
            
            # Security configurations
            self.SECRET_KEY = self._get_config_value(root, "SECRET_KEY")
            self.ALGORITHM = self._get_config_value(root, "ALGORITHM")
            
        except Exception as e:
            raise RuntimeError(f"Failed to load configuration: {str(e)}")
    
    def _get_config_value(self, root, key_name):
        for elem in root.findall(".//add"):
            if elem.get('key') == key_name:
                value = elem.get('value')
                if not value:
                    raise ValueError(f"Empty value for {key_name} in config")
                return value
        raise ValueError(f"{key_name} not found in config")

# Create singleton instance
config = ConfigReader()