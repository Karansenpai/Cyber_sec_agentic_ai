import os
import yaml
from loguru import logger

def load_config(config_path=None):
    """
    Load configuration from a YAML file
    
    Args:
        config_path (str): Path to the config YAML file
        
    Returns:
        dict: Configuration dictionary
    """
    if config_path is None:
        config_path = os.environ.get('CONFIG_PATH', '/app/config/config.yaml')
    
    try:
        with open(config_path, 'r') as file:
            config = yaml.safe_load(file)
            logger.info(f"Configuration loaded from {config_path}")
            return config
    except Exception as e:
        logger.error(f"Failed to load configuration from {config_path}: {e}")
        raise