import json


class ConfigHandler:
    config_file_path = 'config.json'
    
    def __init__(self, config_file=None):
        if config_file is None:
            config_file = self.config_file_path
        
        with open(config_file, 'r') as file:
            self.config = json.load(file)

    def get(self, key, default=None):
        return self.config.get(key, default)


config_handler = ConfigHandler()