import json
import logging
import os


class ConfigHandler:
    """
    A class to handle loading and validating configuration from a JSON file.
    """

    config_file_path = "server_config_linux.json"

    def __init__(self, config_file=None):
        """
        Initialize the ConfigHandler with an optional config file path.

        :param config_file: Path to the configuration file.
                            If None, defaults to 'server_config.json'.
        """
        self.logger = logging.getLogger(__name__)

        self.config = {}
        if config_file is None:
            config_file = self.config_file_path

        self.load_config(config_file)
        self.validate_config()

    def load_config(self, config_file):
        """
        Load the configuration from a JSON file.

        :param config_file: Path to the configuration file.
        """
        if not os.path.exists(config_file):
            self.logger.error(f"Config file {config_file} does not exist.")
            return

        try:
            with open(config_file, "r") as file:
                self.config = json.load(file)
                self.logger.info(
                    f"Config file {config_file} loaded successfully."
                )

        except json.JSONDecodeError as e:
            self.logger.error(
                f"Error parsing JSON config file {config_file}: {e}"
            )

        except Exception as e:
            self.logger.error(f"Error loading config file {config_file}: {e}")

    def get(self, key, default=None):
        """
        Get a configuration value by key.

        :param key: The key to look up in the configuration.
        :param default: The default value to return if the key is not found.
        :return: The value associated with the key, or the default value if the
                 key is not found.
        """
        return self.config.get(key, default)

    def validate_config(self):
        """
        Validate the loaded configuration against required keys
        and their types.
        """
        required_keys = {
            "ftp_host": str,
            "ftp_port": int,
            "file_system_db_path": str,
            "file_system_root_dir": str,
            "ssl_cert_path": str,
            "ssl_key_path": str,
            "implicit_tls": bool,
            "support_FTPS": bool,
            "debug_mode": bool,
            "log_level": str,
            "pasv_ports": dict,
            "listing_options": dict,
        }

        for key, expected_type in required_keys.items():
            if key not in self.config:
                logging.warning(f"Missing required config key: {key}")

            elif not isinstance(self.config[key], expected_type):
                logging.warning(
                    f"Config key {key} has incorrect type. "
                    f"Expected {expected_type}, got {type(self.config[key])}"
                )


config_handler = ConfigHandler()
