import json
import re


class SettingsParser:
    def __init__(self, settings: dict, defaults: dict):
        for key, default in defaults.items():
            value = self.parse_setting_type(settings.get(key, default), default)
            setattr(self, key, value)

    def parse_setting_type(self, value, default):
        if isinstance(default, str):
            return str(value).strip() if value else default

        if isinstance(default, int):
            return int(value) if value else default

        if isinstance(default, bool):
            return bool(value) if value else default

        if isinstance(default, dict):
            if isinstance(value, str):
                try:
                    return json.loads(value)
                except:
                    value = value.strip()
            return value if 0 < len(value) else default

        if isinstance(default, list):
            if isinstance(value, str):
                try:
                    value = json.loads(value)
                except:
                    output_list = re.split(r"\s*,\s*", value)
                    while ("" in output_list): output_list.remove("")
                    value = output_list
            return value if 0 < len(value) else default

        return value

    @property
    def values(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if not k.startswith('__') and not callable(k)}
