import base64
import json
from datetime import datetime, timezone


class AuthenticationToken:
    # Defaults
    _token: str = ""
    _expires_on: int = 0
    _endpoint: str = ""
    _details: list = [{}, {}]

    # Detail Properties
    type: str = ""
    algo: str = ""
    appid: str = ""
    sub: str = ""

    def __init__(self, token: str) -> None:
        self.update(token=token)

    @property
    def token(self) -> str or bool:
        # expired
        if int(datetime.now(timezone.utc).strftime("%s")) > self.expires_on - 60:
            self._token = ""
            self._expires_on = 0
            return False
        # valid
        return self._token

    @token.setter
    def token(self, token: str) -> None:
        self._token = token
        if self._token:
            self._parse_token()

    def _parse_token(self) -> None:
        details = []
        token_parts = self._token.split(".")
        for part in token_parts[0:2]:
            parsed = json.loads(base64.b64decode(part + ('=' * (-len(part) % 4))).decode('utf-8'))
            details.append(parsed)
            if parsed.get("exp", False):
                self.expires_on = parsed["exp"]
        self._details = details

    @property
    def expires_in(self) -> int:
        return max(self.expires_on - int(datetime.now(timezone.utc).strftime("%s")), 0)

    @expires_in.setter
    def expires_in(self, expires_in: int) -> None:
        self.expires_on = int(datetime.now(timezone.utc).strftime("%s")) + expires_in

    @property
    def expires_on(self) -> int:
        return self._expires_on

    @expires_on.setter
    def expires_on(self, expires_on: int) -> None:
        self._expires_on = expires_on

    @property
    def details(self) -> list:
        return self._details

    @property
    def endpoint(self) -> str:
        return self.details[1].get("aud", "No authorized domains")

    @property
    def roles(self) -> list:
        return self.details[1].get("roles", [])

    @property
    def parsed(self) -> dict:
        return {"details": self.details, "summary": self.summary()}

    def update(self, token: str):
        self.token = token

    def expires_timestamp(self) -> str:
        return str(datetime.fromtimestamp(self.expires_on))

    def human_readable_seconds(self, seconds: int = 0) -> str:
        return f"{seconds // 60}m {seconds % 60}s"

    def summary(self) -> dict:
        return {
            "appid": self.details[1].get("appid", "Unknown or empty token"),
            "subscription": self.details[1].get("sub", "Unknown or empty token"),
            "endpoint": self.endpoint,
            "expires_in": self.human_readable_seconds(self.expires_in),
            "expires_on": self.expires_timestamp(),
            "roles": self.roles
        }
