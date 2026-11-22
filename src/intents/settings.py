"""Settings for the intent pilot. Only this package reads them, so a gateway process never holds the provider's key."""

from pydantic import Field, SecretStr, ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict

from intents.literals import DEFAULT_KEEP, LITERAL_TYPES
from usecase.identity import parse_csv


class IntentSettingsError(ValueError):
    """Names the settings that are missing or invalid, never their values."""

    def __init__(self, settings: list[str]):
        super().__init__(", ".join(settings))
        self.settings = settings


class IntentSettings(BaseSettings):
    provider_endpoint: str = Field("", validation_alias="INTENT_PROVIDER_ENDPOINT")
    provider_model: str = Field("", validation_alias="INTENT_PROVIDER_MODEL")
    provider_api_key: SecretStr = Field(SecretStr(""), validation_alias="INTENT_PROVIDER_API_KEY")
    provider_auth_header: str = Field("Authorization", validation_alias="INTENT_PROVIDER_AUTH_HEADER")
    provider_extra_body: str = Field("{}", validation_alias="INTENT_PROVIDER_EXTRA_BODY")
    provider_timeout_seconds: float = Field(120.0, gt=0, le=600, validation_alias="INTENT_PROVIDER_TIMEOUT_SECONDS")
    keep_literals: str = Field(",".join(DEFAULT_KEEP), validation_alias="INTENT_KEEP_LITERALS")
    session_gap_minutes: int = Field(30, ge=1, le=1440, validation_alias="INTENT_SESSION_GAP_MINUTES")

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


def load_settings() -> IntentSettings:
    try:
        return IntentSettings()
    except ValidationError as e:
        # The error text can echo a value, so only the setting names leave here.
        raise IntentSettingsError(sorted({str(error["loc"][0]) for error in e.errors() if error["loc"]})) from None


def kept_literals(settings: IntentSettings) -> frozenset[str]:
    kept = frozenset(parse_csv(settings.keep_literals))
    if not kept <= set(LITERAL_TYPES):
        raise IntentSettingsError(["INTENT_KEEP_LITERALS"])
    return kept
