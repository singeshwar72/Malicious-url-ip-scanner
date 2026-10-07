"""
config.py
~~~~~~~~~
Central configuration for the Malicious URL & IP Scanner application.
All secrets are loaded from environment variables / .env file.
No API keys or secrets are hard-coded here.
"""

import os
from dotenv import load_dotenv

# Load variables from .env file if present
load_dotenv()


class Config:
    # ------------------------------------------------------------------ #
    # Flask
    # ------------------------------------------------------------------ #
    SECRET_KEY: str = os.environ.get("SECRET_KEY", "dev-secret-change-in-production")
    FLASK_ENV: str = os.environ.get("FLASK_ENV", "development")
    DEBUG: bool = os.environ.get("FLASK_DEBUG", "1") == "1"

    # ------------------------------------------------------------------ #
    # Database
    # ------------------------------------------------------------------ #
    DATABASE_PATH: str = os.environ.get("DATABASE_PATH", "scanner_data.db")

    # ------------------------------------------------------------------ #
    # External Reputation API keys (optional)
    # All default to empty string – application works without them.
    # ------------------------------------------------------------------ #
    VIRUSTOTAL_API_KEY: str = os.environ.get("VIRUSTOTAL_API_KEY", "")
    ABUSEIPDB_API_KEY: str = os.environ.get("ABUSEIPDB_API_KEY", "")
    IPINFO_API_KEY: str = os.environ.get("IPINFO_API_KEY", "")

    # ------------------------------------------------------------------ #
    # Rate limiting
    # ------------------------------------------------------------------ #
    RATE_LIMIT: str = os.environ.get("RATE_LIMIT", "30") + " per minute"

    # ------------------------------------------------------------------ #
    # Scanner timeouts (seconds)
    # ------------------------------------------------------------------ #
    DNS_TIMEOUT: int = 5
    HTTP_TIMEOUT: int = 10
    API_TIMEOUT: int = 10

    # ------------------------------------------------------------------ #
    # Risk score thresholds
    # ------------------------------------------------------------------ #
    VERDICT_SAFE: int = 20         # 0  – 19
    VERDICT_LOW_RISK: int = 40     # 20 – 39
    VERDICT_SUSPICIOUS: int = 60   # 40 – 59
    VERDICT_HIGH_RISK: int = 80    # 60 – 79
    # 80 – 100 → MALICIOUS

    # ------------------------------------------------------------------ #
    # Input validation limits
    # ------------------------------------------------------------------ #
    MAX_INPUT_LENGTH: int = 2048

    @classmethod
    def has_virustotal(cls) -> bool:
        return bool(cls.VIRUSTOTAL_API_KEY)

    @classmethod
    def has_abuseipdb(cls) -> bool:
        return bool(cls.ABUSEIPDB_API_KEY)

    @classmethod
    def has_ipinfo(cls) -> bool:
        return bool(cls.IPINFO_API_KEY)

    @classmethod
    def external_services_status(cls) -> dict:
        return {
            "virustotal": cls.has_virustotal(),
            "abuseipdb": cls.has_abuseipdb(),
            "ipinfo": cls.has_ipinfo(),
            "any_enabled": any([cls.has_virustotal(), cls.has_abuseipdb(), cls.has_ipinfo()]),
        }
