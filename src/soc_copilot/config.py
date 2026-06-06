"""Runtime configuration loaded from environment variables / .env file."""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path

from dotenv import load_dotenv
from pydantic import BaseModel, Field

# Load base .env first, then .env.local (which takes precedence and holds local
# secrets / stack-specific overrides; it is gitignored).
load_dotenv()
load_dotenv(".env.local", override=True)


class SplunkConfig(BaseModel):
    host: str = Field(default_factory=lambda: os.getenv("SPLUNK_HOST", "localhost"))
    port: int = Field(default_factory=lambda: int(os.getenv("SPLUNK_PORT", "8089")))
    username: str = Field(default_factory=lambda: os.getenv("SPLUNK_USERNAME", "admin"))
    password: str = Field(default_factory=lambda: os.getenv("SPLUNK_PASSWORD", ""))
    scheme: str = Field(default_factory=lambda: os.getenv("SPLUNK_SCHEME", "https"))
    verify_ssl: bool = Field(
        default_factory=lambda: os.getenv("SPLUNK_VERIFY_SSL", "false").lower() == "true"
    )


class MCPConfig(BaseModel):
    url: str = Field(default_factory=lambda: os.getenv("SPLUNK_MCP_URL", "http://localhost:8001/mcp"))
    token: str = Field(default_factory=lambda: os.getenv("SPLUNK_MCP_TOKEN", ""))


class HECConfig(BaseModel):
    """HTTP Event Collector — the one write path that works through a
    corporate firewall (port 8088) without an 8089 IP allowlist."""

    url: str = Field(default_factory=lambda: os.getenv("SPLUNK_HEC_URL", ""))
    token: str = Field(default_factory=lambda: os.getenv("SPLUNK_HEC_TOKEN", ""))
    verify_ssl: bool = Field(
        default_factory=lambda: os.getenv("SPLUNK_VERIFY_SSL", "false").lower() == "true"
    )

    @property
    def enabled(self) -> bool:
        return bool(self.url and self.token)


class HostedModelConfig(BaseModel):
    url: str = Field(default_factory=lambda: os.getenv("SPLUNK_HOSTED_MODEL_URL", ""))
    token: str = Field(default_factory=lambda: os.getenv("SPLUNK_HOSTED_MODEL_TOKEN", ""))
    reasoning_model: str = Field(
        default_factory=lambda: os.getenv("SPLUNK_REASONING_MODEL", "Foundation-Sec-1.1-8B-Instruct")
    )
    generation_model: str = Field(
        default_factory=lambda: os.getenv("SPLUNK_GENERATION_MODEL", "gpt-oss-20b")
    )


class AgentConfig(BaseModel):
    max_iterations: int = Field(
        default_factory=lambda: int(os.getenv("SOC_COPILOT_MAX_ITERATIONS", "6"))
    )
    feedback_index: str = Field(
        default_factory=lambda: os.getenv("SOC_COPILOT_FEEDBACK_INDEX", "soc_copilot_feedback")
    )
    findings_index: str = Field(
        default_factory=lambda: os.getenv("SOC_COPILOT_FINDINGS_INDEX", "soc_copilot_findings")
    )
    log_level: str = Field(
        default_factory=lambda: os.getenv("SOC_COPILOT_LOG_LEVEL", "INFO")
    )
    memory_path: Path = Field(
        default_factory=lambda: Path(
            os.getenv("SOC_COPILOT_MEMORY_PATH", str(Path.home() / ".soc_copilot" / "memory.json"))
        )
    )


class Settings(BaseModel):
    splunk: SplunkConfig = Field(default_factory=SplunkConfig)
    mcp: MCPConfig = Field(default_factory=MCPConfig)
    hosted: HostedModelConfig = Field(default_factory=HostedModelConfig)
    hec: HECConfig = Field(default_factory=HECConfig)
    agent: AgentConfig = Field(default_factory=AgentConfig)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
