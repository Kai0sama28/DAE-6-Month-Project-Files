from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:  # pragma: no cover - dotenv is optional at runtime
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None  # type: ignore[assignment]

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_MODEL = "nvidia/nemotron-3-ultra-550b-a55b:free"
DEFAULT_FALLBACK_MODELS = ("nvidia/nemotron-3.5-lightning:free",)
DEFAULT_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or not raw.strip():
        return default
    try:
        return float(raw)
    except ValueError:
        return default


@dataclass
class AgentConfig:
    """Runtime configuration for the background triage agent.

    Everything is environment-driven so the same code runs against the live
    lab, in tests, and in a demo without code changes.
    """

    # --- OpenRouter / LLM -------------------------------------------------
    openrouter_api_key: str = ""
    openrouter_model: str = DEFAULT_MODEL
    openrouter_fallback_models: tuple = DEFAULT_FALLBACK_MODELS
    openrouter_base_url: str = DEFAULT_OPENROUTER_BASE_URL
    openrouter_http_referer: str = ""
    openrouter_title: str = "AI-Agentic SOC Triage Engine"
    llm_temperature: float = 0.2
    llm_max_tokens: int = 8000
    llm_timeout_seconds: float = 150.0
    llm_max_retries: int = 1
    llm_budget_seconds: float = 600.0
    use_llm: bool = True

    # --- Watcher ----------------------------------------------------------
    poll_interval_seconds: float = 5.0
    min_rule_level: int = 4
    trigger_min_level: int = 0
    settle_seconds: float = 25.0
    lookback_minutes: int = 30
    post_window_minutes: int = 15
    dedupe_window_minutes: int = 20
    burst_gap_seconds: float = 120.0
    max_correlated_alerts: int = 800
    max_events_in_prompt: int = 60

    # --- Output -----------------------------------------------------------
    reports_dir: Path = field(default_factory=lambda: PROJECT_ROOT / "reports")
    state_file: Path = field(default_factory=lambda: PROJECT_ROOT / "data" / "agent_state.json")
    log_file: Optional[Path] = None

    # --- Notification -----------------------------------------------------
    notify: bool = True
    notify_sound: bool = True
    notify_open_report: bool = True
    notify_title: str = "AI-Agentic SOC"

    # --- Metrics ----------------------------------------------------------
    manual_baseline_minutes: int = 45

    # --- Optional evidence pillars ---------------------------------------
    use_identity_api: bool = True
    use_edr_api: bool = True

    @property
    def llm_enabled(self) -> bool:
        return bool(self.use_llm and self.openrouter_api_key)

    def missing_llm_reason(self) -> Optional[str]:
        if not self.use_llm:
            return "LLM disabled by configuration (AGENT_USE_LLM=false)"
        if not self.openrouter_api_key:
            return "OPENROUTER_API_KEY is not set"
        return None

    @classmethod
    def from_env(cls, load_dotenv_file: bool = True) -> "AgentConfig":
        if load_dotenv_file and load_dotenv is not None:
            env_path = PROJECT_ROOT / ".env"
            if env_path.exists():
                load_dotenv(env_path, override=False)

        reports_dir = Path(
            os.environ.get("AGENT_REPORTS_DIR", str(PROJECT_ROOT / "reports"))
        ).expanduser()
        state_file = Path(
            os.environ.get("AGENT_STATE_FILE", str(PROJECT_ROOT / "data" / "agent_state.json"))
        ).expanduser()
        log_file_raw = os.environ.get("AGENT_LOG_FILE")
        log_file = Path(log_file_raw).expanduser() if log_file_raw else None

        fallback_raw = os.environ.get("OPENROUTER_FALLBACK_MODELS")
        if fallback_raw is None:
            fallbacks = DEFAULT_FALLBACK_MODELS
        else:
            fallbacks = tuple(
                m.strip() for m in fallback_raw.split(",") if m.strip()
            )

        return cls(
            openrouter_api_key=os.environ.get("OPENROUTER_API_KEY", "").strip(),
            openrouter_model=os.environ.get(
                "OPENROUTER_MODEL", DEFAULT_MODEL
            ).strip() or DEFAULT_MODEL,
            openrouter_fallback_models=fallbacks,
            openrouter_base_url=os.environ.get(
                "OPENROUTER_BASE_URL", DEFAULT_OPENROUTER_BASE_URL
            ).rstrip("/"),
            openrouter_http_referer=os.environ.get("OPENROUTER_HTTP_REFERER", "").strip(),
            openrouter_title=os.environ.get(
                "OPENROUTER_TITLE", "AI-Agentic SOC Triage Engine"
            ).strip(),
            llm_temperature=_env_float("AGENT_LLM_TEMPERATURE", 0.2),
            llm_max_tokens=_env_int("AGENT_LLM_MAX_TOKENS", 8000),
            llm_timeout_seconds=_env_float("AGENT_LLM_TIMEOUT", 150.0),
            llm_max_retries=_env_int("AGENT_LLM_MAX_RETRIES", 1),
            llm_budget_seconds=_env_float("AGENT_LLM_BUDGET", 600.0),
            use_llm=_env_bool("AGENT_USE_LLM", True),
            poll_interval_seconds=_env_float("AGENT_POLL_INTERVAL", 5.0),
            min_rule_level=_env_int("AGENT_MIN_LEVEL", 4),
            trigger_min_level=_env_int("AGENT_TRIGGER_MIN_LEVEL", 10),
            settle_seconds=_env_float("AGENT_SETTLE_SECONDS", 25.0),
            lookback_minutes=_env_int("AGENT_LOOKBACK_MINUTES", 30),
            post_window_minutes=_env_int("AGENT_POST_WINDOW_MINUTES", 15),
            dedupe_window_minutes=_env_int("AGENT_DEDUPE_WINDOW_MINUTES", 20),
            burst_gap_seconds=_env_float("AGENT_BURST_GAP_SECONDS", 120.0),
            max_correlated_alerts=_env_int("AGENT_MAX_CORRELATED_ALERTS", 800),
            max_events_in_prompt=_env_int("AGENT_MAX_EVENTS_IN_PROMPT", 60),
            reports_dir=reports_dir,
            state_file=state_file,
            log_file=log_file,
            notify=_env_bool("AGENT_NOTIFY", True),
            notify_sound=_env_bool("AGENT_NOTIFY_SOUND", True),
            notify_open_report=_env_bool("AGENT_NOTIFY_OPEN_REPORT", True),
            notify_title=os.environ.get("AGENT_NOTIFY_TITLE", "AI-Agentic SOC").strip(),
            manual_baseline_minutes=_env_int("AGENT_MANUAL_BASELINE_MINUTES", 45),
            use_identity_api=_env_bool("AGENT_USE_IDENTITY_API", True),
            use_edr_api=_env_bool("AGENT_USE_EDR_API", True),
        )
