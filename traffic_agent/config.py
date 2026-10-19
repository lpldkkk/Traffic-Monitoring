from dataclasses import asdict, dataclass, replace
import json
import math
import os
from pathlib import Path
from urllib.parse import urlsplit


# USD per million tokens. DeepSeek uses the higher peak/cache-miss rate for
# reservation so an off-peak or cache-hit response cannot exhaust the estimate.
MODEL_PRESETS = {
    "OpenAI": {
        "base_url": "https://api.openai.com/v1",
        "models": {"gpt-4o-mini": (0.15, 0.60), "gpt-4.1-mini": (0.40, 1.60)},
    },
    "DeepSeek": {
        "base_url": "https://api.deepseek.com",
        "models": {"deepseek-flash": (0.30, 1.20), "deepseek-v4-pro": (1.32, 3.96)},
    },
}


def provider_for(config):
    host = urlsplit(config.base_url).hostname
    return "OpenAI" if host == "api.openai.com" else "DeepSeek"


def choose_model(config, provider, model):
    if provider not in MODEL_PRESETS or model not in MODEL_PRESETS[provider]["models"]:
        raise ValueError("请选择受支持的服务商和模型")
    preset = MODEL_PRESETS[provider]
    input_price, output_price = preset["models"][model]
    chosen = replace(config, base_url=preset["base_url"], model=model,
                     input_price=input_price, output_price=output_price)
    chosen.validate()
    return chosen


@dataclass
class Config:
    base_url: str = "https://api.deepseek.com"
    model: str = "deepseek-flash"
    max_cost: float = 1.0
    input_price: float = 0.30
    output_price: float = 1.20
    max_steps: int = 8
    max_tools: int = 16
    monitor_seconds: int = 300

    def validate(self):
        u = urlsplit(self.base_url)
        if (u.scheme != "https" and not (u.scheme == "http" and u.hostname in {"localhost", "127.0.0.1", "::1"})) or not u.hostname or u.username or u.password or u.query or u.fragment:
            raise ValueError("Base URL 必须是 HTTPS，或本机 HTTP；不能包含凭据、查询参数或片段")
        if not self.model.strip() or len(self.model) > 100:
            raise ValueError("请填写有效模型名称")
        for name, lo, hi in [("max_steps", 1, 16), ("max_tools", 1, 32), ("monitor_seconds", 60, 86400)]:
            value = getattr(self, name)
            if type(value) is not int or not lo <= value <= hi:
                raise ValueError(f"{name} 必须在 {lo}–{hi} 之间")
        for name in ("max_cost", "input_price", "output_price"):
            value = getattr(self, name)
            if not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
                raise ValueError(f"{name} 必须为正数；单价与预算必须使用相同货币")

    @classmethod
    def load(cls, path):
        has_saved_config = Path(path).exists()
        data = json.loads(Path(path).read_text(encoding="utf-8")) if has_saved_config else {}
        allowed = cls.__dataclass_fields__
        data = {k: v for k, v in data.items() if k in allowed}
        if not has_saved_config:
            for key, env in [("base_url", "LLM_BASE_URL"), ("model", "LLM_MODEL")]:
                if os.getenv(env):
                    data[key] = os.environ[env]
        config = cls(**data)
        # Migrate the earlier DeepSeek names and synchronize the built-in
        # estimate for supported selections, including saved zero prices.
        host = urlsplit(config.base_url).hostname
        if host == "api.deepseek.com":
            model = {"deepseek-chat": "deepseek-flash", "deepseek-reasoner": "deepseek-v4-pro"}.get(config.model, config.model)
            if model in MODEL_PRESETS["DeepSeek"]["models"]:
                return choose_model(config, "DeepSeek", model)
        if host == "api.openai.com" and config.model in MODEL_PRESETS["OpenAI"]["models"]:
            return choose_model(config, "OpenAI", config.model)
        return config

    def save(self, path):
        self.validate()
        Path(path).write_text(json.dumps(asdict(self), indent=2, ensure_ascii=False), encoding="utf-8")
