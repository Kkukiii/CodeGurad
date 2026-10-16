import json
from pathlib import Path

from pydantic import BaseModel, Field


class AIModule(BaseModel):
    name: str = Field(min_length=1)
    role: str = Field(min_length=1)
    input_fields: list[str] = Field(min_length=1)
    output_schema: str = Field(min_length=1)
    system_prompt: str = Field(min_length=1)
    enabled: bool = True


def load_modules(path: Path | None = None) -> list[AIModule]:
    source = path or Path(__file__).parents[1] / "data" / "ai_modules.json"
    if not source.exists():
        return []
    raw = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("AI module configuration must be a JSON array")
    return [AIModule.model_validate(item) for item in raw]
