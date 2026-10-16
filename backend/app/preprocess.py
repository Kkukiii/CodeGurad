from dataclasses import dataclass
from pathlib import Path


MAX_LINES = 600


@dataclass(frozen=True)
class PreparedCode:
    language: str
    numbered: str
    lines: list[str]


def detect_language(filename: str, code: str) -> str:
    suffix = Path(filename).suffix.lower()
    if suffix == ".py" or (suffix not in {".java"} and ("def " in code or "import flask" in code)):
        return "python"
    if suffix == ".java" or "public class " in code or "System.out.println" in code:
        return "java"
    return "unknown"


def prepare_code(code: str, filename: str) -> PreparedCode:
    clean_code = code.replace("\x00", "")
    lines = clean_code.splitlines()
    if len(lines) > MAX_LINES:
        raise ValueError(f"Source exceeds the {MAX_LINES}-line review limit")
    language = detect_language(filename, clean_code)
    numbered = "\n".join(f"{index:4} | {line}" for index, line in enumerate(lines, 1))
    return PreparedCode(language=language, numbered=numbered, lines=lines)
