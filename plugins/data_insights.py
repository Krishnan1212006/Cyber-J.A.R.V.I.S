"""Analyze bounded CSV or JSON files without executing or modifying them."""

import csv
import json
import math
from pathlib import Path

PLUGIN = {
    "name": "data_insights",
    "description": "Analyze a local CSV or JSON file and report row counts, fields, missing values, and numeric summaries.",
    "parameters": {
        "type": "OBJECT",
        "properties": {
            "file_path": {"type": "STRING", "description": "CSV or JSON file to analyze"},
            "output_path": {"type": "STRING", "description": "Optional JSON report path"},
        },
        "required": ["file_path"],
    },
}

MAX_INPUT_BYTES = 25 * 1024 * 1024


def _load_rows(path: Path) -> list[dict]:
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("input file exceeds the 25 MB safety limit")
    if path.suffix.lower() == ".csv":
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            return list(csv.DictReader(handle))
    if path.suffix.lower() == ".json":
        value = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(value, dict):
            value = value.get("rows", [value])
        if not isinstance(value, list) or not all(isinstance(row, dict) for row in value):
            raise ValueError("JSON must contain an object or a list of objects")
        return value
    raise ValueError("only .csv and .json files are supported")


def run(parameters: dict, player=None, session_memory=None) -> str:
    try:
        path = Path(str(parameters.get("file_path", ""))).expanduser()
        if not path.is_file():
            return f"Data file not found: {path}"
        rows = _load_rows(path)
        fields = sorted({str(key) for row in rows for key in row})
        missing = {field: sum(not str(row.get(field, "")).strip() for row in rows) for field in fields}
        numeric = {}
        for field in fields:
            values = []
            for row in rows:
                try:
                    value = float(row.get(field, ""))
                    if math.isfinite(value):
                        values.append(value)
                except (TypeError, ValueError):
                    pass
            if values:
                numeric[field] = {"count": len(values), "min": min(values), "max": max(values), "mean": round(sum(values) / len(values), 4)}
        report = {"file": str(path), "rows": len(rows), "fields": fields, "missing": missing, "numeric": numeric}
        output = str(parameters.get("output_path", "")).strip()
        if output:
            output_path = Path(output).expanduser()
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        summary = f"Analyzed {len(rows)} rows and {len(fields)} fields."
        if numeric:
            summary += f" Numeric fields: {', '.join(numeric)}."
        return summary + (f" Report saved to {output}." if output else "")
    except Exception as exc:
        return f"Data analysis failed: {exc}"