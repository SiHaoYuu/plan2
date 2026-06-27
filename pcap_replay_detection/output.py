from __future__ import annotations

import csv
import json
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any


def write_rows(
    rows: Iterable[dict[str, Any]],
    output_path: str | Path,
    output_format: str,
) -> None:
    materialized = list(rows)
    if output_format == "auto":
        output_format = _format_from_path(output_path)

    if output_format == "csv":
        _write_csv(materialized, output_path)
    elif output_format == "jsonl":
        _write_jsonl(materialized, output_path)
    else:
        raise ValueError(f"unsupported output format: {output_format}")


def _format_from_path(output_path: str | Path) -> str:
    if str(output_path).lower().endswith(".jsonl"):
        return "jsonl"
    return "csv"


def _open_output(output_path: str | Path):
    if str(output_path) == "-":
        return sys.stdout
    return Path(output_path).open("w", newline="", encoding="utf-8")


def _write_csv(rows: list[dict[str, Any]], output_path: str | Path) -> None:
    fieldnames = _fieldnames(rows)
    handle = _open_output(output_path)
    close_handle = handle is not sys.stdout
    try:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
    finally:
        if close_handle:
            handle.close()


def _write_jsonl(rows: list[dict[str, Any]], output_path: str | Path) -> None:
    handle = _open_output(output_path)
    close_handle = handle is not sys.stdout
    try:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    finally:
        if close_handle:
            handle.close()


def _fieldnames(rows: list[dict[str, Any]]) -> list[str]:
    fieldnames: list[str] = []
    for row in rows:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(key)
    return fieldnames
