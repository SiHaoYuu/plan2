from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod

from .records import Prediction


class InferenceBackend(ABC):
    @abstractmethod
    def predict(self, tokens: list[int]) -> Prediction:
        raise NotImplementedError


class MockBackend(InferenceBackend):
    """Deterministic backend for validating the pcap pipeline before model hookup."""

    def __init__(self, labels: tuple[str, ...] | None = None) -> None:
        self.labels = labels or ("benign", "suspicious", "malicious")

    def predict(self, tokens: list[int]) -> Prediction:
        digest = hashlib.sha256(bytes(token % 256 for token in tokens)).digest()
        label_index = digest[0] % len(self.labels)
        raw_confidence = 55 + digest[1] % 41
        confidence = raw_confidence / 100.0

        fallback_score = round((1.0 - confidence) / (len(self.labels) - 1), 6)
        scores = {label: fallback_score for label in self.labels}
        label = self.labels[label_index]
        scores[label] = round(confidence, 6)
        return Prediction(label=label, confidence=round(confidence, 6), scores=scores)


def create_backend(name: str) -> InferenceBackend:
    normalized = name.lower()
    if normalized == "mock":
        return MockBackend()
    if normalized in {"torch", "onnx"}:
        raise NotImplementedError(
            f"{name} backend is reserved for future model integration; use --backend mock for now"
        )
    raise ValueError(f"unknown backend: {name}")
