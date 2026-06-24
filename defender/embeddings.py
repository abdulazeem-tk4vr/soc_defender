from __future__ import annotations

from dataclasses import dataclass


@dataclass
class SentenceTransformerEmbedder:
    model_name: str
    device: str | None = None

    def __post_init__(self) -> None:
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise RuntimeError("Install sentence-transformers to use SentenceTransformerEmbedder") from exc
        self.model = SentenceTransformer(self.model_name, device=self.device)

    def embed(self, texts: list[str]) -> list[list[float]]:
        vectors = self.model.encode(texts, normalize_embeddings=True, show_progress_bar=False)
        return [vector.tolist() for vector in vectors]


@dataclass
class HuggingFaceTransformerEmbedder:
    model_name: str
    device: str | None = None
    max_length: int = 512

    def __post_init__(self) -> None:
        try:
            import torch
            from transformers import AutoModel, AutoTokenizer
        except ImportError as exc:
            raise RuntimeError("Install torch and transformers to use HuggingFaceTransformerEmbedder") from exc
        self.torch = torch
        self.device_name = self.device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
        self.model = AutoModel.from_pretrained(self.model_name).to(self.device_name)
        self.model.eval()

    def embed(self, texts: list[str]) -> list[list[float]]:
        encoded = self.tokenizer(
            texts,
            padding=True,
            truncation=True,
            max_length=self.max_length,
            return_tensors="pt",
        )
        encoded = {key: value.to(self.device_name) for key, value in encoded.items()}
        with self.torch.no_grad():
            output = self.model(**encoded)
        token_embeddings = output.last_hidden_state
        attention_mask = encoded["attention_mask"].unsqueeze(-1).expand(token_embeddings.size()).float()
        summed = (token_embeddings * attention_mask).sum(dim=1)
        counts = attention_mask.sum(dim=1).clamp(min=1e-9)
        vectors = summed / counts
        vectors = self.torch.nn.functional.normalize(vectors, p=2, dim=1)
        return vectors.detach().cpu().tolist()
