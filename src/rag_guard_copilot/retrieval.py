from __future__ import annotations

from dataclasses import dataclass

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

from .schemas import Document


@dataclass
class RetrievalResult:
    doc_id: str
    score: float

def build_index(documents: list[Document]) -> tuple[TfidfVectorizer, object]:
    vectorizer = TfidfVectorizer(stop_words="english")
    matrix = vectorizer.fit_transform([document.content for document in documents])
    return vectorizer, matrix


def search_documents(query: str, documents: list[Document], top_k: int) -> list[RetrievalResult]:
    vectorizer, matrix = build_index(documents)
    query_vector = vectorizer.transform([query])
    scores = cosine_similarity(query_vector, matrix)[0]
    ranked = sorted(zip(documents, scores, strict=True), key=lambda item: item[1], reverse=True)
    return [RetrievalResult(doc_id=document.doc_id, score=float(score)) for document, score in ranked[:top_k]]
