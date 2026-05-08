from __future__ import annotations

from dataclasses import dataclass

import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


@dataclass
class RetrievalResult:
    doc_id: str
    title: str
    group: str
    sensitivity: str
    content: str
    score: float
    access_allowed: bool
    access_reason: str
    injection_flags: list[str]


def build_index(documents_df: pd.DataFrame) -> tuple[TfidfVectorizer, object]:
    vectorizer = TfidfVectorizer(stop_words="english")
    matrix = vectorizer.fit_transform(documents_df["content"].fillna(""))
    return vectorizer, matrix


def search_documents(query: str, documents_df: pd.DataFrame, vectorizer: TfidfVectorizer, matrix, top_k: int) -> pd.DataFrame:
    query_vector = vectorizer.transform([query])
    scores = cosine_similarity(query_vector, matrix)[0]
    results = documents_df.copy()
    results["score"] = scores
    results = results.sort_values("score", ascending=False)
    return results.head(top_k).reset_index(drop=True)
