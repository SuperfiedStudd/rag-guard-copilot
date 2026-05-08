from __future__ import annotations

from functools import lru_cache

import pandas as pd

from .config import DATA_DIR


@lru_cache(maxsize=1)
def load_users() -> pd.DataFrame:
    return pd.read_csv(DATA_DIR / "users.csv")


@lru_cache(maxsize=1)
def load_documents() -> pd.DataFrame:
    return pd.read_csv(DATA_DIR / "documents.csv")
