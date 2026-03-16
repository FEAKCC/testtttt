from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
import pickle
from pathlib import Path
from typing import Iterable


@dataclass
class LabelledContext:
    text: str
    is_true: int


DEFAULT_DATASET = [
    LabelledContext("const apiKey='sk_live_123...'; production billing setup", 1),
    LabelledContext("export STRIPE_SECRET from env and process payment", 1),
    LabelledContext("mongodb://user:pass@db.internal:27017/app", 1),
    LabelledContext("TODO replace with your_token_here before deploy", 0),
    LabelledContext("example credential in docs not real", 0),
    LabelledContext("readme shows sample Bearer token", 0),
    LabelledContext("secret key value for twilio auth in prod", 1),
    LabelledContext("dummy api key for local testing", 0),
]


class ContextModel:
    def __init__(self, model_path: str = ".cache/context_lr.pkl") -> None:
        self.model_path = Path(model_path)
        self.vectorizer = None
        self.model = None
        self.fallback = False

    def fit_or_load(self, dataset: Iterable[LabelledContext] = DEFAULT_DATASET) -> None:
        self.model_path.parent.mkdir(parents=True, exist_ok=True)
        if self.model_path.exists():
            with self.model_path.open("rb") as fh:
                self.vectorizer, self.model, self.fallback = pickle.load(fh)
            return
        try:
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.linear_model import LogisticRegression
        except ImportError:
            self.fallback = True
            with self.model_path.open("wb") as fh:
                pickle.dump((None, None, True), fh)
            return

        data = list(dataset)
        X = [d.text for d in data]
        y = [d.is_true for d in data]
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), lowercase=True, min_df=1)
        Xv = self.vectorizer.fit_transform(X)
        self.model = LogisticRegression(max_iter=1000, class_weight="balanced")
        self.model.fit(Xv, y)
        with self.model_path.open("wb") as fh:
            pickle.dump((self.vectorizer, self.model, False), fh)

    @lru_cache(maxsize=4096)
    def score(self, context: str) -> float:
        if self.model is None and not self.fallback:
            self.fit_or_load()
        if self.fallback:
            bad = ["example", "dummy", "sample", "readme", "tutorial"]
            good = ["token", "secret", "prod", "auth", "key", "password"]
            c = context.lower()
            return max(0.01, min(0.99, 0.5 + 0.12 * sum(w in c for w in good) - 0.18 * sum(w in c for w in bad)))
        Xv = self.vectorizer.transform([context])
        return float(self.model.predict_proba(Xv)[0, 1])
