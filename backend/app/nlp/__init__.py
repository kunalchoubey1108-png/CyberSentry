"""Optional advisory NLP classification (see ``app.nlp.classify``).

Deterministic detection never depends on this package: it is an
advisory text classifier only, and it fails open when unavailable.
"""

from .classify import CLASSES, Classification, classify_messages

__all__ = ["CLASSES", "Classification", "classify_messages"]