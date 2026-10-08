from pathlib import Path
import re

class RAGService:
    """Transparent local lexical RAG baseline. No external web access is required."""
    def __init__(self, kb_dir: Path):
        self.kb_dir = Path(kb_dir)

    def _docs(self):
        docs = []
        for p in sorted(self.kb_dir.rglob("*.md")):
            text = p.read_text(encoding="utf-8")
            docs.append({"source": str(p.relative_to(self.kb_dir)), "text": text})
        return docs

    @staticmethod
    def _tokens(text):
        return set(re.findall(r"[a-zA-Z0-9_.-]{2,}", str(text).lower()))

    def retrieve(self, query, top_k=4):
        q = self._tokens(query)
        scored = []
        for doc in self._docs():
            overlap = len(q & self._tokens(doc["text"]))
            if overlap:
                scored.append((overlap, doc))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [{"source": d["source"], "score": score, "text": d["text"]} for score, d in scored[:top_k]]
