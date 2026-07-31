"""
diagnose_retrieval.py
---------------------
Diagnoses whether the correct MITRE ATT&CK techniques appear in top-5,
top-10, and top-15 retrieval results for common Suricata alert signatures.

Run:  python diagnose_retrieval.py
"""

import sys
import os

# ── ensure rag_mitre is importable from the same folder ──────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from rag_mitre import vector_store, ensemble_retriever

# ---------------------------------------------------------------------------
# Test cases:  (alert_signature, expected_keywords_in_technique_name_or_id)
# ---------------------------------------------------------------------------
TEST_CASES = [
    (
        "ET SCAN Potential Nmap Scan Detected",
        ["network scan", "port scan", "T1046", "network service", "discovery"],
    ),
    (
        "SQL Injection Attempt Detected in Request Parameter",
        ["sql", "injection", "T1190", "exploit public", "web"],
    ),
    (
        "SSH Brute Force Attempt Outbound",
        ["brute force", "T1110", "credential", "ssh", "valid account"],
    ),
    (
        "Executable Download over HTTP",
        ["ingress tool", "T1105", "download", "transfer", "http"],
    ),
    (
        "DNS Query to Known Malware C2 Domain",
        ["c2", "command and control", "T1071", "dns", "application layer"],
    ),
]

TOP_K_VALUES = [5, 10, 15]
SEPARATOR = "-" * 60


def retrieve_raw(query: str, top_k: int) -> list:
    """Return raw document list without calling Ollama."""
    if ensemble_retriever:
        docs = ensemble_retriever.invoke(query)
    else:
        docs = vector_store.similarity_search(query, k=top_k)
    return docs[:top_k]


def check_hit(docs: list, keywords: list) -> bool:
    """Return True if any doc content contains at least one expected keyword."""
    for doc in docs:
        text = doc.page_content.lower()
        if any(kw.lower() in text for kw in keywords):
            return True
    return False


def diagnose():
    if not vector_store:
        print("[!] Vector store not loaded. Exiting.")
        return

    print("\n" + "=" * 60)
    print("      MITRE RAG RETRIEVAL DIAGNOSTIC REPORT")
    print("=" * 60)

    for alert, expected_kws in TEST_CASES:
        print(f"\n[Query] '{alert}'")
        print(f"  Expected keywords: {expected_kws}")
        print(SEPARATOR)

        for k in TOP_K_VALUES:
            docs = retrieve_raw(alert, k)
            hit = check_hit(docs, expected_kws)
            status = "HIT  [OK]" if hit else "MISS [!!]"
            print(f"  top-{k:>2}  =>  {status}")

            if k == max(TOP_K_VALUES):
                print("  --- Top-15 retrieved techniques ---")
                for i, doc in enumerate(docs, 1):
                    name = doc.metadata.get("name", "?")
                    mid  = doc.metadata.get("mitre_id", "?")
                    print(f"  {i:>2}. [{mid}] {name}")

        print()

    # ── Summary & Recommendation ───────────────────────────────────────────
    print("=" * 60)
    print("DIAGNOSIS SUMMARY")
    print("=" * 60)
    print("""
Case A  => Technique appears in top-15 but NOT in top-5:
           FIX: top_k=10 already applied in rag_mitre.py  [DONE]

Case B  => Technique NOT found even in top-15:
           FIX: Re-build FAISS index with richer chunk content
                (add tactic, sub-technique keywords to each chunk).

Case C  => Technique appears in top-5 correctly:
           No fix needed -- retrieval is working well.
""")


if __name__ == "__main__":
    diagnose()
