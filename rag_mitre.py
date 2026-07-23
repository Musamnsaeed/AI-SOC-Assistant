import os
import requests
from langchain_community.vectorstores import FAISS
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_core.documents import Document

# Robust imports for Hybrid Search
try:
    from langchain.retrievers import EnsembleRetriever          # main package
except ImportError:
    try:
        from langchain_community.retrievers import EnsembleRetriever  # older versions
    except ImportError:
        EnsembleRetriever = None

try:
    from langchain_community.retrievers import BM25Retriever
except ImportError:
    try:
        # pyrefly: ignore [missing-import]
        from langchain.retrievers import BM25Retriever
    except ImportError:
        BM25Retriever = None

VECTOR_DB_PATH = "faiss_mitre_index"
STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

print("[*] Initializing Embedding Model (all-mpnet-base-v2)...")
embeddings = HuggingFaceEmbeddings(model_name="sentence-transformers/all-mpnet-base-v2")

# ── Keyword Enrichment: inject real-world attack aliases into specific chunks ──
# Keys = MITRE External ID, Values = extra keywords added to the chunk text.
# Add more entries here as needed without rebuilding the whole pipeline.
KEYWORD_ENRICHMENT = {
    # Web exploitation
    "T1190": "sql injection sqli xss cross-site scripting rce remote code execution "
              "web application exploit CVE public-facing server buffer overflow "
              "command injection path traversal directory traversal LFI RFI SSRF",
    # Ingress tool transfer / file download
    "T1105": "file download http download wget curl executable download "
              "binary transfer tool transfer payload delivery",
    # Brute force / password attacks
    "T1110": "brute force password spray credential stuffing login attempt "
              "ssh brute force rdp brute force dictionary attack",
    # Network scanning
    "T1046": "nmap port scan network scan host discovery service enumeration "
              "vulnerability scan masscan zmap",
    # DNS C2
    "T1071.004": "dns c2 dns tunneling command and control beacon dns query malware domain",
    # Phishing
    "T1566": "phishing spearphishing email attachment malicious link credential harvest",
    # PowerShell
    "T1059.001": "powershell script execution encoded command invoke-expression iex bypass",
    # Lateral movement via SMB
    "T1021.002": "smb lateral movement psexec wmic admin share pass-the-hash",
    # Credential dumping
    "T1003": "credential dump mimikatz lsass dump pass-the-hash ntds dit secretsdump",
    # Exfiltration over web
    "T1041": "data exfiltration upload http post c2 channel outbound transfer",
}

def fetch_and_parse_mitre_stix():
    """
    Downloads official MITRE ATT&CK STIX JSON and extracts all Techniques + Mitigations
    """
    print("[*] Downloading official MITRE ATT&CK Enterprise STIX dataset...")
    try:
        response = requests.get(STIX_URL, timeout=30)
        if response.status_code != 200:
            print(f"[!] Failed to download STIX data. Status code: {response.status_code}")
            return []
        stix_data = response.json()
    except Exception as e:
        print(f"[!] Error downloading MITRE STIX JSON: {e}")
        return []

    documents = []
    objects = stix_data.get("objects", [])

    print("[*] Parsing STIX objects into text chunks...")
    for obj in objects:
        # Filter for attack-pattern (Techniques)
        if obj.get("type") == "attack-pattern" and not obj.get("revoked", False):
            tech_name = obj.get("name", "Unknown")
            tech_desc = obj.get("description", "No description available.")
            
            # Extract External ID (e.g. T1046)
            external_id = "N/A"
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    external_id = ref.get("external_id", "N/A")
                    break

            # Format chunk for Vector DB (Optimized for better semantic match)
            extra_keywords = KEYWORD_ENRICHMENT.get(external_id, "")
            content = (
                f"Technique Name: {tech_name}\n"
                f"MITRE ID: {external_id}\n"
                f"Summary: {tech_name} - {tech_desc[:500]}"
                + (f"\nKeywords: {extra_keywords}" if extra_keywords else "")
            )
            
            metadata = {
                "mitre_id": external_id,
                "name": tech_name
            }
            
            documents.append(Document(page_content=content, metadata=metadata))

    print(f"[+] Total Techniques Extracted: {len(documents)}")
    return documents


def build_or_load_vector_db():
    if os.path.exists(VECTOR_DB_PATH):
        print("[*] Loading existing FAISS Vector DB from disk...")
        vector_store = FAISS.load_local(VECTOR_DB_PATH, embeddings, allow_dangerous_deserialization=True)
    else:
        print("[*] FAISS Index not found. Building full MITRE ATT&CK Vector DB...")
        documents = fetch_and_parse_mitre_stix()
        if not documents:
            print("[!] Could not fetch MITRE data. Vector DB creation aborted.")
            return None
        
        print("[*] Encoding chunks into embeddings and saving to FAISS...")
        vector_store = FAISS.from_documents(documents, embeddings)
        vector_store.save_local(VECTOR_DB_PATH)
        print(f"[+] Vector DB successfully created at '{VECTOR_DB_PATH}'!")

    return vector_store


# Initialize Vector DB Singleton
vector_store = build_or_load_vector_db()

# Initialize Ensemble Retriever for Hybrid Search
ensemble_retriever = None
if vector_store and BM25Retriever and EnsembleRetriever:
    print("[*] Extracting documents from FAISS docstore for Hybrid Search...")
    try:
        mitre_docs = list(vector_store.docstore._dict.values())
        bm25_retriever = BM25Retriever.from_documents(mitre_docs)
        bm25_retriever.k = 10
        
        ensemble_retriever = EnsembleRetriever(
            retrievers=[bm25_retriever, vector_store.as_retriever(search_kwargs={"k": 10})],
            weights=[0.4, 0.6]
        )
        print("[+] Hybrid Ensemble Retriever successfully initialized!")
    except Exception as e:
        print(f"[!] Error initializing Hybrid Retriever: {e}")

OLLAMA_URL = "http://localhost:11434/api/generate"


def _format_fallback(results: list) -> str:
    """Return a clean top-3 candidate summary when Ollama is unavailable."""
    lines = ["[Ollama unavailable — showing top RAG candidates]\n"]
    for i, doc in enumerate(results[:3], 1):
        mid  = doc.metadata.get("mitre_id", "N/A")
        name = doc.metadata.get("name", "Unknown")
        # First 180 chars of description only
        snippet = doc.page_content.split("Summary:")[-1].strip()[:180]
        lines.append(f"#{i}  MITRE ID: {mid}  |  {name}\n    {snippet}\n")
    return "\n".join(lines)


def retrieve_mitre_context(alert_signature, top_k=10):
    """
    Search vector DB for relevant MITRE ATT&CK techniques based on Suricata Alert signature
    and use local Llama 3.2 to select the most accurate technique from top candidates.
    """
    if not vector_store:
        return "No MITRE Knowledge Base loaded."
        
    if ensemble_retriever:
        results = ensemble_retriever.invoke(alert_signature)
    else:
        results = vector_store.similarity_search(alert_signature, k=top_k)
        
    if not results:
        return "No direct MITRE ATT&CK mapping found."
        
    # Ensure we only process at most top_k results
    results = results[:top_k]
        
    # Format candidates
    candidates_list = []
    for idx, doc in enumerate(results):
        candidates_list.append(f"Candidate {idx+1}:\n{doc.page_content}")
    formatted_candidates = "\n\n".join(candidates_list)
    
    prompt = f"""
You are a cybersecurity analyst mapping alerts to MITRE ATT&CK techniques.

Alert: "{alert_signature}"

Here are the top candidate MITRE techniques retrieved by similarity search:
{formatted_candidates}

Task: Select the MOST accurate technique for this alert based on actual attack behavior, 
not just keyword overlap. If none fit well, say so.

Return format:
MITRE ID: 
Technique Name: 
Reasoning: 
"""
    
    payload = {
        "model": "llama3.2",
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.0,
            "num_predict": 150
        }
    }
    
    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=90)
        if response.status_code == 200:
            return response.json().get("response", "No response from model.").strip()
        else:
            print(f"[!] Ollama API returned status code {response.status_code}")
            return _format_fallback(results)
    except Exception as e:
        print(f"[!] Ollama unavailable ({type(e).__name__}). Returning top candidates.")
        return _format_fallback(results)


if __name__ == "__main__":
    # Test queries across different attack categories
    test_queries = [
        "ET SCAN Potential Nmap Scan Detected",
        "SQL Injection Attempt Detected in Request Parameter",
        "SSH Brute Force Attempt Outbound",
        "Executable Download over HTTP"
    ]

    print("\n" + "="*50)
    print("--- FULL MITRE RAG RETRIEVAL VERIFICATION ---")
    print("="*50)

    for query in test_queries:
        print(f"\n[Query] '{query}'")
        context = retrieve_mitre_context(query)
        print(f"[Retrieved Context]\n{context}")
        print("-" * 50)