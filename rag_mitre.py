import os
import json
import requests
from langchain_community.vectorstores import FAISS
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_core.documents import Document

VECTOR_DB_PATH = "faiss_mitre_index"
STIX_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"

print("[*] Initializing Embedding Model (all-MiniLM-L6-v2)...")
embeddings = HuggingFaceEmbeddings(model_name="all-MiniLM-L6-v2")

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
            content = (
                f"Technique Name: {tech_name}\n"
                f"MITRE ID: {external_id}\n"
                f"Summary: {tech_name} - {tech_desc[:250]}"
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


def retrieve_mitre_context(alert_signature, top_k=1):
    """
    Search vector DB for relevant MITRE ATT&CK techniques based on Suricata Alert signature
    """
    if not vector_store:
        return "No MITRE Knowledge Base loaded."
        
    results = vector_store.similarity_search(alert_signature, k=top_k)
    if results:
        return results[0].page_content
    return "No direct MITRE ATT&CK mapping found."


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
        print(f"\n🔍 Query: '{query}'")
        context = retrieve_mitre_context(query)
        print(f"📖 Retrieved Context:\n{context}")
        print("-" * 50)