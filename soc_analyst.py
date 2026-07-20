import requests
import json

def analyze_log_with_local_llm(log_data):
    # Ollama ka local endpoint
    url = "http://localhost:11434/api/generate"
    
    # AI ke liye ek strict security analyst prompt
    prompt = f"""
    You are an expert SOC Analyst. Analyze the following log entry and provide a structured assessment.
    Identify if it is a threat, determine severity (Low, Medium, High), and give a 1-sentence recommendation.

    Log Data:
    {log_data}

    Format your output exactly like this:
    - Verdict: [Threat / Normal]
    - Severity: [Low/Medium/High]
    - Analysis: [Brief explanation]
    - Recommendation: [Action to take]
    """
    
    payload = {
        "model": "llama3.2",  # Jo model aapne download kiya ho
        "prompt": prompt,
        "stream": False
    }
    
    try:
        response = requests.post(url, json=payload)
        response_data = response.json()
        return response_data.get("response", "No response from model.")
    except Exception as e:
        return f"Error connecting to Ollama: {e}"

# Log file read karke analyze karna
if __name__ == "__main__":
    print("Reading sample logs...")
    with open("sample_logs.txt", "r") as file:
        logs = file.readlines()
    
    print("\n--- Starting AI SOC Analysis --- \n")
    for index, log in enumerate(logs):
        print(f"Analyzing Log #{index + 1}: {log.strip()}")
        analysis = analyze_log_with_local_llm(log)
        print(analysis)
        print("-" * 50)