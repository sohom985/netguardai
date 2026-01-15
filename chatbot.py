"""
chatbot.py - AI Chatbot for NetGuardAI
Uses Ollama to answer questions about network traffic.
"""
import requests
import json
import sqlite3
import pandas as pd

# Ollama API endpoint (local)
# Use host.docker.internal to access host from container
OLLAMA_URL = "http://host.docker.internal:11434/api/generate"
MODEL_NAME = "llama3.2:1b"  # Small, fast model

def get_traffic_summary():
    """Get a summary of current traffic data for context."""
    try:
        conn = sqlite3.connect('netguard.db', timeout=5)
        
        # Get basic stats
        total = pd.read_sql("SELECT COUNT(*) as count FROM traffic", conn).iloc[0]['count']
        
        # Get protocol breakdown
        protocols = pd.read_sql("""
            SELECT protocol, COUNT(*) as count 
            FROM traffic 
            GROUP BY protocol
        """, conn)
        
        # Get top talkers
        top_ips = pd.read_sql("""
            SELECT src_ip, COUNT(*) as count 
            FROM traffic 
            GROUP BY src_ip 
            ORDER BY count DESC 
            LIMIT 5
        """, conn)
        
        # Get recent activity
        recent = pd.read_sql("""
            SELECT COUNT(*) as count 
            FROM traffic 
            WHERE timestamp > datetime('now', '-1 hour')
        """, conn).iloc[0]['count']
        
        conn.close()
        
        # Build context string
        context = f"""
Current Network Traffic Summary:
- Total packets captured: {total}
- Packets in last hour: {recent}
- Protocol breakdown: {protocols.to_dict('records')}
- Top 5 source IPs: {top_ips.to_dict('records')}
"""
        return context
    except Exception as e:
        return f"Error getting traffic data: {e}"

def chat(user_message):
    """
    Send a message to Ollama and get a response.
    Includes network traffic context for relevant answers.
    """
    # Get traffic context
    context = get_traffic_summary()
    
    # Build the prompt
    system_prompt = f"""You are NetGuardAI, a helpful network security assistant.
You have access to the following network traffic data:

{context}

Answer the user's question based on this data. Be concise and helpful.
If the question is not about network traffic, still be helpful but note your specialty is network security.
"""
    
    full_prompt = f"{system_prompt}\n\nUser: {user_message}\nAssistant:"
    
    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": MODEL_NAME,
                "prompt": full_prompt,
                "stream": False
            },
            timeout=60
        )
        
        if response.status_code == 200:
            result = response.json()
            return result.get('response', 'No response generated')
        else:
            return f"Error: Ollama returned status {response.status_code}"
            
    except requests.exceptions.ConnectionError:
        return "❌ Cannot connect to Ollama. Make sure Ollama is running!"
    except Exception as e:
        return f"Error: {str(e)}"

# Test the chatbot
if __name__ == "__main__":
    print("🤖 NetGuardAI Chatbot Test")
    print("=" * 40)
    
    # Test questions
    questions = [
        "How many packets have been captured?",
        "What protocols are being used?",
        "Which IP is sending the most traffic?"
    ]
    
    for q in questions:
        print(f"\n❓ {q}")
        answer = chat(q)
        print(f"🤖 {answer}")
