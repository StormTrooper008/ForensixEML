import json
from google import genai
from typing import Dict, Any

def generate_incident_summary(telemetry_data: Dict[str, Any], api_key: str) -> Dict[str, Any]:
    """Feeds forensic telemetry to Gemini to generate a dynamic risk score and executive summary."""
    if not api_key:
        return {
            "ai_score": telemetry_data.get("risk_score", 0), 
            "ai_summary": "⚠️ AI Engine disabled. Please provide a Gemini API Key in Settings to enable automated threat synthesis."
        }
    
    # Initialize the variable up here so the except block can always access it safely
    raw_text = ""
    
    try:
        client = genai.Client(api_key=api_key)
        
        prompt = f"""
        You are an expert cybersecurity analyst. Review the following email forensic telemetry.
        Generate a concise, 3-sentence executive summary explaining the threat level and primary indicators of compromise (IOCs).
        Then, assign a final risk score from 0 to 100 based on the severity of the findings.
        
        Return ONLY a valid JSON object in this exact format, with no markdown formatting or code blocks:
        {{
            "ai_score": <integer>,
            "ai_summary": "<string>"
        }}
        
        Telemetry:
        {json.dumps(telemetry_data, indent=2)}
        """
        
        response = client.models.generate_content(
            model="gemini-3.6-flash",
            contents=prompt,
        )
        
        if not response or not response.text:
            return {
                "ai_score": telemetry_data.get("risk_score", 0),
                "ai_summary": "⚠️ AI response was empty or blocked by safety protocols."
            }
            
        raw_text = str(response.text)
        clean_text = raw_text.replace("```json", "").replace("```", "").strip()
        
        return json.loads(clean_text)
        
    except json.JSONDecodeError:
        safe_preview = raw_text[:100] if raw_text else "No text returned."
        return {
            "ai_score": telemetry_data.get("risk_score", 0), 
            "ai_summary": f"❌ AI returned malformed data instead of JSON. Raw output: {safe_preview}..."
        }
    except Exception as e:
        return {
            "ai_score": telemetry_data.get("risk_score", 0), 
            "ai_summary": f"❌ AI Engine Error: {str(e)}"
        }