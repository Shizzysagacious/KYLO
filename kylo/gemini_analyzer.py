"""Gemini API integration for deep code analysis"""
import os
from typing import Dict, List, Any
from rich.console import Console
from dotenv import load_dotenv

console = Console()
load_dotenv()

# The production URL for the Kylo proxy server. This is hardcoded.
# For local testing, a developer can override this by setting KYLO_PROXY_URL in their .env file.
DEFAULT_PROXY_URL = "https://api.kylo.dev"

def analyze_code_security(code: str, context: Dict[str, Any]) -> List[Dict]:
    """
    Analyzes code by sending it to the central Kylo proxy server.
    This provides a zero-configuration experience for the end-user.
    
    The function will fall back to a direct Gemini call only if the user
    is a founder/admin who has explicitly configured `KYLO_FORCE_GEMINI`
    and has their own API key.
    """
    proxy_url = os.getenv('KYLO_PROXY_URL', DEFAULT_PROXY_URL)

    # --- Primary Path: Use the Public Proxy ---
    try:
        import requests
        payload = {'code': code, 'context': context}
        headers = {'Content-Type': 'application/json'}
        
        r = requests.post(f"{proxy_url.rstrip('/')}/v1/analyze", json=payload, headers=headers, timeout=45)
        
        if r.status_code == 200:
            data = r.json()
            return data.get('issues', [])
        else:
            # If the proxy fails, log a warning but don't fall back unless user is an admin.
            console.print(f'[yellow]Warning: Could not connect to Kylo analysis server (status: {r.status_code}). AI analysis is unavailable.[/yellow]')
            # The server might be down or the user's request was blocked (e.g., rate-limited).
            # We do not expose detailed error messages to the user.
    
    except requests.exceptions.RequestException as e:
        console.print(f'[yellow]Warning: Could not connect to Kylo analysis server. Please check your internet connection.[/yellow]')

    # --- Fallback Path: For Founders/Admins with Direct Gemini Access ---
    # This block is only executed if the proxy fails AND the user has explicitly opted-in.
    kylo_force = os.getenv('KYLO_FORCE_GEMINI', 'false').lower() in ('true', '1', 't')
    if kylo_force:
        console.print('[bold magenta]Proxy failed. Attempting direct Gemini analysis (Founder Mode)...[/bold magenta]')
        return _direct_gemini_call(code, context)

    return []


def _direct_gemini_call(code: str, context: Dict[str, Any]) -> List[Dict]:
    """
    A private function for making a direct call to the Gemini API.
    This is reserved for users who have set KYLO_FORCE_GEMINI.
    """
    try:
        import google.generativeai as genai
    except ImportError:
        console.print('[yellow]google-generativeai package not installed; cannot perform direct analysis.[/yellow]')
        return []

    gemini_key = os.getenv('GEMINI_API_KEY')
    if not gemini_key:
        console.print('[yellow]GEMINI_API_KEY not found; cannot perform direct analysis.[/yellow]')
        return []

    try:
        genai.configure(api_key=gemini_key)
        model = genai.GenerativeModel('gemini-pro')
        prompt = f"Analyze the following code for security vulnerabilities. Return JSON with an 'issues' array.\n\nCODE:\n{code}\n\nCONTEXT:\n{context}"
        
        response = model.generate_content(prompt)
        response_text = response.text.strip().lstrip('```json').rstrip('```')
        
        import json
        data = json.loads(response_text)
        return data.get('issues', [])
        
    except Exception as e:
        console.print(f'[red]Error during direct Gemini call: {e}[/red]')
        return []
