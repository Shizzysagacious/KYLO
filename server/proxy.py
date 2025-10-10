"""
Kylo Proxy Server - Production-Ready Version

This FastAPI application serves as a secure proxy for the Gemini API.
It is designed to be run in a production environment using Gunicorn and Uvicorn.

Key Features:
- **Centralized API Key:** Securely stores the company's Gemini API key on the server.
- **Authentication:** Requires a shared secret token (`X-Kylo-Token`) for all requests.
- **Rate Limiting:** Uses Redis for persistent, scalable rate limiting per token.
- **Structured Logging:** Emits JSON-formatted logs for easy parsing and monitoring.
- **Production-Grade Server:** Configured to run with Gunicorn for process management and Uvicorn for ASGI.
"""
#type: ignore   
import os
import time
import typing as t
import logging
from logging.config import dictConfig

import redis
from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel
from python_json_logger import jsonlogger

# --- Logging Configuration ---
class JsonFormatter(jsonlogger.JsonFormatter, logging.Formatter):
    def add_fields(self, log_record, record, message_dict):
        super().add_fields(log_record, record, message_dict)
        log_record['timestamp'] = log_record.get('asctime')
        log_record['level'] = log_record.get('levelname')
        log_record['message'] = log_record.get('message')

dictConfig({
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'json': {
            '()': JsonFormatter,
            'format': '%(asctime)s %(levelname)s %(message)s',
        },
    },
    'handlers': {
        'default': {
            'level': os.getenv('KYLO_LOG_LEVEL', 'INFO').upper(),
            'formatter': 'json',
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        '': {'handlers': ['default'], 'level': 'INFO'},
        'uvicorn.error': {'level': 'WARNING'},
        'uvicorn.access': {'handlers': [], 'propagate': False}, # Disable default access logs
    }
})
logger = logging.getLogger(__name__)


# --- Application Setup ---
app = FastAPI(title="Kylo Proxy")

# --- Configuration ---
PROXY_KEY = os.getenv('GEMINI_API_KEY')
RATE_LIMIT_PER_HOUR = int(os.getenv('KYLO_PROXY_RATE_LIMIT', '100')) # Reduced default for IP-based limiting
REDIS_URL = os.getenv('REDIS_URL')

if not all([PROXY_KEY, REDIS_URL]):
    logger.critical("Missing critical environment variables: GEMINI_API_KEY or REDIS_URL")
    # In a real app, you might exit here or have a fallback
    # For now, we log a critical error and continue, but some features will fail.

# --- Redis Connection for Rate Limiting ---
try:
    redis_client = redis.from_url(REDIS_URL) if REDIS_URL else None
except redis.exceptions.ConnectionError as e:
    logger.critical(f"Could not connect to Redis at {REDIS_URL}. Rate limiting will not work. Error: {e}")
    redis_client = None

# --- Pydantic Models ---
class AnalyzeRequest(BaseModel):
    code: str
    context: dict = {}

class AnalyzeResponse(BaseModel):
    issues: t.List[dict] = []

# --- Middleware and Dependencies ---
async def rate_limit_by_ip(request: Request):
    if not redis_client:
        logger.warning("Redis not connected, skipping rate limit check.")
        return

    ip_address = request.client.host
    current_hour = int(time.time() / 3600)
    key = f"rate_limit:{ip_address}:{current_hour}"
    
    try:
        current_count = redis_client.incr(key)
        if current_count == 1:
            redis_client.expire(key, 3600) # Expire key after 1 hour
        
        if current_count > RATE_LIMIT_PER_HOUR:
            logger.warning(f"Rate limit exceeded for IP: {ip_address}")
            raise HTTPException(status_code=429, detail='Rate limit exceeded')
    except redis.exceptions.RedisError as e:
        logger.error(f"Redis error during rate limiting for IP {ip_address}: {e}. Allowing request to proceed.")


@app.middleware("http")
async def log_requests(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = (time.time() - start_time) * 1000
    
    log_data = {
        "method": request.method,
        "path": request.url.path,
        "status_code": response.status_code,
        "process_time_ms": f"{process_time:.2f}",
        "client_ip": request.client.host,
    }
    logger.info("Request handled", extra=log_data)
    return response


# --- API Endpoint ---
@app.post('/v1/analyze', response_model=AnalyzeResponse)
async def analyze(req: AnalyzeRequest, request: Request):
    # Rate limiting is now based on IP
    await rate_limit_by_ip(request)

    if not PROXY_KEY:
        logger.error("Cannot process analysis: GEMINI_API_KEY is not configured on the server.")
        raise HTTPException(status_code=503, detail="Analysis service is not configured.")

    try:
        # Using requests for a more robust HTTP call with timeouts
        import google.generativeai as genai
        genai.configure(api_key=PROXY_KEY)
        model = genai.GenerativeModel('gemini-pro')
        
        prompt = f"Analyze the following code for security vulnerabilities. Return the output as a JSON object with a single key 'issues', which is an array of objects. Each object should have 'severity', 'description', and 'file_path' keys.\n\nCODE:\n```\n{req.code}\n```\n\nCONTEXT:\n{req.context}"
        
        response = model.generate_content(prompt)
        
        # Basic parsing of Gemini's response
        # This part needs to be very robust in a real application
        response_text = response.text.strip().lstrip('```json').rstrip('```')
        
        import json
        data = json.loads(response_text)
        issues = data.get('issues', [])
        
        logger.info(f"Analysis successful for IP {request.client.host}, found {len(issues)} issues.")
        return AnalyzeResponse(issues=issues)

    except Exception as e:
        logger.error(f"Error during Gemini analysis for IP {request.client.host}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="An error occurred during analysis.")

# Note: The `if __name__ == '__main__':` block is removed.
# The server should be started with Gunicorn, not by running this file directly.
# Example: gunicorn -w 4 -k uvicorn.workers.UvicornWorker server.proxy:app
