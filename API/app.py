from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
import os
import requests
from jose import jwt, JWTError
import json
import base64

app = FastAPI()
security = HTTPBearer()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)

def get_public_key() -> dict:
    keycloak_internal_url = os.getenv("API_APP_KEYCLOAK_INTERNAL_URL")
    realm = os.getenv("API_APP_KEYCLOAK_REALM")
    url = f"{keycloak_internal_url}/realms/{realm}/protocol/openid-connect/certs"

    resp = requests.get(url)
    resp.raise_for_status()

    jwks = resp.json()
    return jwks['keys']

def verify_jwt(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials

    header_data = token.split('.')[0]
    header_data += '=' * (4 - len(header_data) % 4)
    header = json.loads(base64.b64decode(header_data).decode('utf-8'))
    kid = header.get('kid')

    key = next((k for k in get_public_key() if k['kid'] == kid), None)
 
    try:
        payload = jwt.decode(token, key, algorithms="RS256")

        if "prothetic_user" not in payload.get("realm_access", {}).get("roles", []):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )


reportData = [
    {"action": "rotate", "signalLevel": "medium", "batteryLevel": 85, "startTimestamp" : "2025-07-21T18:25:43.511Z", "stopTimestamp" : "2025-07-21T18:25:43.591Z"}
]

@app.get("/reports")
async def get_reports(user: dict = Depends(verify_jwt)):

    return reportData