# Singpass OAuth Client

## Description

A lightweight Python client for integrating with Singpass' OAuth2 endpoints. This client helps:

- Generate Singpass authorization URLs
- Exchange authorization codes for tokens
- Decrypt and verify ID and access tokens
- Retrieve and verify user info from Singpass

**Note**: This library does not handle session management out of the box.

It is built around the official Singpass standards and uses JOSE for handling JWTs and JWKs.

## Usage

```python
import asyncio
from singpass_client.client import SingpassOauthClient

# Load Singpass discovery data (usually from the Singpass metadata URL)
discovery = {
    "issuer": "https://stg-id.singpass.gov.sg",
    "authorization_endpoint": "https://stg-id.singpass.gov.sg/auth",
    "jwks_uri": "https://stg-id.singpass.gov.sg/.well-known/keys",
    "userinfo_endpoint": "https://stg-id.singpass.gov.sg/userinfo",
}

# Initialize the client
client = SingpassOauthClient(discovery=discovery, client_id="YOUR_CLIENT_ID", scope="openid")

# Step 1: Generate the authorization URL
auth_url, code_verifier, nonce, state = client.create_authorization_url(
    redirect_uri="https://yourapp.com/callback"
)

print("Visit this URL to authenticate:", auth_url)

# After redirection, handle the callback with the returned `code`
# Step 2: Exchange code for tokens
async def exchange_code():
    token_set = await client.handle_callback(
        nonce=nonce,
        code_verifier=code_verifier,
        authorization_code="AUTHORIZATION_CODE_FROM_CALLBACK",
        key_file_path="path/to/your_private_jwks.json",
        sig_key_id="your-signing-key-id",
        en_key_id="your-encryption-key-id"
    )

    access_token = token_set["access_token"]

    # Step 3: Retrieve and verify user info
    user_info = await client.get_info(
        access_token=access_token,
        en_key_id="your-encryption-key-id",
        key_file_path="path/to/your_private_jwks.json",
        nonce=nonce
    )

    print("User info:", user_info)

# Run the async flow
asyncio.run(exchange_code())
```
