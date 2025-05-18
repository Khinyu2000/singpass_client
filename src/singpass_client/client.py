import uuid
import base64
import httpx
import json
import urllib.parse as urlparse
from typing import Any
from joserfc.jwk import KeySet, ECKey, OctKey
from joserfc import jws as _jws
from joserfc import jwe as _jwe
from joserfc._keys import Key

from singpass_client.helpers import (
    generate_token,
    create_s256_code_challenge,
    get_current_timestamp,
    url_encode,
)

from singpass_client.exceptions import (
    BadCodeVerifierSizeError,
    BadEncryptionError,
    BadSignatureError,
    InfoRequestError,
    InvalidClaimError,
    TokenRequestError,
    UnexpectedTokenError,
    InvalidKeyError,
)


class SingpassOauthClient:
    """Simple singpass oauth client that handle singpass endpoints. No server sessions management handled."""

    def __init__(self, discovery: dict[str, Any], client_id: str, scope: str):
        """Initialize RP and singpass data.

        Args:
            discovery (dict[str, Any]): response data from singpass's discovery endpoint.
            client_id (str): RP's client id
            scope (str): scope
        """
        self.AUTHORIZE_ENDPOINT: str = discovery.get("authorization_endpoint")
        self.TOKEN_ENDPOINT: str = discovery.get("token_endpoint")
        self.INFO_ENDPOINT: str = discovery.get("userinfo_endpoint")
        self.JWKS_ENDPOINT = discovery.get("jwks_uri")
        self.ISSUER: str = discovery.get("issuer")
        self.CLIENT_ID: str = client_id
        self.SCOPE: str = scope
        self.REDIRECT_URI: str = None
        self.KEYS: list[Key] = None  # RP's key set

    def _load_key_set(self, key_file_path: str) -> None:
        """Initialize RP's keyset.

        Args:
            key_file_path (str): jwks file path
        """
        with open(key_file_path, "r") as f:
            key_data = json.load(f)
        self.KEYS = KeySet.import_key_set(key_data).keys

    def _decrypt_jwe_token(self, jwe_token: str, en_key: Key) -> str:
        """Decrypt jwe token.

        Args:
            jwe_token (str): jwe_token
            en_key (Key): RP's encryption key

        Returns:
            str: decrypted payload
        """
        try:
            jwe_obj = _jwe.decrypt_compact(jwe_token, en_key)
            return jwe_obj.plaintext.decode("utf-8")
        except Exception as e:
            raise BadEncryptionError(f"BadEncrytionError: {e}")

    def _deserialize_jws_token(self, jws_token: str, sig_key: Key) -> dict[str, Any]:
        """Deserialize jws token.

        Args:
            jws_token (str): jws_token
            sig_key (Key): singpass's signature key

        Returns:
            dict[str, Any]: deserialized payload
        """
        try:
            jws_obj = _jws.deserialize_compact(jws_token, sig_key)
            return json.loads(jws_obj.payload.decode("utf-8"))
        except Exception as e:
            raise BadSignatureError(f"BadSignatureError: {e}")

    def _verify_jwt_header(self, header: dict[str, Any], expected_alg: str) -> None:
        """Veriry jwt token header if it uses the expected key's algorithm.

        Args:
            header (str): header data of the jwt token
            expected_alg (str): signing alogrithm of the public key
        """
        alg = header.get("alg")
        if not alg or alg != expected_alg:
            raise UnexpectedTokenError(
                "UnexpectedTokenError: jwt header contains unexpected algorithm"
            )

    def _decode_jwt_header(self, encoded_header: str) -> dict[str, Any]:
        """Deserialize jwt token header

        Args:
            encoded_header (str): jwt token header

        Returns:
            dict[str, Any]: decoded header data
        """
        padded = encoded_header + "=" * ((4 - len(encoded_header) % 4) % 4)
        decoded_header = base64.urlsafe_b64decode(padded)
        header = json.loads(decoded_header.decode("utf-8"))
        return header

    def _verify_jws_claims(self, claims: dict[str, Any], expected_nonce: str) -> None:
        """Verify claims inside jws payload.

        Args:
            claims (dict[str, Any]): claims data
            expected_nonce (str): nonce value of a RP's session to singpass

        Raises:
            InvalidClaimError: _description_
            InvalidClaimError: _description_
            InvalidClaimError: _description_
            InvalidClaimError: _description_
        """
        aud = claims.get("aud")
        if not aud or aud != self.CLIENT_ID:
            raise InvalidClaimError("InvalidClaimError: invalid aud value")
        iss = claims.get("iss")
        if not iss or iss != self.ISSUER:
            raise InvalidClaimError("InvalidClaimError: invalid iss value")
        current_time = get_current_timestamp()
        exp = claims.get("exp")
        if exp and current_time > exp:
            raise InvalidClaimError("InvalidClaimError: expired exp value")
        nonce = claims.get("nonce")
        if nonce and nonce != expected_nonce:
            raise InvalidClaimError("InvalidClaimError: invalid nonce value")

    async def _request_singpass_jwks(self) -> list[dict[str, Any]]:
        """Request singpass jwks public key set.

        Returns:
            list[dict[str, Any]]: _description_
        """
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    url=self.JWKS_ENDPOINT, headers={"Accept": "application/json"}
                )
                response.raise_for_status()
                data = response.json()
                return data.get("keys")
        except httpx.HTTPError as e:
            raise Exception(f"Exception: {e}")

    def _load_key_from_dict(key_dict: dict[str, Any], kty: str) -> Key:
        """Convert key type from dict into jose Key according to key type

        Args:
            key_dict (dict[str, Any]): key data
            kty (str): key type

        Raises:
            InvalidKeyError: _description_

        Returns:
            Key: jose compatible key type
        """
        if kty == "EC":
            return ECKey.import_key(key_dict)
        elif kty == "oct":
            return OctKey.import_key(key_dict)
        else:
            raise InvalidKeyError(
                "InvalidKeyError: this package can only import ec and oct key"
            )

    def create_authorization_url(
        self,
        redirect_uri: str,
        nonce: str = None,
        state: str = None,
        code_verifier: str = None,
        code_verifier_size: int = 43,
    ) -> str:
        """Get singpass authorization url.

        Args:
            redirect_uri (str): redirected url of the authorization code
            nonce (str, optional): nonce value of RP's session. Defaults to None.
            state (str, optional): state value of RP's session. Defaults to None.
            code_verifier (str, optional): code_verifier value of RP's session. Defaults to None.
            code_verifier_size (int, optional): code_verifier size of RP's session. Defaults to 43.

        Raises:
            BadCodeVerifierSizeError: raise error when code verifier size is not between 43 and 128.

        Returns:
            str: singpass authorization url.
        """
        self.REDIRECT_URI = redirect_uri
        if not nonce:
            nonce = str(uuid.uuid4())
        if not state:
            state = generate_token(32)
        if not code_verifier:
            if code_verifier_size < 43 or code_verifier_size > 128:
                raise BadCodeVerifierSizeError(
                    "BadCodeVerifierSizeError: code verifier size must be between 43 and 128"
                )
            code_verifier = generate_token(code_verifier_size)
            code_challenge = create_s256_code_challenge(code_verifier)
        params = [
            ("scope", self.SCOPE),
            ("response_type", "code"),
            ("client_id", self.CLIENT_ID),
            ("redirect_uri", redirect_uri),
            ("nonce", nonce),
            ("state", state),
            ("code_challenge", code_challenge),
            ("code_challenge_method", "S256"),
        ]
        (sch, net, path, par, query, fra) = urlparse.urlparse(self.AUTHORIZE_ENDPOINT)
        query = url_encode(params)
        uri = urlparse.urlunparse((sch, net, path, par, query, fra))
        return uri, code_verifier, nonce, state

    async def handle_callback(
        self,
        nonce: str,
        code_verifier: str,
        authorization_code: str,
        key_file_path: str,
        sig_key_id: str,
        en_key_id: str,
    ) -> dict[str, Any]:
        """Handle callback that is called with authorization code from singpass.
        1. request token set with client assertion from singpass
        2. validate id_token

        Args:
            nonce (str): nonce value of RP's session
            code_verifier (str): code verifier value of RP's session
            authorization_code (str): authorization code returned from singpass
            key_file_path (str): RP's jwks json file path
            sig_key_id (str): RP's signature key id
            en_key_id (str): RP's encryption key id

        Returns:
            dict[str, Any]: token set
        """

        def _generate_client_assertion() -> str:
            """Generate client assertion jws token using RP's sign key.

            Raises:
                InvalidKeyError: raise if sign key does not have alg value

            Returns:
                str: client assertion jws token
            """
            sig_key_obj = next(key for key in self.KEYS if key.kid == sig_key_id)
            sig_key = sig_key_obj.as_dict(True)
            sig_key_alg = sig_key.get("alg", None)
            if not sig_key_alg:
                raise InvalidKeyError("InvalidKeyError: sign key does not have alg")
            headers = {"alg": sig_key_alg, "typ": "JWT", "kid": sig_key_id}
            iat = get_current_timestamp()
            exp = iat + 60
            claims = {
                "sub": self.CLIENT_ID,
                "aud": self.ISSUER,
                "iss": self.CLIENT_ID,
                "iat": iat,
                "exp": exp,
                "code": authorization_code,
            }
            token = _jws.serialize_compact(
                headers, json.dumps(claims).encode("utf-8"), sig_key_obj
            )
            return token

        async def _request_token(client_assertion: str) -> dict[str, Any]:
            """Request token set from singpass

            Args:
                client_assertion (str): client_assertion

            Raises:
                TokenRequestError: _description_
                TokenRequestError: _description_
                TokenRequestError: _description_
                TokenRequestError: _description_

            Returns:
                dict[str, Any]: return a token set
            """
            if not self.REDIRECT_URI:
                raise TokenRequestError("TokenRequestError: empty redirect uri value")
            data = {
                "client_id": self.CLIENT_ID,
                "redirect_uri": self.REDIRECT_URI,
                "grant_type": "authorization_code",
                "code": authorization_code,
                "scope": self.SCOPE,
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": client_assertion,
                "code_verifier": code_verifier,
            }
            try:
                async with httpx.AsyncClient() as client:
                    response = await client.post(url=self.TOKEN_ENDPOINT, data=data)
                    response.raise_for_status()
                    return response.json()
            except ValueError as e:
                raise TokenRequestError(f"TokenRequestError: {e}")
            except httpx.HTTPError as e:
                raise TokenRequestError(f"TokenRequestError: {e.response.json()}")
            except Exception as e:
                raise TokenRequestError(f"TokenRequestError: {e}")

        try:
            if not self.KEYS:
                self._load_key_set(key_file_path)
            client_assertion = _generate_client_assertion()
            token_set = await _request_token(client_assertion)
            id_token: str = token_set.get("id_token")
            id_token_parts = id_token.split(".")
            jws_token = id_token
            if len(id_token_parts) == 5:
                en_key = next(key for key in self.KEYS if key.kid == en_key_id)
                expected_en_key_alg = en_key.as_dict(True).get("alg")
                jwe_header = self._decode_jwt_header(encoded_header=id_token_parts[0])
                self._verify_jwt_header(
                    header=jwe_header, expected_alg=expected_en_key_alg
                )
                jws_token = self._decrypt_jwe_token(jwe_token=id_token, en_key=en_key)
            jws_header = self._decode_jwt_header(encoded_header=jws_token.split(".")[0])
            singpass_sig_key_id = jws_header.get("kid")
            singpass_keys = await self._request_singpass_jwks()
            singpass_sig_key_dict = next(
                key for key in singpass_keys if key.get("kid") == singpass_sig_key_id
            )
            if not singpass_sig_key_dict:
                raise InvalidKeyError("InvalidKeyError: missing singpass key")
            self._verify_jwt_header(
                header=jws_header, expected_alg=singpass_sig_key_dict.get("alg")
            )
            singpass_sig_key_type = singpass_sig_key_dict.get("kty")
            singpass_sig_key = self._load_key_from_dict(
                key_dict=singpass_sig_key_dict, kty=singpass_sig_key_type
            )
            claims = self._deserialize_jws_token(
                jws_token=jws_token, sig_key=singpass_sig_key
            )
            self._verify_jws_claims(claims=claims, expected_nonce=nonce)
            return token_set
        except Exception as e:
            raise Exception(f"Excpetion: {e}")

    async def get_info(
        self, access_token: str, en_key_id: str, key_file_path: str, nonce: str
    ) -> dict[str, Any]:
        """Request user info using access token

        Args:
            access_token (str): access token
            en_key_id (str): RP's encryption key id
            key_file_path (str): RP's jwks json file path
            nonce (str): nonce value of RP's session

        Raises:
            InvalidKeyError: _description_
            Exception: _description_

        Returns:
            dict[str, Any]: claims
        """

        async def _request_info(access_token: str) -> str:
            """Request user info from singpass

            Args:
                access_token (str): access token

            Raises:
                InfoRequestError: _description_
                InfoRequestError: _description_
                InfoRequestError: _description_
                InfoRequestError: _description_

            Returns:
                str: jwe token return from singpass
            """

            if not self.INFO_ENDPOINT:
                raise InfoRequestError(
                    "InfoRequestError: empty singpass info endpoint value"
                )
            try:
                headers = {
                    "Content-Type": "application/jwt",
                    "Authorization": f"Bearer {access_token}",
                }
                async with httpx.AsyncClient() as client:
                    response = await client.get(url=self.INFO_ENDPOINT, headers=headers)
                    response.raise_for_status()
                    jwe_token = response.text.strip()
                    return jwe_token
            except ValueError as e:
                raise InfoRequestError(f"InfoRequestError: {e}")
            except httpx.HTTPError as e:
                raise InfoRequestError(f"InfoRequestError: {e.response.json()}")
            except Exception as e:
                raise InfoRequestError(f"InfoRequestError: {e}")

        try:
            jwe_token = _request_info(access_token=access_token)
            if not self.KEYS:
                self._load_key_set(key_file_path)
            en_key = next(key for key in self.KEYS if key.kid == en_key_id)
            expected_en_key_alg = en_key.as_dict(True).get("alg")
            jwe_header = self._decode_jwt_header(encoded_header=jwe_token.split(".")[0])
            self._verify_jwt_header(header=jwe_header, expected_alg=expected_en_key_alg)
            jws_token = self._decrypt_jwe_token(jwe_token=jwe_token, en_key=en_key)
            jws_header = self._decode_jwt_header(encoded_header=jws_token.split(".")[0])
            singpass_sig_key_id = jws_header.get("kid")
            singpass_keys = await self._request_singpass_jwks()
            singpass_sig_key_dict = next(
                key for key in singpass_keys if key.get("kid") == singpass_sig_key_id
            )
            if not singpass_sig_key_dict:
                raise InvalidKeyError("InvalidKeyError: missing singpass key")
            self._verify_jwt_header(
                header=jws_header, expected_alg=singpass_sig_key_dict.get("alg")
            )
            singpass_sig_key_type = singpass_sig_key_dict.get("kty")
            singpass_sig_key = self._load_key_from_dict(
                key_dict=singpass_sig_key_dict, kty=singpass_sig_key_type
            )
            claims = self._deserialize_jws_token(
                jws_token=jws_token, sig_key=singpass_sig_key
            )
            self._verify_jws_claims(claims=claims, expected_nonce=nonce)
            return claims
        except Exception as e:
            raise Exception(f"Exception: {e}")
