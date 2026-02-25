import asyncio
import base64
import hashlib
import hmac
import html
import json
import logging
import math
import os
import random
import re
import secrets
import ssl
import time
from typing import Callable
import uuid

import httpx
import jwt
import pkce
import websockets
from urllib.parse import urlparse, parse_qs, quote

from .const import (
    CLIENT_ID,
    CLIENT_SECRET,
    COMMAND_STATUS_CANCELLED,
    COMMAND_STATUS_COMPLETE,
    COMMAND_STATUS_DELIVERED,
    COMMAND_STATUS_PROCESSING,
    LOCK_STATE_JAM,
    LOCK_STATE_LOCK,
    LOCK_STATE_LOCK_JAM,
    LOCK_STATE_UNLOCK,
    LOCK_STATE_UNLOCK_JAM,
    TENANT_ID,
    UNIKEY_API_URL_BASE,
    UNIKEY_INVALID_LOGIN_URL,
    UNIKEY_LOGIN_URL_BASE,
    UNIKEY_WS_URL_BASE,
)

_LOGGER = logging.getLogger(__name__)


class KevoError(Exception):
    pass


class KevoAuthError(KevoError):
    pass


class KevoPermissionError(KevoError):
    pass


class KevoApi:
    MAX_RECONNECT_DELAY: int = 240

    def __init__(
        self,
        device_id: uuid.UUID = None,
        client: httpx.AsyncClient = None,
        ssl_context: ssl.SSLContext = None,
    ):
        self._expires_at = 0
        self._refresh_token: str = None
        self._id_token: str = None
        self._access_token: str = None
        self._user_id: str = None
        self._device_id = device_id if device_id is not None else uuid.uuid4()
        self._devices: list = []
        self._websocket_task: asyncio.Task = None
        self._websocket = None
        self._disconnecting = False
        self._callbacks: list[Callable] = []

        # ssl.create_default_context() and httpx.AsyncClient() both trigger
        # blocking I/O (loading CA certificates) and must not run on the event
        # loop. Both are deferred to _async_init(), called lazily on first use.
        self._ssl_context = ssl_context
        self._ssl_context_initialized = ssl_context is not None
        self._client = client
        self._client_initialized = client is not None

    async def _async_init(self) -> None:
        """Lazily initialize SSL context and HTTP client off the event loop."""
        if self._ssl_context_initialized and self._client_initialized:
            return

        def _blocking_init():
            ssl_ctx = self._ssl_context
            if not self._ssl_context_initialized:
                ssl_ctx = ssl.create_default_context()
            http_client = self._client
            if not self._client_initialized:
                # Reuse our SSL context so httpx doesn't load certification again.
                http_client = httpx.AsyncClient(
                    verify=ssl_ctx, follow_redirects=False
                )
            return ssl_ctx, http_client

        loop = asyncio.get_event_loop()
        ssl_ctx, http_client = await loop.run_in_executor(None, _blocking_init)
        self._ssl_context = ssl_ctx
        self._ssl_context_initialized = True
        self._client = http_client
        self._client_initialized = True

    async def _get_ssl_context(self) -> ssl.SSLContext:
        await self._async_init()
        return self._ssl_context

    async def _get_client(self) -> httpx.AsyncClient:
        await self._async_init()
        return self._client

    # ------------------------------------------------------------------ #
    # Internal helpers                                                     #
    # ------------------------------------------------------------------ #

    def __generate_websocket_verification(self, cnonce: str, snonce: str) -> str:
        """Generate the HMAC-SHA512 verification value for the websocket."""
        secret_bytes = base64.b64decode(CLIENT_SECRET)
        total_bytes = base64.b64decode(snonce) + base64.b64decode(cnonce)
        sign = hmac.new(secret_bytes, total_bytes, hashlib.sha512).digest()
        return base64.b64encode(sign).decode()

    def __generate_certificate(self) -> str:
        """Generate a device certificate (reverse-engineered from the mobile app)."""

        def int_val(v: int) -> list:
            result, i = [], 0
            while True:
                result.append(255 & v)
                v >>= 8
                i += 1
                if i >= 4:
                    break
            return result

        def short_val(v: int) -> list:
            result, i = [], 0
            while True:
                result.append(255 & v)
                v >>= 8
                i += 1
                if i >= 2:
                    break
            return result

        def random_bytes(n: int) -> list:
            return [math.floor(255 * random.random()) for _ in range(n)]

        def uuid_to_bytes(guid: str) -> list:
            parts = guid.split("-")
            result = []
            for index, part in enumerate(parts):
                chunks = re.findall(".{1,2}", part)
                if index < 3:
                    chunks = list(reversed(chunks))
                for chunk in chunks:
                    result.append(int(chunk, 16))
            return list(reversed(result))

        def length_encoded(tag: int, data: list) -> list:
            return [tag] + short_val(len(data)) + data

        now = int(time.time())
        s = [17, 1, 0, 1, 19, 1, 0, 1, 16, 1, 0, 48]
        s += length_encoded(18, int_val(1))
        s += length_encoded(20, int_val(now))
        s += length_encoded(21, int_val(now))
        s += length_encoded(22, int_val(now + 86400))
        s += [48, 1, 0, 6]
        s += length_encoded(49, uuid_to_bytes("00000000-0000-0000-0000-000000000000"))
        s += length_encoded(50, uuid_to_bytes(str(self._device_id)))
        s += length_encoded(53, random_bytes(32))
        s += length_encoded(54, random_bytes(32))
        return base64.b64encode(bytearray(s)).decode()

    async def __get_server_nonce(self) -> str:
        """Retrieve a server nonce."""
        client = await self._get_client()
        client.headers = {"Content-Type": "application/json"}
        res = await client.post(
            UNIKEY_API_URL_BASE + "/api/v2/nonces",
            json={"headers": {"Accept": "application/json"}},
        )
        res.raise_for_status()
        return res.headers["x-unikey-nonce"]

    def __get_client_nonce(self) -> str:
        """Generate a random client nonce."""
        return base64.b64encode(secrets.token_bytes(64)).decode()

    async def __get_headers(self) -> dict:
        """Build the signed request headers required by the API."""
        return {
            "X-unikey-cnonce": self.__get_client_nonce(),
            "X-unikey-context": "Web",
            "X-unikey-nonce": await self.__get_server_nonce(),
            "Authorization": "Bearer " + self._access_token,
            "Accept": "application/json",
        }

    # ------------------------------------------------------------------ #
    # Auth                                                                 #
    # ------------------------------------------------------------------ #

    def _store_tokens(self, json_response: dict) -> None:
        """Persist token data from a token endpoint response."""
        self._access_token = json_response["access_token"]
        self._id_token = json_response["id_token"]
        self._refresh_token = json_response["refresh_token"]
        self._expires_at = time.time() + json_response["expires_in"]

    async def async_refresh_token(self) -> None:
        """Refresh the access token using the stored refresh token."""
        client = await self._get_client()
        res = await client.post(
            UNIKEY_LOGIN_URL_BASE + "/connect/token",
            data={
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "grant_type": "refresh_token",
                "refresh_token": self._refresh_token,
            },
        )
        res.raise_for_status()
        self._store_tokens(res.json())

    async def _ensure_fresh_token(self) -> None:
        """Refresh the access token if it expires within 100 seconds."""
        if self._expires_at < time.time() + 100:
            await self.async_refresh_token()

    async def login(self, username: str, password: str) -> None:
        """Authenticate and obtain tokens via the Unikey OAuth2 PKCE flow.

        A fresh HTTP client and device identity are created on every call so
        that stale cookies and server-side sessions from a previous login never
        interfere with a subsequent one.
        """
        # Reset the HTTP client to clear cookies from any previous login.
        if self._client is not None and self._client_initialized:
            await self._client.aclose()
        self._client = None
        self._client_initialized = False
        client = await self._get_client()

        # Fresh device identity each time — the identity server ties its session
        # to staticDeviceId, and reusing a stale one causes an accounterror.
        self._device_id = uuid.uuid4()

        code_verifier, code_challenge = pkce.generate_pkce_pair()
        certificate = self.__generate_certificate()
        state = hashlib.md5(os.urandom(32)).hexdigest()

        # Step 1: initiate the authorization flow.
        res = await client.get(
            UNIKEY_LOGIN_URL_BASE + "/connect/authorize",
            follow_redirects=False,
            params={
                "client_id": CLIENT_ID,
                "redirect_uri": "https://mykevo.com/#/token",
                "response_type": "code",
                "scope": "openid email profile identity.api tumbler.api tumbler.ws offline_access",
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
                "prompt": "login",
                "response_mode": "query",
                "acr_values": (
                    f"\n    appId:{CLIENT_ID}"
                    f"\n    tenant:{TENANT_ID}"
                    f"\n    tenantCode:KWK"
                    f"\n    tenantClientId:{CLIENT_ID}"
                    f"\n    loginContext:Web"
                    f"\n    deviceType:Browser"
                    f"\n    deviceName:Chrome,(Windows)"
                    f"\n    deviceMake:Chrome,108.0.0.0"
                    f"\n    deviceModel:Windows,10"
                    f"\n    deviceVersion:rp-1.0.2"
                    f"\n    staticDeviceId:{self._device_id}"
                    f"\n    deviceCertificate:{certificate}"
                    f"\n    isDark:false"
                ),
            },
        )
        if res.status_code != 302:
            res.raise_for_status()

        # Step 2: load the login page.
        client.cookies = res.cookies
        res = await client.get(res.headers["Location"], follow_redirects=False)
        res.raise_for_status()

        try:
            rvt = next(re.finditer(
                '<input name="__RequestVerificationToken" .+ value="(.+?)"',
                res.text,
            )).group(1)
            serialized_client = html.unescape(next(re.finditer(
                '<input .+ name="SerializedClient" value="(.+?)"',
                res.text,
            )).group(1))
        except StopIteration:
            raise KevoAuthError()

        # Step 3: submit credentials.
        client.cookies = res.cookies
        res = await client.post(
            UNIKEY_LOGIN_URL_BASE + "/account/login",
            data={
                "SerializedClient": serialized_client,
                "NumFailedAttempts": 0,
                "Username": username,
                "Password": password,
                "login": "",
                "__RequestVerificationToken": rvt,
            },
        )
        if res.status_code != 302:
            res.raise_for_status()

        redirect_location = res.headers["Location"]
        if redirect_location == UNIKEY_INVALID_LOGIN_URL:
            raise KevoAuthError()

        # Step 4: follow the redirect chain until we reach mykevo.com.
        # The auth code lives in the fragment of the final mykevo.com URL.
        # mykevo.com is a React SPA — never fetch it. Instead, parse the code
        # directly from the Location header once mykevo.com is the target host.
        client.cookies = res.cookies
        current_url = redirect_location
        if not current_url.startswith("http"):
            current_url = UNIKEY_LOGIN_URL_BASE + current_url

        code = None
        for _ in range(10):
            parsed = urlparse(current_url)
            if parsed.netloc == "mykevo.com":
                fragment_params = parse_qs(urlparse(parsed.fragment).query)
                query_params = parse_qs(parsed.query)
                if "code" in fragment_params:
                    code = fragment_params["code"][0]
                elif "code" in query_params:
                    code = query_params["code"][0]
                else:
                    raise KevoAuthError()
                break

            res = await client.get(current_url, follow_redirects=False)
            if res.status_code != 302:
                raise KevoAuthError()

            client.cookies = res.cookies
            current_url = res.headers.get("location", "")
            if not current_url.startswith("http"):
                current_url = UNIKEY_LOGIN_URL_BASE + current_url
        else:
            raise KevoAuthError()

        if code is None:
            raise KevoAuthError()

        # Step 5: exchange the auth code for tokens.
        res = await client.post(
            UNIKEY_LOGIN_URL_BASE + "/connect/token",
            data={
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "code": code,
                "code_verifier": code_verifier,
                "grant_type": "authorization_code",
                "redirect_uri": "https://mykevo.com/#/token",
            },
        )
        res.raise_for_status()
        self._store_tokens(res.json())
        self._user_id = jwt.decode(
            self._id_token, options={"verify_signature": False}
        )["sub"]

    # ------------------------------------------------------------------ #
    # API calls                                                            #
    # ------------------------------------------------------------------ #

    async def _api_post(self, url: str, body: dict):
        """POST to the Unikey API, retrying once after a token refresh on 403."""
        client = await self._get_client()
        await self._ensure_fresh_token()
        headers = await self.__get_headers()

        res = await client.post(UNIKEY_API_URL_BASE + url, headers=headers, json=body)
        try:
            res.raise_for_status()
        except httpx.HTTPStatusError as ex:
            if ex.response.status_code == 403:
                await self.async_refresh_token()
                headers = await self.__get_headers()
                res = await client.post(
                    UNIKEY_API_URL_BASE + url, headers=headers, json=body
                )
                try:
                    res.raise_for_status()
                except httpx.HTTPStatusError as retryex:
                    if retryex.response.status_code == 403:
                        raise KevoAuthError()
                    raise
            elif ex.response.status_code == 401:
                raise KevoPermissionError()
            else:
                raise
        return res.json()

    async def get_locks(self) -> list["KevoLock"]:
        """Retrieve the list of locks associated with this account."""
        client = await self._get_client()
        await self._ensure_fresh_token()
        headers = await self.__get_headers()
        url = UNIKEY_API_URL_BASE + "/api/v2/users/" + self._user_id + "/locks"

        res = await client.get(url, headers=headers)
        try:
            res.raise_for_status()
        except httpx.HTTPStatusError as ex:
            if ex.response.status_code == 403:
                await self.async_refresh_token()
                headers = await self.__get_headers()
                res = await client.get(url, headers=headers)
                try:
                    res.raise_for_status()
                except httpx.HTTPStatusError as retryex:
                    if retryex.response.status_code == 403:
                        raise KevoAuthError()
                    raise
            elif ex.response.status_code == 401:
                raise KevoPermissionError()
            else:
                raise

        self._devices = [
            KevoLock(
                self,
                lock["id"],
                lock["name"],
                lock["firmwareVersion"],
                lock["batteryLevel"],
                lock["boltState"],
                lock["brand"],
            )
            for lock in res.json()["locks"]
        ]
        return self._devices

    # ------------------------------------------------------------------ #
    # WebSocket                                                            #
    # ------------------------------------------------------------------ #

    def __process_message(self, message: str) -> None:
        """Update lock state from an incoming websocket message."""
        try:
            json_body = json.loads(message)
            if json_body["messageType"] != "LockStatus":
                return

            message_body = json_body["messageData"]
            lock = next(
                (x for x in self._devices if x.lock_id == message_body["lockId"]),
                None,
            )
            if lock is None:
                return

            lock.battery_level = message_body["batteryLevel"]
            bolt_state = message_body["boltState"]
            command = message_body["command"]
            command_status = command["status"] if command is not None else None

            if bolt_state == LOCK_STATE_LOCK:
                lock.is_locked, lock.is_jammed = True, False
            elif bolt_state == LOCK_STATE_UNLOCK:
                lock.is_locked, lock.is_jammed = False, False
            elif bolt_state == LOCK_STATE_JAM:
                lock.is_jammed = True
            elif bolt_state == LOCK_STATE_LOCK_JAM:
                lock.is_locked, lock.is_jammed = True, True
            elif bolt_state == LOCK_STATE_UNLOCK_JAM:
                lock.is_locked, lock.is_jammed = False, True
            else:
                _LOGGER.warning("Unknown bolt state: %s", bolt_state)
                lock.is_locked = lock.is_jammed = None

            if command_status in (COMMAND_STATUS_COMPLETE, COMMAND_STATUS_CANCELLED):
                lock.is_locking = lock.is_unlocking = False
            elif command_status in (COMMAND_STATUS_PROCESSING, COMMAND_STATUS_DELIVERED):
                lock.is_locking = command["type"] == LOCK_STATE_LOCK
                lock.is_unlocking = not lock.is_locking

            for callback in self._callbacks:
                try:
                    callback(lock)
                except Exception as err:
                    _LOGGER.error("Callback error: %s", err)

        except Exception as ex:
            _LOGGER.error("Error processing websocket message: %s", ex)

    async def __websocket_reconnect(self, refresh_token: bool = False) -> None:
        """Schedule a reconnect with exponential backoff.

        If refresh_token is True the access token is refreshed before the next
        attempt — used when the server rejects the connection with HTTP 401.
        """
        if refresh_token:
            try:
                await self.async_refresh_token()
                # A successful token refresh resets the backoff so we reconnect
                # quickly rather than waiting out the full backoff delay.
                self._reconnect_attempts = 0
            except Exception as ex:
                _LOGGER.error("WebSocket token refresh failed: %s", ex)
                # Refresh failed — keep the backoff delay so we don't spam.

        self._reconnect_attempts += 1
        delay = min(2 ** self._reconnect_attempts, self.MAX_RECONNECT_DELAY)
        await asyncio.sleep(delay)
        self._websocket_task = asyncio.create_task(self.__websocket_connect())

    async def websocket_close(self) -> None:
        """Close the websocket connection."""
        self._disconnecting = True
        if self._websocket is not None:
            await self._websocket.close()
        if self._websocket_task is not None:
            self._websocket_task.cancel()

    async def __websocket_connect(self) -> None:
        """Open the websocket and listen for lock state updates."""
        # Ensure the token is fresh before building the auth query string.
        # If the token is about to expire (or already expired from a previous
        # 401 cycle) this refreshes it proactively rather than waiting for
        # the server to reject the connection.
        await self._ensure_fresh_token()

        auth_token = quote(f"Bearer {self._access_token}", safe="!~*'()")
        cnonce = self.__get_client_nonce()
        try:
            snonce = await self.__get_server_nonce()
        except httpx.HTTPStatusError:
            raise
        except Exception:
            _LOGGER.error("Failed to retrieve server nonce, retrying")
            await self.__websocket_reconnect()
            return

        verification = quote(
            self.__generate_websocket_verification(cnonce, snonce), safe="!~*'()"
        )
        cnonce = quote(cnonce, safe="!~*'()")
        snonce = quote(snonce, safe="!~*'()")
        query_string = (
            f"?Authorization={auth_token}"
            f"&X-unikey-context=web"
            f"&X-unikey-cnonce={cnonce}"
            f"&X-unikey-nonce={snonce}"
            f"&X-unikey-request-verification={verification}"
            f"&X-unikey-message-content-type=application%2Fjson&"
        )
        ssl_context = await self._get_ssl_context()
        try:
            async with websockets.connect(
                UNIKEY_WS_URL_BASE + "/v3/web/" + self._user_id + query_string,
                ping_interval=10,
                user_agent_header=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/108.0.0.0 Safari/537.36"
                ),
                ssl=ssl_context,
            ) as websocket:
                self._reconnect_attempts = 0
                self._websocket = websocket
                async for message in websocket:
                    self.__process_message(message)
        except websockets.ConnectionClosed:
            if not self._disconnecting:
                _LOGGER.error("WebSocket connection closed, retrying")
                await self.__websocket_reconnect()
        except Exception as ex:
            err_str = str(ex)
            if "401" in err_str:
                # The server rejected the connection because the token has
                # expired. Refresh it before the next reconnect attempt.
                _LOGGER.warning("WebSocket token expired (HTTP 401), refreshing and retrying")
                await self.__websocket_reconnect(refresh_token=True)
            else:
                _LOGGER.error("WebSocket error: %s, retrying", ex)
                await self.__websocket_reconnect()

    async def websocket_connect(self) -> asyncio.Task:
        """Start the websocket listener as a background task."""
        self._reconnect_attempts = 0
        self._disconnecting = False
        if self._websocket_task is not None:
            self._websocket_task.cancel()
        self._websocket_task = asyncio.create_task(self.__websocket_connect())
        return self._websocket_task

    def register_callback(self, callback: Callable) -> Callable:
        """Register a callback for lock state changes. Returns an unregister function."""
        self._callbacks.append(callback)

        def unregister():
            self._callbacks.remove(callback)

        return unregister

    def unregister_callback(self, callback: Callable) -> None:
        """Remove a previously registered callback."""
        self._callbacks.remove(callback)


class KevoLock:
    def __init__(
        self,
        api: KevoApi,
        lock_id: str,
        name: str,
        firmware: str,
        battery_level: float,
        state: str,
        brand: str,
    ):
        self._api = api
        self._lock_id = lock_id
        self._name = name
        self._firmware = firmware
        self._battery_level = battery_level
        self._brand = brand
        self._is_locking = False
        self._is_unlocking = False
        self._is_locked = state in ("Locked", "LockedBoltJam")
        self._is_jammed = state in ("BoltJam", "UnlockedBoltJam", "LockedBoltJam")

    @property
    def lock_id(self) -> str:
        return self._lock_id

    @property
    def name(self) -> str:
        return self._name

    @property
    def firmware(self) -> str:
        return self._firmware

    @firmware.setter
    def firmware(self, value: str):
        self._firmware = value

    @property
    def battery_level(self) -> float:
        return self._battery_level

    @battery_level.setter
    def battery_level(self, value: float):
        self._battery_level = value

    @property
    def is_locked(self) -> bool:
        return self._is_locked

    @is_locked.setter
    def is_locked(self, value: bool):
        self._is_locked = value

    @property
    def is_jammed(self) -> bool:
        return self._is_jammed

    @is_jammed.setter
    def is_jammed(self, value: bool):
        self._is_jammed = value

    @property
    def is_locking(self) -> bool:
        return self._is_locking

    @is_locking.setter
    def is_locking(self, value: bool):
        self._is_locking = value

    @property
    def is_unlocking(self) -> bool:
        return self._is_unlocking

    @is_unlocking.setter
    def is_unlocking(self, value: bool):
        self._is_unlocking = value

    @property
    def brand(self) -> str:
        return self._brand

    @brand.setter
    def brand(self, value: str):
        self._brand = value

    @property
    def api(self) -> KevoApi:
        return self._api

    async def lock(self):
        """Send a lock command."""
        return await self._api._api_post(
            f"/api/v2/users/{self._api._user_id}/locks/{self._lock_id}/commands",
            {"command": LOCK_STATE_LOCK},
        )

    async def unlock(self):
        """Send an unlock command."""
        return await self._api._api_post(
            f"/api/v2/users/{self._api._user_id}/locks/{self._lock_id}/commands",
            {"command": LOCK_STATE_UNLOCK},
        )
