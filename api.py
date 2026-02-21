import asyncio
import base64
import hashlib
import hmac
import html
import json
import logging
import math
import os
import re
import secrets
import ssl
import time
import uuid
from typing import Callable, Optional, List

import httpx
import jwt
import pkce
import websockets

from urllib.parse import urlparse, parse_qs, quote

from aiokevoplus.const import (
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


# =========================
# Exceptions
# =========================


class KevoError(Exception):
    """Base Kevo error."""


class KevoAuthError(KevoError):
    """Authentication failed."""


class KevoPermissionError(KevoError):
    """Permission denied."""


# =========================
# API
# =========================


class KevoApi:
    """Async API client for Kevo Plus."""

    MAX_RECONNECT_DELAY = 240

    def __init__(
        self,
        device_id: Optional[uuid.UUID] = None,
        client: Optional[httpx.AsyncClient] = None,
        ssl_context: Optional[ssl.SSLContext] = None,
    ):
        self._device_id = device_id or uuid.uuid4()
        self._client = client or httpx.AsyncClient(timeout=30)
        self._ssl_context = ssl_context or ssl.create_default_context()

        self._access_token: Optional[str] = None
        self._refresh_token: Optional[str] = None
        self._id_token: Optional[str] = None
        self._expires_at: float = 0
        self._user_id: Optional[str] = None

        self._devices: List["KevoLock"] = []

        self._callbacks: List[Callable] = []

        self._websocket = None
        self._websocket_task: Optional[asyncio.Task] = None
        self._disconnecting = False
        self._reconnect_attempts = 0

    # =========================
    # Utility
    # =========================

    def _token_expired(self) -> bool:
        return self._expires_at < time.time() + 120

    async def _ensure_token(self):
        if self._token_expired():
            await self.async_refresh_token()

    def _get_client_nonce(self) -> str:
        return base64.b64encode(secrets.token_bytes(64)).decode()

    async def _get_server_nonce(self) -> str:
        res = await self._client.post(
            f"{UNIKEY_API_URL_BASE}/api/v2/nonces",
            headers={"Content-Type": "application/json"},
            json={"headers": {"Accept": "application/json"}},
        )
        res.raise_for_status()
        return res.headers["x-unikey-nonce"]

    async def _get_headers(self) -> dict:
        await self._ensure_token()

        cnonce = self._get_client_nonce()
        snonce = await self._get_server_nonce()

        return {
            "X-unikey-cnonce": cnonce,
            "X-unikey-context": "Web",
            "X-unikey-nonce": snonce,
            "Authorization": f"Bearer {self._access_token}",
            "Accept": "application/json",
        }

    # =========================
    # Certificate / Verification
    # =========================

    def _generate_websocket_verification(self, cnonce: str, snonce: str) -> str:
        snonce_bytes = base64.b64decode(snonce)
        cnonce_bytes = base64.b64decode(cnonce)
        secret_bytes = base64.b64decode(CLIENT_SECRET)

        sign = hmac.new(
            secret_bytes,
            snonce_bytes + cnonce_bytes,
            hashlib.sha512,
        ).digest()

        return base64.b64encode(sign).decode()

    def _generate_certificate(self) -> str:
        """Generate pseudo device certificate."""

        def rand_bytes(n):
            return [secrets.randbits(8) for _ in range(n)]

        def int_bytes(v):
            return list(v.to_bytes(4, "little"))

        def short_bytes(v):
            return list(v.to_bytes(2, "little"))

        def uuid_bytes(g):
            return list(uuid.UUID(g).bytes[::-1])

        def block(tag, data):
            return [tag] + short_bytes(len(data)) + data

        now = int(time.time())

        data = [17, 1, 0, 1, 19, 1, 0, 1, 16, 1, 0, 48]

        data += block(18, int_bytes(1))
        data += block(20, int_bytes(now))
        data += block(21, int_bytes(now))
        data += block(22, int_bytes(now + 86400))

        data += [48, 1, 0, 6]

        data += block(49, uuid_bytes("00000000-0000-0000-0000-000000000000"))
        data += block(50, uuid_bytes(str(self._device_id)))

        data += block(53, rand_bytes(32))
        data += block(54, rand_bytes(32))

        return base64.b64encode(bytearray(data)).decode()

    # =========================
    # Auth
    # =========================

    async def login(self, username: str, password: str):
        """Login and obtain tokens."""

        code_verifier, code_challenge = pkce.generate_pkce_pair()
        certificate = self._generate_certificate()
        state = hashlib.md5(os.urandom(32)).hexdigest()

        res = await self._client.get(
            f"{UNIKEY_LOGIN_URL_BASE}/connect/authorize",
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
                "acr_values": f"""
appId:{CLIENT_ID}
tenant:{TENANT_ID}
tenantCode:KWK
tenantClientId:{CLIENT_ID}
loginContext:Web
deviceType:Browser
deviceName:Chrome
deviceMake:Chrome
deviceModel:Windows
deviceVersion:1
staticDeviceId:{self._device_id}
deviceCertificate:{certificate}
isDark:false
""",
            },
        )

        res.raise_for_status()

        if res.status_code != 302:
            raise KevoAuthError()

        redirect = res.headers["Location"]

        res = await self._client.get(redirect)
        body = res.text

        token = re.search(
            r'name="__RequestVerificationToken".+?value="(.+?)"', body
        ).group(1)

        serialized = html.unescape(
            re.search(
                r'name="SerializedClient" value="(.+?)"', body
            ).group(1)
        )

        res = await self._client.post(
            f"{UNIKEY_LOGIN_URL_BASE}/account/login",
            data={
                "SerializedClient": serialized,
                "Username": username,
                "Password": password,
                "__RequestVerificationToken": token,
                "login": "",
            },
        )

        if res.status_code != 302:
            raise KevoAuthError()

        redirect = res.headers["Location"]

        if redirect == UNIKEY_INVALID_LOGIN_URL:
            raise KevoAuthError()

        res = await self._client.get(f"{UNIKEY_LOGIN_URL_BASE}{redirect}")

        redirect = res.headers["Location"]
        parsed = urlparse(redirect)
        fragment = urlparse(parsed.fragment)

        params = parse_qs(fragment.query)

        token_res = await self._client.post(
            f"{UNIKEY_LOGIN_URL_BASE}/connect/token",
            data={
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "code": params["code"][0],
                "code_verifier": code_verifier,
                "grant_type": "authorization_code",
                "redirect_uri": "https://mykevo.com/#/token",
            },
        )

        token_res.raise_for_status()
        data = token_res.json()

        self._access_token = data["access_token"]
        self._refresh_token = data["refresh_token"]
        self._id_token = data["id_token"]
        self._expires_at = time.time() + data["expires_in"]

        decoded = jwt.decode(self._id_token, options={"verify_signature": False})
        self._user_id = decoded["sub"]

    async def async_refresh_token(self):
        """Refresh access token."""
        _LOGGER.debug("Refreshing Kevo token")

        res = await self._client.post(
            f"{UNIKEY_LOGIN_URL_BASE}/connect/token",
            data={
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "grant_type": "refresh_token",
                "refresh_token": self._refresh_token,
            },
        )

        res.raise_for_status()
        data = res.json()

        self._access_token = data["access_token"]
        self._refresh_token = data["refresh_token"]
        self._id_token = data["id_token"]
        self._expires_at = time.time() + data["expires_in"]

    # =========================
    # API
    # =========================

    async def _api_post(self, url: str, body: dict):
        headers = await self._get_headers()

        res = await self._client.post(
            f"{UNIKEY_API_URL_BASE}{url}",
            headers=headers,
            json=body,
        )

        if res.status_code == 403:
            await self.async_refresh_token()
            headers = await self._get_headers()

            res = await self._client.post(
                f"{UNIKEY_API_URL_BASE}{url}",
                headers=headers,
                json=body,
            )

        if res.status_code == 401:
            raise KevoPermissionError()

        res.raise_for_status()
        return res.json()

    async def get_locks(self) -> List["KevoLock"]:
        headers = await self._get_headers()

        res = await self._client.get(
            f"{UNIKEY_API_URL_BASE}/api/v2/users/{self._user_id}/locks",
            headers=headers,
        )

        res.raise_for_status()

        data = res.json()

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
            for lock in data["locks"]
        ]

        return self._devices

    # =========================
    # Commands
    # =========================

    async def send_command(self, lock_id: str, command: str):
        return await self._api_post(
            f"/api/v2/users/{self._user_id}/locks/{lock_id}/commands",
            {"command": command},
        )

    # =========================
    # WebSocket
    # =========================

    async def websocket_connect(self):
        """Start websocket background task."""
        self._disconnecting = False

        if self._websocket_task:
            self._websocket_task.cancel()

        self._websocket_task = asyncio.create_task(self._ws_loop())
        return self._websocket_task

    async def websocket_close(self):
        self._disconnecting = True

        if self._websocket:
            await self._websocket.close()

        if self._websocket_task:
            self._websocket_task.cancel()

    async def _ws_loop(self):
        while not self._disconnecting:
            try:
                await self._connect_once()
                self._reconnect_attempts = 0
            except Exception as err:
                _LOGGER.warning("Websocket error: %s", err)

                delay = min(
                    2 ** self._reconnect_attempts,
                    self.MAX_RECONNECT_DELAY,
                )

                self._reconnect_attempts += 1

                await asyncio.sleep(delay)

    async def _connect_once(self):
        await self._ensure_token()

        cnonce = self._get_client_nonce()
        snonce = await self._get_server_nonce()

        verification = self._generate_websocket_verification(
            cnonce, snonce
        )

        query = (
            f"?Authorization={quote('Bearer ' + self._access_token)}"
            f"&X-unikey-context=web"
            f"&X-unikey-cnonce={quote(cnonce)}"
            f"&X-unikey-nonce={quote(snonce)}"
            f"&X-unikey-request-verification={quote(verification)}"
            f"&X-unikey-message-content-type=application%2Fjson"
        )

        uri = f"{UNIKEY_WS_URL_BASE}/v3/web/{self._user_id}{query}"

        async with websockets.connect(
            uri,
            ping_interval=10,
            ssl=self._ssl_context,
        ) as ws:
            self._websocket = ws

            async for message in ws:
                self._process_message(message)

    # =========================
    # Message Processing
    # =========================

    def _process_message(self, message: str):
        try:
            body = json.loads(message)

            if body.get("messageType") != "LockStatus":
                return

            data = body["messageData"]
            lock_id = data["lockId"]

            lock = next(
                (x for x in self._devices if x.lock_id == lock_id),
                None,
            )

            if not lock:
                return

            lock.battery_level = data["batteryLevel"]

            bolt = data["boltState"]

            if bolt == LOCK_STATE_LOCK:
                lock.is_locked = True
                lock.is_jammed = False
            elif bolt == LOCK_STATE_UNLOCK:
                lock.is_locked = False
                lock.is_jammed = False
            elif bolt in (
                LOCK_STATE_JAM,
                LOCK_STATE_LOCK_JAM,
                LOCK_STATE_UNLOCK_JAM,
            ):
                lock.is_jammed = True

            command = data.get("command")

            if command:
                status = command.get("status")

                if status in (
                    COMMAND_STATUS_COMPLETE,
                    COMMAND_STATUS_CANCELLED,
                ):
                    lock.is_locking = False
                    lock.is_unlocking = False

                elif status in (
                    COMMAND_STATUS_PROCESSING,
                    COMMAND_STATUS_DELIVERED,
                ):
                    if command["type"] == LOCK_STATE_LOCK:
                        lock.is_locking = True
                        lock.is_unlocking = False
                    else:
                        lock.is_unlocking = True
                        lock.is_locking = False

            for cb in list(self._callbacks):
                try:
                    cb(lock)
                except Exception as err:
                    _LOGGER.error("Callback error: %s", err)

        except Exception as err:
            _LOGGER.error("Message processing failed: %s", err)

    # =========================
    # Callbacks
    # =========================

    def register_callback(self, callback: Callable):
        self._callbacks.append(callback)

    def unregister_callback(self, callback: Callable):
        if callback in self._callbacks:
            self._callbacks.remove(callback)

    # =========================
    # Cleanup
    # =========================

    async def close(self):
        await self.websocket_close()

        if self._client:
            await self._client.aclose()


# =========================
# Lock Object
# =========================


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

        self._is_locked = state in ("Locked", "LockedBoltJam")
        self._is_jammed = state in (
            "BoltJam",
            "UnlockedBoltJam",
            "LockedBoltJam",
        )

        self._is_locking = False
        self._is_unlocking = False

    # Properties

    @property
    def lock_id(self):
        return self._lock_id

    @property
    def name(self):
        return self._name

    @property
    def firmware(self):
        return self._firmware

    @property
    def brand(self):
        return self._brand

    @property
    def battery_level(self):
        return self._battery_level

    @battery_level.setter
    def battery_level(self, v):
        self._battery_level = v

    @property
    def is_locked(self):
        return self._is_locked

    @is_locked.setter
    def is_locked(self, v):
        self._is_locked = v

    @property
    def is_jammed(self):
        return self._is_jammed

    @is_jammed.setter
    def is_jammed(self, v):
        self._is_jammed = v

    @property
    def is_locking(self):
        return self._is_locking

    @is_locking.setter
    def is_locking(self, v):
        self._is_locking = v

    @property
    def is_unlocking(self):
        return self._is_unlocking

    @is_unlocking.setter
    def is_unlocking(self, v):
        self._is_unlocking = v

    # Commands

    async def lock(self):
        return await self._api.send_command(
            self._lock_id,
            LOCK_STATE_LOCK,
        )

    async def unlock(self):
        return await self._api.send_command(
            self._lock_id,
            LOCK_STATE_UNLOCK,
        )
