"""The Kevo Plus integration."""
from __future__ import annotations

import asyncio
import hashlib
import logging
import uuid

from .api import KevoApi, KevoAuthError
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CONF_PASSWORD,
    CONF_USERNAME,
    EVENT_HOMEASSISTANT_STOP,
    Platform,
)
from homeassistant.core import Event, HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from .const import CONF_LOCKS, DOMAIN

_LOGGER = logging.getLogger(__name__)

PLATFORMS: list[Platform] = [Platform.LOCK, Platform.SENSOR]


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up Kevo Plus from a config entry."""

    hass.data.setdefault(DOMAIN, {})
    password = entry.data.get(CONF_PASSWORD)
    device_id = uuid.UUID(bytes=hashlib.md5(password.encode()).digest())
    client = KevoApi(device_id)

    try:
        await client.login(entry.data.get(CONF_USERNAME), password)
    except KevoAuthError as auth_ex:
        raise ConfigEntryAuthFailed("Invalid credentials") from auth_ex
    except Exception as ex:
        raise ConfigEntryNotReady("Error connecting to Kevo server") from ex

    locks = entry.options.get(CONF_LOCKS)
    if locks is None:
        locks = entry.data.get(CONF_LOCKS)
    coordinator = KevoCoordinator(hass, client, entry, locks)
    try:
        await coordinator.get_devices()
    except Exception as ex:
        raise ConfigEntryNotReady("Failed to get Kevo devices") from ex

    hass.data[DOMAIN][entry.entry_id] = coordinator

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    await coordinator.async_config_entry_first_refresh()
    entry.async_on_unload(entry.add_update_listener(update_listener))

    async def _async_disconnect(event: Event) -> None:
        """Disconnect from Websocket."""
        await hass.data[DOMAIN][entry.entry_id].api.websocket_close()

    entry.async_on_unload(
        hass.bus.async_listen_once(EVENT_HOMEASSISTANT_STOP, _async_disconnect)
    )

    return True


async def update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Reload to update options."""
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    if unload_ok := await hass.config_entries.async_unload_platforms(entry, PLATFORMS):
        await hass.data[DOMAIN][entry.entry_id].api.websocket_close()
        hass.data[DOMAIN].pop(entry.entry_id)

    return unload_ok


class KevoCoordinator(DataUpdateCoordinator):
    """Kevo Data Coordinator."""

    def __init__(
        self, hass: HomeAssistant, api: KevoApi, entry: ConfigEntry, locks: list[str]
    ) -> None:
        """Initialize the coordinator."""
        super().__init__(
            hass,
            _LOGGER,
            # Name of the data. For logging purposes.
            name="Kevo",
        )
        self.api = api
        self.hass = hass
        self.entry = entry
        self._devices = None
        self._device_lock = asyncio.Lock()
        self._selected_locks = locks

    async def get_all_devices(self) -> list:
        """Retrieve all devices available in the api."""
        return await self.api.get_locks()

    async def get_devices(self) -> list:
        """Retrieve the devices associated with the coordinator."""
        async with self._device_lock:
            if self._devices is None:
                try:
                    self._devices = [
                        device
                        for device in await self.api.get_locks()
                        if device.lock_id in self._selected_locks
                    ]
                except KevoAuthError:
                    await self.entry.async_start_reauth(self.hass)
            return self._devices

    async def _async_update_data(self):
        await self.api.websocket_connect()
