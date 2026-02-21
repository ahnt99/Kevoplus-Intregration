"""Support for Kevo Plus locks."""
from typing import Any

from aiokevoplus import KevoAuthError, KevoLock
from homeassistant.components.lock import LockEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import PlatformNotReady
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import KevoCoordinator
from .const import DOMAIN, MODEL


async def async_setup_entry(hass: HomeAssistant, config: ConfigEntry, add_entities):
    """Setup the lock platform."""
    coordinator: KevoCoordinator = hass.data[DOMAIN][config.entry_id]

    try:
        devices = await coordinator.get_devices()
    except Exception as ex:
        raise PlatformNotReady("Error getting devices") from ex

    entities = []
    for lock in devices:
        entities.append(
            KevoLockEntity(hass=hass, name="Lock", device=lock, coordinator=coordinator)
        )

    add_entities(entities)


class KevoLockEntity(LockEntity, CoordinatorEntity):
    """Representation of a Kevo Lock."""

    def __init__(
        self,
        hass: HomeAssistant,
        name: str,
        device: KevoLock,
        coordinator: KevoCoordinator,
    ) -> None:
        self._hass = hass
        self._device = device
        self._coordinator: KevoCoordinator = coordinator

        self._attr_name = name
        self._attr_has_entity_name = True

        self._attr_unique_id = device.lock_id + "_lock"
        self._attr_is_locked = device.is_locked
        self._attr_is_jammed = device.is_jammed
        self._attr_is_locking = device.is_locking
        self._attr_is_unlocking = device.is_unlocking

        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, device.lock_id)},
            manufacturer=device.brand,
            name=device.name,
            model=MODEL,
            sw_version=device.firmware,
        )

        super().__init__(coordinator)

    async def async_lock(self, **kwargs: Any) -> None:
        try:
            await self._device.lock()
        except KevoAuthError:
            await self._coordinator.entry.async_start_reauth(self._hass)

    async def async_unlock(self, **kwargs: Any) -> None:
        try:
            await self._device.unlock()
        except KevoAuthError:
            await self._coordinator.entry.async_start_reauth(self._hass)

    async def async_added_to_hass(self) -> None:
        self.async_on_remove(self._device.api.register_callback(self._update_data))

    @callback
    def _update_data(self, args):
        self._attr_is_locked = self._device.is_locked
        self._attr_is_locking = self._device.is_locking
        self._attr_is_unlocking = self._device.is_unlocking
        self._attr_is_jammed = self._device.is_jammed
        self.schedule_update_ha_state(False)
