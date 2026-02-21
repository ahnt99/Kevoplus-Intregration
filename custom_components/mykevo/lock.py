from homeassistant.components.lock import LockEntity
from homeassistant.helpers.entity import DeviceInfo

from .const import DOMAIN


async def async_setup_entry(hass, entry, async_add_entities):

    coordinator = hass.data[DOMAIN][entry.entry_id]

    entities = [
        KevoLockEntity(coordinator, lock)
        for lock in coordinator.devices
    ]

    async_add_entities(entities)


class KevoLockEntity(LockEntity):

    def __init__(self, coordinator, lock):
        self.coordinator = coordinator
        self.lock = lock
        self._attr_name = lock.name
        self._attr_unique_id = lock.lock_id

    @property
    def is_locked(self):
        return self.lock.is_locked

    async def async_lock(self, **kwargs):
        await self.lock.lock()

    async def async_unlock(self, **kwargs):
        await self.lock.unlock()

    @property
    def device_info(self):

        return DeviceInfo(
            identifiers={(DOMAIN, self.lock.lock_id)},
            name=self.lock.name,
            manufacturer="Kwikset",
            model=self.lock.brand,
            sw_version=self.lock.firmware,
        )
