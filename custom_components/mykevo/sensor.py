from homeassistant.components.sensor import SensorEntity
from homeassistant.helpers.entity import DeviceInfo

from .const import DOMAIN


async def async_setup_entry(hass, entry, async_add_entities):

    coordinator = hass.data[DOMAIN][entry.entry_id]

    entities = []

    for lock in coordinator.devices:
        entities.append(KevoBatterySensor(coordinator, lock))
        entities.append(KevoFirmwareSensor(coordinator, lock))

    async_add_entities(entities)


class BaseSensor(SensorEntity):

    def __init__(self, coordinator, lock):
        self.coordinator = coordinator
        self.lock = lock

    @property
    def device_info(self):
        return DeviceInfo(
            identifiers={(DOMAIN, self.lock.lock_id)},
        )


class KevoBatterySensor(BaseSensor):

    @property
    def name(self):
        return f"{self.lock.name} Battery"

    @property
    def unique_id(self):
        return f"{self.lock.lock_id}_battery"

    @property
    def native_value(self):
        return round(self.lock.battery_level * 100)


class KevoFirmwareSensor(BaseSensor):

    @property
    def name(self):
        return f"{self.lock.name} Firmware"

    @property
    def unique_id(self):
        return f"{self.lock.lock_id}_firmware"

    @property
    def native_value(self):
        return self.lock.firmware
