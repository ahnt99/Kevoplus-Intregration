from homeassistant.components.sensor import SensorEntity
from homeassistant.helpers.update_coordinator import CoordinatorEntity
from .const import DOMAIN

async def async_setup_entry(hass, entry, async_add_entities):
    coordinator = hass.data[DOMAIN][entry.entry_id]
    async_add_entities([MySensor(coordinator)])

class MySensor(CoordinatorEntity, SensorEntity):
    _attr_name = "My Integration Sensor"

    def __init__(self, coordinator):
        super().__init__(coordinator)
        self._attr_unique_id = "my_integration_sensor"

    @property
    def native_value(self):
        return self.coordinator.data.get("value")
