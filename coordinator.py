from datetime import timedelta
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from .api import MyIntegrationApi
from .const import DOMAIN, DEFAULT_SCAN_INTERVAL

class MyDataUpdateCoordinator(DataUpdateCoordinator):
    def __init__(self, hass: HomeAssistant, entry: ConfigEntry):
        self.api = MyIntegrationApi(entry.data["api_key"])
        super().__init__(
            hass,
            logger=hass.logger,
            name=DOMAIN,
            update_interval=timedelta(seconds=DEFAULT_SCAN_INTERVAL),
        )

    async def _async_update_data(self):
        try:
            return await self.api.async_get_data()
        except Exception as err:
            raise UpdateFailed(f"Error fetching data: {err}") from err
