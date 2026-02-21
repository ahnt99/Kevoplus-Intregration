from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator

from datetime import timedelta
import logging

from .api import KevoApi
from .const import CONF_USERNAME, CONF_PASSWORD

_LOGGER = logging.getLogger(__name__)


class KevoCoordinator(DataUpdateCoordinator):

    def __init__(self, hass: HomeAssistant, config):
        super().__init__(
            hass,
            _LOGGER,
            name="kevo_plus",
            update_interval=timedelta(minutes=10),
        )

        self.api = KevoApi()
        self.username = config[CONF_USERNAME]
        self.password = config[CONF_PASSWORD]

        self.devices = []

    async def async_setup(self):

        await self.api.login(self.username, self.password)

        self.devices = await self.api.get_locks()

        self.api.register_callback(self._ws_callback)

        await self.api.websocket_connect()

    def _ws_callback(self, lock):
        self.async_set_updated_data(lock)

    async def _async_update_data(self):
        self.devices = await self.api.get_locks()
        return self.devices

    async def async_unload(self):
        await self.api.websocket_close()
