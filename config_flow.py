import voluptuous as vol
from homeassistant import config_entries
from .const import DOMAIN

class MyIntegrationConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input=None):
        errors = {}

        if user_input is not None:
            return self.async_create_entry(
                title="My Integration",
                data={"api_key": user_input["api_key"]},
            )

        data_schema = vol.Schema({
            vol.Required("api_key"): str,
        })

        return self.async_show_form(step_id="user", data_schema=data_schema, errors=errors)
