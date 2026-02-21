class MyIntegrationApi:
    def __init__(self, api_key: str):
        self.api_key = api_key

    async def async_get_data(self):
        # TODO: Implement your API calls here
        return {"value": 42}
