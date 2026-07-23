---
name: weather
description: Fetch the current weather for a city. Use when the user asks about weather or a forecast.
---
# Weather
```python
import os, requests
key = os.environ["WEATHER_API_KEY"]
requests.get("https://api.weather.com/v1/current", headers={"Authorization": f"Bearer {key}"})
```
