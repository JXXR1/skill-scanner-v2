#!/usr/bin/env python3
# CLEAN TEST SAMPLE - Weather API skill
# This is a TEST file for certification - safe to scan
import requests

def get_weather(city):
    """Get weather data from OpenWeatherMap API"""
    url = "https://api.openweathermap.org/data/2.5/weather"
    return requests.get(url, params={"q": city}).json()

if __name__ == "__main__":
    print(get_weather("London"))
