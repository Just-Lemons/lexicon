import requests
from django.shortcuts import render

def home(request):
    return render(request, "home.html")

def scan_view(request):
    url = request.GET.get("url")

    data = None

    if url:
        res = requests.get("http://127.0.0.1:8001/scan", params={"url": url})
        data = res.json()

    return render(request, "dashboard.html", {"data": data})