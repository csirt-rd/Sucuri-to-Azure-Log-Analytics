#!/usr/bin/env python3
import threading, requests, json, hashlib, base64, hmac
from datetime import datetime, timedelta

# Azure Log Analytics
AZURE_WORKSPACE_ID = "..."
AZURE_SHARED_KEY = "..."
AZURE_LOG_TYPE = "..."
# Sucuri Info
SUCURI_API_URL = "https://waf.sucuri.net/api?v2"
SUCURI_API_KEY = "..."
SUCURI_SITES = [
    ...
]

def sucuri_to_log_analytics(key, secret, date, mutex):
    mutex.acquire()
    body = requests.post(
        SUCURI_API_URL,
        data={
            "k": key,
            "s": secret,
            "a": "audit_trails",
            "date": date.strftime("%Y-%m-%d"),
            "format": "json"
        }
    ).json()
    if len(body) > 2 and len(body) > 6:
        for o in body:
            try:
                o["request_date"] = date.strftime("%d-%b-%Y")
                o["request_time"] = datetime.now().strftime("%H:%M:%S")
            except:
                pass
            try:
                del o['geo_location']
            except KeyError:
                continue
            except TypeError:
                pass
        body = json.dumps(body)
        rfc1123date = datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        x_headers = 'x-ms-date:' + rfc1123date
        authorization = "SharedKey {}:{}".format(
            AZURE_WORKSPACE_ID,
            base64.b64encode(
                hmac.new(
                    base64.b64decode(
                        AZURE_SHARED_KEY
                    ),
                    bytes(
                        '\n'.join([
                            'POST',
                            str(len(body)),
                            'application/json',
                            x_headers,
                            '/api/logs']),
                        encoding='utf-8'),
                    digestmod=hashlib.sha256
                ).digest()
            ).decode()
        )
        requests.post(
            f"https://{AZURE_WORKSPACE_ID}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01",
            data=body,
            headers= {
            'content-type': 'application/json',
            'Authorization': authorization,
            'Log-Type': AZURE_LOG_TYPE,
            'x-ms-date': rfc1123date
            }
        )
    mutex.release()

if __name__ == "__main__":
    yesterday = datetime.now() - timedelta(1)
    threads = list()
    mtx = threading.Lock()
    for i in SUCURI_SITES:
        data = requests.post(
            SUCURI_API_URL,
            data={
                "k": SUCURI_API_KEY,
                "s": i['secret'],
                "a": "show_settings"
            }
        ).json()
        i['enabled'] = True if data['output']['proxy_active'] == 1 else False
        i['domain'] = data['output']['domain']
        i['key'] = SUCURI_API_KEY
        if i["enabled"]:
            x = threading.Thread(
                target=sucuri_to_log_analytics,
                args=(
                    i["key"],
                    i["secret"],
                    yesterday,
                    mtx
                ), daemon=True
            )
            threads.append(x)
            x.start()
    for index, thread in enumerate(threads):
        thread.join()
