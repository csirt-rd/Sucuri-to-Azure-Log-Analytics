#!/usr/bin/env python3
from datetime import datetime, timedelta
from os import getcwd, makedirs
import json
import hashlib
import base64
import hmac
import requests

# Azure Log Analytics
AZURE_WORKSPACE_ID = ""
AZURE_SHARED_KEY = ""
AZURE_LOG_TYPE = ""
# Sucuri Info
SUCURI_API_URL = "https://waf.sucuri.net/api?v2"
SUCURI_SITES = []

def daterange(start, end):    
    for n in range(int ((end - start).days)):
        yield start + timedelta(n)

LOG_FILE = '-'.join([
    '/'.join([getcwd(), 'logs', 'log']),
    datetime.now().strftime("%Y%m%d")
]) + '.txt' 
yesterday = datetime.now() - timedelta(1)

# Azure Log Analytics sh!t
def sucuri_to_log_analytics(): 
    try:    
        makedirs('/'.join([getcwd(), 'logs']))
    except FileExistsError: 
        pass
    for i in SUCURI_SITES: 
        if i["enabled"]:    
            try:
                body = requests.post(
                    SUCURI_API_URL, 
                    data={
                        "k": i["key"],  
                        "s": i["secret"],   
                        "a": "audit_trails",    
                        "date": yesterday.strftime("%Y-%m-%d"),    
                        "format": "json" 
                    }
                ).json()  
                if len(body) > 2 and len(body) > 6:   
                    for x in body:
                        try:
                            x["request_date"] = yesterday.strftime("%d-%b-%Y")
                            x["request_time"] = datetime.now().strftime("%H:%M:%S")
                            try:
                                del x['geo_location']
                            except KeyError:
                                continue
                            except TypeError:
                                pass
                        except:
                            pass
                    body = json.dumps(body)
                    with open(LOG_FILE, 'a', encoding='utf-8') as l:    
                        l.write(
                            ' '.join([
                                datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S:%f")[:-3],
                                '+00:00',
                                '[INF]',
                                'Getting 1000 logs from',
                                i["domain"],
                                'at',
                                datetime.now().strftime("%Y-%m-%d"),
                                '\n'
                            ])
                        )
                    l.close()   
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
                        'Log-Type': 'SucuriAuditTrails',
                        'x-ms-date': rfc1123date
                        }
                    )
                    with open(LOG_FILE, 'a', encoding='utf-8') as l:
                        l.write(
                            ' '.join([
                                datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S:%f")[:-3],
                                '+00:00',
                                '[INF]',
                                'Sending to',
                                'SucuriAuditTrails',
                                'LogAnalytics',
                                '\n'
                            ])
                        )
                    l.close()   
            except:
                continue

if __name__ == "__main__":
    sucuri_to_log_analytics()
