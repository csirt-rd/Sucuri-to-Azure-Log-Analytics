<p align="center">
  <a href="https://github.com/othneildrew/Best-README-Template">
    <img width="946" alt="Ciberseguridad" src="https://user-images.githubusercontent.com/46871300/125079966-38ef8380-e092-11eb-9b5e-8bd0314d9274.PNG">
  </a>
 
   <h3 align="center">Transfiere eventos de Sucuri hacia Azure LogAnalytics</h3>

  <p>
  Script para transferir eventos del Sucuri Web Application Firewall (WAF) hacia Azure LogAnalytics, en formato JSON.
  </p>
</p>

## TLP: WHITE
---

#### Requerimientos:

* [Python3.8+](https://www.python.org/downloads/)

#### Como ejecutar:

Ejecute:

```
python3 -m venv env
```

En Windows, corra:

```
env\Scripts\activate.bat
```

En Unix o MacOS, corra:

```
source env/bin/activate
```

Luego ejecute:

```
pip install -r requirements.txt
```

Finalmente:

```
python3 app.py
```

#### Configuración:

```python
AZURE_WORKSPACE_ID = ...   # Cambiar al LogAnalytics Workspace ID correspondiente
AZURE_SHARED_KEY = ...     # Cambiar al LogAnalytics Workspace shared key correspondiente
AZURE_LOG_TYPE = ...       # Cambiar al nombre de Custom Log de LogAnalytics Workspace correspondiente
SUCURI_SITES = [
    {
        "secret": "...",   # Añadir tantos API_SECRET como le sea necesario.
        ...
    },
]
```

#### Referencias:

https://waf.sucuri.net/?apidocs
https://docs.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api
https://medium.com/slalom-build/reading-and-writing-to-azure-log-analytics-c78461056862
