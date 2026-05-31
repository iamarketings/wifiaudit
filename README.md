# wifiaudit

Outil d'audit Wi-Fi Windows — CLI en C++17 (architecture MVC)

## Fonctionnalités
- Scan des réseaux Wi-Fi avec détection WPS, vendor OUI, sécurité
- Scan continu en background
- Connexion à un réseau
- Mode moniteur (carte compatible requise)
- Serveur API REST HTTP (port 8080)
- Server-Sent Events pour mises à jour temps réel

## Pré-requis
- Windows 10/11 (x64)
- [Npcap](https://npcap.com/) installé
- Privilèges administrateur recommandés
- Visual Studio Build Tools (MSVC C++17)

## Compilation

```powershell
$env:INCLUDE = "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\14.50.35717\include;" +
               "C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\ucrt;" +
               "C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um;" +
               "C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\shared"

$env:LIB = "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\14.50.35717\lib\x64;" +
           "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\ucrt\x64;" +
           "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x64"

cl /nologo /utf-8 /std:c++17 /EHsc /Fe:build\wificli.exe /Fo:build\ `
  src\main.cpp src\model\WifiManager.cpp src\model\MonitorMode.cpp `
  src\view\Display.cpp src\controller\ApiServer.cpp `
  src\utils\Wps.cpp src\utils\oui_data.cpp `
  /link wlanapi.lib ole32.lib iphlpapi.lib ws2_32.lib advapi32.lib
```

## Lancement

```
build\wificli.exe
```

## API REST

| Endpoint | Description |
|----------|-------------|
| `GET /interfaces` | Liste des interfaces WLAN |
| `GET /aps` | APs en cache |
| `GET /scan?guid=<GUID>` | Déclenche un scan |
| `POST /monitor` | Active/désactive le mode moniteur |
| `POST /connect` | Connexion réseau |
| `GET /stream` | Server-Sent Events (live APs) |
