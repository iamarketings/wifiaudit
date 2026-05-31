# CLAUDE.md

Outil d'audit Wi-Fi Windows — `wificli` v2.0 (C++17, MVC)

---

## Structure du projet

```
projetx/
├── build/                     — binaires compilés (wificli.exe, *.obj)
├── src/
│   ├── main.cpp               — point d'entrée + vérification dépendances
│   ├── model/
│   │   ├── WifiManager.hpp/.cpp   — scan, connexion, interfaces (wlanapi)
│   │   └── MonitorMode.hpp/.cpp   — monitor mode via Npcap/Packet.dll
│   ├── view/
│   │   └── Display.hpp/.cpp       — rendu terminal ANSI
│   ├── controller/
│   │   └── ApiServer.hpp/.cpp     — serveur HTTP REST (port 8080)
│   └── utils/
│       ├── OuiLookup.hpp          — interface lookup OUI (vendor)
│       ├── oui_data.cpp           — base de données OUI (39 478 entrées, auto-généré)
│       ├── Wps.hpp/.cpp           — détection WPS dans les IEs 802.11
│       └── gen_oui.py             — script de régénération de oui_data.cpp
└── CLAUDE.md
```

---

## Compilation

### Environnement MSVC (Visual Studio 18 BuildTools)

```powershell
$env:INCLUDE = "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\14.50.35717\include;" +
               "C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\ucrt;" +
               "C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um;" +
               "C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\shared"

$env:LIB = "C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\14.50.35717\lib\x64;" +
           "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\ucrt\x64;" +
           "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.26100.0\um\x64"

cl /nologo /utf-8 /std:c++17 /EHsc /Fe:build\wificli.exe /Fo:build\ `
  src\main.cpp `
  src\model\WifiManager.cpp `
  src\model\MonitorMode.cpp `
  src\view\Display.cpp `
  src\controller\ApiServer.cpp `
  src\utils\Wps.cpp `
  src\utils\oui_data.cpp `
  /link wlanapi.lib ole32.lib iphlpapi.lib ws2_32.lib advapi32.lib
```

### Lancement (admin recommandé)

```
build\wificli.exe
```

---

## Dépendances runtime

| Dépendance | Requis | Détecté au démarrage |
|------------|--------|---------------------|
| Service WLAN AutoConfig | **Oui** (scan) | Oui — bloquant si absent |
| Npcap (Packet.dll) | Pour monitor mode | Oui — avertissement si absent |
| Privilèges admin | Pour Npcap/monitor | Oui — avertissement si absent |

---

## API REST (port 8080)

| Méthode | Endpoint | Description |
|---------|----------|-------------|
| GET | `/` | Index (liste des endpoints) |
| GET | `/interfaces` | Liste des interfaces WLAN |
| GET | `/aps` | APs en cache |
| GET | `/scan?guid=<GUID>` | Déclenche un scan |
| POST | `/monitor` | Active/désactive le mode moniteur |
| POST | `/connect` | Connexion à un réseau |
| GET | `/stream` | Server-Sent Events (mises à jour APs) |

---

## Limitations connues

- **Monitor mode** : la carte USB 802.11n (Ralink `netr28ux.inf`, 2007) ne supporte
  pas `OID_802_11_MONITOR_MODE`. Npcap 1.x a supprimé `PacketSetOid`/`PacketQueryOid`.
  Le mode moniteur **ne fonctionne pas** sur cette carte sous Windows.
  Solutions : carte Alfa AWUS036ACH / Kali Linux / WSL2+USB-IP.
