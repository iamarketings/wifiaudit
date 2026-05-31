#include "WifiManager.hpp"
#include "../utils/OuiLookup.hpp"
#include "../utils/Wps.hpp"
#include "MonitorMode.hpp"
#include "../view/Display.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>

/* ---- Scan tuning ---- */
#define SCAN_POLL_MAX      20
#define SCAN_POLL_MS       400
#define SCAN_INITIAL_MS    2000
#define SCAN_STABLE_ROUNDS 2   /* stop when AP count is stable N times */

/* ============================================================
 * Helpers
 * ============================================================ */

static std::string guidToString(const GUID& g) {
    char buf[64];
    snprintf(buf, sizeof(buf),
        "%08lX-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
        g.Data1, g.Data2, g.Data3,
        g.Data4[0], g.Data4[1],
        g.Data4[2], g.Data4[3],
        g.Data4[4], g.Data4[5],
        g.Data4[6], g.Data4[7]);
    return buf;
}

static std::string bssidToString(const DOT11_MAC_ADDRESS& mac) {
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return buf;
}

static std::string wstrToUtf8(const wchar_t* wstr, int len = -1) {
    if (!wstr) return {};
    int wlen = (len < 0) ? (int)wcslen(wstr) : len;
    if (wlen == 0) return {};
    int needed = WideCharToMultiByte(CP_UTF8, 0, wstr, wlen, NULL, 0, NULL, NULL);
    if (needed <= 0) return {};
    std::string result((size_t)needed, '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr, wlen, &result[0], needed, NULL, NULL);
    return result;
}

/* ============================================================
 * WifiManager
 * ============================================================ */

WifiManager::WifiManager()
    : m_handle(NULL)
    , m_version(0)
    , m_scanThread(NULL)
    , m_scanRunning(false)
{
    DWORD ret = WlanOpenHandle(2, NULL, &m_version, &m_handle);
    if (ret != ERROR_SUCCESS) {
        printf("[-] WlanOpenHandle echec: %lu\n", ret);
        m_handle = NULL;
    } else {
        printf("[+] WifiManager initialise (API v%lu)\n", m_version);
    }
    InitializeCriticalSection(&m_apLock);
}

WifiManager::~WifiManager() {
    stopBackgroundScan();
    if (m_handle) WlanCloseHandle(m_handle, NULL);
    DeleteCriticalSection(&m_apLock);
}

/* ---- Interface enumeration ---- */

std::vector<InterfaceInfo> WifiManager::getInterfaces() const {
    std::vector<InterfaceInfo> result;
    if (!m_handle) return result;

    PWLAN_INTERFACE_INFO_LIST pList = NULL;
    if (WlanEnumInterfaces(m_handle, NULL, &pList) != ERROR_SUCCESS || !pList)
        return result;

    for (DWORD i = 0; i < pList->dwNumberOfItems; ++i) {
        InterfaceInfo info;
        info.index = (int)i;
        info.name  = wstrToUtf8(pList->InterfaceInfo[i].strInterfaceDescription);
        info.guid  = guidToString(pList->InterfaceInfo[i].InterfaceGuid);
        info.state = pList->InterfaceInfo[i].isState;
        result.push_back(info);
    }

    WlanFreeMemory(pList);
    return result;
}

bool WifiManager::resolveInterface(int idx, GUID& outGuid, std::string& outName) const {
    if (!m_handle) return false;

    PWLAN_INTERFACE_INFO_LIST pList = NULL;
    if (WlanEnumInterfaces(m_handle, NULL, &pList) != ERROR_SUCCESS || !pList)
        return false;

    bool found = false;
    if ((DWORD)idx < pList->dwNumberOfItems) {
        outGuid = pList->InterfaceInfo[idx].InterfaceGuid;
        outName = wstrToUtf8(pList->InterfaceInfo[idx].strInterfaceDescription);
        found   = true;
    }
    WlanFreeMemory(pList);
    return found;
}

/* ---- Synchronous scan ---- */

std::vector<APInfo> WifiManager::scan(const GUID& guid, bool wait) {
    std::vector<APInfo> result;
    if (!m_handle) return result;

    DWORD dwResult = WlanScan(m_handle, &guid, NULL, NULL, NULL);
    if (dwResult != ERROR_SUCCESS) {
        printf("[-] WlanScan echec: %lu\n", dwResult);
        return result;
    }
    if (!wait) return result;

    Sleep(SCAN_INITIAL_MS);

    PWLAN_BSS_LIST              pBssList = NULL;
    PWLAN_AVAILABLE_NETWORK_LIST pNetList = NULL;
    DWORD bestCount    = 0;
    int   stableRounds = 0;

    for (int tries = 0; tries < SCAN_POLL_MAX; ++tries) {
        if (pBssList) { WlanFreeMemory(pBssList); pBssList = NULL; }
        if (pNetList) { WlanFreeMemory(pNetList);  pNetList = NULL; }

        dwResult = WlanGetNetworkBssList(m_handle, &guid, NULL,
                        dot11_BSS_type_any, TRUE, NULL, &pBssList);
        if (dwResult != ERROR_SUCCESS) { Sleep(SCAN_POLL_MS); continue; }

        dwResult = WlanGetAvailableNetworkList(m_handle, &guid, 0, NULL, &pNetList);
        if (dwResult != ERROR_SUCCESS) { Sleep(SCAN_POLL_MS); continue; }

        DWORD count = pBssList->dwNumberOfItems;
        if (count > bestCount) {
            bestCount    = count;
            stableRounds = 0;
        } else {
            if (++stableRounds >= SCAN_STABLE_ROUNDS && bestCount > 0)
                break;
        }
        Sleep(SCAN_POLL_MS);
    }

    if (!pBssList || !pNetList) {
        if (pBssList) WlanFreeMemory(pBssList);
        if (pNetList) WlanFreeMemory(pNetList);
        return result;
    }

    /* Build SSID -> security map */
    struct SecInfo { bool sec; unsigned long auth; unsigned long cipher; };
    std::map<std::string, SecInfo> secMap;

    for (DWORD i = 0; i < pNetList->dwNumberOfItems; ++i) {
        auto& net = pNetList->Network[i];
        const char* ssidPtr = (const char*)net.dot11Ssid.ucSSID;
        std::string ssid(ssidPtr, ssidPtr + net.dot11Ssid.uSSIDLength);
        secMap[ssid] = { net.bSecurityEnabled != FALSE,
                         (unsigned long)net.dot11DefaultAuthAlgorithm,
                         (unsigned long)net.dot11DefaultCipherAlgorithm };
    }

    /* Parse BSS entries */
    for (DWORD i = 0; i < pBssList->dwNumberOfItems; ++i) {
        auto& bss = pBssList->wlanBssEntries[i];

        APInfo ap;
        ap.bssid   = bssidToString(bss.dot11Bssid);
        ap.channel = freqToChannel(bss.ulChCenterFrequency);
        ap.rssi    = (long)bss.lRssi;
        ap.quality = signalQuality(ap.rssi);
        const char* ssidPtr = (const char*)bss.dot11Ssid.ucSSID;
        ap.ssid.assign(ssidPtr, ssidPtr + bss.dot11Ssid.uSSIDLength);
        if (ap.ssid.empty()) ap.ssid = "<hidden>";

        ap.vendor = ouiLookup(bss.dot11Bssid);

        auto it = secMap.find(ap.ssid);
        ap.security = (it != secMap.end())
            ? encryptionString(it->second.sec, it->second.auth, it->second.cipher)
            : "?";

        if (bss.ulIeOffset > 0 && bss.ulIeSize > 0) {
            const uint8_t* ieData = (const uint8_t*)&bss + bss.ulIeOffset;
            ap.wps = hasWPS(ieData, bss.ulIeSize);
        } else {
            ap.wps = false;
        }

        result.push_back(ap);
    }

    WlanFreeMemory(pBssList);
    WlanFreeMemory(pNetList);
    return result;
}

/* ---- Background scan ---- */

DWORD WINAPI WifiManager::scanThreadProc(LPVOID lp) {
    auto* self = (WifiManager*)lp;
    while (self->m_scanRunning) {
        auto aps = self->scan(self->m_scanGuid, true);
        EnterCriticalSection(&self->m_apLock);
        self->m_currentAPs = std::move(aps);
        LeaveCriticalSection(&self->m_apLock);
        for (int i = 0; i < 20 && self->m_scanRunning; ++i) Sleep(500);
    }
    return 0;
}

HANDLE WifiManager::startBackgroundScan(const GUID& guid) {
    if (m_scanRunning) stopBackgroundScan();
    m_scanGuid    = guid;
    m_scanRunning = true;
    m_scanThread  = CreateThread(NULL, 0, scanThreadProc, this, 0, NULL);
    if (!m_scanThread) {
        m_scanRunning = false;
        printf("[-] Echec creation thread de scan\n");
    }
    return m_scanThread;
}

void WifiManager::stopBackgroundScan() {
    if (!m_scanRunning) return;
    m_scanRunning = false;
    if (m_scanThread) {
        WaitForSingleObject(m_scanThread, 10000);
        CloseHandle(m_scanThread);
        m_scanThread = NULL;
    }
}

std::vector<APInfo> WifiManager::getCurrentAPs() const {
    EnterCriticalSection(&m_apLock);
    auto copy = m_currentAPs;
    LeaveCriticalSection(&m_apLock);
    return copy;
}

/* ---- Connection ---- */

bool WifiManager::connect(const GUID& guid, const std::string& ssid, const std::string& xmlPath) {
    if (!m_handle) return false;

    std::string xmlContent;
    if (xmlPath.empty()) {
        xmlContent =
            "<?xml version=\"1.0\"?>\n"
            "<WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\">\n"
            "  <name>" + ssid + "</name>\n"
            "  <SSIDConfig><SSID><name>" + ssid + "</name></SSID></SSIDConfig>\n"
            "  <connectionType>ESS</connectionType>\n"
            "  <MSM><security><authEncryption>\n"
            "    <authentication>open</authentication>\n"
            "    <encryption>none</encryption>\n"
            "    <useOneX>false</useOneX>\n"
            "  </authEncryption></security></MSM>\n"
            "</WLANProfile>\n";
    } else {
        FILE* f = fopen(xmlPath.c_str(), "rb");
        if (!f) { printf("[-] Profil inaccessible: %s\n", xmlPath.c_str()); return false; }
        fseek(f, 0, SEEK_END);
        long len = ftell(f);
        fseek(f, 0, SEEK_SET);
        xmlContent.resize((size_t)len);
        if (len > 0) fread(&xmlContent[0], 1, (size_t)len, f);
        fclose(f);
    }

    int wlen = MultiByteToWideChar(CP_UTF8, 0, xmlContent.c_str(), -1, NULL, 0);
    auto* wxml = (wchar_t*)malloc((size_t)wlen * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, xmlContent.c_str(), -1, wxml, wlen);

    DWORD ret = WlanSetProfile(m_handle, &guid, 0, wxml, NULL, TRUE, NULL, NULL);
    free(wxml);
    if (ret != ERROR_SUCCESS) { printf("[-] WlanSetProfile echec: %lu\n", ret); return false; }

    wlen = MultiByteToWideChar(CP_UTF8, 0, ssid.c_str(), -1, NULL, 0);
    auto* wssid = (wchar_t*)malloc((size_t)wlen * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, ssid.c_str(), -1, wssid, wlen);

    WLAN_CONNECTION_PARAMETERS params = {};
    params.wlanConnectionMode = wlan_connection_mode_profile;
    params.strProfile         = wssid;
    params.dot11BssType       = dot11_BSS_type_infrastructure;

    ret = WlanConnect(m_handle, &guid, &params, NULL);
    free(wssid);
    if (ret != ERROR_SUCCESS) { printf("[-] WlanConnect echec: %lu\n", ret); return false; }

    printf("[+] Connexion en cours vers '%s'...\n", ssid.c_str());
    return true;
}

/* ---- Monitor mode delegation ---- */

bool WifiManager::enableMonitorMode(const std::string& guid, const std::string& desc) {
    return MonitorMode::enable(guid, desc);
}

bool WifiManager::disableMonitorMode(const std::string& guid, const std::string& desc) {
    return MonitorMode::disable(guid, desc);
}
