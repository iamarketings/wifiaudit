#ifndef WIFIMANAGER_HPP
#define WIFIMANAGER_HPP

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wlanapi.h>
#include <string>
#include <vector>
#include <cstdint>

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "ole32.lib")

/* ============================================================
 * Data structures
 * ============================================================ */

struct InterfaceInfo {
    int         index;
    std::string name;   /* UTF-8 */
    std::string guid;   /* GUID as string (no braces) */
    int         state;  /* wlan_interface_state */
};

struct APInfo {
    std::string   bssid;
    std::string   ssid;
    unsigned long channel;
    long          rssi;
    std::string   quality;    /* Excellent / Bon / Moyen / Faible */
    std::string   vendor;     /* OUI vendor name */
    bool          wps;
    std::string   security;   /* e.g. WPA2-PSK-CCMP, OPN */
};

/* ============================================================
 * WifiManager — RAII wrapper around Native Wifi API
 * ============================================================ */

class WifiManager {
public:
    WifiManager();
    ~WifiManager();
    WifiManager(const WifiManager&)            = delete;
    WifiManager& operator=(const WifiManager&) = delete;

    /* Interface enumeration */
    std::vector<InterfaceInfo> getInterfaces() const;
    bool resolveInterface(int idx, GUID& outGuid, std::string& outName) const;

    /* Scanning */
    std::vector<APInfo> scan(const GUID& guid, bool wait = true);
    HANDLE              startBackgroundScan(const GUID& guid);
    void                stopBackgroundScan();
    std::vector<APInfo> getCurrentAPs() const;

    /* Connection */
    bool connect(const GUID& guid, const std::string& ssid, const std::string& xmlPath);

    /* Monitor mode (delegates to MonitorMode module) */
    bool enableMonitorMode (const std::string& interfaceGuid, const std::string& interfaceDesc = {});
    bool disableMonitorMode(const std::string& interfaceGuid, const std::string& interfaceDesc = {});

    HANDLE handle() const { return m_handle; }

private:
    HANDLE m_handle;
    DWORD  m_version;

    /* Background scan */
    HANDLE           m_scanThread;
    volatile bool    m_scanRunning;
    GUID             m_scanGuid;

    /* Thread-safe AP list */
    mutable CRITICAL_SECTION m_apLock;
    std::vector<APInfo>      m_currentAPs;

    static DWORD WINAPI scanThreadProc(LPVOID lp);
};

#endif /* WIFIMANAGER_HPP */
