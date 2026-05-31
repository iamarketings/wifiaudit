#include "Display.hpp"
#include "../model/WifiManager.hpp"
#include <cstdio>
#include <algorithm>

/* ============================================================
 * Signal helpers
 * ============================================================ */

std::string signalQuality(long rssi) {
    if (rssi >= -50) return "Excellent";
    if (rssi >= -67) return "Bon";
    if (rssi >= -75) return "Moyen";
    if (rssi >= -82) return "Faible";
    return "Tres faible";
}

unsigned long freqToChannel(unsigned long freq) {
    if (freq >= 2412000 && freq <= 2484000)
        return (freq - 2412000) / 5000 + 1;
    if (freq >= 5000000 && freq <= 5900000)
        return (freq - 5000000) / 5000;
    if (freq >= 5925000 && freq <= 7125000)
        return (freq - 5925000) / 5000 + 1;   /* 6 GHz */
    return 0;
}

std::string encryptionString(bool sec, unsigned long auth, unsigned long cipher) {
    if (!sec) return "OPN";

    const char* authStr = "UNK";
    switch (auth) {
        case DOT11_AUTH_ALGO_80211_OPEN:       authStr = "OPEN";     break;
        case DOT11_AUTH_ALGO_80211_SHARED_KEY: authStr = "SHARED";   break;
        case DOT11_AUTH_ALGO_WPA:              authStr = "WPA";      break;
        case DOT11_AUTH_ALGO_WPA_PSK:          authStr = "WPA-PSK";  break;
        case DOT11_AUTH_ALGO_WPA_NONE:         authStr = "WPA-NONE"; break;
        case DOT11_AUTH_ALGO_RSNA:             authStr = "WPA2";     break;
        case DOT11_AUTH_ALGO_RSNA_PSK:         authStr = "WPA2-PSK"; break;
        case 8:                                authStr = "WPA3-SAE"; break;
        case 9:                                authStr = "OWE";      break;
        case 10:                               authStr = "WPA3-ENT"; break;
        default: break;
    }

    const char* cipherStr = "";
    switch (cipher) {
        case DOT11_CIPHER_ALGO_NONE:   cipherStr = "";       break;
        case DOT11_CIPHER_ALGO_WEP40:  cipherStr = "-WEP40"; break;
        case DOT11_CIPHER_ALGO_TKIP:   cipherStr = "-TKIP";  break;
        case DOT11_CIPHER_ALGO_CCMP:   cipherStr = "-CCMP";  break;
        case DOT11_CIPHER_ALGO_WEP104: cipherStr = "-WEP104";break;
        case DOT11_CIPHER_ALGO_WEP:    cipherStr = "-WEP";   break;
        case DOT11_CIPHER_ALGO_GCMP:   cipherStr = "-GCMP";  break;
        default:                       cipherStr = "-?";     break;
    }
    return std::string(authStr) + cipherStr;
}

/* ============================================================
 * Terminal rendering
 * ============================================================ */

static const char* rssiColor(long rssi) {
    if (rssi >= -67) return GRN;
    if (rssi >= -82) return YLW;
    return RED;
}

void drawScanTable(const std::vector<APInfo>& aps) {
    printf("%-4s %-17s %-24s %-4s %-10s %-14s %-4s %-22s\n",
           "N", "BSSID", "SSID", "CH", "Signal", "Securite", "WPS", "Vendeur");
    printf("---- ----------------- ------------------------ "
           "---- ---------- -------------- ---- ----------------------\n");

    for (size_t i = 0; i < aps.size(); ++i) {
        const auto& ap = aps[i];

        std::string ssid = ap.ssid;
        if (ssid.size() > 23) { ssid.resize(21); ssid += "..."; }

        std::string vendor = ap.vendor.empty() ? "-" : ap.vendor;
        if (vendor.size() > 21) { vendor.resize(19); vendor += "..."; }

        printf("%-4zu %-17s %-24s %-4lu %s%-10s" RST " %-14s %-4s %-22s\n",
               i + 1,
               ap.bssid.c_str(),
               ssid.c_str(),
               ap.channel,
               rssiColor(ap.rssi),
               ap.quality.c_str(),
               ap.security.c_str(),
               ap.wps ? "OUI" : "NON",
               vendor.c_str());
    }
}

void drawInterfaces(const std::vector<InterfaceInfo>& ifaces) {
    printf("%-4s %-30s %-38s %s\n", "N", "Nom", "GUID", "Etat");
    printf("---- ------------------------------ "
           "-------------------------------------- ----------\n");

    for (const auto& iface : ifaces) {
        const char* state = "INCONNU";
        switch (iface.state) {
            case wlan_interface_state_connected:             state = "Connecte";    break;
            case wlan_interface_state_disconnected:          state = "Deconnecte";  break;
            case wlan_interface_state_ad_hoc_network_formed: state = "Ad-Hoc";      break;
            default: break;
        }

        std::string name = iface.name;
        if (name.size() > 29) { name.resize(27); name += "..."; }

        printf("%-4d %-30s %-38s %s\n",
               iface.index, name.c_str(), iface.guid.c_str(), state);
    }
}

/* ============================================================
 * Terminal control
 * ============================================================ */

void clearScreen() { printf("\033[2J\033[H"); }
void hideCursor()  { printf("\033[?25l"); fflush(stdout); }
void showCursor()  { printf("\033[?25h"); fflush(stdout); }
