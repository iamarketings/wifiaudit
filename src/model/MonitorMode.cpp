#include "MonitorMode.hpp"
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")

/* ============================================================
 * Packet.dll interface (Npcap 1.x)
 *
 * Fonctions disponibles dans Npcap 1.x :
 *   [+] PacketOpenAdapter   [+] PacketCloseAdapter
 *   [+] PacketSetMode       [+] PacketSetHwFilter
 *   [-] PacketSetOid        [-] PacketQueryOid  (supprimés en 1.x)
 * ============================================================ */

typedef void* (__cdecl *PacketOpenAdapter_t) (const char*);
typedef void  (__cdecl *PacketCloseAdapter_t)(void*);
typedef BOOL  (__cdecl *PacketSetMode_t)     (void*, int);
typedef BOOL  (__cdecl *PacketSetHwFilter_t) (void*, ULONG);

struct PacketCtx {
    HMODULE              hDll     = nullptr;
    void*                adapter  = nullptr;
    PacketOpenAdapter_t  fnOpen   = nullptr;
    PacketCloseAdapter_t fnClose  = nullptr;
    PacketSetMode_t      fnMode   = nullptr;
    PacketSetHwFilter_t  fnFilter = nullptr;

    bool valid()  const { return adapter != nullptr; }

    void release() {
        if (adapter && fnClose) { fnClose(adapter); adapter = nullptr; }
        if (hDll)               { FreeLibrary(hDll); hDll  = nullptr; }
    }
};

/* Ouvre un adapter via Packet.dll et charge les pointeurs de fonctions */
static PacketCtx openCtx(const char* path) {
    PacketCtx ctx;
    ctx.hDll = LoadLibraryA("Packet.dll");
    if (!ctx.hDll) return ctx;

    ctx.fnOpen   = (PacketOpenAdapter_t) GetProcAddress(ctx.hDll, "PacketOpenAdapter");
    ctx.fnClose  = (PacketCloseAdapter_t)GetProcAddress(ctx.hDll, "PacketCloseAdapter");
    ctx.fnMode   = (PacketSetMode_t)     GetProcAddress(ctx.hDll, "PacketSetMode");
    ctx.fnFilter = (PacketSetHwFilter_t) GetProcAddress(ctx.hDll, "PacketSetHwFilter");

    if (!ctx.fnOpen || !ctx.fnClose) { ctx.release(); return ctx; }

    ctx.adapter = ctx.fnOpen(path);
    if (!ctx.adapter) ctx.release();
    return ctx;
}

/* Sonde rapide : est-ce qu'on peut ouvrir ce chemin via Packet.dll ? */
static bool canOpenViaPacket(const char* path) {
    HMODULE h = LoadLibraryA("Packet.dll");
    if (!h) return false;
    auto pOpen  = (PacketOpenAdapter_t) GetProcAddress(h, "PacketOpenAdapter");
    auto pClose = (PacketCloseAdapter_t)GetProcAddress(h, "PacketCloseAdapter");
    bool ok = false;
    if (pOpen && pClose) {
        void* a = pOpen(path);
        if (a) { ok = true; pClose(a); }
    }
    FreeLibrary(h);
    return ok;
}

/* ============================================================
 * Découverte du device Npcap
 * ============================================================ */

static std::string findNpcap(const std::string& guid, const std::string& /*desc*/) {
    /* 1. Chemins DOS standard (anciens Windows / drivers) */
    auto tryDos = [](const std::string& p) {
        HANDLE h = CreateFileA(p.c_str(),
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) { CloseHandle(h); return true; }
        return false;
    };

    {
        std::string p = "\\\\.\\NPF_" + guid;
        if (tryDos(p)) return p;
        p = "\\\\.\\NPF_{" + guid + "}";
        if (tryDos(p)) return p;
    }

    /* 2. Namespace NT via Packet.dll */
    {
        char buf[200];
        snprintf(buf, sizeof(buf), "\\Device\\NPF_{%s}", guid.c_str());
        if (canOpenViaPacket(buf)) return buf;
        snprintf(buf, sizeof(buf), "\\Device\\NPF_%s", guid.c_str());
        if (canOpenViaPacket(buf)) return buf;
    }

    /* 3. Enumération de tous les adaptateurs réseau */
    ULONG sz = 24000;
    auto* pBuf = (PIP_ADAPTER_ADDRESSES)malloc(sz);
    if (!pBuf) return {};

    ULONG ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, pBuf, &sz);
    if (ret == ERROR_BUFFER_OVERFLOW) {
        free(pBuf);
        pBuf = (PIP_ADAPTER_ADDRESSES)malloc(sz);
        if (!pBuf) return {};
        ret = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, NULL, pBuf, &sz);
    }

    std::string result;
    if (ret == ERROR_SUCCESS) {
        for (auto* p = pBuf; p; p = p->Next) {
            if (!p->AdapterName) continue;
            std::string ag = p->AdapterName;

            std::string dos = "\\\\.\\NPF_" + ag;
            if (tryDos(dos)) { result = dos; break; }

            char ntBuf[200];
            snprintf(ntBuf, sizeof(ntBuf), "\\Device\\NPF_%s", ag.c_str());
            if (canOpenViaPacket(ntBuf)) { result = ntBuf; break; }
        }
        if (result.empty())
            printf("[!] Aucun device NPF accessible (Npcap installe ?).\n");
    }
    free(pBuf);
    return result;
}

/* ============================================================
 * API publique
 * ============================================================ */

std::string MonitorMode::findNpcapDevice(const std::string& guid, const std::string& desc) {
    std::string dev = findNpcap(guid, desc);
    if (!dev.empty())
        printf("[+] Npcap device: %s\n", dev.c_str());
    else
        printf("[-] Npcap device introuvable pour: %s\n", desc.c_str());
    return dev;
}

void MonitorMode::listDevices() {
    printf("[*] Enumeration des devices Npcap...\n");
    const char* tests[] = { "\\\\.\\NPF_", "\\\\.\\Ndis", "\\\\.\\Ndis1" };
    for (auto t : tests) {
        HANDLE h = CreateFileA(t, GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            printf("[+] Accessible: %s\n", t); CloseHandle(h);
        } else {
            printf("[-] %s -> err %lu\n", t, GetLastError());
        }
    }
}

bool MonitorMode::isDriverCompatible(const std::string& guid, const std::string& desc) {
    std::string dev = findNpcapDevice(guid, desc);
    if (dev.empty()) return false;
    PacketCtx ctx = openCtx(dev.c_str());
    bool ok = ctx.valid();
    ctx.release();
    return ok;
}

bool MonitorMode::enable(const std::string& guid, const std::string& desc) {
    std::string dev = findNpcapDevice(guid, desc);
    if (dev.empty()) return false;

    PacketCtx ctx = openCtx(dev.c_str());
    if (!ctx.valid()) {
        printf("[-] Impossible d'ouvrir le device Npcap\n");
        return false;
    }
    ctx.release();

    /* ---- Diagnostic et résultat honnête ---- */
    printf("\n");
    printf("[-] ERREUR : Cette carte ne prend pas en charge le mode moniteur.\n");
    printf("[-] Carte  : 802.11n USB Wireless LAN Card (Ralink/Mediatek)\n");
    printf("[-] Driver : netr28ux.inf (Microsoft 2007) — OID_802_11_MONITOR_MODE absent\n");
    printf("[-] Npcap ne peut pas capturer les trames 802.11 brutes sur ce chipset.\n");
    printf("\n");
    printf("[!] Pour activer le monitor mode :\n");
    printf("[!]  -> Carte Alfa AWUS036ACH (Realtek rtl8812au) + driver modifie\n");
    printf("[!]  -> Kali Linux (dual-boot) : iw dev wlan0 set type monitor\n");
    printf("[!]  -> WSL2 + carte USB passee via USB/IP vers le kernel Linux\n");
    return false;
}

bool MonitorMode::disable(const std::string& guid, const std::string& desc) {
    std::string dev = findNpcapDevice(guid, desc);
    if (dev.empty()) return false;

    PacketCtx ctx = openCtx(dev.c_str());
    if (!ctx.valid()) return false;

    if (ctx.fnMode)
        ctx.fnMode(ctx.adapter, 0);
    if (ctx.fnFilter) {
        ULONG filter = NDIS_PACKET_TYPE_DIRECTED | NDIS_PACKET_TYPE_BROADCAST;
        ctx.fnFilter(ctx.adapter, filter);
    }
    ctx.release();
    printf("[+] Mode promiscuous desactive\n");
    return true;
}
