#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <wlanapi.h>

#include "model/WifiManager.hpp"
#include "view/Display.hpp"
#include "controller/ApiServer.hpp"

/* ============================================================
 * Banner
 * ============================================================ */

static void printBanner() {
    printf(BLD CYN);
    printf("  __        ___ _ _ _   _ _\n");
    printf("  \\ \\      / __| (_) |_(_) |\n");
    printf("   \\ \\ /\\ / / _` | | __| | |\n");
    printf("    \\ V  V / (_| | | |_| | |\n");
    printf("     \\_/\\_/ \\__,_|_|\\__|_|_|  v2.0 (C++17 / MVC)\n");
    printf(RST);
    printf("  Outil d'audit Wi-Fi Windows\n");
    printf("  %s\n\n", std::string(52, '-').c_str());
}

/* ============================================================
 * Verification des dependances au demarrage
 * Retourne false si une dependance critique est absente.
 * ============================================================ */

static bool checkDependencies() {
    bool ok = true;

    printf("[*] Verification des dependances...\n\n");

    /* 1. Privileges administrateur */
    bool isAdmin = false;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION elev = {};
        DWORD sz = sizeof(elev);
        if (GetTokenInformation(hToken, TokenElevation, &elev, sz, &sz))
            isAdmin = (elev.TokenIsElevated != 0);
        CloseHandle(hToken);
    }
    if (isAdmin) {
        printf("[+] Privileges : Administrateur\n");
    } else {
        printf("[!] ATTENTION  : Privileges utilisateur standard detectes.\n");
        printf("[!]              Certaines fonctions (mode monitor, Npcap)\n");
        printf("[!]              necessitent d'etre lance en Administrateur.\n");
        /* Non bloquant — l'outil fonctionne en partie sans admin */
    }

    /* 2. Npcap (Packet.dll) */
    const char* npcapPaths[] = {
        "C:\\Windows\\System32\\Npcap\\Packet.dll",
        "C:\\Windows\\System32\\Packet.dll",
        NULL
    };
    bool npcapFound = false;
    for (int i = 0; npcapPaths[i]; ++i) {
        if (GetFileAttributesA(npcapPaths[i]) != INVALID_FILE_ATTRIBUTES) {
            printf("[+] Npcap     : %s\n", npcapPaths[i]);
            npcapFound = true;
            break;
        }
    }
    if (!npcapFound) {
        printf("[-] NPCAP MANQUANT : Packet.dll introuvable.\n");
        printf("[-]   -> Telecharger et installer Npcap depuis : https://npcap.com/\n");
        printf("[-]   -> Le mode moniteur / capture ne sera PAS disponible.\n");
        /* Non bloquant — le scan wlanapi fonctionne sans Npcap */
    }

    /* 3. Service WLAN AutoConfig */
    {
        HANDLE hWlan = NULL;
        DWORD  ver   = 0;
        DWORD  ret   = WlanOpenHandle(2, NULL, &ver, &hWlan);
        if (ret == ERROR_SUCCESS) {
            printf("[+] WLAN      : Service OK (API v%lu)\n", ver);
            WlanCloseHandle(hWlan, NULL);
        } else {
            printf("[-] WLAN INACCESSIBLE : WlanOpenHandle echec (err %lu)\n", ret);
            printf("[-]   -> Verifiez que le service 'WLAN AutoConfig' est demarre :\n");
            printf("[-]   -> services.msc -> WLAN AutoConfig -> Demarrer\n");
            ok = false;   /* Bloquant — sans WLAN le scan est impossible */
        }
    }

    printf("\n");
    return ok;
}

/* ============================================================
 * Point d'entree
 * ============================================================ */

int main() {
    SetConsoleOutputCP(CP_UTF8);
    hideCursor();
    printBanner();

    /* Verifier les dependances avant tout */
    if (!checkDependencies()) {
        printf("[-] Dependance critique manquante. Appuyez sur Entree pour quitter.\n");
        showCursor();
        (void)getchar();
        return 1;
    }

    WifiManager wifi;

    /* Enumerer les interfaces */
    auto ifaces = wifi.getInterfaces();
    if (ifaces.empty()) {
        printf("[-] Aucune interface Wi-Fi detectee.\n");
        showCursor();
        return 1;
    }

    /* Selection de l'interface */
    printf("\n" BLD "Interfaces disponibles :" RST "\n");
    drawInterfaces(ifaces);

    printf("\nSelectionnez une interface (0-%zu): ", ifaces.size() - 1);
    showCursor();

    char line[32] = {};
    if (!fgets(line, sizeof(line), stdin)) { showCursor(); return 0; }
    int selIdx = atoi(line);
    if (selIdx < 0 || (size_t)selIdx >= ifaces.size()) selIdx = 0;

    GUID        selGuid = {};
    std::string selName = ifaces[selIdx].name;
    wifi.resolveInterface(selIdx, selGuid, selName);
    printf("\n[+] Interface : %s\n\n", selName.c_str());

    /* ---- Boucle interactive ---- */
    ApiServer* server  = nullptr;
    bool       running = true;

    while (running) {
        printf(BLD "=== MENU === [" RST "%s" BLD "]" RST "\n", selName.c_str());
        printf("  1. Scanner les reseaux\n");
        printf("  2. Scanner en continu (background)\n");
        printf("  3. Afficher les resultats du scan\n");
        printf("  4. Connecter a un reseau\n");
        printf("  5. Activer le mode moniteur\n");
        printf("  6. Desactiver le mode moniteur\n");
        printf("  7. Demarrer le serveur API (port 8080)\n");
        printf("  8. Arreter le serveur API\n");
        printf("  9. Changer d'interface\n");
        printf("  0. Quitter\n");
        printf("Choix: ");

        if (!fgets(line, sizeof(line), stdin)) break;
        int choice = atoi(line);
        printf("\n");

        switch (choice) {

            case 1: {
                printf("[*] Scan en cours...\n");
                auto aps = wifi.scan(selGuid, true);
                printf("[+] %zu point(s) d'acces trouve(s)\n\n", aps.size());
                drawScanTable(aps);
                printf("\n");
                break;
            }

            case 2: {
                printf("[*] Scan continu demarre...\n");
                wifi.startBackgroundScan(selGuid);
                showCursor();
                for (int i = 0; i < 10; ++i) {
                    clearScreen();
                    printBanner();
                    printf("[*] Scan continu — mise a jour %d/10\n\n", i + 1);
                    drawScanTable(wifi.getCurrentAPs());
                    std::this_thread::sleep_for(std::chrono::seconds(3));
                }
                wifi.stopBackgroundScan();
                printf("\n[*] Scan continu termine\n");
                break;
            }

            case 3: {
                auto aps = wifi.getCurrentAPs();
                printf("[+] %zu point(s) d'acces en cache\n\n", aps.size());
                drawScanTable(aps);
                printf("\n");
                break;
            }

            case 4: {
                showCursor();
                auto aps = wifi.getCurrentAPs();
                if (aps.empty()) {
                    printf("[-] Aucun AP en cache. Lancez d'abord un scan.\n");
                    break;
                }
                drawScanTable(aps);
                printf("\nNumero de l'AP a rejoindre: ");
                if (!fgets(line, sizeof(line), stdin)) break;
                int apIdx = atoi(line);
                if (apIdx < 1 || (size_t)apIdx > aps.size()) {
                    printf("[-] Choix invalide\n");
                    break;
                }
                printf("Profil XML (vide = reseau ouvert): ");
                char profile[512] = {};
                if (fgets(profile, sizeof(profile), stdin)) {
                    size_t plen = strlen(profile);
                    if (plen > 0 && profile[plen - 1] == '\n')
                        profile[plen - 1] = '\0';
                }
                wifi.connect(selGuid, aps[apIdx - 1].ssid, profile);
                break;
            }

            case 5: {
                printf("[*] Activation du mode moniteur...\n");
                bool ok = wifi.enableMonitorMode(
                    ifaces[selIdx].guid, ifaces[selIdx].name);
                printf("%s\n", ok ? "[+] Mode moniteur actif" : "[-] ECHEC — voir details ci-dessus");
                break;
            }

            case 6: {
                printf("[*] Desactivation du mode moniteur...\n");
                bool ok = wifi.disableMonitorMode(
                    ifaces[selIdx].guid, ifaces[selIdx].name);
                printf("%s\n", ok ? "[+] OK" : "[-] ECHEC");
                break;
            }

            case 7: {
                if (server) {
                    printf("[-] Serveur deja en cours d'execution (port %d)\n", server->port());
                } else {
                    server = new ApiServer(wifi, 8080);
                    if (server->start()) {
                        printf("[+] Serveur API demarre : http://0.0.0.0:8080\n");
                    } else {
                        printf("[-] Echec du demarrage du serveur\n");
                        delete server; server = nullptr;
                    }
                }
                break;
            }

            case 8: {
                if (server) {
                    server->stop();
                    delete server; server = nullptr;
                    printf("[+] Serveur API arrete\n");
                } else {
                    printf("[-] Aucun serveur en cours\n");
                }
                break;
            }

            case 9: {
                auto ifs = wifi.getInterfaces();
                if (ifs.empty()) { printf("[-] Aucune interface detectee\n"); break; }
                drawInterfaces(ifs);
                printf("\nNouvelle interface (0-%zu): ", ifs.size() - 1);
                showCursor();
                if (!fgets(line, sizeof(line), stdin)) break;
                int newIdx = atoi(line);
                if (newIdx >= 0 && (size_t)newIdx < ifs.size()) {
                    selIdx  = newIdx;
                    selName = ifs[selIdx].name;
                    wifi.resolveInterface(selIdx, selGuid, selName);
                    printf("[+] Interface : %s\n", selName.c_str());
                } else {
                    printf("[-] Choix invalide\n");
                }
                printf("\n");
                break;
            }

            case 0:
                running = false;
                break;

            default:
                printf("[-] Choix invalide\n");
                break;
        }
    }

    /* Nettoyage */
    if (server) { server->stop(); delete server; }
    wifi.stopBackgroundScan();
    showCursor();
    printf("[+] A bientot !\n");
    return 0;
}
