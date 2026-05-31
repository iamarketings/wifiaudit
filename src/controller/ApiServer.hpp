#ifndef APISERVER_HPP
#define APISERVER_HPP

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <string>
#include <thread>
#include <atomic>

#pragma comment(lib, "ws2_32.lib")

class WifiManager;   /* forward declaration */

/* ============================================================
 * ApiServer — serveur HTTP REST léger (port 8080 par défaut)
 *
 * Endpoints :
 *   GET  /interfaces          — liste des interfaces WLAN
 *   GET  /aps                 — APs actuellement en cache
 *   GET  /scan?guid=<GUID>    — déclenche un scan et retourne les APs
 *   POST /monitor             — active/désactive le mode moniteur
 *   POST /connect             — connecte à un réseau
 *   GET  /stream              — Server-Sent Events (mises à jour APs)
 *   GET  /                    — index JSON (liste des endpoints)
 * ============================================================ */
class ApiServer {
public:
    explicit ApiServer(WifiManager& wifi, int port = 8080);
    ~ApiServer();

    bool start();
    void stop();

    bool isRunning() const { return m_running.load(); }
    int  port()      const { return m_port; }

private:
    WifiManager&       m_wifi;
    int                m_port;
    SOCKET             m_listenSock;
    std::atomic<bool>  m_running;
    std::thread*       m_thread;

    /* Server loop */
    void serverThread();
    void handleClient(SOCKET client);

    /* Route handlers */
    void handleInterfaces (SOCKET s);
    void handleAPs        (SOCKET s);
    void handleScan       (SOCKET s, const std::string& query);
    void handleMonitor    (SOCKET s, const std::string& body);
    void handleConnect    (SOCKET s, const std::string& body);
    void handleStream     (SOCKET s);
    void handleIndex      (SOCKET s);

    /* HTTP helpers */
    void sendResponse(SOCKET s, int status,
                      const std::string& contentType,
                      const std::string& body);
    void sendJSON (SOCKET s, int status, const std::string& json);
    void sendError(SOCKET s, const std::string& msg);

    /* Request parsing */
    struct Request {
        std::string method;
        std::string path;
        std::string query;
        std::string body;
    };
    static Request parseRequest(const char* raw, int len);
};

#endif /* APISERVER_HPP */
