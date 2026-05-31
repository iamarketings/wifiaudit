#include "ApiServer.hpp"
#include "../model/WifiManager.hpp"
#include <cstdio>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

/* ============================================================
 * Construction / destruction
 * ============================================================ */

ApiServer::ApiServer(WifiManager& wifi, int port)
    : m_wifi(wifi)
    , m_port(port)
    , m_listenSock(INVALID_SOCKET)
    , m_running(false)
    , m_thread(nullptr)
{}

ApiServer::~ApiServer() { stop(); }

/* ============================================================
 * Start / Stop
 * ============================================================ */

bool ApiServer::start() {
    if (m_running) return true;
    m_running = true;
    m_thread  = new std::thread(&ApiServer::serverThread, this);
    return true;
}

void ApiServer::stop() {
    m_running = false;
    if (m_listenSock != INVALID_SOCKET) {
        closesocket(m_listenSock);
        m_listenSock = INVALID_SOCKET;
    }
    if (m_thread && m_thread->joinable()) {
        m_thread->join();
        delete m_thread;
        m_thread = nullptr;
    }
}

/* ============================================================
 * Server thread
 * ============================================================ */

void ApiServer::serverThread() {
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("[-] WSAStartup echec\n");
        m_running = false;
        return;
    }

    m_listenSock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_listenSock == INVALID_SOCKET) {
        printf("[-] socket() echec: %d\n", WSAGetLastError());
        WSACleanup(); m_running = false; return;
    }

    int opt = 1;
    setsockopt(m_listenSock, SOL_SOCKET, SO_REUSEADDR, (const char*)&opt, sizeof(opt));

    sockaddr_in addr = {};
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port        = htons((u_short)m_port);

    if (bind(m_listenSock, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
        printf("[-] bind() echec sur le port %d: %d\n", m_port, WSAGetLastError());
        closesocket(m_listenSock); WSACleanup(); m_running = false; return;
    }

    if (listen(m_listenSock, SOMAXCONN) == SOCKET_ERROR) {
        printf("[-] listen() echec: %d\n", WSAGetLastError());
        closesocket(m_listenSock); WSACleanup(); m_running = false; return;
    }

    printf("[+] API server en ecoute sur http://0.0.0.0:%d\n", m_port);

    while (m_running) {
        sockaddr_in client = {};
        int clientLen = sizeof(client);
        SOCKET cs = accept(m_listenSock, (sockaddr*)&client, &clientLen);
        if (cs == INVALID_SOCKET) { continue; }
        handleClient(cs);
        closesocket(cs);
    }

    closesocket(m_listenSock);
    WSACleanup();
    printf("[*] API server arrete\n");
}

/* ============================================================
 * Request parsing
 * ============================================================ */

ApiServer::Request ApiServer::parseRequest(const char* raw, int len) {
    Request req;
    if (len < 4) return req;

    std::string s(raw, (size_t)len);

    size_t eol = s.find("\r\n");
    if (eol == std::string::npos) return req;
    std::string line = s.substr(0, eol);

    size_t sp1 = line.find(' ');
    if (sp1 == std::string::npos) return req;
    size_t sp2 = line.find(' ', sp1 + 1);
    if (sp2 == std::string::npos) return req;

    req.method     = line.substr(0, sp1);
    std::string path = line.substr(sp1 + 1, sp2 - sp1 - 1);

    size_t qm = path.find('?');
    if (qm != std::string::npos) {
        req.query = path.substr(qm + 1);
        req.path  = path.substr(0, qm);
    } else {
        req.path = path;
    }

    size_t hdrEnd = s.find("\r\n\r\n");
    if (hdrEnd != std::string::npos && (int)(hdrEnd + 4) < len)
        req.body = s.substr(hdrEnd + 4);

    return req;
}

/* ============================================================
 * HTTP response helpers
 * ============================================================ */

void ApiServer::sendResponse(SOCKET s, int status,
                              const std::string& contentType,
                              const std::string& body) {
    const char* txt = (status == 200) ? "OK"
                    : (status == 201) ? "Created"
                    : (status == 204) ? "No Content"
                    : (status == 400) ? "Bad Request"
                    : (status == 404) ? "Not Found"
                    : "Internal Server Error";

    char hdr[512];
    int hdrLen = snprintf(hdr, sizeof(hdr),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: %s\r\n"
        "Content-Length: %llu\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type\r\n"
        "Connection: close\r\n"
        "\r\n",
        status, txt, contentType.c_str(), (unsigned long long)body.size());

    send(s, hdr, hdrLen, 0);
    if (!body.empty()) send(s, body.data(), (int)body.size(), 0);
}

void ApiServer::sendJSON (SOCKET s, int status, const std::string& json) {
    sendResponse(s, status, "application/json", json);
}

void ApiServer::sendError(SOCKET s, const std::string& msg) {
    sendJSON(s, 500, "{\"error\":\"" + msg + "\"}");
}

/* ============================================================
 * JSON helpers
 * ============================================================ */

static std::string jsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 4);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if ((unsigned char)c >= 32) out += c;
                else out += '?';
        }
    }
    return out;
}

static std::string apToJSON(const APInfo& ap) {
    std::string j = "  {\n";
    j += "    \"bssid\": \""    + jsonEscape(ap.bssid)    + "\",\n";
    j += "    \"ssid\": \""     + jsonEscape(ap.ssid)     + "\",\n";
    j += "    \"channel\": "    + std::to_string(ap.channel) + ",\n";
    j += "    \"rssi\": "       + std::to_string(ap.rssi)    + ",\n";
    j += "    \"quality\": \""  + jsonEscape(ap.quality)  + "\",\n";
    j += "    \"vendor\": \""   + jsonEscape(ap.vendor)   + "\",\n";
    j += std::string("    \"wps\": ") + (ap.wps ? "true" : "false") + ",\n";
    j += "    \"security\": \"" + jsonEscape(ap.security) + "\"\n";
    j += "  }";
    return j;
}

static std::string apsToJSON(const std::vector<APInfo>& aps) {
    std::string json = "[\n";
    for (size_t i = 0; i < aps.size(); ++i) {
        json += apToJSON(aps[i]);
        if (i < aps.size() - 1) json += ",";
        json += "\n";
    }
    json += "]";
    return json;
}

static GUID parseGuid(const std::string& guidStr) {
    GUID g = {};
    sscanf(guidStr.c_str(),
        "%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX",
        &g.Data1, &g.Data2, &g.Data3,
        &g.Data4[0], &g.Data4[1],
        &g.Data4[2], &g.Data4[3],
        &g.Data4[4], &g.Data4[5],
        &g.Data4[6], &g.Data4[7]);
    return g;
}

static std::string extractJsonStr(const std::string& body, const std::string& key) {
    size_t p = body.find("\"" + key + "\"");
    if (p == std::string::npos) return {};
    size_t q1 = body.find('"', p + key.size() + 2);
    if (q1 == std::string::npos) return {};
    size_t q2 = body.find('"', q1 + 1);
    if (q2 == std::string::npos) return {};
    return body.substr(q1 + 1, q2 - q1 - 1);
}

/* ============================================================
 * Route handlers
 * ============================================================ */

void ApiServer::handleIndex(SOCKET s) {
    sendJSON(s, 200,
        "{"
        "\"name\":\"wificli-api\","
        "\"version\":\"2.0\","
        "\"endpoints\":["
        "\"/interfaces\","
        "\"/aps\","
        "\"/scan?guid=<GUID>\","
        "\"/monitor\","
        "\"/connect\","
        "\"/stream\""
        "]}");
}

void ApiServer::handleInterfaces(SOCKET s) {
    auto ifaces = m_wifi.getInterfaces();
    std::string json = "[\n";
    for (size_t i = 0; i < ifaces.size(); ++i) {
        json += "  {\n";
        json += "    \"index\": " + std::to_string(ifaces[i].index) + ",\n";
        json += "    \"name\": \""  + jsonEscape(ifaces[i].name) + "\",\n";
        json += "    \"guid\": \""  + jsonEscape(ifaces[i].guid) + "\",\n";
        json += "    \"state\": "   + std::to_string(ifaces[i].state) + "\n";
        json += "  }";
        if (i < ifaces.size() - 1) json += ",";
        json += "\n";
    }
    json += "]";
    sendJSON(s, 200, json);
}

void ApiServer::handleAPs(SOCKET s) {
    sendJSON(s, 200, apsToJSON(m_wifi.getCurrentAPs()));
}

void ApiServer::handleScan(SOCKET s, const std::string& query) {
    /* ?guid=XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX */
    std::string guidStr;
    size_t p = query.find("guid=");
    if (p != std::string::npos) {
        guidStr = query.substr(p + 5);
        size_t amp = guidStr.find('&');
        if (amp != std::string::npos) guidStr = guidStr.substr(0, amp);
    }

    if (guidStr.empty()) {
        sendJSON(s, 400, "{\"error\":\"Parametre guid manquant\"}");
        return;
    }

    GUID g = parseGuid(guidStr);
    auto aps = m_wifi.scan(g, true);
    sendJSON(s, 200, apsToJSON(aps));
}

void ApiServer::handleMonitor(SOCKET s, const std::string& body) {
    /* POST body: {"guid":"...","enable":true} */
    std::string guid = extractJsonStr(body, "guid");
    if (guid.empty()) {
        sendJSON(s, 400, "{\"error\":\"Champ guid manquant\"}");
        return;
    }

    bool enable = (body.find("false") == std::string::npos &&
                   body.find("disable") == std::string::npos);

    bool ok = enable
        ? m_wifi.enableMonitorMode(guid)
        : m_wifi.disableMonitorMode(guid);

    char resp[256];
    snprintf(resp, sizeof(resp),
        "{\"success\":%s,\"mode\":\"%s\"}",
        ok ? "true" : "false",
        enable ? "monitor" : "managed");
    sendJSON(s, ok ? 200 : 500, resp);
}

void ApiServer::handleConnect(SOCKET s, const std::string& body) {
    /* POST body: {"guid":"...","ssid":"...","profile":"path.xml"} */
    std::string guid    = extractJsonStr(body, "guid");
    std::string ssid    = extractJsonStr(body, "ssid");
    std::string profile = extractJsonStr(body, "profile");

    if (guid.empty() || ssid.empty()) {
        sendJSON(s, 400, "{\"error\":\"Champs guid et ssid requis\"}");
        return;
    }

    GUID g = parseGuid(guid);
    bool ok = m_wifi.connect(g, ssid, profile);

    char resp[256];
    snprintf(resp, sizeof(resp),
        "{\"success\":%s,\"ssid\":\"%s\"}",
        ok ? "true" : "false",
        jsonEscape(ssid).c_str());
    sendJSON(s, ok ? 200 : 500, resp);
}

void ApiServer::handleStream(SOCKET s) {
    /* Server-Sent Events — mises à jour APs toutes les 3 secondes */
    const char* hdr =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/event-stream\r\n"
        "Cache-Control: no-cache\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Connection: keep-alive\r\n"
        "\r\n";
    send(s, hdr, (int)strlen(hdr), 0);

    for (int i = 0; i < 30 && m_running; ++i) {
        std::string json = apsToJSON(m_wifi.getCurrentAPs());
        std::string msg  = "data: " + json + "\n\n";
        if (send(s, msg.data(), (int)msg.size(), 0) == SOCKET_ERROR) break;
        Sleep(3000);
    }
}

/* ============================================================
 * Client handler (dispatcher)
 * ============================================================ */

void ApiServer::handleClient(SOCKET cs) {
    int timeout = 5000;
    setsockopt(cs, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    char buf[8192];
    int len = recv(cs, buf, sizeof(buf) - 1, 0);
    if (len <= 0) return;
    buf[len] = '\0';

    Request req = parseRequest(buf, len);

    /* CORS preflight */
    if (req.method == "OPTIONS") {
        sendResponse(cs, 204, "text/plain", "");
        return;
    }

    /* Route dispatch */
    if (req.path == "/" || req.path == "/api")
        handleIndex(cs);
    else if (req.path == "/interfaces" || req.path == "/api/interfaces")
        handleInterfaces(cs);
    else if (req.path == "/aps" || req.path == "/api/aps")
        handleAPs(cs);
    else if (req.path == "/scan" || req.path == "/api/scan")
        handleScan(cs, req.query);
    else if (req.path == "/monitor" || req.path == "/api/monitor")
        handleMonitor(cs, req.body);
    else if (req.path == "/connect" || req.path == "/api/connect")
        handleConnect(cs, req.body);
    else if (req.path == "/stream" || req.path == "/api/stream")
        handleStream(cs);
    else
        sendJSON(cs, 404, "{\"error\":\"Endpoint inconnu\"}");
}
