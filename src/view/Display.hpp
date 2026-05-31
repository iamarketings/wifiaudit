#ifndef DISPLAY_HPP
#define DISPLAY_HPP

#include <string>
#include <vector>

/* ---- ANSI color codes ---- */
#define RST "\033[0m"
#define BLD "\033[1m"
#define RED "\033[31m"
#define GRN "\033[32m"
#define YLW "\033[33m"
#define CYN "\033[36m"
#define GRY "\033[90m"

/* Forward declarations (avoid including WifiManager.hpp here) */
struct APInfo;
struct InterfaceInfo;

/* ---- Signal helpers (also used by WifiManager) ---- */
std::string   signalQuality(long rssi);
unsigned long freqToChannel(unsigned long freqKHz);
std::string   encryptionString(bool sec, unsigned long auth, unsigned long cipher);

/* ---- Terminal rendering ---- */
void drawScanTable  (const std::vector<APInfo>&       aps);
void drawInterfaces (const std::vector<InterfaceInfo>& ifaces);

/* ---- Terminal control ---- */
void clearScreen();
void hideCursor();
void showCursor();

#endif /* DISPLAY_HPP */
