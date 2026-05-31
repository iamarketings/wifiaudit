#include "Wps.hpp"

/* WPS : Tag 0xDD (Vendor Specific), OUI 00:50:F2, type 0x04 */
bool hasWPS(const uint8_t* ieData, unsigned long ieSize) {
    unsigned long i = 0;
    while (i + 2 <= ieSize) {
        uint8_t tag      = ieData[i];
        uint8_t len      = ieData[i + 1];
        unsigned long next = i + 2 + len;
        if (next > ieSize) break;

        if (tag == 0xDD && len >= 5) {
            if (ieData[i+2] == 0x00 &&
                ieData[i+3] == 0x50 &&
                ieData[i+4] == 0xF2 &&
                ieData[i+5] == 0x04)
                return true;
        }
        /* Variante rare tag 0x85 */
        if (tag == 0x85 && len >= 4) {
            if (ieData[i+2] == 0x00 &&
                ieData[i+3] == 0x50 &&
                ieData[i+4] == 0xF2)
                return true;
        }
        i = next;
    }
    return false;
}
