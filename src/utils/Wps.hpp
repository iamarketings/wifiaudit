#ifndef WPS_HPP
#define WPS_HPP

#include <cstdint>

/* Retourne true si un élément IE WPS est trouvé dans les données de balise 802.11.
 * Tag 0xDD (Vendor Specific), OUI 00:50:F2, type 0x04. */
bool hasWPS(const uint8_t* ieData, unsigned long ieSize);

#endif /* WPS_HPP */
