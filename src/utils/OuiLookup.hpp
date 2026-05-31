#ifndef OUILOOKUP_HPP
#define OUILOOKUP_HPP

#include <string>
#include <cstdint>

/* Retourne le nom du fabricant pour les 3 premiers octets d'une adresse MAC.
 * Retourne une chaîne vide si non trouvé. */
std::string ouiLookup(const uint8_t bssid[6]);

#endif /* OUILOOKUP_HPP */
