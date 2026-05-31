#ifndef MONITORMODE_HPP
#define MONITORMODE_HPP

#include <string>

/*
 * MonitorMode — activation du mode moniteur / promiscuous via Npcap (Packet.dll).
 *
 * Limitations connues :
 *   - La carte Ralink/Mediatek (netr28ux.inf, 2007) ne supporte pas
 *     OID_802_11_MONITOR_MODE sous Windows. On active le mode promiscuous
 *     comme meilleur effort et on retourne false pour signaler l'échec.
 *   - Npcap 1.x a supprimé PacketSetOid/PacketQueryOid.
 *     On utilise PacketSetHwFilter + PacketSetMode (disponibles).
 */

/* OIDs (ntddndis.h / windot11.h) — définis manuellement pour éviter WDK */
#ifndef OID_802_11_MONITOR_MODE
#define OID_802_11_MONITOR_MODE       0x0D01011C
#endif
#ifndef OID_802_11_HARDWARE_STATUS
#define OID_802_11_HARDWARE_STATUS    0x0D010114
#endif
#ifndef OID_GEN_CURRENT_PACKET_FILTER
#define OID_GEN_CURRENT_PACKET_FILTER 0x0001010E
#endif

/* NDIS packet filter flags */
#ifndef NDIS_PACKET_TYPE_DIRECTED
#define NDIS_PACKET_TYPE_DIRECTED       0x0001
#endif
#ifndef NDIS_PACKET_TYPE_MULTICAST
#define NDIS_PACKET_TYPE_MULTICAST      0x0002
#endif
#ifndef NDIS_PACKET_TYPE_BROADCAST
#define NDIS_PACKET_TYPE_BROADCAST      0x0008
#endif
#ifndef NDIS_PACKET_TYPE_PROMISCUOUS
#define NDIS_PACKET_TYPE_PROMISCUOUS    0x0020
#endif
#ifndef NDIS_PACKET_TYPE_802_11_RAW_RX
#define NDIS_PACKET_TYPE_802_11_RAW_RX  0x0100
#endif
#ifndef NDIS_PACKET_TYPE_802_11_MONITOR
#define NDIS_PACKET_TYPE_802_11_MONITOR 0x0200
#endif

namespace MonitorMode {

    /* Tente d'activer le monitor mode.
     * Retourne true uniquement si le driver supporte réellement le mode moniteur.
     * Sur les cartes incompatibles, affiche un diagnostic et retourne false. */
    bool enable(const std::string& interfaceGuid, const std::string& interfaceDesc = {});

    /* Désactive le monitor mode / promiscuous */
    bool disable(const std::string& interfaceGuid, const std::string& interfaceDesc = {});

    /* Vérifie si le driver est compatible */
    bool isDriverCompatible(const std::string& interfaceGuid, const std::string& interfaceDesc = {});

    /* Retourne le chemin du device Npcap associé au GUID */
    std::string findNpcapDevice(const std::string& interfaceGuid, const std::string& interfaceDesc = {});

    /* Debug : liste les devices NDIS/NPF accessibles */
    void listDevices();

} /* namespace MonitorMode */

#endif /* MONITORMODE_HPP */
