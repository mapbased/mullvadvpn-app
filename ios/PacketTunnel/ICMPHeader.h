//
//  ICMPHeader.h
//  MullvadVPN
//
//  Created by pronebird on 15/02/2022.
//  Copyright © 2022 Mullvad VPN AB. All rights reserved.
//

#ifndef ICMPHeader_h
#define ICMPHeader_h

#include <stdint.h>

typedef struct __attribute__((packed)) {
    uint8_t type;
    uint8_t code;
    uint16_t checksum;
    uint16_t identifier;
    uint16_t sequenceNumber;
} ICMPHeader;

#if DEBUG
typedef struct __attribute__((packed)) {
    uint8_t versionAndHeaderLength;
    uint8_t differentiatedServices;
    uint16_t totalLength;
    uint16_t identification;
    uint16_t flagsAndFragmentOffset;
    uint8_t timeToLive;
    uint8_t protocol;
    uint16_t headerChecksum;
    uint8_t sourceAddress[4];
    uint8_t destinationAddress[4];
} IPv4Header;
#endif

#endif /* ICMPHeader_h */
