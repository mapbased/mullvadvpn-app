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

#endif /* ICMPHeader_h */
