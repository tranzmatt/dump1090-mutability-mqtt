// Part of dump1090, a Mode S message decoder for RTLSDR devices.
//
// interactive.c: aircraft tracking and interactive display
//
// Copyright (c) 2014,2015 Oliver Jowett <oliver@mutability.co.uk>
//
// This file is free software: you may copy, redistribute and/or modify it  
// under the terms of the GNU General Public License as published by the
// Free Software Foundation, either version 2 of the License, or (at your  
// option) any later version.  
//
// This file is distributed in the hope that it will be useful, but  
// WITHOUT ANY WARRANTY; without even the implied warranty of  
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU  
// General Public License for more details.
//
// You should have received a copy of the GNU General Public License  
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// This file incorporates work covered by the following copyright and  
// permission notice:
//
//   Copyright (C) 2012 by Salvatore Sanfilippo <antirez@gmail.com>
//
//   All rights reserved.
//
//   Redistribution and use in source and binary forms, with or without
//   modification, are permitted provided that the following conditions are
//   met:
//
//    *  Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//
//    *  Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
//   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
//   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
//   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
//   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
//   HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
//   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
//   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
//   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
//   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
//   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "dump1090.h"

//
//========================= Interactive mode ===============================


static int convert_altitude(int ft)
{
    if (Modes.metric)
        return (ft * 0.3048);
    else
        return ft;
}

static int convert_speed(int kts)
{
    if (Modes.metric)
        return (kts * 1.852);
    else
        return kts;
}

//
//=========================================================================
//
// Show the currently captured interactive data on screen.
//
void interactiveShowData(void) {
    struct aircraft *a = Modes.aircrafts;
    static uint64_t next_update;
    uint64_t now = mstime();
    int count = 0;
    char progress;
    char spinner[4] = "|/-\\";

    // Refresh screen every (MODES_INTERACTIVE_REFRESH_TIME) miliseconde
    if (now < next_update)
        return;

    next_update = now + MODES_INTERACTIVE_REFRESH_TIME;

    progress = spinner[(now/1000)%4];

#ifndef _WIN32
    printf("\x1b[H\x1b[2J");    // Clear the screen
#else
    cls();
#endif

    if (Modes.interactive_rtl1090 == 0) {
        printf (
" Hex    Mode  Sqwk  Flight   Alt    Spd  Hdg    Lat      Long   RSSI  Msgs  Ti%c\n", progress);
    } else {
        printf (
" Hex   Flight   Alt      V/S GS  TT  SSR  G*456^ Msgs    Seen %c\n", progress);
    }
    printf(
"-------------------------------------------------------------------------------\n");

    while(a && (count < Modes.interactive_rows)) {

        if ((now - a->seen) < Modes.interactive_display_ttl)
            {
            int msgs  = a->messages;
            int flags = a->modeACflags;

            if ( (((flags & (MODEAC_MSG_FLAG                             )) == 0                    ) && (msgs > 1  ) )
              || (((flags & (MODEAC_MSG_MODES_HIT | MODEAC_MSG_MODEA_ONLY)) == MODEAC_MSG_MODEA_ONLY) && (msgs > 4  ) ) 
              || (((flags & (MODEAC_MSG_MODES_HIT | MODEAC_MSG_MODEC_OLD )) == 0                    ) && (msgs > 127) ) 
              ) {
                char strSquawk[5] = " ";
                char strFl[12]     = " ";
                char strTt[5]     = " ";
                char strGs[5]     = " ";

                if (trackDataValid(&a->squawk_valid)) {
                    snprintf(strSquawk,5,"%04x", a->squawk);
                }

                if (trackDataValid(&a->speed_valid)) {
                    snprintf (strGs, 5,"%3d", convert_speed(a->speed));
                }

                if (trackDataValid(&a->heading_valid)) {
                    snprintf (strTt, 5,"%03d", a->heading);
                }

                if (msgs > 99999) {
                    msgs = 99999;
                }

                if (Modes.interactive_rtl1090) { // RTL1090 display mode
                    if (trackDataValid(&a->altitude_valid)) {
                        snprintf(strFl,11,"F%03d",((a->altitude+50)/100));
                    }
                    printf("%06x %-8s %-4s         %-3s %-3s %4s        %-6d  %-2.0f\n", 
                           a->addr, a->callsign, strFl, strGs, strTt, strSquawk, msgs, (now - a->seen)/1000.0);

                } else {                         // Dump1090 display mode
                    char strMode[5]               = "    ";
                    char strLat[8]                = " ";
                    char strLon[9]                = " ";
                    double * pSig                 = a->signalLevel;
                    double signalAverage = (pSig[0] + pSig[1] + pSig[2] + pSig[3] + 
                                            pSig[4] + pSig[5] + pSig[6] + pSig[7]) / 8.0; 

                    if ((flags & MODEAC_MSG_FLAG) == 0) {
                        strMode[0] = 'S';
                    } else if (flags & MODEAC_MSG_MODEA_ONLY) {
                        strMode[0] = 'A';
                    }
                    if (flags & MODEAC_MSG_MODEA_HIT) {strMode[2] = 'a';}
                    if (flags & MODEAC_MSG_MODEC_HIT) {strMode[3] = 'c';}

                    if (trackDataValid(&a->position_valid)) {
                        snprintf(strLat, 8,"%7.03f", a->lat);
                        snprintf(strLon, 9,"%8.03f", a->lon);
                    }

                    if (trackDataValid(&a->airground_valid) && a->airground == AG_GROUND) {
                        snprintf(strFl, 7," grnd");
                    } else if (Modes.use_gnss && trackDataValid(&a->altitude_gnss_valid)) {
                        snprintf(strFl, 7, "%5dH", convert_altitude(a->altitude_gnss));
                    } else if (trackDataValid(&a->altitude_valid)) {
                        snprintf(strFl, 7, "%5d ", convert_altitude(a->altitude));
                    }

                    printf("%s%06X %-4s  %-4s  %-8s %6s %3s  %3s  %7s %8s %5.1f %5d %2.0f\n",
                           (a->addr & MODES_NON_ICAO_ADDRESS) ? "~" : " ", (a->addr & 0xffffff),
                           strMode, strSquawk, a->callsign, strFl, strGs, strTt,
                           strLat, strLon, 10 * log10(signalAverage), msgs, (now - a->seen)/1000.0);
                }
                count++;
            }
        }
        a = a->next;
    }
}

//
//=========================================================================
//
