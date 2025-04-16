#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mosquitto.h>
#include <unistd.h>  // For access() function

#include "mqtt.h"
#include "dump1090.h" // Include this to get the modesMessage structure definition

// Common system CA certificate paths on various platforms
#define DEFAULT_CA_CERT_PATHS 4
static const char *default_ca_paths[DEFAULT_CA_CERT_PATHS] = {
    "/etc/ssl/certs/ca-certificates.crt",      // Debian/Ubuntu/Gentoo
    "/etc/pki/tls/certs/ca-bundle.crt",        // Fedora/RHEL/CentOS
    "/etc/ssl/ca-bundle.pem",                  // OpenSUSE
    "/usr/local/etc/openssl/cert.pem"          // FreeBSD/macOS
};
// Global Mosquitto client handle
static struct mosquitto *mosq = NULL;
static mqtt_config_t current_config;  // Changed from struct mqtt_config_t
// Helper function to check if a file exists and is readable
static int file_exists(const char *path) {
    return (access(path, R_OK) == 0);
}

// Address type string conversion helper
static const char *addrtype_to_string(int addrtype) {
    switch (addrtype) {
        case ADDR_ADSB_ICAO: return "adsb_icao";
        case ADDR_ADSB_ICAO_NT: return "adsb_icao_nt";
        case ADDR_ADSR_ICAO: return "adsr_icao";
        case ADDR_TISB_ICAO: return "tisb_icao";
        case ADDR_ADSB_OTHER: return "adsb_other";
        case ADDR_ADSR_OTHER: return "adsr_other";
        case ADDR_TISB_OTHER: return "tisb_other";
        case ADDR_TISB_TRACKFILE: return "tisb_track";
        default: return "unknown";
    }
}

// Initialize MQTT connection
int mqtt_init(const mqtt_config_t *config) {
    int rc;

    // Initialize Mosquitto library
    mosquitto_lib_init();

    // Save current configuration
    memcpy(&current_config, config, sizeof(mqtt_config_t));

    // Create a new Mosquitto client instance
    mosq = mosquitto_new(NULL, true, NULL);
    if (!mosq) {
        fprintf(stderr, "Error: Unable to create Mosquitto client\n");
        return -1;
    }

    // Set username and password if provided
    if (config->username[0] != '\0') {
        rc = mosquitto_username_pw_set(mosq, config->username,
                                     config->password[0] != '\0' ? config->password : NULL);
        if (rc != MOSQ_ERR_SUCCESS) {
            fprintf(stderr, "Error setting MQTT credentials: %s\n", mosquitto_strerror(rc));
            mosquitto_destroy(mosq);
            mosq = NULL;
            return -1;
        }
    }

    // Configure TLS if enabled
    if (config->use_tls) {
        const char *ca_cert_path = NULL;

        // Check if a custom CA cert was specified and is valid
        if (config->ca_cert[0] != '\0' && file_exists(config->ca_cert)) {
            ca_cert_path = config->ca_cert;
        } else {
            // Try to find a valid system CA path
            for (int i = 0; i < DEFAULT_CA_CERT_PATHS; i++) {
                if (file_exists(default_ca_paths[i])) {
                    ca_cert_path = default_ca_paths[i];
                    fprintf(stderr, "Using system default CA certificate: %s\n", ca_cert_path);
                    break;
                }
            }

            if (ca_cert_path == NULL) {
                fprintf(stderr, "Warning: No valid CA certificate path found. TLS verification may fail.\n");
            }
        }

        rc = mosquitto_tls_set(mosq, ca_cert_path, NULL, NULL, NULL, NULL);
        if (rc != MOSQ_ERR_SUCCESS) {
            fprintf(stderr, "Error setting up TLS: %s\n", mosquitto_strerror(rc));
            mosquitto_destroy(mosq);
            mosq = NULL;
            return -1;
        }
    }

    // Connect to the MQTT broker
    rc = mosquitto_connect(mosq, config->host, config->port, 60);
    if (rc != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "Error connecting to MQTT broker: %s\n", mosquitto_strerror(rc));
        mosquitto_destroy(mosq);
        mosq = NULL;
        return -1;
    }

    // Start the network thread
    rc = mosquitto_loop_start(mosq);
    if (rc != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "Error starting Mosquitto network thread: %s\n", mosquitto_strerror(rc));
        mosquitto_disconnect(mosq);
        mosquitto_destroy(mosq);
        mosq = NULL;
        return -1;
    }

    return 0;
}

// Publish a message to the configured MQTT topic
int mqtt_publish(const char *message) {
    int rc;

    if (!mosq) {
        return -1;
    }

    rc = mosquitto_publish(mosq, NULL, current_config.topic,
                         strlen(message), message, 0, false);

    if (rc != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "Error publishing to MQTT: %s\n", mosquitto_strerror(rc));
        return -1;
    }
    return 0;
}

// Format and publish an ADS-B message to MQTT with detailed information
void mqtt_publish_adsb_message(struct modesMessage *mm) {
    char message[4096]; // Larger buffer size for comprehensive data
    int len = 0;
    struct timespec ts;

    // Skip if MQTT is not enabled or if mosq client is not initialized
    if (!current_config.enabled || !mosq)
        return;

    // Get current system time with microsecond precision
    clock_gettime(CLOCK_REALTIME, &ts);

    // Start the JSON message
    len += sprintf(message + len, "{");

    // Add system timestamp (when we detected the message)
    len += sprintf(message + len, "\"system_time\":%llu.%06lu,",
                 (unsigned long long)ts.tv_sec, (unsigned long)ts.tv_nsec / 1000);

    // Add operational timestamp from the message (when the SDR received it)
    len += sprintf(message + len, "\"operational_time\":%llu.%02lu,",
                 (unsigned long long)mm->sysTimestampMsg.tv_sec,
                 (unsigned long)mm->sysTimestampMsg.tv_nsec / 10000000);

    // Basic message information
    len += sprintf(message + len, "\"icao\":\"%06x\",", mm->addr);
    len += sprintf(message + len, "\"addrtype\":\"%s\",", addrtype_to_string(mm->addrtype));

    // Add raw message hex
    len += sprintf(message + len, "\"raw\":\"");
    for (int i = 0; i < (mm->msgbits + 7) / 8; i++) {
        len += sprintf(message + len, "%02x", mm->msg[i]);
    }
    len += sprintf(message + len, "\",");

    // Message details
    len += sprintf(message + len, "\"df\":%d,", mm->msgtype);
    len += sprintf(message + len, "\"ca\":%d,", mm->CA);

    // Message type information based on DF17/18 ME type
    if (mm->msgtype == 17 || mm->msgtype == 18) {
        len += sprintf(message + len, "\"metype\":%d,", mm->metype);
        if (mm->mesub > 0) {
            len += sprintf(message + len, "\"mesub\":%d,", mm->mesub);
        }

        // Decode ME type to human-readable format
        switch(mm->metype) {
            case 1: // Identification
                len += sprintf(message + len, "\"message_type\":\"Aircraft identification\",");
                break;
            case 2: // Surface position
                len += sprintf(message + len, "\"message_type\":\"Surface position\",");
                break;
            case 3: // Airborne position (barometric altitude)
                len += sprintf(message + len, "\"message_type\":\"Airborne position (barometric altitude)\",");
                break;
            case 4: // Airborne position (GNSS altitude)
                len += sprintf(message + len, "\"message_type\":\"Airborne position (GNSS altitude)\",");
                break;
            case 5: // Surface position (high precision)
                len += sprintf(message + len, "\"message_type\":\"Surface position (high precision)\",");
                break;
            case 19: // Airborne velocity
                len += sprintf(message + len, "\"message_type\":\"Airborne velocity\",");
                break;
            case 28: // Aircraft status
                len += sprintf(message + len, "\"message_type\":\"Aircraft status\",");
                break;
            case 29: // Target state and status information
                len += sprintf(message + len, "\"message_type\":\"Target state and status\",");
                if (mm->mesub == 1) {
                    len += sprintf(message + len, "\"message_subtype\":\"Target state and status (V2)\",");
                }
                break;
            case 31: // Aircraft operation status
                len += sprintf(message + len, "\"message_type\":\"Aircraft operation status\",");
                break;
            default:
                len += sprintf(message + len, "\"message_type\":\"Unknown (%d)\",", mm->metype);
                break;
        }
    }

    // Signal quality information
    len += sprintf(message + len, "\"crc\":\"%06x\",", mm->crc);
    len += sprintf(message + len, "\"rssi\":%.1f,", 10 * log10(mm->signalLevel * MAX_POWER));
    if (mm->score > 0) {
        len += sprintf(message + len, "\"score\":%d,", mm->score);
    }
    if (mm->correctedbits > 0) {
        len += sprintf(message + len, "\"correctedbits\":%d,", mm->correctedbits);
    }

    // Source information
    switch(mm->source) {
        case SOURCE_ADSB:
            len += sprintf(message + len, "\"source\":\"adsb\",");
            break;
        case SOURCE_MLAT:
            len += sprintf(message + len, "\"source\":\"mlat\",");
            break;
        case SOURCE_MODE_S:
            len += sprintf(message + len, "\"source\":\"mode_s\",");
            break;
        case SOURCE_MODE_S_CHECKED:
            len += sprintf(message + len, "\"source\":\"mode_s_checked\",");
            break;
        case SOURCE_TISB:
            len += sprintf(message + len, "\"source\":\"tisb\",");
            break;
        default:
            len += sprintf(message + len, "\"source\":\"unknown\",");
    }

    // Air/Ground state
    switch(mm->airground) {
        case AG_GROUND:
            len += sprintf(message + len, "\"airground\":\"ground\",");
            break;
        case AG_AIRBORNE:
            len += sprintf(message + len, "\"airground\":\"airborne\",");
            break;
        case AG_UNCERTAIN:
            len += sprintf(message + len, "\"airground\":\"uncertain\",");
            break;
        default:
            len += sprintf(message + len, "\"airground\":\"invalid\",");
    }

    // Altitude information
    if (mm->altitude_valid) {
        len += sprintf(message + len, "\"altitude\":%d,", mm->altitude);
        // Add altitude source
        if (mm->altitude_source == ALTITUDE_BARO) {
            len += sprintf(message + len, "\"altitude_source\":\"barometric\",");
        } else if (mm->altitude_source == ALTITUDE_GNSS) {
            len += sprintf(message + len, "\"altitude_source\":\"gnss\",");
        }

        // Add altitude units
        if (mm->altitude_unit == UNIT_FEET) {
            len += sprintf(message + len, "\"altitude_unit\":\"feet\",");
        } else {
            len += sprintf(message + len, "\"altitude_unit\":\"meters\",");
        }
    }

    // GNSS/Baro delta if available
    if (mm->gnss_delta_valid) {
        len += sprintf(message + len, "\"gnss_delta\":%d,", mm->gnss_delta);
    }

    // Speed information
    if (mm->speed_valid) {
        len += sprintf(message + len, "\"speed\":%d,", mm->speed);
        // Add speed source
        switch(mm->speed_source) {
            case SPEED_GROUNDSPEED:
                len += sprintf(message + len, "\"speed_source\":\"groundspeed\",");
                break;
            case SPEED_IAS:
                len += sprintf(message + len, "\"speed_source\":\"ias\",");
                break;
            case SPEED_TAS:
                len += sprintf(message + len, "\"speed_source\":\"tas\",");
                break;
        }
    }

    // Heading information
    if (mm->heading_valid) {
        len += sprintf(message + len, "\"heading\":%d,", mm->heading);
        // Add heading source
        if (mm->heading_source == HEADING_TRUE) {
            len += sprintf(message + len, "\"heading_source\":\"true\",");
        } else if (mm->heading_source == HEADING_MAGNETIC) {
            len += sprintf(message + len, "\"heading_source\":\"magnetic\",");
        }
    }

    // Vertical rate information
    if (mm->vert_rate_valid) {
        len += sprintf(message + len, "\"vert_rate\":%d,", mm->vert_rate);

        // Add vertical rate source
        if (mm->vert_rate_source == ALTITUDE_BARO) {
            len += sprintf(message + len, "\"vert_rate_source\":\"barometric\",");
        } else if (mm->vert_rate_source == ALTITUDE_GNSS) {
            len += sprintf(message + len, "\"vert_rate_source\":\"gnss\",");
        }
    }

    // Position information
    if (mm->cpr_decoded) {
        len += sprintf(message + len, "\"lat\":%.6f,\"lon\":%.6f,", mm->decoded_lat, mm->decoded_lon);
    }

    // Add raw CPR data
    if (mm->cpr_valid) {
        len += sprintf(message + len, "\"cpr_lat\":%u,\"cpr_lon\":%u,", mm->cpr_lat, mm->cpr_lon);
        len += sprintf(message + len, "\"cpr_odd\":%s,", mm->cpr_odd ? "true" : "false");

        // Add CPR type
        switch(mm->cpr_type) {
            case CPR_SURFACE:
                len += sprintf(message + len, "\"cpr_type\":\"surface\",");
                break;
            case CPR_AIRBORNE:
                len += sprintf(message + len, "\"cpr_type\":\"airborne\",");
                break;
            case CPR_COARSE:
                len += sprintf(message + len, "\"cpr_type\":\"coarse\",");
                break;
        }

        // Add NUCp/NIC value
        len += sprintf(message + len, "\"cpr_nucp\":%u,", mm->cpr_nucp);
    }

    // Aircraft identification
    if (mm->callsign_valid) {
        // Trim trailing spaces from callsign
        char trimmed_callsign[9];
        strncpy(trimmed_callsign, mm->callsign, 8);
        trimmed_callsign[8] = '\0';
        int last = 7;
        while (last >= 0 && trimmed_callsign[last] == ' ') {
            trimmed_callsign[last--] = '\0';
        }
        len += sprintf(message + len, "\"callsign\":\"%s\",", trimmed_callsign);
    }

    // Transponder information
    if (mm->squawk_valid) {
        len += sprintf(message + len, "\"squawk\":\"%04x\",", mm->squawk);
    }

    // SPI flag
    if (mm->spi_valid) {
        len += sprintf(message + len, "\"spi\":%s,", mm->spi ? "true" : "false");
    }

    // Alert flag
    if (mm->alert_valid) {
        len += sprintf(message + len, "\"alert\":%s,", mm->alert ? "true" : "false");
    }

    // Category information
    if (mm->category_valid) {
        len += sprintf(message + len, "\"category\":\"%02x\",", mm->category);
    }

    // Target State & Status information (for ADS-B V2)
    if (mm->tss.valid) {
        len += sprintf(message + len, "\"tss\":{");

        if (mm->tss.altitude_valid) {
            len += sprintf(message + len, "\"altitude_type\":\"%s\",",
                         mm->tss.altitude_type == TSS_ALTITUDE_MCP ? "MCP" : "FMS");
            len += sprintf(message + len, "\"altitude\":%d,", mm->tss.altitude);
        }

        if (mm->tss.baro_valid) {
            len += sprintf(message + len, "\"baro\":%.1f,", mm->tss.baro);
        }

        if (mm->tss.heading_valid) {
            len += sprintf(message + len, "\"heading\":%d,", mm->tss.heading);
        }

        if (mm->tss.mode_valid) {
            len += sprintf(message + len, "\"mode_autopilot\":%s,",
                         mm->tss.mode_autopilot ? "true" : "false");
            len += sprintf(message + len, "\"mode_vnav\":%s,",
                         mm->tss.mode_vnav ? "true" : "false");
            len += sprintf(message + len, "\"mode_alt_hold\":%s,",
                         mm->tss.mode_alt_hold ? "true" : "false");
            len += sprintf(message + len, "\"mode_approach\":%s,",
                         mm->tss.mode_approach ? "true" : "false");
        }

        if (mm->tss.acas_operational) {
            len += sprintf(message + len, "\"acas_operational\":true,");
        }

        len += sprintf(message + len, "\"nac_p\":%d,", mm->tss.nac_p);
        len += sprintf(message + len, "\"nic_baro\":%d,", mm->tss.nic_baro);
        len += sprintf(message + len, "\"sil\":%d,", mm->tss.sil);
        len += sprintf(message + len, "\"sil_type\":\"%s\"",
                     mm->tss.sil_type == SIL_PER_HOUR ? "per_hour" : "per_sample");

        // Close the TSS object
        len += sprintf(message + len, "},");
    }

    // Operational status information
    if (mm->opstatus.valid) {
        len += sprintf(message + len, "\"opstatus\":{");

        len += sprintf(message + len, "\"version\":%d,", mm->opstatus.version);

        // Operational modes
        if (mm->opstatus.om_acas_ra)
            len += sprintf(message + len, "\"acas_ra\":true,");

        if (mm->opstatus.om_ident)
            len += sprintf(message + len, "\"ident\":true,");

        if (mm->opstatus.om_atc)
            len += sprintf(message + len, "\"atc\":true,");

        if (mm->opstatus.om_saf)
            len += sprintf(message + len, "\"saf\":true,");

        len += sprintf(message + len, "\"sda\":%d,", mm->opstatus.om_sda);

        // Capability codes
        if (mm->opstatus.cc_acas)
            len += sprintf(message + len, "\"cc_acas\":true,");

        if (mm->opstatus.cc_cdti)
            len += sprintf(message + len, "\"cc_cdti\":true,");

        if (mm->opstatus.cc_1090_in)
            len += sprintf(message + len, "\"cc_1090_in\":true,");

        if (mm->opstatus.cc_arv)
            len += sprintf(message + len, "\"cc_arv\":true,");

        if (mm->opstatus.cc_ts)
            len += sprintf(message + len, "\"cc_ts\":true,");

        len += sprintf(message + len, "\"cc_tc\":%d,", mm->opstatus.cc_tc);

        if (mm->opstatus.cc_uat_in)
            len += sprintf(message + len, "\"cc_uat_in\":true,");

        if (mm->opstatus.cc_poa)
            len += sprintf(message + len, "\"cc_poa\":true,");

        if (mm->opstatus.cc_b2_low)
            len += sprintf(message + len, "\"cc_b2_low\":true,");

        len += sprintf(message + len, "\"cc_nac_v\":%d,", mm->opstatus.cc_nac_v);

        if (mm->opstatus.cc_nic_supp_c)
            len += sprintf(message + len, "\"cc_nic_supp_c\":true,");

        if (mm->opstatus.cc_lw_valid)
            len += sprintf(message + len, "\"cc_lw_valid\":true,");

        if (mm->opstatus.nic_supp_a)
            len += sprintf(message + len, "\"nic_supp_a\":true,");

        len += sprintf(message + len, "\"nac_p\":%d,", mm->opstatus.nac_p);
        len += sprintf(message + len, "\"gva\":%d,", mm->opstatus.gva);
        len += sprintf(message + len, "\"sil\":%d,", mm->opstatus.sil);

        if (mm->opstatus.nic_baro)
            len += sprintf(message + len, "\"nic_baro\":true,");

        len += sprintf(message + len, "\"sil_type\":\"%s\",",
                     mm->opstatus.sil_type == SIL_PER_HOUR ? "per_hour" : "per_sample");

        len += sprintf(message + len, "\"track_angle\":\"%s\",",
                     mm->opstatus.track_angle == ANGLE_HEADING ? "heading" : "track");

        len += sprintf(message + len, "\"hrd\":\"%s\"",
                     mm->opstatus.hrd == HEADING_TRUE ? "true" : "magnetic");

        // Close the opstatus object
        len += sprintf(message + len, "},");
    }

    // Remove trailing comma if present
    if (message[len-1] == ',')
        message[len-1] = '}';
    else
        message[len] = '}';

    // Publish to MQTT
    mqtt_publish(message);
}

// Clean up MQTT resources
void mqtt_cleanup(void) {
    if (mosq) {
        mosquitto_loop_stop(mosq, true);
        mosquitto_disconnect(mosq);
        mosquitto_destroy(mosq);
        mosq = NULL;
        mosquitto_lib_cleanup();
    }
}
