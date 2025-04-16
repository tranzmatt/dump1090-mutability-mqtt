
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
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

// Get the interface name used by the default route
char* get_default_route_interface() {
    static char iface[IFNAMSIZ] = {0};
    FILE *fp;
    char line[256], *p, *c;

    // Try to read the default route from /proc/net/route
    fp = fopen("/proc/net/route", "r");
    if (fp == NULL) {
        return NULL;
    }

    // Skip the header line
    if (fgets(line, sizeof(line), fp) == NULL) {
        fclose(fp);
        return NULL;
    }

    // Find the line with the default route (destination 0.0.0.0)
    while (fgets(line, sizeof(line), fp) != NULL) {
        p = strtok(line, "\t");
        if (p == NULL) continue;

        // Save the interface name
        strncpy(iface, p, sizeof(iface) - 1);

        // Check if this is the default route
        c = strtok(NULL, "\t");
        if (c == NULL) continue;

        if (strcmp(c, "00000000") == 0) {  // 0.0.0.0 in hex
            fclose(fp);
            return iface;
        }
    }

    fclose(fp);

    // If we get here, no default route was found
    // Try running "route -n" as a fallback
    fp = popen("route -n | grep '^0\\.0\\.0\\.0' | tr -s ' ' | cut -d' ' -f8", "r");
    if (fp == NULL) {
        return NULL;
    }

    if (fgets(iface, sizeof(iface), fp) != NULL) {
        // Remove trailing newline if present
        size_t len = strlen(iface);
        if (len > 0 && iface[len - 1] == '\n') {
            iface[len - 1] = '\0';
        }

        pclose(fp);
        return iface;
    }

    pclose(fp);
    return NULL;
}

// Get MAC address for the specified interface
int get_mac_address(const char *ifname, char *mac_buf, size_t mac_buf_size) {
    if (!ifname || !mac_buf || mac_buf_size < 13) return 0;

    struct ifreq ifr;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 0;

    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return 0;
    }

    unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;

    // Format the MAC address (without colons)
    snprintf(mac_buf, mac_buf_size, "%02X%02X%02X%02X%02X%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

    close(fd);
    return 1;
}

// Get device name using hostname and MAC from default route interface
void get_device_name(char *device_name, size_t size) {
    // First try to get device name from environment variable
    char *env_device_name = getenv("DEVICE_NAME");
    if (env_device_name != NULL) {
        strncpy(device_name, env_device_name, size - 1);
        device_name[size - 1] = '\0';
        return;
    }

    // Get hostname
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) != 0) {
        strcpy(hostname, "unknown");
    }

    // Get the interface used by the default route
    char *default_iface = get_default_route_interface();
    if (default_iface) {
        char mac_address[13] = {0};  // 12 hex chars + null

        if (get_mac_address(default_iface, mac_address, sizeof(mac_address))) {
            // Combine hostname and MAC address
            snprintf(device_name, size, "%s-%s", hostname, mac_address);
            return;
        }
    }

    // Fallback - try all non-loopback interfaces
    struct ifaddrs *ifaddrs;
    if (getifaddrs(&ifaddrs) == 0) {
        for (struct ifaddrs *ifa = ifaddrs; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == NULL)
                continue;

            // Skip loopback interfaces
            if (!(ifa->ifa_flags & IFF_LOOPBACK)) {
                char mac_address[13] = {0};  // 12 hex chars + null

                if (get_mac_address(ifa->ifa_name, mac_address, sizeof(mac_address))) {
                    // Combine hostname and MAC address
                    snprintf(device_name, size, "%s-%s", hostname, mac_address);
                    freeifaddrs(ifaddrs);
                    return;
                }
            }
        }

        freeifaddrs(ifaddrs);
    }

    // If all else fails, just use the hostname
    strncpy(device_name, hostname, size - 1);
    device_name[size - 1] = '\0';
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



// Format and publish an ADS-B message to MQTT with enhanced information
void mqtt_publish_adsb_message(struct modesMessage *mm) {
    char message[8192]; // Increased buffer size for comprehensive data
    char inner_json[4096]; // Buffer for the ADS-B JSON part
    char device_name[256] = {0}; // Buffer for device name
    char iso8601_time[64]; // Buffer for ISO 8601 timestamp
    int len = 0;
    int inner_len = 0;
    struct timespec ts;

    // Skip if MQTT is not enabled or if mosq client is not initialized
    if (!current_config.enabled || !mosq)
        return;

    // Get current system time with microsecond precision
    clock_gettime(CLOCK_REALTIME, &ts);

    // Format the timestamp as ISO 8601 with microsecond precision
    struct tm *tm_info = gmtime(&ts.tv_sec);
    strftime(iso8601_time, sizeof(iso8601_time), "%Y-%m-%dT%H:%M:%S", tm_info);
    sprintf(iso8601_time + strlen(iso8601_time), ".%06ldZ", ts.tv_nsec / 1000);

    // Get device name - now using our improved function
    get_device_name(device_name, sizeof(device_name));

    // Start the inner JSON with ADS-B data
    inner_len += sprintf(inner_json + inner_len, "{");

    // Add basic message information
    inner_len += sprintf(inner_json + inner_len, "\"icao\":\"%06x\",", mm->addr);
    inner_len += sprintf(inner_json + inner_len, "\"addrtype\":\"%s\",", addrtype_to_string(mm->addrtype));

    // Add raw message hex
    inner_len += sprintf(inner_json + inner_len, "\"raw\":\"");
    for (int i = 0; i < (mm->msgbits + 7) / 8; i++) {
        inner_len += sprintf(inner_json + inner_len, "%02x", mm->msg[i]);
    }
    inner_len += sprintf(inner_json + inner_len, "\",");

    // Message details
    inner_len += sprintf(inner_json + inner_len, "\"df\":%d,", mm->msgtype);
    inner_len += sprintf(inner_json + inner_len, "\"ca\":%d,", mm->CA);

    // Add CRC information
    inner_len += sprintf(inner_json + inner_len, "\"crc\":\"%06x\",", mm->crc);

    // Add corrected bits if any
    if (mm->correctedbits > 0) {
        inner_len += sprintf(inner_json + inner_len, "\"correctedbits\":%d,", mm->correctedbits);
    }

    // Message type information based on DF17/18 ME type
    if (mm->msgtype == 17 || mm->msgtype == 18) {
        inner_len += sprintf(inner_json + inner_len, "\"metype\":%d,", mm->metype);
        if (mm->mesub > 0) {
            inner_len += sprintf(inner_json + inner_len, "\"mesub\":%d,", mm->mesub);
        }
    }

    // Signal quality information
    inner_len += sprintf(inner_json + inner_len, "\"rssi\":%.1f,", 10 * log10(mm->signalLevel * MAX_POWER));
    if (mm->score > 0) {
        inner_len += sprintf(inner_json + inner_len, "\"score\":%d,", mm->score);
    }

    // Add operational timestamp from the message (when the SDR received it)
    inner_len += sprintf(inner_json + inner_len, "\"operational_time\":%llu.%02lu,",
                 (unsigned long long)mm->sysTimestampMsg.tv_sec,
                 (unsigned long)mm->sysTimestampMsg.tv_nsec / 10000000);

    // Source information
    switch(mm->source) {
        case SOURCE_ADSB:
            inner_len += sprintf(inner_json + inner_len, "\"source\":\"adsb\",");
            break;
        case SOURCE_MLAT:
            inner_len += sprintf(inner_json + inner_len, "\"source\":\"mlat\",");
            break;
        case SOURCE_MODE_S:
            inner_len += sprintf(inner_json + inner_len, "\"source\":\"mode_s\",");
            break;
        case SOURCE_MODE_S_CHECKED:
            inner_len += sprintf(inner_json + inner_len, "\"source\":\"mode_s_checked\",");
            break;
        case SOURCE_TISB:
            inner_len += sprintf(inner_json + inner_len, "\"source\":\"tisb\",");
            break;
        default:
            inner_len += sprintf(inner_json + inner_len, "\"source\":\"unknown\",");
    }

    // Air/Ground state
    switch(mm->airground) {
        case AG_GROUND:
            inner_len += sprintf(inner_json + inner_len, "\"airground\":\"ground\",");
            break;
        case AG_AIRBORNE:
            inner_len += sprintf(inner_json + inner_len, "\"airground\":\"airborne\",");
            break;
        case AG_UNCERTAIN:
            inner_len += sprintf(inner_json + inner_len, "\"airground\":\"uncertain\",");
            break;
        default:
            inner_len += sprintf(inner_json + inner_len, "\"airground\":\"invalid\",");
    }

    // Altitude information
    if (mm->altitude_valid) {
        inner_len += sprintf(inner_json + inner_len, "\"altitude\":%d,", mm->altitude);

        // Add altitude source
        if (mm->altitude_source == ALTITUDE_BARO) {
            inner_len += sprintf(inner_json + inner_len, "\"altitude_source\":\"barometric\",");
        } else if (mm->altitude_source == ALTITUDE_GNSS) {
            inner_len += sprintf(inner_json + inner_len, "\"altitude_source\":\"gnss\",");
        }

        // Add altitude units
        if (mm->altitude_unit == UNIT_FEET) {
            inner_len += sprintf(inner_json + inner_len, "\"altitude_unit\":\"feet\",");
        } else {
            inner_len += sprintf(inner_json + inner_len, "\"altitude_unit\":\"meters\",");
        }
    }

    // GNSS/Baro delta if available
    if (mm->gnss_delta_valid) {
        inner_len += sprintf(inner_json + inner_len, "\"gnss_delta\":%d,", mm->gnss_delta);
    }

    // Speed information
    if (mm->speed_valid) {
        inner_len += sprintf(inner_json + inner_len, "\"speed\":%d,", mm->speed);

        // Add speed source
        switch(mm->speed_source) {
            case SPEED_GROUNDSPEED:
                inner_len += sprintf(inner_json + inner_len, "\"speed_source\":\"groundspeed\",");
                break;
            case SPEED_IAS:
                inner_len += sprintf(inner_json + inner_len, "\"speed_source\":\"ias\",");
                break;
            case SPEED_TAS:
                inner_len += sprintf(inner_json + inner_len, "\"speed_source\":\"tas\",");
                break;
        }
    }

    // Heading information
    if (mm->heading_valid) {
        inner_len += sprintf(inner_json + inner_len, "\"heading\":%d,", mm->heading);

        // Add heading source
        if (mm->heading_source == HEADING_TRUE) {
            inner_len += sprintf(inner_json + inner_len, "\"heading_source\":\"true\",");
        } else if (mm->heading_source == HEADING_MAGNETIC) {
            inner_len += sprintf(inner_json + inner_len, "\"heading_source\":\"magnetic\",");
        }
    }

    // Vertical rate information
    if (mm->vert_rate_valid) {
        inner_len += sprintf(inner_json + inner_len, "\"vert_rate\":%d,", mm->vert_rate);

        // Add vertical rate source
        if (mm->vert_rate_source == ALTITUDE_BARO) {
            inner_len += sprintf(inner_json + inner_len, "\"vert_rate_source\":\"barometric\",");
        } else if (mm->vert_rate_source == ALTITUDE_GNSS) {
            inner_len += sprintf(inner_json + inner_len, "\"vert_rate_source\":\"gnss\",");
        }
    }

    // Position information (decoded)
    if (mm->cpr_decoded) {
        inner_len += sprintf(inner_json + inner_len, "\"lat\":%.6f,\"lon\":%.6f,", mm->decoded_lat, mm->decoded_lon);
    }

    // Add raw CPR data
    if (mm->cpr_valid) {
        inner_len += sprintf(inner_json + inner_len, "\"cpr_lat\":%u,\"cpr_lon\":%u,", mm->cpr_lat, mm->cpr_lon);
        inner_len += sprintf(inner_json + inner_len, "\"cpr_odd\":%s,", mm->cpr_odd ? "true" : "false");

        // Add CPR type
        switch(mm->cpr_type) {
            case CPR_SURFACE:
                inner_len += sprintf(inner_json + inner_len, "\"cpr_type\":\"surface\",");
                break;
            case CPR_AIRBORNE:
                inner_len += sprintf(inner_json + inner_len, "\"cpr_type\":\"airborne\",");
                break;
            case CPR_COARSE:
                inner_len += sprintf(inner_json + inner_len, "\"cpr_type\":\"coarse\",");
                break;
        }

        // Add NUCp/NIC value
        inner_len += sprintf(inner_json + inner_len, "\"cpr_nucp\":%u,", mm->cpr_nucp);
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
        inner_len += sprintf(inner_json + inner_len, "\"callsign\":\"%s\",", trimmed_callsign);
    }

    // Transponder information
    if (mm->squawk_valid) {
        inner_len += sprintf(inner_json + inner_len, "\"squawk\":\"%04x\",", mm->squawk);
    }

    // SPI flag
    if (mm->spi_valid) {
        inner_len += sprintf(inner_json + inner_len, "\"spi\":%s,", mm->spi ? "true" : "false");
    }

    // Alert flag
    if (mm->alert_valid) {
        inner_len += sprintf(inner_json + inner_len, "\"alert\":%s,", mm->alert ? "true" : "false");
    }

    // Category information
    if (mm->category_valid) {
        inner_len += sprintf(inner_json + inner_len, "\"category\":\"%02x\",", mm->category);
    }

    // Target State & Status information (for ADS-B V2)
    if (mm->tss.valid) {
        inner_len += sprintf(inner_json + inner_len, "\"tss\":{");

        if (mm->tss.altitude_valid) {
            inner_len += sprintf(inner_json + inner_len, "\"altitude_type\":\"%s\",",
                         mm->tss.altitude_type == TSS_ALTITUDE_MCP ? "MCP" : "FMS");
            inner_len += sprintf(inner_json + inner_len, "\"altitude\":%d,", mm->tss.altitude);
        }

        if (mm->tss.baro_valid) {
            inner_len += sprintf(inner_json + inner_len, "\"baro\":%.1f,", mm->tss.baro);
        }

        if (mm->tss.heading_valid) {
            inner_len += sprintf(inner_json + inner_len, "\"heading\":%d,", mm->tss.heading);
        }

        if (mm->tss.mode_valid) {
            inner_len += sprintf(inner_json + inner_len, "\"mode_autopilot\":%s,",
                         mm->tss.mode_autopilot ? "true" : "false");
            inner_len += sprintf(inner_json + inner_len, "\"mode_vnav\":%s,",
                         mm->tss.mode_vnav ? "true" : "false");
            inner_len += sprintf(inner_json + inner_len, "\"mode_alt_hold\":%s,",
                         mm->tss.mode_alt_hold ? "true" : "false");
            inner_len += sprintf(inner_json + inner_len, "\"mode_approach\":%s,",
                         mm->tss.mode_approach ? "true" : "false");
        }

        if (mm->tss.acas_operational) {
            inner_len += sprintf(inner_json + inner_len, "\"acas_operational\":true,");
        }

        inner_len += sprintf(inner_json + inner_len, "\"nac_p\":%d,", mm->tss.nac_p);
        inner_len += sprintf(inner_json + inner_len, "\"nic_baro\":%d,", mm->tss.nic_baro);
        inner_len += sprintf(inner_json + inner_len, "\"sil\":%d,", mm->tss.sil);
        inner_len += sprintf(inner_json + inner_len, "\"sil_type\":\"%s\"",
                     mm->tss.sil_type == SIL_PER_HOUR ? "per_hour" : "per_sample");

        // Close the TSS object
        inner_len += sprintf(inner_json + inner_len, "},");
    }

    // Operational status information
    if (mm->opstatus.valid) {
        inner_len += sprintf(inner_json + inner_len, "\"opstatus\":{");

        inner_len += sprintf(inner_json + inner_len, "\"version\":%d,", mm->opstatus.version);

        // Operational modes
        if (mm->opstatus.om_acas_ra)
            inner_len += sprintf(inner_json + inner_len, "\"acas_ra\":true,");

        if (mm->opstatus.om_ident)
            inner_len += sprintf(inner_json + inner_len, "\"ident\":true,");

        if (mm->opstatus.om_atc)
            inner_len += sprintf(inner_json + inner_len, "\"atc\":true,");

        if (mm->opstatus.om_saf)
            inner_len += sprintf(inner_json + inner_len, "\"saf\":true,");

        inner_len += sprintf(inner_json + inner_len, "\"sda\":%d,", mm->opstatus.om_sda);

        // Capability codes
        if (mm->opstatus.cc_acas)
            inner_len += sprintf(inner_json + inner_len, "\"cc_acas\":true,");

        if (mm->opstatus.cc_cdti)
            inner_len += sprintf(inner_json + inner_len, "\"cc_cdti\":true,");

        if (mm->opstatus.cc_1090_in)
            inner_len += sprintf(inner_json + inner_len, "\"cc_1090_in\":true,");

        if (mm->opstatus.cc_arv)
            inner_len += sprintf(inner_json + inner_len, "\"cc_arv\":true,");

        if (mm->opstatus.cc_ts)
            inner_len += sprintf(inner_json + inner_len, "\"cc_ts\":true,");

        inner_len += sprintf(inner_json + inner_len, "\"cc_tc\":%d,", mm->opstatus.cc_tc);

        if (mm->opstatus.cc_uat_in)
            inner_len += sprintf(inner_json + inner_len, "\"cc_uat_in\":true,");

        if (mm->opstatus.cc_poa)
            inner_len += sprintf(inner_json + inner_len, "\"cc_poa\":true,");

        if (mm->opstatus.cc_b2_low)
            inner_len += sprintf(inner_json + inner_len, "\"cc_b2_low\":true,");

        inner_len += sprintf(inner_json + inner_len, "\"cc_nac_v\":%d,", mm->opstatus.cc_nac_v);

        if (mm->opstatus.cc_nic_supp_c)
            inner_len += sprintf(inner_json + inner_len, "\"cc_nic_supp_c\":true,");

        if (mm->opstatus.cc_lw_valid)
            inner_len += sprintf(inner_json + inner_len, "\"cc_lw_valid\":true,");

        if (mm->opstatus.nic_supp_a)
            inner_len += sprintf(inner_json + inner_len, "\"nic_supp_a\":true,");

        inner_len += sprintf(inner_json + inner_len, "\"nac_p\":%d,", mm->opstatus.nac_p);
        inner_len += sprintf(inner_json + inner_len, "\"gva\":%d,", mm->opstatus.gva);
        inner_len += sprintf(inner_json + inner_len, "\"sil\":%d,", mm->opstatus.sil);

        if (mm->opstatus.nic_baro)
            inner_len += sprintf(inner_json + inner_len, "\"nic_baro\":true,");

        inner_len += sprintf(inner_json + inner_len, "\"sil_type\":\"%s\",",
                     mm->opstatus.sil_type == SIL_PER_HOUR ? "per_hour" : "per_sample");

        inner_len += sprintf(inner_json + inner_len, "\"track_angle\":\"%s\",",
                     mm->opstatus.track_angle == ANGLE_HEADING ? "heading" : "track");

        inner_len += sprintf(inner_json + inner_len, "\"hrd\":\"%s\"",
                     mm->opstatus.hrd == HEADING_TRUE ? "true" : "magnetic");

        // Close the opstatus object
        inner_len += sprintf(inner_json + inner_len, "},");
    }

    // Remove trailing comma from inner JSON if present
    if (inner_json[inner_len-1] == ',')
        inner_json[inner_len-1] = '}';
    else
        inner_json[inner_len] = '}';

    // Create the outer JSON wrapper
    len += sprintf(message + len, "{");
    len += sprintf(message + len, "\"device\":\"%s\",", device_name);
    len += sprintf(message + len, "\"detection_time\":\"%s\",", iso8601_time);
    len += sprintf(message + len, "\"adsb\":%s", inner_json);
    len += sprintf(message + len, "}");

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
