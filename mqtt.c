#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mosquitto.h>

#include "mqtt.h"
#include "dump1090.h" // Include this to get the modesMessage structure definition

// Global Mosquitto client handle
static struct mosquitto *mosq = NULL;
static mqtt_config_t current_config;  // Changed from struct mqtt_config_t

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
        rc = mosquitto_tls_set(mosq, 
                             config->ca_cert[0] != '\0' ? config->ca_cert : NULL, 
                             NULL, NULL, NULL, NULL);
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

// Format and publish an ADS-B message to MQTT
void mqtt_publish_adsb_message(struct modesMessage *mm) {
    char message[1024];
    int len = 0;
    
    // Skip if MQTT is not enabled or if mosq client is not initialized
    if (!current_config.enabled || !mosq)
        return;
        
    // Format the message as JSON
    len += sprintf(message + len, "{\"timestamp\":%llu,", (unsigned long long)mm->sysTimestampMsg.tv_sec);
    len += sprintf(message + len, "\"addr\":\"%06x\",", mm->addr);
    
    if (mm->addrtype != ADDR_ADSB_ICAO)
        len += sprintf(message + len, "\"addrtype\":\"%s\",", addrtype_to_string(mm->addrtype));
    
    if (mm->altitude_valid)
        len += sprintf(message + len, "\"altitude\":%d,", mm->altitude);
        
    if (mm->speed_valid)
        len += sprintf(message + len, "\"speed\":%d,", mm->speed);
        
    if (mm->heading_valid)
        len += sprintf(message + len, "\"heading\":%d,", mm->heading);
        
    if (mm->cpr_decoded)
        len += sprintf(message + len, "\"lat\":%.6f,\"lon\":%.6f,", mm->decoded_lat, mm->decoded_lon);
        
    if (mm->callsign_valid)
        len += sprintf(message + len, "\"callsign\":\"%s\",", mm->callsign);
        
    if (mm->squawk_valid)
        len += sprintf(message + len, "\"squawk\":\"%04x\",", mm->squawk);

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
