#ifndef MQTT_H
#define MQTT_H

#ifdef __cplusplus
extern "C" {
#endif

// Forward declaration of the modesMessage struct from dump1090.h
// This avoids having to include the entire dump1090.h in this header
struct modesMessage;

// MQTT configuration structure.
typedef struct {
    int enabled;            // Enable MQTT output if set to 1.
    char host[256];         // MQTT broker host name.
    int port;               // MQTT broker port.
    char username[128];     // MQTT authentication username.
    char password[128];     // MQTT authentication password.
    char topic[128];        // Topic where messages will be published.
    int use_tls;            // 1 to enable TLS, 0 otherwise.
    char ca_cert[256];      // Path to CA certificate file (if needed for TLS).
} mqtt_config_t;

// Initialize the MQTT client with the given configuration.
// Returns 0 on success or a nonzero error code on failure.
int mqtt_init(const mqtt_config_t *config);

// Publish a message to the preconfigured MQTT topic.
// Returns 0 on success or a nonzero error code if publishing fails.
int mqtt_publish(const char *message);

// Format and publish an ADS-B message to MQTT
// This handles creating the JSON representation of the message
void mqtt_publish_adsb_message(struct modesMessage *mm);

// Clean up and disconnect the MQTT client.
void mqtt_cleanup(void);

#ifdef __cplusplus
}
#endif

#endif // MQTT_H
