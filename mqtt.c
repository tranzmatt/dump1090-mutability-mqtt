#include "mqtt.h"
#include <MQTTClient.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Global MQTT client handle and topic.
static MQTTClient client;
static int connected = 0;
static char mqtt_topic[128] = "adsb/raw"; // Default topic

int mqtt_init(const mqtt_config_t *config) {
    char address[300];
    int rc;
    MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
    MQTTClient_SSLOptions ssl_opts = MQTTClient_SSLOptions_initializer;  // Always compiled in

    // Choose protocol based on runtime TLS setting.
    if (config->use_tls) {
        snprintf(address, sizeof(address), "ssl://%s:%d", config->host, config->port);
    } else {
        snprintf(address, sizeof(address), "tcp://%s:%d", config->host, config->port);
    }

    // Create the MQTT client.
    rc = MQTTClient_create(&client, address, "dump1090", MQTTCLIENT_PERSISTENCE_NONE, NULL);
    if (rc != MQTTCLIENT_SUCCESS) {
        fprintf(stderr, "Failed to create MQTT client, return code %d\n", rc);
        return rc;
    }

    // Set username and password if provided.
    if (strlen(config->username) > 0) {
        conn_opts.username = config->username;
        conn_opts.password = config->password;
    }
    conn_opts.keepAliveInterval = 20;
    conn_opts.cleansession = 1;

    // Always compile in TLS support; enable it based on runtime flag.
    if (config->use_tls) {
        // If a CA certificate file path is provided, configure TLS accordingly.
        if (strlen(config->ca_cert) > 0) {
            ssl_opts.trustStore = config->ca_cert;
            ssl_opts.enableServerCertAuth = 1;
        }
        conn_opts.ssl = &ssl_opts;
    }

    // Connect to the MQTT broker.
    rc = MQTTClient_connect(client, &conn_opts);
    if (rc != MQTTCLIENT_SUCCESS) {
        fprintf(stderr, "Failed to connect to MQTT broker, return code %d\n", rc);
        return rc;
    }
    connected = 1;

    // Save the topic from configuration.
    strncpy(mqtt_topic, config->topic, sizeof(mqtt_topic) - 1);
    mqtt_topic[sizeof(mqtt_topic) - 1] = '\0';

    return 0;
}

int mqtt_publish(const char *message) {
    if (!connected)
        return -1;

    MQTTClient_message pubmsg = MQTTClient_message_initializer;
    MQTTClient_deliveryToken token;
    pubmsg.payload = (void *)message;
    pubmsg.payloadlen = (int)strlen(message);
    pubmsg.qos = 1;
    pubmsg.retained = 0;

    int rc = MQTTClient_publishMessage(client, mqtt_topic, &pubmsg, &token);
    if (rc != MQTTCLIENT_SUCCESS) {
        fprintf(stderr, "Failed to publish message, return code %d\n", rc);
        return rc;
    }
    rc = MQTTClient_waitForCompletion(client, token, 1000L);
    return rc;
}

void mqtt_cleanup(void) {
    if (connected) {
        MQTTClient_disconnect(client, 1000);
        MQTTClient_destroy(&client);
        connected = 0;
    }
}

