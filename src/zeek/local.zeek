# local.zeek
# Deploy to: /etc/zeek/site/local.zeek (append to existing config)
#
# Fix from Plan.pdf: zeek-mqtt is built-in as of Zeek v6+.
# Do NOT run: sudo zkg install zeek/zeek-mqtt (causes version conflict)
# Load it directly from base protocols instead.

# Built-in Zeek v6+ MQTT protocol support (no zkg install needed)
@load base/protocols/mqtt

# IoT scan detection (install via: sudo zkg install zeek/bro-simple-scan)
@load packages/bro-simple-scan

# Long connection / C2 beacon detection (install via: sudo zkg install corelight/zeek-long-connections)
@load packages/corelight/zeek-long-connections

# Custom MQTT publish log stream for LegalTrace behavioral analysis
event zeek_init() {
    Log::create_stream(MQTT::PUBLISH_LOG, [$columns=MQTT::PublishInfo, $path="mqtt_pub"]);
}
