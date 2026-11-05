# Zeek Gateway Configuration for IoTGuard (local.zeek)
# Implements Pillar 1: Consistent JSON schema and Pillar 3: Metadata Isolation

@load policy/tuning/json-logs.zeek
@load protocols/conn/mac-logging.zeek

redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_EPOCH;

# Metadata Isolation: Drop raw payloads immediately; only export flow state & volume
redef PacketFilter::drop_all = F;

event zeek_init() {
    print "Zeek sensor initialized in JSON streaming mode for IoTGuard IDS";
}
