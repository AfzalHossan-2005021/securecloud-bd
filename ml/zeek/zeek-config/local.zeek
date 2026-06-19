##! SecureCloud-BD Zeek local policy
##!
##! Loads the protocol analyzers and log writers consumed by the
##! SecureCloud-BD feature extraction pipeline.  Deploy by copying (or
##! symlinking) this file to /opt/zeek/share/zeek/site/local.zeek, then
##! running ``zeekctl install && zeekctl restart``.
##!
##! Logs written by this policy
##! ---------------------------
##! conn.log    Primary source for ML feature extraction (flow-to-features.py)
##! dns.log     DNS query telemetry
##! http.log    HTTP transaction metadata
##! ssl.log     TLS handshake metadata
##! weird.log   Protocol anomalies flagged by Zeek itself
##!
##! JSON output
##! -----------
##! policy/tuning/json-logs is loaded below so every log file is written as
##! newline-delimited JSON (one object per line).  flow-to-features.py
##! requires this format; do not remove it.

# ---------------------------------------------------------------------------
# Core log framework
# ---------------------------------------------------------------------------

@load base/frameworks/logging
@load base/frameworks/notice
@load base/frameworks/signatures

# ---------------------------------------------------------------------------
# Protocol analyzers — each populates its own log file
# ---------------------------------------------------------------------------

@load base/protocols/conn        ##! conn.log — the primary ML input
@load base/protocols/dns         ##! dns.log
@load base/protocols/http        ##! http.log
@load base/protocols/ssl         ##! ssl.log

# ---------------------------------------------------------------------------
# Anomaly / miscellaneous
# ---------------------------------------------------------------------------

@load base/misc/weird            ##! weird.log — Zeek-native protocol anomalies
@load base/misc/scan             ##! Scan detection (populates notices)

# ---------------------------------------------------------------------------
# Tuning — JSON log format (required by flow-to-features.py)
# ---------------------------------------------------------------------------

@load policy/tuning/json-logs    ##! Write all logs as JSONL, not TSV

# ---------------------------------------------------------------------------
# Optional: Intel framework for IOC matching
##! Uncomment and populate intel/securecloud.intel to enable.
# ---------------------------------------------------------------------------
# @load policy/frameworks/intel/seen
# @load policy/frameworks/intel/do_notice
# redef Intel::read_files += { "/opt/zeek/share/zeek/site/intel/securecloud.intel" };

# ---------------------------------------------------------------------------
# conn.log — ensure all fields needed by flow-to-features.py are written
# ---------------------------------------------------------------------------

# These fields are written by default; listed here for documentation.
# SecureCloud-BD extracts: duration, orig_bytes, resp_bytes, orig_pkts,
# resp_pkts, orig_ip_bytes, resp_ip_bytes, missed_bytes, proto, service,
# conn_state — all available in base/protocols/conn without any extensions.

redef Conn::default_log_policy = function(rec: Conn::Info, id: Log::ID,
                                           filter: Log::Filter): bool
{
    # Log every completed connection, including those with 0-byte payloads.
    # Removing this hook would use Zeek's built-in filter (same behaviour).
    return T;
};

# ---------------------------------------------------------------------------
# Logging tuning
# ---------------------------------------------------------------------------

# Reduce conn.log spam from noisy internal services if needed.
# Uncomment and add subnets to suppress high-volume internal traffic.
# redef restrict_filters += { ["conn"] = "not (ip src 10.0.0.0/8 and
#     ip dst 10.0.0.0/8 and (tcp port 443 or tcp port 80))" };

# Log rotation interval (seconds).  Default: 3600.  ZeekControl also sets
# this via zeekctl.cfg; the value here acts as a per-process override.
redef Log::default_rotation_interval = 1hr;

# ---------------------------------------------------------------------------
# Notice framework
# ---------------------------------------------------------------------------

# Export notices to notice.log (default) and optionally to syslog.
# hook Notice::policy(n: Notice::Info)
# {
#     add n$actions[Notice::ACTION_LOG];
# }
