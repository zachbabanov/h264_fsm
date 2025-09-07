# QoS and Logging

We log the following events (suitable to compute QoS metrics):

- `LOG_NET_INFO("send_packet: ...")` : when client sends a packet — use to compute throughput.
- `LOG_VIDEO_INFO("video_send")` and `LOG_VIDEO_INFO("video_receive")` : track video bytes sent/received.
- `LOG_FEC_INFO("encode ...")` and `LOG_FEC_INFO("decode ...")` : FEC parameters `k`, `m`, packet_seq, encoded/decoded lengths.
- `LOG_PLAYER_INFO` : start/stop player, writer-thread events and write errors.
- Buffer limit events: `playerBuffer` soft/hard limit logs.

Suggested metrics to compute offline from logs:
- Overhead ratio = encoded_len / payload_len
- Packet loss / recovery success: compare sent seq and received seq (requires synchronized clocks or client inserting timestamp)
- Throughput: sum of bytes per time window
- Buffer drops and starvation events
