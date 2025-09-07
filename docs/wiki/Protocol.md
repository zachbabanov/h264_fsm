# Protocol

Two channels:
- TCP stream: used for transporting FEC packets (header + payload).
- UDP control: used for register/heartbeat/broadcast (lightweight control).

## UDP header (control)

```cpp
struct UdpHeader {
uint32_t client_id;
uint16_t command_id; // CMD_REGISTER, CMD_HEARTBEAT, etc.
uint16_t flags;
uint32_t seq;
};
```

## FEC packet format (TCP)
Each TCP message is framed as:

`[FecPacketHeader (network order)] [encoded_payload bytes]`

where `FecPacketHeader` contains:

```cpp
struct FecPacketHeader {
uint32_t client_id; // client id
uint32_t packet_seq; // packet monotonic number
uint16_t fec_k; // data symbols count
uint16_t fec_m; // parity symbols count
uint16_t flags; // reserved
uint32_t payload_len; // length of encoded payload
};
```

Currently `encoded_payload` == original payload (stub). In the future will contain rscoder output.


