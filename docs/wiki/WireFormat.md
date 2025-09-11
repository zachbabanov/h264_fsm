# Wire format / Packet headers (RFC-style)

Документ описывает прикладные заголовки, используемые между клиентом и сервером. Оформление — в стиле RFC / IP: смещения (offset), длины, big-endian (сетевой порядок байт).

**Ключевые замечания (важно)**

* Все многобайтовые поля на проводе — **в сетевом порядке байт (big-endian)**.
* Структуры на стороне кода помечены `#pragma pack(push,1)` — **packed** (без выравнивания).
* Формат прикладного пакета по TCP:  

[FecPacketHeader (26 bytes)] [encoded_payload (payload_len bytes)]

* Единицы времени (PTS) — **миллисекунды (ms)**.
* При парсинге: сначала читается `FecPacketHeader`, из него — `payload_len` (host order), затем сервер ждёт `payload_len` байт и только затем декодирует.

---

## 1) UDP control header (`UdpHeader`) — 12 байт

C-структура (из `include/common.hpp`):

```cpp
#pragma pack(push,1)
struct UdpHeader {
  uint32_t client_id;   // 4
  uint16_t command_id;  // 2
  uint16_t flags;       // 2
  uint32_t seq;         // 4
};
#pragma pack(pop)
```

## Byte map (offsets, big-endian)

```
Offset:  0                   4           6           8        12
Bytes:  +--------------------+-----------+-----------+----------+
        | client_id (32bit)  | cmd (16)  | flags(16) | seq (32) |
        +--------------------+-----------+-----------+----------+
Total: 12 bytes
```

### Поля

* client_id (32) — идентификатор клиента. Клиент при регистрации шлёт 0; сервер отвечает CMD_REGISTER_RESP с назначенным id.
* command_id (16) — команда:

  * 1 = CMD_REGISTER
  * 2 = CMD_REGISTER_RESP
  * 3 = CMD_HEARTBEAT
  * 4 = CMD_BROADCAST

* flags (16) — зарезервировано (битовая маска).
* seq (32) — последовательный номер/nonce для запроса/ответа.

### Пример (REGISTER):

```
client_id: 00 00 00 00
cmd:       00 01
flags:     00 00
seq:       00 00 00 01
```

