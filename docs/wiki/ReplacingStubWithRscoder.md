# Replacing StubFec with rscoder — guide

Эта страница — практическое руководство по замене `StubFec` (заглушки) на реальную Reed–Solomon implementation (пример — `zachbabanov/rscoder`).

> Предположение: вы используете `FetchContent`/header-only `rscoder` или локальную копию `rs.hpp` в include path.

---

## 1) Общая концепция

* Цель: для каждого входного блока данных (Annex-B NAL) формировать FEC-окружение, в котором данные разбиваются на `k` *symbols*, затем генерируются `m` parity symbols. На провод отправляется набор символов (data+parity).
* В заголовке `FecPacketHeader` фиксируются `fec_k`/`fec_m` и `payload_len` — сразу понимается, сколько байт payload.
* На стороне сервера — когда собираем полный payload, мы должны разбить payload на фрагменты/символы, восстановить оригинал (если есть потери) и получить raw NAL bytes.

---

## 2) Рекомендованный внутренний layout payload (практический и совместимый)

**Вариант A (простой):** payload = последовательность кодированных символов, каждый фиксированного размера `SYMBOL_BYTES` (например, 256 байт).

```
payload = [symbol0][symbol1]...[symbolN-1] // N = (k+m)
```

* Тогда `payload_len = (k + m) * SYMBOL_BYTES`.
* Сервер при разборе должен знать `SYMBOL_BYTES` и `k` (берётся из заголовка). Если `SYMBOL_BYTES` фиксирован (например, 256), всё просто.
* Преимущество: простота парсинга, минимальная метаинформация.

**Вариант B (более гибкий):** payload = small global subheader (например, 2 байта: SYMBOL_BYTES экспонента?), затем подряд `symbols`.
* Предпочтение: Вариант A проще и совместим с текущей практикой логов (в проекте часто встречалось 256).

---

## 3) Pseudocode — `encode_with_header` (клиент)

```cpp
// in encoder.cpp
std::vector<char> encode_with_header(uint32_t client_id, uint32_t packet_seq,
                                     uint16_t fec_k, uint16_t fec_m, uint16_t flags,
                                     uint64_t pts, const char* data, size_t len) {
    // 1) choose symbol size (SYMBOL_BYTES). E.g. 256.
    const size_t SYMBOL_BYTES = 256;

    // 2) compute how many data symbols needed: k_symbols = ceil(len / SYMBOL_BYTES)
    size_t k_symbols = (len + SYMBOL_BYTES - 1) / SYMBOL_BYTES;
    if (k_symbols > fec_k) { 
       // If k_symbols > fec_k, you can either:
       //  - split NAL into multiple packets
       //  - or increase fec_k to k_symbols (preferred)
    }

    // 3) Prepare matrix: fill k_symbols data symbol buffers (pad with zeros up to SYMBOL_BYTES)
    std::vector<std::vector<uint8_t>> data_symbols(k_symbols, std::vector<uint8_t>(SYMBOL_BYTES,0));
    copy bytes from data into data_symbols[0..k_symbols-1], padding trailing bytes.

    // 4) Call rscoder to compute parity: generates m parity symbols of SYMBOL_BYTES each:
    //    rscoder.encode(data_symbols, parity_symbols)
    // 5) Construct payload as concatenation: data_symbols(0..k-1) then parity_symbols(0..m-1).
    // 6) Set header.payload_len = (k + m) * SYMBOL_BYTES
    // 7) Prepend FecPacketHeader (converted via hton_*)
    // 8) return vector(header + payload)
}
```

>Примечание: Если len (входный NAL) > k * SYMBOL_BYTES, разделите NAL на несколько пакетов (каждый с собственной header/payload).

## 4) Pseudocode — decode_payload / decode_packet (сервер)

```
FecPacket decode_packet(const char* packet_bytes, size_t packet_len){
    FecPacket pkt;
    // 1) parse header (parse_header does ntoh)
    FecPacketHeader hdr = parse_header(...);

    // 2) payload_len = hdr.payload_len; check packet_len >= header + payload_len
    // 3) SYMBOL_BYTES = 256; k = hdr.fec_k; m = hdr.fec_m;
    size_t total_symbols = (size_t) (hdr.payload_len / SYMBOL_BYTES);
    if ((hdr.payload_len % SYMBOL_BYTES) != 0) {
        // malformed — log and return empty pkt
    }

    // 4) Extract contiguous symbol buffers from payload
    // 5) Provide them to rscoder decoder; if some symbols missing, mark locations and pass nils
    // 6) rscoder.reconstruct(...) -> returns original data symbols
    // 7) Join data symbols into original byte sequence; trim padding using original length if stored
}
```
