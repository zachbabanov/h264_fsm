## QoS and Logging

Документ описывает, какие события логируются, какие метрики можно собирать и как интерпретировать логи для оценки качества (latency, throughput, buffer, packet loss / recovery).

---

## Логи — категории (используются в проекте)
* `GEN` — общие сообщения (стартап, ошибки).
* `NET` — сетевые события (sock init, send/recv, udp register).
* `VIDEO` — события, относящиеся к видео (queued frame, sent frame, frame_latency).
* `FEC` — события кодера/декодера (encode/decode, параметры, ошибки).
* `PLAYER` — события player process (start/stop, writes, writer-thread).

---

## Важные лог-сообщения (примеры) и как их использовать

### 1) Client-side

```
LOG_NET_INFO("TCP socket initialized to {}:{}", host, port);
LOG_NET_INFO("UDP register sent seq={}", seq);
LOG_GEN_INFO("Assigned client id={}", clientId);
LOG_FEC_INFO("encode_with_header: client_id={} seq={} fec_k={} fec_m={} pts={} orig_len={} fragments={} encoded_len={} total_packet={}", ...);
LOG_FEC_DEBUG("encode_with_header: first_encoded_fragment_hex={}", hex_dump(...));
LOG_VIDEO_INFO("video_send: client_id={} seq={} nal_index={} nal_bytes={}", ...);
```

**Из них** можно вычислить:
* Отправленный throughput (сумма `total_packet` за окно времени).
* Overhead ratio = `encoded_len / orig_len`.
* Параметры FEC (k/m) — для анализа корреляции overhead vs recovery.

---

### 2) Server-side

```
LOG_FEC_INFO("decode_packet: client_id={} seq={} fec_k={} fec_m={} pts={} payload_len={} decoded_len={} fragments={}", ...);
LOG_FEC_ERROR("decode_payload: RS decode failed for fragment {}/{}", ...);
LOG_PLAYER_INFO("Queued frame for client_id={} pts={} is_keyframe={} size={}", ...);
LOG_VIDEO_INFO("frame_latency: client_id={} pts={} target_offset={} elapsed={} latency={} queue_size={} ", ...);
LOG_PLAYER_INFO("Sent frame for client_id={} pts={} size={}", ...);
```


**frame_latency** fields explained:
* `pts` — PTS value attached to frame (ms)
* `target_offset` — often equals `pts - first_pts` or other base; method in server uses `first_pts` as base.
* `elapsed` — wallclock ms since server `start_time`.
* `latency = elapsed - target_offset` — если >0 то мы отображаем frame позже ожидаемого, если <0 — воспроизводим раньше. (положительное значение = задержка, отрицательное = мы воспроизводим быстрее/опережаем цель).

---

## Добавления (в проекте)

* При ошибке декодирования добавлен **hexdump** первых N байт (по умолчанию N = 64/128) — помогает быстро отличать структурные ошибки (например, начало NAL не совпадает с 0x000001).
* Логируются **orig_len**, `fragments`, `encoded_len` и `decoded_len` — удобно для offline-аналитики.
* Лог `frame_latency` (см. выше) выводится для каждого кадра.

---

## Метрики и как их извлечь

1. **Throughput** (kbps) = sum(packet_total_bytes) * 8 / window_ms * 1000
2. **Overhead ratio** = sum(encoded_len) / sum(orig_len)
3. **Frame latency** — усреднять поле `latency` по времени/окну.
4. **Queue size** — `frame_queue.size()` в логах показывает задействованную буферизацию.
5. **Recovery failure rate** — считать `LOG_FEC_ERROR("RS decode failed")` / total_packets.

---

## Примеры команд для извлечения метрик (shell)
```bash
# Throughput (approx) за последние N строк
grep 'video_send' project.log | awk '{sum += $NF} END {print sum*8/1024/1024 " Mbps"}'

# Средняя latency
grep 'frame_latency' project.log | awk -F'latency=' '{sum+= $2; n++} END {print sum/n " ms"}'
```