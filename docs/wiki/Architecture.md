# Architecture — component overview

Проект разделён на компоненты:

- **server** — прослушивает TCP-порт, принимает FEC-пакеты от клиентов, декодирует payload и пишет H.264 байты в stdin плеера (ffplay) на per-client основе.
- **client** — читает raw H.264 Annex-B файл (NALs) и отправляет их в виде FEC-пакетов.
- **player** — abstraction over ffplay (platform-specific implementation): создаёт дочерний процесс, настраивает stdin, пишет байты (non-blocking).
- **encoder** — FEC-интерфейс: `StubFec` (pass-through) или интегрированный `rscoder`.
- **logger** — общая лог-система (fmt-based), категории: GENERAL, VIDEO, FEC, PLAYER, NETWORK.

---

## Finite State Machine (per connection)

Каждое TCP-соединение на сервере представлено структурой `Connection` и FSM:

```
READING -> PROCESSING -> WRITING -> CLOSING
```

* `READING` — чтение из сокета, собирательный буфер `inBuffer`.
* `PROCESSING` — разбор пакетов, decode_packet, формирование `VideoFrame` и `frame_queue`.
* `WRITING` — попытки записать данные в `player` (запись в pipe/queue).
* `CLOSING` — очистка ресурсов, остановка player, закрытие сокета.

---

## Threading / I/O model

* **Linux:** epoll-based non-blocking loop:
  - `listenSocket_` и `udpFd` в epoll.
  - Для каждого client fd — EPOLLIN | EPOLLRDHUP.
  - player write_fds регистрируются с EPOLLOUT (edge/level).
* **Windows:** WSAPoll loop (аналогичная логика). Player использует writer thread + queue.
* Player (Linux) — один процесс per-client (fork/exec), родитель пишет в pipe (non-blocking).
* Клиент использует non-blocking sockets и небольшие задержки между пакетами для управления throughput.

---

## Player integration

* ffplay запускается с аргументами, подходящими для низкой задержки:

```
-fflags nobuffer -flags low_delay -framedrop -f h264 -i - -window_title "..."
```

* При отправке ключевого кадра (IDR) сервер *препендит* последние SPS/PPS (которые он отслеживает при получении) перед отправкой IDR в player. Это необходимо для корректной инициализации декодера ffplay.

---

## Buffering and flow control

* `Connection` содержит `playerBuffer` (string) и `frame_queue`.
* Пороговые значения:
* `MAX_PLAYER_BUFFER` — soft limit (4 MB) — при превышении делается drop из середины.
* `MAX_PLAYER_BUFFER_HARD` — hard limit (16 MB) — при превышении закрывается соединение.
* Это простая защита от переполнения при медленной стороне вывода (ffplay).

---

## Windows parity (статус и замечания)

Проект содержит реализации для Windows:
* WSAPoll loop вместо epoll.
* Player implemented via CreateProcess + writer thread + queue.
* Рекомендуется тестировать все race conditions и поведение non-blocking I/O на Windows.

---

## Where to modify

* `src/server.cpp` — main loop, accept, handle client events.
* `src/client.cpp` — NAL extraction, tcp streaming and udp register.
* `src/encoder.*`  — FEC API: `encode_with_header`, `parse_header`, `decode_payload`, `decode_packet`.
* `include/*` — типы и заголовки.

---
