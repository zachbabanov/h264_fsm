# Project Wiki - Home

Добро пожаловать в вики проекта. Здесь собрана документация по архитектуре, протоколам, замене заглушки FEC на реальную реализацию (rscoder), инструкции по сборке и рекомендации по отладке и метрикам.

**Содержание:**
- [Architecture](Architecture) — компонентная архитектура и модель соединений (FSM).
- [Wire format / Headers](WireFormat) — подробная спецификация заголовков (RFC/IP-стиль), байтовые смещения, примеры hex.
- [Protocol](Protocol) — общий протокол взаимодействия (TCP/UDP) и поведение клиента/сервера.
- [ReplacingStubWithRscoder](ReplacingStubWithRscoder) — пошаговое руководство по интеграции `rscoder` (реальный Reed–Solomon).
- [QoS and Logging](QoS_and_Logging) — какие метрики логируются, как вычислять latency/throughput/overhead.
- [Build](Build) — инструкции по сборке проекта (CMake, FetchContent, fmt, rscoder).

> Рекомендация: начните с `Architecture` и `WireFormat`, чтобы иметь общее представление о потоках данных и формате пакетов.
