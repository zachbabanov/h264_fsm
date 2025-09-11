# Build / CMake / dependencies

Документ объясняет, как собрать проект локально и какие зависимости подтягиваются через `FetchContent`.

---

## Зависимости

* `fmt` — используется в логгере.
* `rscoder` — Reed-Solomon header-only (используется при интеграции).
* `Catch2` — для unit tests (опционально, via FetchContent).

> В CMake используется `FetchContent` для подгрузки `fmt` и `rscoder`. Если ваша среда не позволяет git-clone из CI, можно клонировать `rscoder`/`fmt` в `deps/` и добавить include path вручную.

---

## Основной CMakeLists.txt (важные моменты)

* `project_core` — библиотека (STATIC) содержащая `src/*.cpp`.
* `target_link_libraries(project_core PUBLIC fmt::fmt)` — `fmt` подключается PUBLIC, чтобы `server`/`client` имели include-path во время компиляции (логгер использует `fmt` в заголовках).
* Если FetchContent падает на `rscoder` из-за ветки `master/main` — исправьте GIT_TAG на актуальный (например `main`).

---

## типичные ошибки и отладка

**Ошибка**: `fatal error: fmt/core.h: No such file or directory`  
**Причина**: `fmt` не привязан как PUBLIC к `project_core` или FetchContent не выполнился.  
**Fix**:
* Убедитесь, что `FetchContent_MakeAvailable(fmt)` прошёл успешно.
* Убедитесь, что `target_link_libraries(project_core PUBLIC fmt::fmt)` (не PRIVATE).
* Сделайте **чистую** конфигурацию: удалите `CMakeCache.txt`, `CMakeFiles` и каталог сборки, затем `cmake ..`/`cmake --build`.

**Ошибка**: `Failed to checkout tag: 'master'` при `rscoder`  
**Fix**: поменяйте `GIT_TAG` на `main` или конкретный commit hash/тег, т.к. некоторые репозитории переехали на `main`.

---

## Сборка (пример)
```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . -j$(nproc)
```

> **Windows notes**<br>
> На Windows используется `ws2_32` и `WSAPoll`-подобная логика.
> Для корректной сборки под Windows используйте `MSVC` + штатный `FetchContent` (`CMake >= 3.14`). Обратите внимание на опцию `-D_WIN32_WINNT=0x0601`.
