# 👾 elfobf


<div align="center">

[![Platform](https://img.shields.io/badge/platform-Linux-blue?logo=linux&logoColor=white)](https://www.linux.org/)
[![Language](https://img.shields.io/badge/language-Python%203-3776AB?logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

*Advanced ELF binary protection — Compress, Encrypt, Polymorph, Fileless Execute*

</div>

---

> [!WARNING]
> This tool is for educational purposes and authorized security auditing only. The author is not responsible for any misuse.

---

## 📖 Table of Contents | Оглавление

- [English](#english)
  - [📋 Overview](#-overview)
  - [✨ Features](#-features)
  - [🔒 Complete Protection Pipeline](#-complete-protection-pipeline)
  - [🚀 Quick Start](#-quick-start)
  - [⚙️ Deep Technical Analysis](#️-deep-technical-analysis)
  - [📁 Output](#-output)
  - [⚠️ Requirements](#️-requirements)
  - [🔧 Troubleshooting](#-troubleshooting)

- [Русский](#русский)
  - [📋 Обзор](#-обзор)
  - [✨ Возможности](#-возможности)
  - [🔒 Полный конвейер защиты](#-полный-конвейер-защиты)
  - [🚀 Быстрый старт](#-быстрый-старт)
  - [⚙️ Глубокий технический анализ](#️-глубокий-технический-анализ)
  - [📁 Результат](#-результат)
  - [⚠️ Требования](#️-требования)
  - [🔧 Устранение неполадок](#-устранение-неполадок)

---

# English

## 📋 Overview

**ELF-OBF** is a military-grade ELF binary obfuscation tool that transforms standard Linux executables into heavily armored, self-decrypting, fileless-executing binaries.

### What makes it unique?

| Component | Implementation |
|-----------|----------------|
| **Single SYSCALL Macro** | One unified macro for ALL system calls — reduces code size, centralizes obfuscation |
| **Obfuscated Syscall Numbers** | XORed with random key at compile-time — no plaintext syscall numbers in binary |
| **Shifted Syscall Numbers** | `memfd_create` and `execveat` are bit-shifted by random amounts |
| **RLE Compression** | Custom byte-level run-length encoding — typical 30-60% size reduction |
| **XOR Stream Cipher** | 16-128 byte key + salt + feedback mechanism — each byte depends on all previous |
| **Polymorphic C Stub** | 100% unique per build — random identifiers from 129-char alphabet |
| **Dead Code Injection** | 150+ combinatorial ASM patterns + random C junk statements |
| **SSTRIP Integration** | Embedded pre-compiled SSTRIP binary — removes section headers completely |
| **Polyglot Signatures** | 27 different file format headers injected |
| **Fileless Execution** | `memfd_create` + `execveat` with `AT_EMPTY_PATH` — zero disk trace |
| **Anti-Debug** | TracerPid check + PR_SET_PTRACER + PR_SET_DUMPABLE |
| **Memory Protection** | mlockall(MCL_ALL) + F_SEAL_ALL — prevents swapping and memory modification |
| **Highly Optimized Builder** | Memoryviews, pre-compiled SSTRIP, single-pass compression, GC control |

## ✨ Features

### Core Protection

| Feature | Description |
|---------|-------------|
| 🗜️ **RLE Compression** | Byte-level RLE with 0x80 repeat flag, typical 30-60% reduction |
| 🔐 **XOR Stream Cipher** | Salt + key mutation with feedback — non-linear encryption |
| 🎲 **Polymorphic Stub** | Random function/variable names from 129-char alphabet (Latin + Cyrillic + Ukrainian) |
| 📝 **Dead ASM Injection** | 25+ patterns: `nop`, `pause`, `clc`, `xor`, `lea`, `push/pop` + register combinations |
| 🔧 **Dead C Injection** | Random junk statements in SYSCALL macro, ANTIDEBUG, and loader body |

### Compilation & Linking

| Feature | Description |
|---------|-------------|
| 🏗️ **MUSL/GCC Auto-detect** | Prefers MUSL for smaller output, falls back to GCC |
| 📦 **Custom Linker Script** | Random base address (0x400000 + random*0x1000), discards all unused sections |
| 🚫 **Compiler Flags** | `-Os -static-pie -fomit-frame-pointer -fno-stack-protector -Wl,--strip-all` |
| 🧹 **SSTRIP** | Removes section headers completely — breaks `objdump`, `readelf`, `gdb` |

### Runtime Protection

| Feature | Description |
|---------|-------------|
| 💾 **Fileless Execution** | `memfd_create` → write → seal → `execveat` with `AT_EMPTY_PATH` |
| 🛡️ **Anti-Debug** | Parses `/proc/self/status` for `TracerPid` (obfuscated string in binary) |
| 🔒 **PTRACE Block** | `prctl(PR_SET_PTRACER, 0)` — only children can ptrace |
| 🚫 **No New Privs** | `prctl(PR_SET_NO_NEW_PRIVS, 1)` — prevents setuid escalation |
| 📵 **No Core Dumps** | `prctl(PR_SET_DUMPABLE, 0)` — blocks gcore and coredumps |
| 🔐 **Memory Lock** | `mlockall(MCL_ALL)` — prevents swapping to disk |
| 🔏 **Sealed Memory FD** | `fcntl(F_ADD_SEALS, F_SEALS_ALL)` — prevents modification before exec |

### Polyglot Signatures (27 formats)

| Signature | Format |
|-----------|--------|
| `\x7FELF` | ELF (native) |
| `MZ` + `PE` | Windows PE |
| `\x89PNG` | PNG Image |
| `%PDF` | PDF Document |
| `PK\x03\x04` | ZIP Archive |
| `\x1F\x8B` | GZIP |
| `\xFD\x37\x7A\x58\x5A` | XZ/LZMA |
| `\x21\x3C\x61\x72\x63\x68\x3E` | AR Archive |
| `\xCA\xFE\xBA\xBE` | Mach-O (32-bit) |
| `\xCF\xFA\xED\xFE` | Mach-O (64-bit) |
| `#!/bin/bash` | Shell Script |
| `UPX!` | UPX Packer |
| `\xFF\xD8\xFF\xE0` | JPEG |
| `BM` | BMP |
| `ID3` | MP3 |
| `ftypisom` | MP4 |
| `SQLite format 3` | SQLite |
| `\xD0\xCF\x11\xE0` | MS Office |
| `\x00\x61\x73\x6D` | WebAssembly |
| `\xFE\xED\xFA\xCE` | Mach-O (32-bit, alternative) |
| `\xBE\xBA\xFE\xCA` | Java Class |
| `\x99\x01` | DOS COM |
| `\x00\x01\x00\x00` | TrueType Font |
| `<?xml` | XML |
| `<!DOCTYPE` | HTML |
| `\x25\x21` | PostScript |
| `\x3C\x3F\x78\x6D\x6C` | XML Declaration |

## 🔒 Complete Protection Pipeline

```
PHASE 1: ELF VALIDATION
├── Checks ELF magic (\x7FELF)
├── Validates x86_64 architecture
└── Memory-maps file with MADV_SEQUENTIAL

PHASE 2: RLE COMPRESSION
├── Flag byte: 0x00-0x7F = literal run, 0x80-0xFF = repeat run
├── Minimum repeat threshold: 3 identical bytes
├── Maximum literal run: 126 bytes
└── Output buffer: exact pre-allocation

PHASE 3: XOR STREAM ENCRYPTION
├── Key: 16-128 random bytes + random salt (0-255)
├── State: i = (x ^ ((y << 1) ^ (i >> 1))) & 0xFF
├── Operations: XOR → rotate left 3 → add (y ^ 0xA5)
└── /proc/self/status string also encrypted

PHASE 4: POLYMORPHIC LOADER GENERATION
├── Random identifiers: 4-254 chars, 129-char alphabet
├── Obfuscated constants: XORed and shifted syscall numbers
├── Random dead code: 150+ ASM patterns, 11 junk per SYSCALL macro
└── Unique linker script: random base address + random polyglot signature

PHASE 5: C COMPILATION
├── Compiler: MUSL (preferred) or GCC
├── 20+ aggressive compiler flags for size and stealth
└── Custom linker script with discarded sections

PHASE 6: SSTRIP
├── Embedded pre-compiled SSTRIP binary (~13KB)
├── Truncates section header table
└── Result: "ghost" ELF — runs but has no visible sections
```

## 🚀 Quick Start

### 📥 Download

```bash
git clone https://github.com/vk-candpython/elfobf.git
cd elfobf
```

### 📦 Requirements

```bash
# Install MUSL (recommended for smaller output)
sudo apt install musl-tools    # Debian/Ubuntu
sudo pacman -S musl            # Arch

# Or use GCC (auto-detected)
sudo apt install gcc
```

### 🏃 Usage

```bash
python3 elfobf.py <elf1> [elf2 ...]
```

**Example:**
```bash
python3 elfobf.py /bin/ls
```

**Output:**
```
[  OK  ]: architecture is valid (x86_64)
[  OK  ]: using compiler(/usr/bin/musl-gcc)

[ INFO ]: Start processing -> /bin/ls

[ INFO ]: obfuscating: ELF(/bin/ls)
[ INFO ]: compressing: {####################} 100%  (DONE)
[  OK  ]: compressed:  (142144 -> 89123) bytes  |  saved: 53021 bytes (37.3%)
[ INFO ]: encrypting:  {####################} 100%  (DONE)
[ BUILD ]: file(./_mkelfobf/link.ld)
[ BUILD ]: file(./_mkelfobf/payload.bin)
[ BUILD ]: file(./_mkelfobf/loader.c)
[ BUILD ]: file(./_mkelfobf/sstrip.elf)
[  OK  ]: compiled  .................  (DONE)
[  OK  ]: striped   .................  (DONE)
[ INFO ]: time      .................  (1.23s)
[  OK  ]: outfile(./elfobf-ls, 45678 bytes)
[  OK  ]: obfuscation complete ELF(/bin/ls)

[ INFO ]: End processing -> /bin/ls

[  OK  ]: cleanup build dir(./_mkelfobf)
```

## ⚙️ Deep Technical Analysis

### The SYSCALL Macro (One for ALL)

A single unified macro handles every system call in the loader. Each expansion injects 11 random junk statements. The syscall is made via `call` to a trampoline function that contains random dead code before and after the `syscall` instruction. Clobbers `rcx` and `r11` per x86_64 ABI.

### The Syscall Trampoline

A dedicated static function with `.hidden` visibility contains the actual `syscall` instruction, surrounded by random junk ASM. This centralizes all syscalls through one obfuscated gate.

### RLE Decompression (Runtime)

The decompressor processes the encrypted payload byte-by-byte. Each byte is first decrypted via the DEC macro, then interpreted as either a repeat run (0x80 flag set) or literal run. Output is written in 4KB chunks to the sealed memory file descriptor.

### DEC Macro (Decrypt Single Byte)

The inverse of the encryption function: subtract `(y ^ 0xA5)`, rotate right 3, XOR with derived key and state. The state `g` is updated with a non-linear feedback function: `g = (b ^ ((y << 1) ^ (i >> 1))) & 0xFF`.

### ANTIDEBUG Macro

The string `/proc/self/status` is encrypted in the binary. The macro decrypts it at runtime, opens the file, and searches for an obfuscated `TracerPid:` pattern (each character XORed with different keys). Returns the TracerPid value: 0 = clean, >0 = debugger detected. All buffers are securely zeroed before return.

### Fileless Execution

The payload is decrypted and decompressed directly into a memory file descriptor created via `memfd_create`. The fd is then sealed with `F_SEAL_ALL` to prevent any modification before execution via `execveat` with `AT_EMPTY_PATH`.

### ZEROS Macro (Secure Memory Wipe)

Uses `rep stosq` in reverse direction (DF=1) to zero sensitive buffers. Reverse direction makes memory forensics recovery harder.

### Dead Code Injection Patterns

25+ base ASM patterns combined with 10 registers generate 150+ unique dead code combinations at build time. Additionally, the C code is peppered with random statements between every meaningful line.

### Builder Optimizations

| Optimization | Implementation |
|--------------|----------------|
| **Memoryviews** | Zero-copy slicing, no intermediate allocations |
| **Pre-allocated Buffers** | Exact size calculation for RLE output |
| **MADV_SEQUENTIAL** | Hint kernel for sequential access |
| **Chunked I/O** | 4KB chunks for large files |
| **Pre-compiled SSTRIP** | Embedded as bytes, written once per session |
| **Single-pass Compression** | RLE compresses in one pass |
| **In-place Encryption** | XOR modifies buffer directly |
| **GC Control** | `gc.disable()` + manual `gc.collect()` |
| **Color Output Caching** | Memoized ANSI color codes |

## 📁 Output

```
original_elf  →  elfobf-original_elf
```

**Output binary properties:**
- Stripped of all symbols and section headers
- Contains encrypted payload in `.rodata`-like section
- Executes entirely from memory
- Leaves no traces on disk (except the binary itself)
- Typically **30-60% smaller** than original

## ⚠️ Requirements

| Requirement | Version | Notes |
|-------------|---------|-------|
| **Python** | 3.6+ | Required for builder |
| **MUSL-GCC** | Any | Recommended (smaller output) |
| **GCC** | Any | Fallback |
| **Linux Kernel** | 3.17+ | For `memfd_create` |
| **Linux Kernel** | 3.19+ | For `execveat` |
| **Architecture** | x86_64 | Only 64-bit |

## 🔧 Troubleshooting

| Issue | Solution |
|-------|----------|
| `Cannot determine architecture` | Only x86_64 supported |
| `No suitable compiler found` | Install `musl-tools` or `gcc` |
| `compilation failed` | Check compiler; try GCC if MUSL fails |
| `execveat: Function not implemented` | Kernel < 3.19 |
| `memfd_create: Function not implemented` | Kernel < 3.17 |
| Obfuscated binary segfaults | Original may need dynamic libraries |
| `gdb` still attaches | Use `PR_SET_PTRACER` + TracerPid |
| Binary size increased | Normal for very small binaries |

---

# Русский

## 📋 Обзор

**ELF-OBF** — инструмент обфускации ELF-бинарников военного уровня, который превращает стандартные исполняемые файлы Linux в сильно бронированные, саморасшифровывающиеся бинарники с бесфайловым выполнением.

### Что делает его уникальным?

| Компонент | Реализация |
|-----------|------------|
| **Единый макрос SYSCALL** | Один для ВСЕХ системных вызовов — уменьшает размер кода, централизует обфускацию |
| **Обфусцированные номера syscall** | XOR со случайным ключом — в бинарнике нет открытых номеров |
| **Сдвинутые номера syscall** | `memfd_create` и `execveat` сдвинуты на случайные биты |
| **RLE-сжатие** | Кастомное побайтовое кодирование — типичное сжатие 30-60% |
| **Потоковый XOR-шифр** | Ключ 16-128 байт + соль + обратная связь — каждый байт зависит от предыдущих |
| **Полиморфный C-стаб** | 100% уникален для каждой сборки — имена из 129-символьного алфавита |
| **Впрыск мёртвого кода** | 150+ комбинаторных ASM-паттернов + случайный мусор в C |
| **Интеграция SSTRIP** | Встроенный предскомпилированный SSTRIP — полное удаление заголовков секций |
| **Полиглот-сигнатуры** | 27 различных заголовков форматов файлов |
| **Бесфайловое выполнение** | `memfd_create` + `execveat` с `AT_EMPTY_PATH` — нулевой след на диске |
| **Анти-отладка** | Проверка TracerPid + PR_SET_PTRACER + PR_SET_DUMPABLE |
| **Защита памяти** | mlockall(MCL_ALL) + F_SEAL_ALL |
| **Оптимизированный билдер** | Memoryviews, предскомпилированный SSTRIP, однопроходное сжатие, контроль GC |

## ✨ Возможности

### Основная защита

| Возможность | Описание |
|-------------|----------|
| 🗜️ **RLE-сжатие** | Побайтовое RLE с флагом 0x80, типичное сжатие 30-60% |
| 🔐 **Потоковый XOR-шифр** | Соль + мутация ключа с обратной связью — нелинейное шифрование |
| 🎲 **Полиморфная заглушка** | Случайные имена из 129-символьного алфавита (латиница + кириллица + украинский) |
| 📝 **Впрыск мёртвого ASM** | 25+ паттернов + комбинации с 10 регистрами = 150+ вариантов |
| 🔧 **Впрыск мёртвого C** | Случайный мусор в макросе SYSCALL, ANTIDEBUG и теле загрузчика |

### Компиляция и линковка

| Возможность | Описание |
|-------------|----------|
| 🏗️ **Автовыбор MUSL/GCC** | Предпочитает MUSL для меньшего размера |
| 📦 **Кастомный линкер-скрипт** | Случайный базовый адрес, сбрасывает все неиспользуемые секции |
| 🚫 **Флаги компилятора** | `-Os -static-pie -fomit-frame-pointer -fno-stack-protector -Wl,--strip-all` |
| 🧹 **SSTRIP** | Полное удаление заголовков секций — ломает `objdump`, `readelf`, `gdb` |

### Защита времени выполнения

| Возможность | Описание |
|-------------|----------|
| 💾 **Бесфайловое выполнение** | `memfd_create` → запись → seal → `execveat` с `AT_EMPTY_PATH` |
| 🛡️ **Анти-отладка** | Парсинг `/proc/self/status` для `TracerPid` (строка зашифрована в бинарнике) |
| 🔒 **Блокировка PTRACE** | `prctl(PR_SET_PTRACER, 0)` — только потомки могут трассировать |
| 🚫 **Запрет новых привилегий** | `prctl(PR_SET_NO_NEW_PRIVS, 1)` |
| 📵 **Запрет core-дампов** | `prctl(PR_SET_DUMPABLE, 0)` |
| 🔐 **Блокировка памяти** | `mlockall(MCL_ALL)` |
| 🔏 **Запечатанный memory FD** | `fcntl(F_ADD_SEALS, F_SEALS_ALL)` |

## 🔒 Полный конвейер защиты

*(См. английскую версию для подробной диаграммы)*

## 🚀 Быстрый старт

```bash
git clone https://github.com/vk-candpython/elfobf.git
cd elfobf
python3 elfobf.py /bin/ls
./elfobf-ls
```

## ⚙️ Глубокий технический анализ

### Макрос SYSCALL (Один на ВСЕ)

Единый унифицированный макрос обрабатывает каждый системный вызов в загрузчике. Каждое раскрытие впрыскивает 11 случайных мусорных инструкций. Системный вызов делается через `call` к функции-трамплину, которая содержит случайный мёртвый код до и после инструкции `syscall`.

### RLE-распаковка (во время выполнения)

Распаковщик обрабатывает зашифрованные данные побайтово. Каждый байт сначала расшифровывается через макрос DEC, затем интерпретируется как повторяющаяся серия (флаг 0x80) или литеральная серия. Вывод пишется чанками по 4 КБ в запечатанный файловый дескриптор в памяти.

### Макрос DEC (Расшифровка одного байта)

Обратная функция шифрования: вычитание `(y ^ 0xA5)`, поворот вправо на 3, XOR с производным ключом и состоянием. Состояние `g` обновляется нелинейной функцией с обратной связью: `g = (b ^ ((y << 1) ^ (i >> 1))) & 0xFF`.

### Макрос ANTIDEBUG

Строка `/proc/self/status` зашифрована в бинарнике. Макрос расшифровывает её во время выполнения, открывает файл и ищет обфусцированный паттерн `TracerPid:` (каждый символ XOR с разными ключами). Возвращает значение TracerPid: 0 = чисто, >0 = обнаружен отладчик. Все буферы безопасно затираются перед возвратом.

### Бесфайловое выполнение

Полезная нагрузка расшифровывается и распаковывается напрямую в файловый дескриптор в памяти, созданный через `memfd_create`. Затем fd запечатывается с `F_SEAL_ALL` для предотвращения любых модификаций перед выполнением через `execveat` с `AT_EMPTY_PATH`.

### Макрос ZEROS (Безопасное затирание памяти)

Использует `rep stosq` в обратном направлении (DF=1) для затирания чувствительных буферов. Обратное направление усложняет восстановление memory forensics.

### Оптимизации билдера

| Оптимизация | Реализация |
|-------------|------------|
| **Memoryviews** | Zero-copy слайсинг |
| **Предвыделенные буферы** | Точный расчёт размера для RLE |
| **MADV_SEQUENTIAL** | Подсказка ядру о последовательном доступе |
| **Чанковый I/O** | Блоки по 4 КБ для больших файлов |
| **Предскомпилированный SSTRIP** | Встроен как байты, записывается один раз |
| **Однопроходное сжатие** | RLE сжимает за один проход |
| **Шифрование на месте** | XOR модифицирует буфер напрямую |
| **Контроль GC** | `gc.disable()` + ручной `gc.collect()` |
| **Кеширование цветов** | Мемоизация ANSI-кодов |

## 📁 Результат

```
оригинальный_elf  →  elfobf-оригинальный_elf
```

## ⚠️ Требования

| Требование | Версия | Примечания |
|------------|--------|------------|
| **Python** | 3.6+ | Для билдера |
| **MUSL-GCC** | Любая | Рекомендуется |
| **GCC** | Любая | Запасной |
| **Ядро Linux** | 3.17+ | Для `memfd_create` |
| **Ядро Linux** | 3.19+ | Для `execveat` |
| **Архитектура** | x86_64 | Только 64-бит |

## 🔧 Устранение неполадок

| Проблема | Решение |
|----------|---------|
| `Cannot determine architecture` | Только x86_64 |
| `No suitable compiler found` | Установи `musl-tools` или `gcc` |
| `compilation failed` | Проверь компилятор |
| `execveat: Function not implemented` | Ядро < 3.19 |
| `memfd_create: Function not implemented` | Ядро < 3.17 |
| Обфусцированный бинарник падает | Оригинал может требовать динамические библиотеки |

---

<div align="center">

**[⬆ Back to Top](#-elfobf)**

*ELF Obfuscation for Linux*

</div>
