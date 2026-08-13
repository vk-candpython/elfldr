# 👾 elflhr


<div align="center">

[![Platform](https://img.shields.io/badge/platform-Linux-blue?logo=linux&logoColor=white)](https://www.kernel.org)
[![Language](https://img.shields.io/badge/language-C-00599C?logo=c)](https://en.cppreference.com/)
[![Builder](https://img.shields.io/badge/builder-Python%203-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

*Compress, Encrypt, Fileless Execute — One ELF binary, zero disk traces.*

</div>

---

> [!WARNING]
> This tool is intended **only** for educational purposes and authorized security auditing.  
> The author assumes no liability for any misuse or damage.

---

## 📖 Table of Contents | Оглавление

- [English](#english)
  - [📋 Overview](#-overview)
  - [✨ Features](#-features)
  - [🔒 Complete Packing Pipeline](#-complete-packing-pipeline)
  - [🚀 Quick Start](#-quick-start)
  - [⚙️ Build-time Configuration Flags](#️-build-time-configuration-flags)
  - [⚙️ Technical Highlights](#️-technical-highlights)
  - [📁 Output](#-output)
  - [⚠️ Requirements](#️-requirements)
  - [🔧 Troubleshooting](#-troubleshooting)

- [Русский](#русский)
  - [📋 Обзор](#-обзор)
  - [✨ Возможности](#-возможности)
  - [🔒 Полный конвейер упаковки](#-полный-конвейер-упаковки)
  - [🚀 Быстрый старт](#-быстрый-старт)
  - [⚙️ Флаги конфигурации времени сборки](#️-флаги-конфигурации-времени-сборки)
  - [⚙️ Технические особенности](#️-технические-особенности)
  - [📁 Результат](#-результат)
  - [⚠️ Требования](#️-требования)
  - [🔧 Устранение неполадок](#-устранение-неполадок)

---

# English

## 📋 Overview

**ELFLHR** — is a reflective ELF loader and packer that transforms standard Linux ELF64 binaries into self‑contained, encrypted, fileless‑executing executables.  
It combines efficient RLE compression, a unique ARX stream cipher, and a fully reflective loader stub written in pure C — no libc, no external dependencies, all syscalls called directly.

The loader never writes the original image to disk: it reads its own overlay, decrypts and decompresses the payload directly in memory, and executes it via `memfd_create` + `execveat`. The result is a single ELF binary that hides the original code and evades common static and dynamic analysis.

### Key Components

| Component | Description |
|-----------|-------------|
| **Reflective Loader** | Pure C, no libc; all syscalls via custom `syscall` macro |
| **ARX Stream Cipher** | Unique stateful byte mixer with data‑dependent rotation and non‑linear key scheduling |
| **RLE Compression** | Efficient run‑length encoding reduces payload size |
| **Runtime Protection** | Built‑in anti‑analysis, memory cleanup |
| **Fileless Execution** | Payload runs from `memfd` — no disk writes, no temporary files |

## ✨ Features

### Core Packing

| Feature | Description |
|---------|-------------|
| 🗜️ **Compression** | Custom RLE reduces size by 10‑40% on typical ELF binaries |
| 🔐 **Encryption** | ARX stream cipher with feedback — each byte depends on all previous |
| 🧠 **Overlay Packaging** | Payload + key appended to loader stub, read at runtime |
| 🚀 **Fileless Launch** | `memfd_create` + `execveat` — zero disk footprint |

### Compilation & Linking

| Feature | Description |
|---------|-------------|
| 🏗️ **Minimal Environment** | `-nostdlib -ffreestanding` — no libc |
| 🧹 **Stripped Binary** | `-s`, `-g0`, no symbols, minimal footprint |
| ⚡ **Optimised Output** | `-O3`, `--gc-sections`, `-fvisibility=hidden` — **5 KB loader** |

### Runtime Protection

| Feature | Description |
|---------|-------------|
| 🛡️ **Anti‑analysis** | Detects debugging and virtualised environments |
| 🧹 **Memory Cleanup** | All mmap buffers freed before execveat |

### Builder (Python)

| Feature | Description |
|---------|-------------|
| 🐍 **Pure Python 3** | No external dependencies |
| 🔑 **Random Key Generation** | 16, 32, 64, 128‑byte keys |
| 📊 **Statistics** | Displays original size, compressed size, saving percentage, and elapsed time |

## 🔒 Complete Packing Pipeline

```
PHASE 1: ELF VALIDATION
├── Checks magic (\x7fELF)
├── Confirms x86‑64 machine type (e_machine = 62)
├── Verifies ET_EXEC or ET_DYN type
└── Enforces size limits (256 B – 256 MiB)

PHASE 2: COMPRESSION
├── Custom run‑length encoding (min run 3, max 127)
└── Typical size reduction: 10‑40%

PHASE 3: ENCRYPTION
├── Random key generation (16–128 bytes)
├── ARX stream cipher (reverse of DEC_BYTE macro)
└── Data‑dependent feedback ensures uniqueness

PHASE 4: STUB ASSEMBLY
├── Loader stub (pre‑compiled ELF64)
├── Overlay layout:
│   ├── total_len (4 bytes)
│   ├── key_size  (1 byte)
│   ├── key       (N bytes)
│   ├── raw_len   (4 bytes)
│   └── payload   (encrypted + compressed data)
└── Single executable ready to deploy

PHASE 5: RUNTIME (Loader Execution)
├── Reads overlay from /proc/self/exe
├── Extracts key and payload
├── Decrypts + decompresses payload into memfd
├── Applies F_SEALS_ALL protection
├── execveat() executes the payload
└── Clean exit on failure
```

## 🚀 Quick Start

### 📥 Build the Loader Stub

The loader is written in C and compiled with GCC. Use the following command:

```bash
gcc -o loader loader.c -e _start                                       \
    -m64 -static-pie -nostdlib -ffreestanding                          \
    -s -g0 -O3 -Wl,-O3,-z,noseparate-code,-z,noexecstack               \
    -Wl,--gc-sections,--sort-common,--build-id=none                    \
    -fno-semantic-interposition -fipa-pta -fstrict-aliasing            \
    -fvisibility=hidden -fomit-frame-pointer                           \
    -fmerge-all-constants -ffunction-sections -fdata-sections          \
    -fno-stack-check -fno-stack-protector -fno-stack-clash-protection  \
    -fno-unwind-tables -fno-asynchronous-unwind-tables -fno-exceptions \
    -fno-ident -fno-common -fno-plt
```

This produces `loader` — the reflective loader stub (**~5 KB**).

### 🐍 Builder (Python)

```bash
python3 elflhr.py myapp.elf
```

The builder compresses and encrypts `myapp.elf`, then attaches the overlay to a copy of the loader stub, creating `./elflhr-myapp.elf`.

**Output example:**
```
Start processing  -> myapp.elf

[*] compressed    :  16656 -> 5268 bytes  |  saved: 11388 bytes (68.4%)
[+] output file   :  ./elflhr-myapp.elf (18701 bytes)
[*] elapsed time  :  0.0s

End of processing -> myapp.elf
```

### 🧪 Testing

```bash
./elflhr-myapp.elf
```

## ⚙️ Build-time Configuration Flags

The loader (`lindef.h`) exposes three compile‑time switches that control its behaviour:

```c
#define USING_ANTI_VM      1
#define USING_ANTI_SANDBOX 1
#define USING_ANTI_DEBUG   1
```

| Flag | Default | Description |
|------|---------|-------------|
| **`USING_ANTI_VM`** | `1` | Enables detection of virtualised environments |
| **`USING_ANTI_SANDBOX`** | `1` | Enables container/sandbox detection |
| **`USING_ANTI_DEBUG`** | `1` | Enables anti‑debugging checks |

> Changing any flag requires rebuilding the loader stub before packing.

## ⚙️ Technical Highlights

- **Direct Linux Syscalls** – all system calls are invoked via a custom `syscall` macro with automatic argument counting, eliminating any libc dependency.
- **Stack‑Based Path Construction** – all `/proc` and `/sys` paths are built on the stack using `UINT64` bit‑packing, avoiding static strings and reducing footprint.
- **RLE + ARX Cipher** – custom run‑length encoding combined with a stateful ARX stream cipher. The `DEC_BYTE` macro implements a multi‑round transformation with prime‑based key scheduling and data‑dependent rotation.
- **Overlay with Integrity** – payload is appended as an overlay; `F_SEALS_ALL` on `memfd` prevents any modifications after sealing.
- **Payload Extraction** – `ReadOverLay` reads the overlay from `/proc/self/exe` using `lseek` + `read`, with size marker at the end for easy detection.
- **Memory Cleanup** – all `mmap` buffers are freed with `FREE_MMAP` macro before `execveat`, leaving no leaked memory.
- **Tiny Footprint** – the loader stub compiles to **~5 KB**, making it one of the smallest reflective ELF loaders available.

## 📁 Output

```
original.elf  →  elflhr-original.elf
```

- Single ELF executable containing loader + encrypted payload
- No imports, no symbols, no strings in plaintext
- Executes completely in memory via `memfd_create`
- Typical size of the loader stub: **~5 KB**

## ⚠️ Requirements

| Requirement | Version | Notes |
|-------------|---------|-------|
| **Loader Compiler** | GCC (Linux x86_64) | `gcc`, `ld` |
| **Builder** | Python 3.6+ | No extra packages needed |
| **Target Platform** | Linux x86_64 | Tested on Ubuntu, Debian, Arch |

## 🔧 Troubleshooting

| Issue | Solution |
|-------|----------|
| `compilation fails` | Ensure GCC is installed and supports `-static-pie`. Check for missing headers. |
| `builder reports "Invalid ELF image"` | The input must be a 64‑bit ELF (ET_EXEC or ET_DYN) for x86_64. Check with `file`. |
| `Bus error (SIGBUS)` | Check the overlay size in the builder (`raw_len`). Ensure it matches the actual payload size. |
| `./loader: cannot execute: required file not found` | The loader stub must be built with `-static-pie` to be position‑independent. |
| `file size too large` | Maximum input size is 256 MiB by default. Adjust `ELF_FILE_MAX_SIZE` in the builder if needed. |

---

# Русский

## 📋 Обзор

**ELFLHR** — это рефлективный ELF‑загрузчик и упаковщик, превращающий стандартные Linux‑бинарники (ELF64) в автономные, зашифрованные, бесфайлово‑исполняемые программы.  
В основе лежат эффективное RLE‑сжатие, уникальный потоковый ARX‑шифр и загрузчик на чистом C, не требующий libc и напрямую использующий системные вызовы Linux.

Загрузчик никогда не сохраняет исходный образ на диск: он читает собственный оверлей, расшифровывает и распаковывает полезную нагрузку прямо в памяти и запускает её через `memfd_create` + `execveat`. Результат — один ELF‑файл, скрывающий оригинальный код.

### Ключевые компоненты

| Компонент | Описание |
|-----------|----------|
| **Рефлективный загрузчик** | Чистый C, без libc; все системные вызовы через макрос `syscall` |
| **ARX‑шифр** | Уникальный потоковый шифр с обратной связью, зависящей от данных ротацией и нелинейным планированием ключей |
| **RLE‑сжатие** | Эффективное кодирование длин серий |
| **Защита времени выполнения** | Встроенные анти‑анализ, очистка памяти |
| **Бесфайловое выполнение** | Запуск из `memfd` — никакой записи на диск, никаких временных файлов |

## ✨ Возможности

*(Полный список см. в английской версии)*

## 🔒 Полный конвейер упаковки

*(Идентичен английской версии)*

## 🚀 Быстрый старт

### 📥 Сборка загрузчика

Загрузчик написан на C и компилируется с помощью GCC. Используйте следующую команду:

*(Полный список см. в английской версии)*

Эта команда создаёт `loader` — рефлективный загрузчик (**~5 КБ**).

### 🐍 Билдер (Python)

```bash
python3 elflhr.py myapp.elf
```

Билдер сжимает и шифрует `myapp.elf`, затем прикрепляет оверлей к копии загрузчика, создавая `./elflhr-myapp.elf`.

### 🧪 Тестирование

```bash
./elflhr-myapp.elf
```

## ⚙️ Флаги конфигурации времени сборки

Загрузчик (`lindef.h`) предоставляет три compile‑time флага:

```c
#define USING_ANTI_VM      1
#define USING_ANTI_SANDBOX 1
#define USING_ANTI_DEBUG   1
```

| Флаг | Описание |
|------|----------|
| **`USING_ANTI_VM`** | Включает детект виртуальных машин |
| **`USING_ANTI_SANDBOX`** | Включает детект песочниц/контейнеров |
| **`USING_ANTI_DEBUG`** | Включает защиту от отладки |

> Изменение любого флага требует пересборки загрузчика.

## ⚙️ Технические особенности

- **Прямые системные вызовы Linux** – все системные вызовы вызываются через собственный макрос `syscall` с автоматическим подсчётом аргументов, исключая зависимость от libc.
- **Стековое построение путей** – все пути `/proc` и `/sys` строятся на стеке с помощью битовой упаковки в `UINT64`, избегая статических строк и уменьшая размер.
- **RLE + ARX‑шифр** – пользовательское RLE‑сжатие в сочетании с потоковым ARX‑шифром. Макрос `DEC_BYTE` реализует многопроходное преобразование с нелинейным планированием ключей и зависящей от данных ротацией.
- **Оверлей с защитой целостности** – полезная нагрузка добавляется как оверлей; `F_SEALS_ALL` на `memfd` предотвращает любые изменения после наложения печатей.
- **Извлечение полезной нагрузки** – `ReadOverLay` читает оверлей из `/proc/self/exe` с использованием `lseek` + `read`, с маркером размера в конце.
- **Очистка памяти** – все `mmap`‑буферы освобождаются через макрос `FREE_MMAP` перед `execveat`.
- **Минимальный размер** – загрузчик собирается в **~5 КБ**.

## 📁 Результат

```
оригинал.elf  →  elflhr-оригинал.elf
```

- Один ELF‑файл, содержащий загрузчик + зашифрованную полезную нагрузку
- Без импортов, символов и строк в открытом виде
- Полностью выполняется в памяти через `memfd_create`
- Типичный размер загрузчика: **~5 КБ**

## ⚠️ Требования

| Требование | Версия | Примечания |
|------------|--------|------------|
| **Компилятор загрузчика** | GCC (Linux x86_64) | `gcc`, `ld` |
| **Билдер** | Python 3.6+ | Без дополнительных пакетов |
| **Целевая платформа** | Linux x86_64 | Проверено на Ubuntu, Debian, Arch |

## 🔧 Устранение неполадок

*(См. английскую секцию Troubleshooting)*

---

<div align="center">

**[⬆ Back to Top](#-elflhr)**

*Reflective ELF Loader & Packer*

</div>
