
![Build Status](https://github.com/altushkaso2/BugReportChecker/actions/workflows/release.yml/badge.svg)
![Latest Release](https://img.shields.io/github/v/release/altushkaso2/BugReportChecker?label=latest%20version)
![Downloads](https://img.shields.io/github/downloads/altushkaso2/BugReportChecker/total?label=downloads)
![Language](https://img.shields.io/github/languages/top/altushkaso2/BugReportChecker)

Консольная утилита для быстрого анализа файлов `bugreport.txt` с устройств Android.

Она сканирует отчеты на наличие признаков модификации системы (root, Magisk, LSPosed, KernelSU и т.д.), кастомных сборок и других аномалий, а затем выставляет итоговый балл "опасности".

## 🚀 Демонстрация (Пример вывода)

Вот как выглядит финальный отчет в консоли:

```text
--- General Information ---
Model: Pixel 6 Pro
Android Version: 14
Magisk Version: 27.0 (Alpha)
Серийный номер: 123456ABCDEF
Bootloader: Разблокирован (unlocked (cmdline))
SELinux Status: Enforcing
Build Fingerprint: google/raven/raven:14/AP11.231020.013/10811657:user/release-keys

--- Analysis Results ---

Final Score: 9/10
Verdict: Critical. High-confidence evidence of system modification was detected.

[Root & Frameworks]: Detected
- Magisk property detected (Version: 27.0) [Alpha]
- Root Process: 'magiskd' process detected.
- High-Confidence: Hooking framework trace 'libzygisk' found in crash log.
- Zygisk library loaded into a process.

[Root Hiding & Evasion]: Detected
- Play Integrity Fix property detected: ro.pif.name

[File System & Mounts]: Detected
- Magic Mount: System partition mounted from Magisk modules directory.

... (и другие категории) ...

Results saved to: Pixel_6_Pro_log.txt
````

## ✨ Основные фичи

**Кросплатформенность:** Работает на Windows, macOS и Linux.

**Глубокий анализ:** Использует более 40+ правил для обнаружения Magisk, KernelSU, LSPosed, Zygisk, Play Integrity Fix, BusyBox и многих других.

**Система Оценки:** Выдает простой и понятный балл от 0 (Чисто) до 10 (Критично).

**Детальный отчет:** Сохраняет полный лог анализа в `.txt` файл для дальнейшего изучения.

**Нулевые зависимости:** Скомпилированные бинарники работают "из коробки" без установки чего-либо.

## 🛠️ Как использовать (Для пользователей)

### 1\. Скачать

Перейдите в раздел **[Releases](https://www.google.com/search?q=https://github.com/altushkaso2/BugReportChecker/releases)** и скачайте архив для вашей операционной системы (Windows, Linux или macOS).

### 2\. Запустить

Это консольная утилита. Есть два способа запуска:

#### Способ 1: Интерактивное меню

Просто запустите программу без аргументов, чтобы открыть меню:

```bash
# Пример для всех операционных систем
./BugReportChecker
```

Появится меню, где можно выбрать режим анализа. После выбора программа просканирует стандартные папки на наличие багрепортов.

```text
=====================================
  DebugReport Checker  
  (Created by altushkaso2)
=====================================
1) Analyze Report (Release)
2) Analyze Report (Debug)
3) Exit
-------------------------------------
Select option: 
```

> [\!NOTE]
> **Где программа ищет багрепорты:**
>
> Утилита ищет файлы, содержащие `bugreport` в названии, в 5-ти местах:
>
> 1.  **Домашняя директория** (`/home/username` или `C:\Users\username`)
> 2.  **Рабочий стол**
> 3.  **Загрузки**
> 4.  **Папка `storage/downloads`** (для совместимости с Termux)
> 5.  **Текущая директория** (откуда вы запустили `BugReportChecker`)
>
> *(Логика поиска: `/src/Application.cpp` в функции `findBugReports()`)*

#### Способ 2: Прямой запуск (Рекомендуемый)

Вы можете передать путь к файлу `bugreport.txt` напрямую как аргумент.

```bash
# Пример для Linux/macOS
./BugReportChecker /путь/к/вашему/bugreport.txt

# Пример для Windows (CMD/PowerShell)
.\BugReportChecker.exe C:\Users\Admin\Desktop\bugreport.txt
```

## 🖥️ Сборка из исходников (Для разработчиков)

Для сборки проекта вам понадобится `CMake` и C++17 компилятор.

1.  **Клонировать репозиторий**

    ```bash
    git clone https://github.com/altushkaso2/BugReportChecker.git
    cd BugReportChecker
    ```

2.  **Создать папку для сборки**

    ```bash
    mkdir build && cd build
    ```

3.  **Сконфигурировать (Release билд)**

    ```bash
    cmake .. -DCMAKE_BUILD_TYPE=Release
    ```

4.  **Собрать**

    ```bash
    cmake --build .
    ```

Бинарный файл `BugReportChecker` (или `BugReportChecker.exe`) появится в папке `build`.

## 📄 Лицензия

Все права защищены.

```
Have fun :D
```
