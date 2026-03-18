ZavetSec Triage v1.0
====================
Экспресс-триаж для живых Windows-систем.
Без зависимостей. Без установки. PowerShell 5.1.

ЧТО ДЕЛАЕТ
----------
Собирает криминалистические артефакты с работающего Windows-хоста и
упаковывает всё в ZIP с меткой времени. Все 17 модулей сбора работают
за один проход. Никаких внешних инструментов, интернета и следов на
диске — кроме итогового ZIP.

ТРЕБОВАНИЯ
----------
- PowerShell 5.1+
- Права локального администратора (настоятельно рекомендуется)
- sqlite3.exe опционально — полный разбор баз браузеров

ИСПОЛЬЗОВАНИЕ
-------------
Локально (запустить PowerShell от имени администратора):

    .\Invoke-ZavetSecTriage.ps1
    .\Invoke-ZavetSecTriage.ps1 -OutputDir C:\DFIR

Удалённо через PsExec (тихо, без взаимодействия с пользователем):

    psexec \\TARGET -s -d powershell.exe -NonInteractive -WindowStyle Hidden
        -ExecutionPolicy Bypass -File "\\share\Invoke-ZavetSecTriage.ps1"
        -OutputDir "\\share\output"

    -s  запуск от SYSTEM (полный доступ, пароль не нужен)
    -d  detached — не ждёт завершения

РЕЗУЛЬТАТ
---------
Файл: ZavetSec_<имя_хоста>_<метка_времени>.zip

Структура внутри ZIP:
    System\          - информация об ОС, обновления, установленное ПО
    Processes\       - список процессов с хешами и подписями
    Network\         - соединения, кеш DNS, ARP, именованные каналы
    Persistence\     - ключи автозапуска, задачи, службы, WMI-подписки
    Users\           - учётные записи, сессии, Kerberos-билеты
    Logs\            - CSV событий и сырые EVTX-файлы
    Forensics\       - prefetch, история браузеров, BITS, буфер обмена,
                       LNK-файлы, артефакты реестра, highlights
    Config\          - hosts-файл, правила фаервола, сканирование ADS
    triage_metadata.json   - сводка по сбору и уровень риска
    triage_highlights.csv  - все срабатывания, отсортированные по критичности

ЧТЕНИЕ РЕЗУЛЬТАТОВ
------------------
CSV     - Excel или LibreOffice Calc
JSON    - VS Code, Блокнот, любой браузер
EVTX    - Просмотр событий Windows
          Chainsaw: chainsaw hunt Logs\ --sigma rules\
          Hayabusa: hayabusa csv-timeline -d Logs\ -o tl.csv
SQLite  - DB Browser for SQLite (sqlitebrowser.org)

С ЧЕГО НАЧАТЬ
-------------
1. Forensics\triage_highlights.csv   -- сортировать по Severity
2. Processes\processes.csv           -- фильтр Suspicious = True
3. Network\tcp_connections.csv       -- фильтр IsExternal = True
4. Forensics\browser_history_all.csv -- открыть в Excel
