ZavetSec Triage v1.1
====================
Экспресс-триаж для живых Windows-систем.
Без зависимостей. Без установки. PowerShell 5.1.

ЧТО ДЕЛАЕТ
----------
Собирает криминалистические артефакты с работающего Windows-хоста и
упаковывает всё в ZIP с HTML-отчётом триажа. Все 18 модулей сбора
работают за один проход. Никаких внешних инструментов, интернета и
следов на диске — кроме итогового ZIP.

ЧТО НОВОГО В v1.1
-----------------
- HTML-отчёт (triage_report.html) в корне архива — открывается в любом
  браузере, тёмная тема, вкладки, цветовая маркировка по критичности,
  теги MITRE ATT&CK
- Правила фаервола: новая колонка Action (Allow/Block); теперь
  собираются все активные правила в обе стороны, а не только
  Allow-входящие и Block-исходящие
- Именованные каналы: добавлены колонки OwnerPID, ProcessName, ProcessPath
- UDP-соединения: добавлены колонки ProcessName и ProcessPath
- История браузеров: сырые SQLite-базы убраны, только CSV-вывод
- Задачи планировщика: исправлена проблема с кодировкой (символ п»ї в
  начале файла при открытии в Excel)
- Имя архива: <имя_хоста>_<метка_времени>.zip (без префикса ZavetSec_)
- Цвета вывода: [+] успех = зелёный, [!] предупреждения = жёлтый,
  [-] информация = серый

ТРЕБОВАНИЯ
----------
- PowerShell 5.1+
- Права локального администратора (настоятельно рекомендуется)
- sqlite3.exe опционально — полный разбор истории браузеров с заголовками,
  счётчиками посещений и временными метками вместо regex-фолбэка

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
Файл: <имя_хоста>_<метка_времени>.zip

Структура внутри ZIP:
    triage_report.html     - интерактивный HTML-отчёт, начните отсюда
    triage_metadata.json   - сводка по сбору и уровень риска
    System\          - информация об ОС, обновления, установленное ПО
    Processes\       - список процессов с хешами и подписями
    Network\         - TCP/UDP с путями процессов, кеш DNS, ARP,
                       именованные каналы с владельцами
    Persistence\     - ключи автозапуска, задачи, службы, WMI-подписки
    Users\           - учётные записи, сессии, Kerberos-билеты, история PS
    Logs\            - CSV событий и сырые EVTX-файлы
    Forensics\       - prefetch, история браузеров CSV, BITS, буфер обмена,
                       LNK-файлы, теневые копии, информация об учётных
                       данных, highlights (все находки в одном месте)
    Config\          - hosts-файл, правила фаервола с колонкой Action,
                       сканирование ADS
    Registry\        - UserAssist, MUICache, TypedURLs, RecentDocs

ЧТЕНИЕ РЕЗУЛЬТАТОВ
------------------
HTML    - любой браузер, открыть triage_report.html напрямую
CSV     - Excel или LibreOffice Calc
JSON    - VS Code, Блокнот, любой браузер
EVTX    - Просмотр событий Windows
          Chainsaw: chainsaw hunt Logs\ --sigma rules\
          Hayabusa: hayabusa csv-timeline -d Logs\ -o tl.csv

С ЧЕГО НАЧАТЬ
-------------
1. triage_report.html                - визуальный обзор, открыть в браузере
2. Forensics\triage_highlights.csv   - сортировать по Severity
3. Processes\processes.csv           - фильтр Suspicious = True
4. Network\tcp_connections.csv       - фильтр IsExternal = True и State = Established
5. Persistence\autoruns.csv          - проверить неизвестные элементы
