# 1CLNR_MiktotikAddressListsTool

## Эта программа предоставляет следующие возможности:
### сканирует локальную копию репозитория https://github.com/RockBlack-VPN/ip-address
 парсит BAT файлы с командами route add для извлечения IP-адресов и подсетей
 обработывает доменные файлы для создания списков адресов (_domain)
 с оптимизацией IP-адресов (удаление вложенных подсетей, объединение соседних)

## Генерация файлов для Mikrotik

out.lists.rsc - списки адресов
out.mangle.rsc - mangle правила
out.log - подробный лог выполнения

## Особенности:

Поддержка параметра -merge для объединения с существующими списками (если нужно объединить с уже имеющимися правилами на роутере)
Интерактивный режим при запуске без параметров

Валидация и очистка команд Mikrotik

Обработка доменов (удаление протоколов, добавление www. версий)

Использование:

```bash
# Справка
python _1CLNR_MiktotikAddressListsTool.py --help

# Запуск с параметрами
python _1CLNR_MiktotikAddressListsTool.py -m route_mark -f ./input -o ./output

# С объединением существующих списков
python _1CLNR_MiktotikAddressListsTool.py -m route_mark -f ./lists -o ./routeros -merge ./existing.rsc

# Интерактивный режим
python _1CLNR_MiktotikAddressListsTool.py
```

##Требования:

Python 3.6+

Стандартные библиотеки (os, sys, re, argparse, ipaddress, pathlib, logging)

Программа включает подробное логирование, обработку ошибок и проверку входных данных для обеспечения надежной работы.