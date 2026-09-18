# Списки маршрутизации (DNSGuru001/Domain_and_IP)

Этот репозиторий ведёт программа **routelist**: она добавляет домены и подсети, которые должны
уходить через VPN, и держит файлы в формате, понятном роутеру с **podkop** и панелям **3x-ui/xray**.
Ветка: `main`.

## Раскладка

```
domains/<slug>.lst        суффиксы: домен и все его поддомены (podkop bare, xray domain:)
hosts/<slug>.lst          точные имена хостов (podkop — как суффикс, xray full:)
subnets/ipv4/<slug>.lst   IPv4-подсети в CIDR (podkop subnet list, xray ip)
subnets/ipv6/<slug>.lst   IPv6-подсети — только для xray (podkop их не читает)
domains/all.lst           объединение domains/* и hosts/* — ЕДИНСТВЕННЫЙ URL доменов для podkop
subnets/ipv4/all.lst      объединение подсетей (после схлопывания) — URL подсетей для podkop
meta/<slug>.json          служебные данные сервиса (происхождение, даты); без URL и личных данных
tools/build.py            проверка формата: python3 tools/build.py --check  (или --fix)
```

Формат файлов: UTF-8, только LF, одна запись в строке, без комментариев и пустых строк, строки
уникальны и отсортированы, файл заканчивается переводом строки. Пустой список — файл размером 0 байт.
Агрегаты `all.lst` пересчитываются программой в том же коммите, что и изменение сервиса — руками их
править не нужно.

## Подключение к podkop (OpenWrt)

```
uci add_list podkop.main.remote_domain_lists='https://raw.githubusercontent.com/DNSGuru001/Domain_and_IP/main/domains/all.lst'
uci add_list podkop.main.remote_subnet_lists='https://raw.githubusercontent.com/DNSGuru001/Domain_and_IP/main/subnets/ipv4/all.lst'
uci set podkop.main.update_interval='1h'
uci commit podkop
service podkop restart
```

Замените `main` на имя своей секции podkop, если она называется иначе. Если GitHub с роутера
недоступен напрямую, включите загрузку списков через прокси: `uci set podkop.main.download_lists_via_proxy='1'`.

Важно:

* podkop читает только `https://raw.githubusercontent.com/...` — ссылки вида `github.com/.../blob/...`
  не работают, репозиторий должен быть **публичным**.
* Пока `all.lst` пуст (до первой записи), в логе podkop появляется строка «Download … failed» — это
  безвредно и исчезнет после первого добавления.
* Новые записи подхватываются по расписанию `update_interval` (плюс до 5 минут кэша raw-сервера) или
  сразу командой `/usr/bin/podkop list_update`. **Удаления вступают в силу только после
  `service podkop restart`.**

## Ручные правки

Правки руками допустимы, но программа проверяет формат строго: неверная строка блокирует
дальнейшие коммиты до нормализации (`routelist render`, кнопка «Нормализовать репозиторий» в GUI).
Перед пушем полезно запустить `python3 tools/build.py --check`.
