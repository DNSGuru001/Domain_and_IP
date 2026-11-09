#!/usr/bin/env python3
"""Проверка/починка репозитория списков routelist (только стандартная библиотека Python 3.12+).

Этот файл копируется в репозиторий списков как ``tools/build.py`` и запускается в CI
(``python3 tools/build.py --check``) или вручную. Он НЕ зависит от пакета routelist, но обязан
воспроизводить его формат байт-в-байт (см. tests/test_build_parity.py в репозитории инструмента).

Правила формата:
  * domains/<slug>.lst, hosts/<slug>.lst — домены в форме, которую принимает podkop
    (строчные ASCII/punycode, без ведущей/завершающей точки, с хотя бы одной точкой);
  * subnets/ipv4/<slug>.lst — IPv4 CIDR всегда с префиксом (1.2.3.4/32), хостовые биты нулевые;
  * subnets/ipv6/<slug>.lst — IPv6 CIDR в сжатой форме с префиксом;
  * каждый файл: ASCII, LF, без пустых строк/пробелов/комментариев, уникальные, отсортированные
    строки, завершающий LF; пустой список = файл 0 байт (только для агрегатов);
  * domains/all.lst = domains/* ∪ hosts/* минус хосты, покрытые суффиксом;
    subnets/ipv4/all.lst = объединение (collapse); subnets/ipv6/all.lst — только если есть IPv6;
  * сервисы с "route": "direct" в meta входят не в эти агрегаты, а в direct/domains.lst,
    direct/subnets-ipv4.lst и direct/subnets-ipv6.lst (правила те же);
  * meta/<slug>.json — валидный JSON-объект с полем "slug", равным имени файла.

Коды выхода: 0 — всё в порядке, 1 — найдены проблемы (отчёт в stdout), 2 — ошибка запуска.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
import unicodedata
from pathlib import Path

DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
RESERVED_SLUGS = {"all"}
MAX_HOST_LEN = 253

KIND_DOMAIN = "domain"
KIND_HOST = "host"
KIND_CIDR4 = "cidr4"
KIND_CIDR6 = "cidr6"
KIND_BY_DIR = {
    "domains": KIND_DOMAIN,
    "hosts": KIND_HOST,
    "subnets/ipv4": KIND_CIDR4,
    "subnets/ipv6": KIND_CIDR6,
}
AGG_DOMAINS = "domains/all.lst"
AGG_IPV4 = "subnets/ipv4/all.lst"
AGG_IPV6 = "subnets/ipv6/all.lst"
DIRECT_DIR = "direct"
AGG_DIRECT_DOMAINS = "direct/domains.lst"
AGG_DIRECT_IPV4 = "direct/subnets-ipv4.lst"
AGG_DIRECT_IPV6 = "direct/subnets-ipv6.lst"
AGGREGATES = {
    AGG_DOMAINS: KIND_DOMAIN,
    AGG_IPV4: KIND_CIDR4,
    AGG_IPV6: KIND_CIDR6,
    AGG_DIRECT_DOMAINS: KIND_DOMAIN,
    AGG_DIRECT_IPV4: KIND_CIDR4,
    AGG_DIRECT_IPV6: KIND_CIDR6,
}
META_DIR = "meta"
ROUTE_VPN = "vpn"
ROUTE_DIRECT = "direct"

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


# ---- ключи сортировки и рендер (должны совпадать с routelist.core) --------------------------------


def domain_sort_key(host: str) -> tuple[str, ...]:
    return tuple(reversed(host.split(".")))


def network_sort_key(net: Network) -> tuple[int, int, int]:
    return (net.version, int(net.network_address), net.prefixlen)


def render_network(net: Network) -> str:
    return f"{net.network_address}/{net.prefixlen}"


def render_lst(values: set[str] | list[str], kind: str) -> bytes:
    uniq = set(values)
    if not uniq:
        return b""
    if kind in (KIND_CIDR4, KIND_CIDR6):
        ordered = sorted(uniq, key=lambda v: network_sort_key(ipaddress.ip_network(v, strict=False)))
    else:
        ordered = sorted(uniq, key=domain_sort_key)
    return ("\n".join(ordered) + "\n").encode("ascii")


def is_covered_by_suffix(host: str, suffixes: list[str]) -> bool:
    return any(host == suf or host.endswith("." + suf) for suf in suffixes)


def collapse(nets: list[Network]) -> list[Network]:
    v4 = [n for n in nets if isinstance(n, ipaddress.IPv4Network)]
    v6 = [n for n in nets if isinstance(n, ipaddress.IPv6Network)]
    out: list[Network] = list(ipaddress.collapse_addresses(v4))
    out.extend(ipaddress.collapse_addresses(v6))
    return out


# ---- проверка отдельных значений -----------------------------------------------------------------


def is_valid_a_label(label: str) -> bool:
    """Метка xn-- декодируется в допустимое имя. В routelist.core это делает пакет idna (IDNA 2008);
    здесь только stdlib, поэтому проверка приближённая: буквы, цифры и знаки в канонической форме."""
    try:
        decoded = label[4:].encode("ascii").decode("punycode")
    except UnicodeError:
        return False
    if decoded.isascii() or decoded != unicodedata.normalize("NFC", decoded.lower()):
        return False
    return all(ch == "-" or unicodedata.category(ch)[0] in "LMN" for ch in decoded)


def check_value(value: str, kind: str) -> str | None:
    """None, если строка каноническая для своего вида; иначе причина по-русски."""
    if kind in (KIND_DOMAIN, KIND_HOST):
        if not DOMAIN_RE.match(value):
            return "podkop отбросит строку (только строчные a-z0-9, дефис, точки)"
        if "." not in value:
            return "имя без точки не принимается"
        if len(value) > MAX_HOST_LEN:
            return "слишком длинное имя"
        if any(label.startswith("xn--") and not is_valid_a_label(label) for label in value.split(".")):
            return "некорректная punycode-метка"
        return None
    try:
        net = ipaddress.ip_network(value, strict=True)
    except ValueError:
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError:
            return "недопустимый IP/CIDR"
        return "хостовые биты за префиксом должны быть нулевыми"
    if kind == KIND_CIDR4 and net.version != 4:
        return "в subnets/ipv4 допустимы только IPv4"
    if kind == KIND_CIDR6 and net.version != 6:
        return "в subnets/ipv6 допустимы только IPv6"
    if render_network(net) != value:
        return f"неканоническая запись, ожидается {render_network(net)}"
    return None


def parse_lst(data: bytes, path: str, kind: str) -> tuple[list[str], list[str]]:
    """Строгий разбор файла: (значения, проблемы). Повторяет routelist.core.formats.parse_lst."""
    problems: list[str] = []
    if not data:
        return [], problems
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        problems.append(f"{path}: файл содержит не-ASCII символы")
        text = data.decode("utf-8", errors="replace")
    lines = text.split("\n")
    if text.endswith("\n"):
        lines = lines[:-1]
    else:
        problems.append(f"{path}:{len(lines)}: нет завершающего LF: {lines[-1]!r}")
    values: list[str] = []
    seen: set[str] = set()
    for lineno, raw in enumerate(lines, start=1):
        line = raw
        if line.endswith("\r"):
            problems.append(f"{path}:{lineno}: CRLF вместо LF")
            line = line[:-1]
        if line != line.strip():
            problems.append(f"{path}:{lineno}: пробелы по краям: {line!r}")
            line = line.strip()
        if not line:
            problems.append(f"{path}:{lineno}: пустая строка")
            continue
        if "#" in line or "//" in line:
            problems.append(f"{path}:{lineno}: комментарии не поддерживаются podkop: {line!r}")
            continue
        if line in seen:
            problems.append(f"{path}:{lineno}: дубликат: {line!r}")
            continue
        seen.add(line)
        reason = check_value(line, kind)
        if reason is not None:
            problems.append(f"{path}:{lineno}: {reason}: {line!r}")
            continue
        values.append(line)
    if values and render_lst(values, kind) != ("\n".join(values) + "\n").encode("ascii"):
        problems.append(
            f"{path}: строки не отсортированы (домены — по перевёрнутым меткам, сети — по адресу)"
        )
    return values, problems


# ---- сканирование репозитория --------------------------------------------------------------------


class Repo:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.problems: list[str] = []
        # kind -> slug -> values
        self.services: dict[str, dict[str, list[str]]] = {k: {} for k in KIND_BY_DIR.values()}
        self.aggregates: dict[str, bytes | None] = {}
        self.direct: set[str] = set()  # сервисы с прямым маршрутом

    def rel(self, p: Path) -> str:
        return p.relative_to(self.root).as_posix()

    def read_routes(self) -> None:
        """Какие сервисы идут напрямую: поле route в meta/<slug>.json (нет поля — через VPN)."""
        meta_dir = self.root / META_DIR
        if not meta_dir.is_dir():
            return
        for p in sorted(meta_dir.glob("*.json")):
            try:
                obj = json.loads(p.read_bytes().decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                continue
            route = (obj.get("route") if isinstance(obj, dict) else None) or ROUTE_VPN
            if route == ROUTE_DIRECT:
                self.direct.add(p.stem)
            elif route != ROUTE_VPN:
                self.problems.append(f'{self.rel(p)}: недопустимый маршрут {route!r} (ожидается "direct")')

    def scan(self) -> None:
        for directory, kind in KIND_BY_DIR.items():
            dir_path = self.root / directory
            if not dir_path.is_dir():
                continue
            for p in sorted(dir_path.iterdir()):
                rel = self.rel(p)
                if p.is_dir():
                    self.problems.append(f"{rel}: посторонний каталог в {directory}/")
                    continue
                if rel in AGGREGATES:
                    self.aggregates[rel] = p.read_bytes()
                    continue
                if p.suffix != ".lst":
                    self.problems.append(f"{rel}: посторонний файл (ожидается только *.lst)")
                    continue
                slug = p.stem
                if not SLUG_RE.match(slug) or slug in RESERVED_SLUGS:
                    self.problems.append(f"{rel}: недопустимое имя сервиса {slug!r}")
                    continue
                data = p.read_bytes()
                if not data:
                    self.problems.append(f"{rel}: пустой файл сервиса должен быть удалён")
                    continue
                values, probs = parse_lst(data, rel, kind)
                self.problems.extend(probs)
                self.services[kind][slug] = values
        subnets = self.root / "subnets"
        if subnets.is_dir():
            for p in sorted(subnets.iterdir()):
                if p.name not in ("ipv4", "ipv6"):
                    self.problems.append(f"{self.rel(p)}: посторонний элемент в subnets/")
        direct_dir = self.root / DIRECT_DIR
        if direct_dir.is_dir():
            for p in sorted(direct_dir.iterdir()):
                rel = self.rel(p)
                if rel in AGGREGATES:
                    self.aggregates[rel] = p.read_bytes()
                else:
                    self.problems.append(f"{rel}: посторонний элемент в {DIRECT_DIR}/")
        for agg in AGGREGATES:
            self.aggregates.setdefault(agg, None)
        self.read_routes()
        meta_dir = self.root / META_DIR
        if meta_dir.is_dir():
            for p in sorted(meta_dir.iterdir()):
                rel = self.rel(p)
                if p.is_dir() or p.suffix != ".json":
                    self.problems.append(f"{rel}: посторонний файл (ожидается только *.json)")
                    continue
                slug = p.stem
                if not SLUG_RE.match(slug) or slug in RESERVED_SLUGS:
                    self.problems.append(f"{rel}: недопустимое имя сервиса {slug!r}")
                    continue
                try:
                    obj = json.loads(p.read_bytes().decode("utf-8"))
                except (ValueError, UnicodeDecodeError) as exc:
                    self.problems.append(f"{rel}: невалидный JSON: {exc}")
                    continue
                if not isinstance(obj, dict) or obj.get("slug") != slug:
                    self.problems.append(f'{rel}: ожидается JSON-объект с "slug": "{slug}"')

    # ---- агрегаты -------------------------------------------------------------------------------
    def expected_aggregates(self) -> dict[str, bytes]:
        return {
            **self._aggregates(False, AGG_DOMAINS, AGG_IPV4, AGG_IPV6),
            **self._aggregates(True, AGG_DIRECT_DOMAINS, AGG_DIRECT_IPV4, AGG_DIRECT_IPV6),
        }

    def _aggregates(self, direct: bool, domains: str, ipv4: str, ipv6: str) -> dict[str, bytes]:
        def values(kind: str) -> list[str]:
            return [
                v
                for slug, vals in self.services[kind].items()
                if (slug in self.direct) == direct
                for v in vals
            ]

        suffixes = sorted(set(values(KIND_DOMAIN)))
        hosts = set(values(KIND_HOST))
        all_domains = set(suffixes) | {h for h in hosts if not is_covered_by_suffix(h, suffixes)}
        v4 = [ipaddress.ip_network(v) for v in values(KIND_CIDR4)]
        v6 = [ipaddress.ip_network(v) for v in values(KIND_CIDR6)]
        out = {
            domains: render_lst(all_domains, KIND_DOMAIN),
            ipv4: render_lst([render_network(n) for n in collapse(v4)], KIND_CIDR4),
        }
        v6_rendered = [render_network(n) for n in collapse(v6)]
        if v6_rendered:
            out[ipv6] = render_lst(v6_rendered, KIND_CIDR6)
        return out

    def check_aggregates(self) -> None:
        expected = self.expected_aggregates()
        for path in AGGREGATES:
            actual = self.aggregates.get(path)
            want = expected.get(path)
            if want is None:
                if actual is not None:
                    self.problems.append(f"{path}: агрегат должен отсутствовать (нет записей IPv6)")
                continue
            if actual is None:
                if not want and path.startswith(DIRECT_DIR + "/"):
                    continue  # прямых сервисов нет, а файлы появятся с первым коммитом программы
                self.problems.append(f"{path}: агрегат отсутствует (ожидается {_count(want)} строк)")
                continue
            if actual != want:
                self.problems.append(f"{path}: агрегат не совпадает с расчётом{_diff_hint(actual, want)}")


def _count(data: bytes) -> int:
    return data.count(b"\n")


def _diff_hint(actual: bytes, want: bytes) -> str:
    a = set(actual.decode("utf-8", errors="replace").split("\n")) - {""}
    w = set(want.decode("ascii").split("\n")) - {""}
    extra = sorted(a - w)
    missing = sorted(w - a)
    parts: list[str] = []
    if extra:
        parts.append("лишние: " + ", ".join(extra[:5]) + (" …" if len(extra) > 5 else ""))
    if missing:
        parts.append("не хватает: " + ", ".join(missing[:5]) + (" …" if len(missing) > 5 else ""))
    if not parts:
        parts.append("порядок строк или формат (LF, завершающий перевод строки)")
    return " — " + "; ".join(parts)


def check(root: Path) -> list[str]:
    """Полная проверка каталога. Пустой список — репозиторий корректен."""
    repo = Repo(root)
    repo.scan()
    repo.check_aggregates()
    return repo.problems


# ---- починка -------------------------------------------------------------------------------------


def _idn_to_ascii(s: str) -> str:
    """IDN → punycode по меткам, как idna.encode(uts46=True) в routelist.core.

    Кодек "idna" из stdlib (IDNA 2003) не подходит: он превратил бы faß.de в другой домен, fass.de."""
    s = unicodedata.normalize("NFKC", s).replace("\u3002", ".").lower()
    return ".".join(
        label if label.isascii() else "xn--" + label.encode("punycode").decode("ascii")
        for label in s.split(".")
    )


def _lenient_domain(raw: str) -> str | None:
    s = raw.strip().lower().rstrip(".")
    while s.startswith(("*.", ".")):
        s = s[2:] if s.startswith("*.") else s[1:]
    if not s.isascii():
        s = _idn_to_ascii(s)
    return s if check_value(s, KIND_DOMAIN) is None else None


def _lenient_network(raw: str, kind: str) -> str | None:
    try:
        net = ipaddress.ip_network(raw.strip(), strict=False)
    except ValueError:
        return None
    if (kind == KIND_CIDR4) != (net.version == 4):
        return None
    return render_network(net)


def fix(root: Path) -> list[str]:
    """Переписать файлы сервисов в каноническом виде и пересчитать агрегаты. Возвращает отчёт."""
    report: list[str] = []
    repo = Repo(root)
    for directory, kind in KIND_BY_DIR.items():
        dir_path = root / directory
        if not dir_path.is_dir():
            continue
        for p in sorted(dir_path.glob("*.lst")):
            rel = repo.rel(p)
            if rel in AGGREGATES:
                continue
            slug = p.stem
            if not SLUG_RE.match(slug) or slug in RESERVED_SLUGS:
                report.append(f"{rel}: пропущен — недопустимое имя сервиса")
                continue
            values: set[str] = set()
            for lineno, raw in enumerate(p.read_bytes().decode("utf-8", errors="replace").split("\n"), 1):
                line = raw.strip()
                if not line or line.startswith(("#", "//")):
                    continue
                line = line.split("#", 1)[0].split("//", 1)[0].strip()
                if not line:
                    continue
                fixed = (
                    _lenient_domain(line)
                    if kind in (KIND_DOMAIN, KIND_HOST)
                    else _lenient_network(line, kind)
                )
                if fixed is None:
                    report.append(f"{rel}:{lineno}: строка отброшена: {line!r}")
                    continue
                values.add(fixed)
            if values:
                data = render_lst(values, kind)
                if p.read_bytes() != data:
                    p.write_bytes(data)
                    report.append(f"{rel}: переписан ({len(values)} строк)")
                repo.services[kind][slug] = sorted(values)
            else:
                p.unlink()
                report.append(f"{rel}: удалён (пусто)")
    repo.read_routes()
    expected = repo.expected_aggregates()
    for path, data in expected.items():
        target = root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists() or target.read_bytes() != data:
            target.write_bytes(data)
            report.append(f"{path}: агрегат обновлён ({_count(data)} строк)")
    for path in (AGG_IPV6, AGG_DIRECT_IPV6):
        ipv6_agg = root / path
        if path not in expected and ipv6_agg.exists():
            ipv6_agg.unlink()
            report.append(f"{path}: удалён (нет записей IPv6)")
    meta_dir = root / META_DIR
    if meta_dir.is_dir():
        for p in sorted(meta_dir.glob("*.json")):
            try:
                obj = json.loads(p.read_bytes().decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                report.append(f"{repo.rel(p)}: невалидный JSON — не тронут, исправьте вручную")
                continue
            canon = (json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
            if p.read_bytes() != canon:
                p.write_bytes(canon)
                report.append(f"{repo.rel(p)}: JSON приведён к каноническому виду")
    return report


# ---- CLI -----------------------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Проверка/починка репозитория списков routelist.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="проверить и выйти с кодом 1 при проблемах")
    mode.add_argument("--fix", action="store_true", help="переписать файлы в каноническом виде")
    parser.add_argument("--root", default=".", help="корень репозитория списков (по умолчанию — текущий)")
    args = parser.parse_args(argv)
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # type: ignore[union-attr]
    except (AttributeError, ValueError):
        pass
    root = Path(args.root).resolve()
    if not root.is_dir():
        print(f"каталог не найден: {root}")
        return 2
    if args.fix:
        for line in fix(root):
            print(line)
    problems = check(root)
    if problems:
        print(f"Найдено проблем: {len(problems)}")
        for line in problems:
            print("  " + line)
        return 1
    print("OK: списки и агрегаты корректны")
    return 0


if __name__ == "__main__":
    sys.exit(main())
