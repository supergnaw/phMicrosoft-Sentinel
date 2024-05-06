import re
from typing import Iterator, Match, Any, AnyStr, Pattern

re_flags = {
    "a": re.ASCII,
    "i": re.IGNORECASE,
    "l": re.LOCALE,
    "m": re.MULTILINE,
    "s": re.DOTALL,
    "u": re.UNICODE,
    "x": re.VERBOSE
}

if not hasattr(re, 'NOFLAG'):
    setattr(re, 'NOFLAG', 0)

# SPECIALTY INTERNAL FUNCTIONS

def _parse_regex(pattern: Pattern[AnyStr], pre_flags: int = re.NOFLAG) -> Pattern[Any] or Pattern[str or Any]:
    if not re.fullmatch(pattern=r"^\/(.*)\/([\w]*)$", string=f"{pattern}"):
        return re.compile(pattern, pre_flags)

    pattern, flags = re.fullmatch(pattern=r"^\/(.*)\/([\w]*)$", string=f"{pattern}").groups()
    flags = _parse_flags(flags, pre_flags)

    return re.compile(pattern, flags)


def _parse_flags(flags: str = "", pre_flags: int = re.NOFLAG) -> int:
    parsed_flags = pre_flags
    flags = re.sub(pattern=r"[^ailmsux]", repl="", string=flags)

    for character_flag in flags:
        parsed_flags |= re_flags.get(character_flag, re.NOFLAG)

    return parsed_flags


# CUSTOM FUNCTIONS

def is_regex(pattern: AnyStr) -> bool:
    """
    Checks if a string is a regex pattern.

    :param pattern: input string to test
    :return: true if it is a regex string, false if not
    """
    if not pattern.strip():
        return False
    if "/" != pattern[0]:
        pattern = f"/{pattern}"
    if "/" != pattern[-1]:
        pattern = f"{pattern}/"
    if re.fullmatch(pattern=r"^\/(.*)\/([\w]*)$", string=f"{pattern}"):
        return True
    return False

# UPDATED RE FUNCTIONS USING COMPILED REGEX

def compile(pattern: Pattern[AnyStr], flags: int = re.NOFLAG) -> re.Pattern:
    return _parse_regex(pattern, flags)


def search(pattern: bytes or Pattern[AnyStr], string: str, flags: int = re.NOFLAG) -> Match[bytes] or None or Match[str]:
    return re.search(_parse_regex(pattern, flags), string)


def match(pattern: bytes or Pattern[AnyStr], string: str, flags: int = re.NOFLAG) -> Match[bytes] or None or Match[str]:
    return re.match(_parse_regex(pattern, flags), string)


def fullmatch(pattern: bytes or Pattern[AnyStr], string: str, flags: int = re.NOFLAG) -> Match[bytes] or None or Match[str]:
    return re.fullmatch(_parse_regex(pattern, flags), string)


def split(pattern: bytes or Pattern[AnyStr], string: str, maxsplit: int = 0, flags: int = re.NOFLAG) -> list[bytes or Any] or list[str or Any]:
    return re.split(_parse_regex(pattern, flags), string, maxsplit, flags)


def findall(pattern: bytes or Pattern[AnyStr], string, flags: int = re.NOFLAG) -> list[Any]:
    return re.findall(_parse_regex(pattern, flags), string)


def finditer(pattern: bytes or Pattern[AnyStr], string, flags: int = re.NOFLAG) -> Iterator[Match[bytes]] or Iterator[Match[str]]:
    return re.finditer(_parse_regex(pattern, flags), string)


def sub(pattern: bytes or Pattern[AnyStr], repl, string, count: int = 0, flags: int = re.NOFLAG) -> bytes or str:
    return re.sub(_parse_regex(pattern, flags), repl, string, count)


def subn(pattern: bytes or Pattern[AnyStr], repl, string, count: int = 0, flags: int = re.NOFLAG) -> tuple[bytes, int] or tuple[str, int]:
    return re.subn(_parse_regex(pattern, flags), repl, string, count)