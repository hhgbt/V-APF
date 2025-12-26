import random
import urllib.parse

# 简单的字符替换映射，用于 homoglyph 替换（有限样例）
HOMOGLYPHS = {
    "a": "а",  # Cyrillic a
    "e": "е",
    "o": "о",
    "i": "і",
    "c": "с",
    "A": "А",
}


def case_flip(s: str):
    # 生成大小写交替、全部大写、全部小写等变体
    yield s.lower()
    yield s.upper()
    # alternating
    alt = ''.join(ch.upper() if i % 2 == 0 else ch.lower() for i, ch in enumerate(s))
    yield alt


def url_encode(s: str, times: int = 1):
    out = s
    for _ in range(times):
        out = urllib.parse.quote(out, safe='')
    return out


def double_encode(s: str):
    return url_encode(s, times=2)


def inject_comments(s: str):
    # 在空格处注入 SQL 注释风格的扰动，或在等号/关键字周围插入注释
    if not s:
        return s
    variants = []
    variants.append(s.replace(' ', '/**/'))
    variants.append(s.replace(' ', '/* */'))
    variants.append(s.replace(' OR ', '/**/OR/**/'))
    variants.append(s.replace(' or ', '/**/or/**/'))
    return variants


def null_byte_terminate(s: str):
    return s + '\x00'


def append_percent00(s: str):
    return s + '%00'


def space_tab_variants(s: str):
    yield s.replace(' ', '%20')
    yield s.replace(' ', '+')
    yield s.replace(' ', '%09')


def homoglyphs(s: str):
    out = []
    for i in range(min(3, len(s))):
        # replace up to first few characters with homoglyphs when possible
        lst = list(s)
        ch = lst[i]
        if ch in HOMOGLYPHS:
            lst[i] = HOMOGLYPHS[ch]
            out.append(''.join(lst))
    return out


class Mutator:
    def __init__(self, max_attempts: int = 10):
        self.max_attempts = max_attempts

    def generate(self, payload: str):
        """Yield mutated payloads in order of likely effectiveness.

        不重复产出，最多 self.max_attempts 个变体。
        """
        seen = set()
        def offer(x):
            if not x:
                return False
            if x in seen:
                return False
            seen.add(x)
            return True

        # 1) case flips
        for v in case_flip(payload):
            if offer(v):
                yield v
                if len(seen) >= self.max_attempts:
                    return

        # 2) url encodings
        ue = url_encode(payload, times=1)
        if offer(ue):
            yield ue
            if len(seen) >= self.max_attempts:
                return

        de = double_encode(payload)
        if offer(de):
            yield de
            if len(seen) >= self.max_attempts:
                return

        # 3) comment injection
        for v in inject_comments(payload):
            if offer(v):
                yield v
                if len(seen) >= self.max_attempts:
                    return

        # 4) space/tab variants
        for v in space_tab_variants(payload):
            if offer(v):
                yield v
                if len(seen) >= self.max_attempts:
                    return

        # 5) homoglyphs
        for v in homoglyphs(payload):
            if offer(v):
                yield v
                if len(seen) >= self.max_attempts:
                    return

        # 6) null termination and percent00
        for v in (null_byte_terminate(payload), append_percent00(payload)):
            if offer(v):
                yield v
                if len(seen) >= self.max_attempts:
                    return

        # 7) combinations: small random mixes
        attempts = 0
        while len(seen) < self.max_attempts and attempts < 20:
            attempts += 1
            cand = payload
            # randomly apply 1-3 transforms
            funcs = [lambda s: s.upper(), lambda s: url_encode(s), lambda s: s.replace(' ', '/**/'), lambda s: append_percent00(s)]
            k = random.randint(1, 3)
            for _ in range(k):
                f = random.choice(funcs)
                cand = f(cand)
            if offer(cand):
                yield cand
                if len(seen) >= self.max_attempts:
                    return
