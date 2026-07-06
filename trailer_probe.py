# -*- coding: utf-8 -*-
"""트레일러(끝 4바이트) 체크섬 알고리즘 규명 도구.

.dd 바이너리 파일의 마지막 4바이트가 어떤 체크섬인지 그리드 탐색으로 찾는다:

  알고리즘(CRC-32 변종들/Adler/Fletcher/단순합) × 계산 범위 × 엔디언

판정 논리:
  - 파일 1개 일치 = 우연 확률 2^-32 → 강한 후보
  - 모든 파일 일치 = 사실상 확정
  - 아무것도 안 나오면 CRC RevEng 으로 파라미터 역산 (도움말 출력 참고)

사용:
  python trailer_probe.py dumps/            # 폴더의 모든 .tdf 안의 .dd 전수 조사
  python trailer_probe.py file.tdf          # 특정 TDF
  python trailer_probe.py raw.dd --raw      # 압축 해제된 .dd 직접
  python trailer_probe.py dumps/ --limit 50 # 앞 50개 파일만 (빠른 1차 스캔)
"""

import struct
import sys
import zlib
import zipfile
from pathlib import Path
from collections import Counter, defaultdict

MAGIC = b'\x17\xfa\xae\x4e'
TRAILER_LEN = 4

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass


# ── 일반화 CRC-32 (테이블 구동) ──────────────────────────────────────
def _reflect(v, bits):
    r = 0
    for i in range(bits):
        if (v >> i) & 1:
            r |= 1 << (bits - 1 - i)
    return r


class CRC32:
    """CRC RevEng 카탈로그 파라미터(poly/init/refin/refout/xorout) 그대로 구현."""

    def __init__(self, name, poly, init, refin, refout, xorout):
        assert refin == refout, '카탈로그의 32비트 CRC는 전부 refin==refout'
        self.name = name
        self.refin = refin
        self.xorout = xorout
        self.init = _reflect(init, 32) if refin else init
        self.table = []
        if refin:
            poly_r = _reflect(poly, 32)
            for b in range(256):
                c = b
                for _ in range(8):
                    c = (c >> 1) ^ poly_r if c & 1 else c >> 1
                self.table.append(c)
        else:
            for b in range(256):
                c = b << 24
                for _ in range(8):
                    c = ((c << 1) ^ poly) & 0xffffffff if c & 0x80000000 else (c << 1) & 0xffffffff
                self.table.append(c)

    def __call__(self, data):
        crc = self.init
        t = self.table
        if self.refin:
            for byte in data:
                crc = (crc >> 8) ^ t[(crc ^ byte) & 0xff]
        else:
            for byte in data:
                crc = ((crc << 8) & 0xffffffff) ^ t[((crc >> 24) ^ byte) & 0xff]
        return crc ^ self.xorout


def _fletcher32(data):
    # 표준 Fletcher-32: 16비트 워드 단위 (홀수 길이는 0 패딩), LE 워드 기준
    if len(data) % 2:
        data = data + b'\x00'
    s1 = s2 = 0
    for (w,) in struct.iter_unpack('<H', data):
        s1 = (s1 + w) % 65535
        s2 = (s2 + s1) % 65535
    return (s2 << 16) | s1


def _sum32(data):
    return sum(data) & 0xffffffff


def _xor32_be(data):
    if len(data) % 4:
        data = data + b'\x00' * (4 - len(data) % 4)
    x = 0
    for (w,) in struct.iter_unpack('>I', data):
        x ^= w
    return x


# (이름, 계산 함수) — zlib 내장이 있는 건 내장 사용 (훨씬 빠름)
ALGOS = [
    ('CRC-32 (zlib/ISO-HDLC)', lambda d: zlib.crc32(d) & 0xffffffff),
    ('CRC-32/JAMCRC',          lambda d: (zlib.crc32(d) ^ 0xffffffff) & 0xffffffff),
    ('Adler-32',               lambda d: zlib.adler32(d) & 0xffffffff),
    ('CRC-32/BZIP2',   CRC32('bzip2',   0x04C11DB7, 0xFFFFFFFF, False, False, 0xFFFFFFFF)),
    ('CRC-32/MPEG-2',  CRC32('mpeg2',   0x04C11DB7, 0xFFFFFFFF, False, False, 0x00000000)),
    ('CRC-32/POSIX',   CRC32('posix',   0x04C11DB7, 0x00000000, False, False, 0xFFFFFFFF)),
    ('CRC-32C',        CRC32('crc32c',  0x1EDC6F41, 0xFFFFFFFF, True,  True,  0xFFFFFFFF)),
    ('CRC-32D',        CRC32('crc32d',  0xA833982B, 0xFFFFFFFF, True,  True,  0xFFFFFFFF)),
    ('CRC-32/AUTOSAR', CRC32('autosar', 0xF4ACFB13, 0xFFFFFFFF, True,  True,  0xFFFFFFFF)),
    ('CRC-32/AIXM',    CRC32('aixm',    0x814141AB, 0x00000000, False, False, 0x00000000)),
    ('CRC-32/XFER',    CRC32('xfer',    0x000000AF, 0x00000000, False, False, 0x00000000)),
    ('Fletcher-32',    _fletcher32),
    ('sum32 (바이트 합)', _sum32),
    ('xor32 (BE 워드 XOR)', _xor32_be),
]


def make_ranges(raw):
    """계산 범위 후보. (라벨, bytes)"""
    body_end = len(raw) - TRAILER_LEN
    return [
        ('전체-트레일러 [0:n-4]', raw[:body_end]),
        ('매직 제외 본문 [4:n-4]', raw[4:body_end]),
        ('트레일러 0치환 전체',   raw[:body_end] + b'\x00' * TRAILER_LEN),
    ]


def probe_one(raw, name=''):
    """단일 .dd 에 대해 (알고리즘 × 범위 × 엔디언) 그리드 탐색 → 매치 리스트"""
    if len(raw) < 8 or raw[:4] != MAGIC:
        return None  # 바이너리 .dd 아님
    trailer = raw[-TRAILER_LEN:]
    t_be = struct.unpack('>I', trailer)[0]
    t_le = struct.unpack('<I', trailer)[0]

    matches = []
    for rng_label, chunk in make_ranges(raw):
        for algo_name, fn in ALGOS:
            v = fn(chunk)
            if v == t_be:
                matches.append((algo_name, rng_label, 'BE'))
            if v == t_le and t_le != t_be:
                matches.append((algo_name, rng_label, 'LE'))
    return {'name': name, 'trailer': trailer.hex(' '), 'matches': matches}


def iter_dd(paths, raw_mode=False):
    """경로들에서 (이름, bytes) 를 순서대로 낸다. .tdf 는 풀어서, .dd 는 그대로."""
    for p in paths:
        p = Path(p)
        if p.is_dir():
            files = sorted(set(p.rglob('*.tdf')) | set(p.rglob('*.TDF'))
                           | set(p.rglob('*.dd')))
        else:
            files = [p]
        for f in files:
            if raw_mode or f.suffix.lower() == '.dd':
                yield str(f), f.read_bytes()
            elif zipfile.is_zipfile(f):
                with zipfile.ZipFile(f) as zf:
                    for n in zf.namelist():
                        if n.endswith('.dd'):
                            yield f'{f.name}::{n}', zf.read(n)


def main():
    import argparse
    ap = argparse.ArgumentParser(description='트레일러 체크섬 알고리즘 그리드 탐색')
    ap.add_argument('paths', nargs='+', help='TDF/DD 파일 또는 폴더')
    ap.add_argument('--raw', action='store_true', help='입력을 원시 .dd 로 취급')
    ap.add_argument('--limit', type=int, help='검사할 .dd 최대 개수')
    ap.add_argument('-v', '--verbose', action='store_true', help='파일별 매치 상세 출력')
    args = ap.parse_args()

    total = 0          # 검사한 바이너리 .dd 수
    skipped = 0        # 매직 없어서 건너뛴 수
    hit_counter = Counter()          # (algo, range, endian) -> 일치 파일 수
    no_match_files = []
    trailer_seen = defaultdict(list)  # 트레일러 값 -> 파일들 (중복 관찰용)

    for name, raw in iter_dd(args.paths, args.raw):
        res = probe_one(raw, name)
        if res is None:
            skipped += 1
            continue
        total += 1
        trailer_seen[res['trailer']].append(name)
        if res['matches']:
            for m in res['matches']:
                hit_counter[m] += 1
            if args.verbose:
                print(f"✓ {name}  trailer=[{res['trailer']}]")
                for a, r, e in res['matches']:
                    print(f"    {a}  /  {r}  /  {e}")
        else:
            no_match_files.append(name)
            if args.verbose:
                print(f"✗ {name}  trailer=[{res['trailer']}]  매치 없음")
        if args.limit and total >= args.limit:
            break

    print(f"\n{'=' * 64}")
    print(f"검사: 바이너리 .dd {total}개 (매직 없음 {skipped}개 제외)")
    if not total:
        return

    print(f"\n[후보별 일치율]  ← {total}/{total} 이면 확정")
    if hit_counter:
        for (algo, rng, endian), cnt in hit_counter.most_common():
            mark = '★ 확정' if cnt == total else ''
            print(f"  {cnt:>4}/{total}  {algo:<26} {rng:<22} {endian}  {mark}")
    else:
        print('  (그리드 내 일치 없음)')

    confirmed = [k for k, c in hit_counter.items() if c == total]
    if confirmed:
        print('\n결론: 트레일러 =')
        for algo, rng, endian in confirmed:
            print(f'  {algo} over ({rng}), {endian} 저장')
    else:
        print('\n그리드에서 확정 실패. 다음 단계:')
        print('  1) 트레일러 중복 관찰 — 같은 트레일러가 서로 다른 내용에서 반복되면')
        print('     체크섬이 아니라 ID/타임스탬프일 수 있음:')
        dup = {t: fs for t, fs in trailer_seen.items() if len(fs) > 1}
        if dup:
            for t, fs in list(dup.items())[:5]:
                print(f'       [{t}] × {len(fs)}회: {fs[:3]} ...')
        else:
            print('       (중복 없음 — 체크섬 가능성 높음)')
        print('  2) CRC RevEng 으로 미지 파라미터 역산 (poly/init/xorout 전부 미지여도 가능):')
        print('     reveng -w 32 -s <본문+트레일러 hex> <본문+트레일러 hex> ...')
        print('     (짧은 .dd 여러 개를 골라 "계산범위+트레일러" 를 hex 로 이어붙여 입력)')
        print('  3) CRC 선형성 활용 — 길이가 같은 두 파일이 있으면')
        print('     crc(a) xor crc(b) 에서 init/xorout 효과가 소거되어 poly 만 검증 가능')

    if no_match_files and not args.verbose:
        print(f'\n매치 없던 파일 {len(no_match_files)}개 (앞 5개): {no_match_files[:5]}')


if __name__ == '__main__':
    main()
