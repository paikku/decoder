# -*- coding: utf-8 -*-
"""트레일러 체크섬 역산 솔버 — 표준 그리드(trailer_probe.py) 실패 시 2단계.

reveng 없이 미지 파라미터 체크섬을 수학적으로 역산한다:

  [A] 중복 분석 — 트레일러가 같은 고유 파일이 있으면 콘텐츠 체크섬 아님.
  [S] 트레일러 통계 — 바이트 위치별 분포로 구조(카운터/합/해시) 힌트.
  [N] 근사-중복 포렌식 — 몇 바이트만 다른 파일 쌍에서 "바이트 하나가 바뀌면
      트레일러가 어떻게 변하나"를 직접 관찰. 체크섬 종류를 가장 확실하게 가른다:
        · 트레일러 불변  → 그 위치는 체크섬 범위 밖
        · 산술 차이가 바이트 차이와 일치(위치 무관) → 합산형
        · 위치 따라 XOR 패턴이 달라짐 → CRC/다항식형
  [B] CRC poly 역산 — 같은 길이 쌍의 차분은 init/xorout 을 소거하므로,
      CRC 라면 P 가 D = (aΔ)·x^(32+pad) ⊕ tΔ 를 나눈다. 쌍 여러 개의
      GF(2) 다항식 GCD = P. 비트순서(msb/lsb) × 워드 바이트스왑(무/16/32비트)
      × 트레일러 해석(BE/LE/비트반전) × 제로패딩(0/4B) 전 조합 시도.
  [C] init/xorout 결정 — E(len)=F(init,len)⊕xorout 를 GF(2) 연립방정식으로.
  [D] 합산/XOR 계열 역산 — 워드합(8/16/32비트, BE/LE)·워드XOR 에 미지 상수가
      붙은 형태를 차분으로 검출하고 상수를 복원.
  [끝] 전 파일 검증 + dd_main.py 에 붙일 검증 코드 출력.

사용:
  python trailer_solve.py dumps/          # 폴더 (하위 .tdf/.dd 전부)
  python trailer_solve.py file.tdf -v
  python trailer_solve.py raw.dd --raw
"""

import struct
import sys
import zipfile
import hashlib
from pathlib import Path
from collections import defaultdict

MAGIC = b'\x17\xfa\xae\x4e'
MAX_PAIR_SIZE = 65536      # GCD 에 쓸 쌍의 최대 크기
MAX_PAIRS = 16             # GCD 에 넣을 쌍 수 (여러 길이 그룹에서 앵커+교차 방식)
NEAR_MAX_DIFF = 8          # 근사-중복으로 인정할 최대 상이 바이트 수
NEAR_BUDGET = 60000        # 근사-중복 탐색 비교 횟수 상한

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

BITREV = bytes(int(f'{i:08b}'[::-1], 2) for i in range(256))


def bitrev32(v):
    return (BITREV[v & 0xff] << 24 | BITREV[(v >> 8) & 0xff] << 16
            | BITREV[(v >> 16) & 0xff] << 8 | BITREV[(v >> 24) & 0xff])


def swap_words(b, w):
    """w바이트 워드 안에서 바이트 순서 반전 (꼬리 자투리는 그대로)."""
    n = len(b) - len(b) % w
    out = bytearray(len(b))
    for i in range(0, n, w):
        out[i:i + w] = b[i:i + w][::-1]
    out[n:] = b[n:]
    return bytes(out)


# ── GF(2) 다항식 연산 (big int = 계수 비트열) ──────────────────────
def poly_mod(a, p):
    dp = p.bit_length()
    da = a.bit_length()
    while da >= dp:
        a ^= p << (da - dp)
        da = a.bit_length()
    return a


def poly_gcd(a, b):
    while b:
        a, b = b, poly_mod(a, b)
    return a


def poly_div(a, b):
    """GF(2) 다항식 나눗셈 몫 (나눠떨어질 때만 사용)."""
    q = 0
    db = b.bit_length()
    da = a.bit_length()
    while da >= db:
        sh = da - db
        q |= 1 << sh
        a ^= b << sh
        da = a.bit_length()
    return q


def strip_small_factors(g):
    """x 와 (x+1) 인수를 제거해 32차에 도달하면 반환, 아니면 원본 유지."""
    while g and not g & 1:          # x 인수
        g >>= 1
    while g.bit_length() - 1 > 32 and poly_mod(g, 0b11) == 0:   # (x+1) 인수
        g = poly_div(g, 0b11)
    return g


# ── 레지스터 구현 (MSB-first, 스트림 공간) ─────────────────────────
def make_table(poly32):
    tbl = []
    for b in range(256):
        c = b << 24
        for _ in range(8):
            c = ((c << 1) ^ poly32) & 0xffffffff if c & 0x80000000 else (c << 1) & 0xffffffff
        tbl.append(c)
    return tbl


def crc_reg(data, table, init=0):
    crc = init
    for byte in data:
        crc = ((crc << 8) & 0xffffffff) ^ table[((crc >> 24) ^ byte) & 0xff]
    return crc


# ── F(init, L): 0바이트 L개 전진 = 32×32 GF(2) 행렬 거듭제곱 ───────
def mat_apply(cols, v):
    r, i = 0, 0
    while v:
        if v & 1:
            r ^= cols[i]
        v >>= 1
        i += 1
    return r


def mat_mul(A, B):
    return [mat_apply(A, B[i]) for i in range(32)]


def mat_pow(M, e):
    R = [1 << i for i in range(32)]
    while e:
        if e & 1:
            R = mat_mul(M, R)
        M = mat_mul(M, M)
        e >>= 1
    return R


def advance_matrix(table, nbytes):
    Z = [crc_reg(b'\x00', table, init=1 << i) for i in range(32)]
    return mat_pow(Z, nbytes)


# ── GF(2) 연립방정식 (32 미지수) ────────────────────────────────────
def solve_gf2(equations):
    rows = []
    for cols, target in equations:
        for j in range(32):
            mask = 0
            for i in range(32):
                if (cols[i] >> j) & 1:
                    mask |= 1 << i
            rows.append((mask, (target >> j) & 1))
    piv = {}
    for mask, rhs in rows:
        for b, (pm, pr) in list(piv.items()):
            if (mask >> b) & 1:
                mask ^= pm
                rhs ^= pr
        if mask == 0:
            if rhs:
                return None
            continue
        b = mask.bit_length() - 1
        for b2, (pm, pr) in list(piv.items()):
            if (pm >> b) & 1:
                piv[b2] = (pm ^ mask, pr ^ rhs)
        piv[b] = (mask, rhs)
    x = 0
    for b, (m, r) in piv.items():
        if r:
            x |= 1 << b
    return x


# ── 입력 수집 ───────────────────────────────────────────────────────
def iter_dd(paths, raw_mode=False):
    for p in paths:
        p = Path(p)
        files = (sorted(set(p.rglob('*.tdf')) | set(p.rglob('*.TDF')) | set(p.rglob('*.dd')))
                 if p.is_dir() else [p])
        for f in files:
            if raw_mode or f.suffix.lower() == '.dd':
                yield str(f), f.read_bytes()
            elif zipfile.is_zipfile(f):
                with zipfile.ZipFile(f) as zf:
                    for n in zf.namelist():
                        if n.endswith('.dd'):
                            yield f'{f.name}::{n}', zf.read(n)


# 스트림 변형: 비트순서 × 워드 바이트스왑
STREAMS = ('msb', 'lsb', 'msb_sw16', 'lsb_sw16', 'msb_sw32', 'lsb_sw32')
TINTERPS = ('BE', 'LE', 'BE_rev', 'LE_rev')
PADS = (0, 4)   # 체크섬 범위가 "트레일러를 0으로 친 전체"인 변형 대비


def to_stream(body, stream):
    if stream.endswith('_sw16'):
        body = swap_words(body, 2)
    elif stream.endswith('_sw32'):
        body = swap_words(body, 4)
    if stream.startswith('lsb'):
        body = body.translate(BITREV)
    return body


def read_trailer(t4, interp):
    be = struct.unpack('>I', t4)[0]
    le = struct.unpack('<I', t4)[0]
    return {'BE': be, 'LE': le, 'BE_rev': bitrev32(be), 'LE_rev': bitrev32(le)}[interp]


# ── 합산/XOR 계열 ───────────────────────────────────────────────────
def wsum(b, w, endian):
    s = 0
    n = len(b) - len(b) % w
    for i in range(0, n, w):
        s += int.from_bytes(b[i:i + w], endian)
    if n < len(b):
        s += int.from_bytes(b[n:], endian)
    return s & 0xffffffff


def wxor(b, w, endian):
    x = 0
    n = len(b) - len(b) % w
    for i in range(0, n, w):
        x ^= int.from_bytes(b[i:i + w], endian)
    if n < len(b):
        x ^= int.from_bytes(b[n:], endian)
    return x


SUM_FUNCS = [
    ('sum8',     lambda b: sum(b) & 0xffffffff),
    ('sum16_BE', lambda b: wsum(b, 2, 'big')),
    ('sum16_LE', lambda b: wsum(b, 2, 'little')),
    ('sum32_BE', lambda b: wsum(b, 4, 'big')),
    ('sum32_LE', lambda b: wsum(b, 4, 'little')),
]
XOR_FUNCS = [
    ('xor16_BE', lambda b: wxor(b, 2, 'big')),
    ('xor16_LE', lambda b: wxor(b, 2, 'little')),
    ('xor32_BE', lambda b: wxor(b, 4, 'big')),
    ('xor32_LE', lambda b: wxor(b, 4, 'little')),
]


def emit_snippet(kind, **kw):
    print('\n' + '=' * 64)
    print('★★ 확정! dd_main.py 에 붙일 검증 함수: ★★')
    print('=' * 64)
    if kind == 'crc':
        t_expr = {
            'BE': "int.from_bytes(raw[-4:], 'big')",
            'LE': "int.from_bytes(raw[-4:], 'little')",
            'BE_rev': "_bitrev32(int.from_bytes(raw[-4:], 'big'))",
            'LE_rev': "_bitrev32(int.from_bytes(raw[-4:], 'little'))",
        }[kw['tinterp']]
        lines = []
        if kw['stream'].endswith('_sw16'):
            lines.append("    body = _swap_words(body, 2)")
        elif kw['stream'].endswith('_sw32'):
            lines.append("    body = _swap_words(body, 4)")
        if kw['stream'].startswith('lsb'):
            lines.append("    body = body.translate(BITREV)")
        if kw['pad']:
            lines.append(f"    body = body + b'\\x00' * {kw['pad']}")
        transform = ('\n' + '\n'.join(lines)) if lines else ''
        print(f'''
BITREV = bytes(int(f'{{i:08b}}'[::-1], 2) for i in range(256))

def _bitrev32(v):
    return (BITREV[v & 0xff] << 24 | BITREV[(v >> 8) & 0xff] << 16
            | BITREV[(v >> 16) & 0xff] << 8 | BITREV[(v >> 24) & 0xff])

def _swap_words(b, w):
    n = len(b) - len(b) % w
    out = bytearray(len(b))
    for i in range(0, n, w):
        out[i:i + w] = b[i:i + w][::-1]
    out[n:] = b[n:]
    return bytes(out)

_T = []
for b in range(256):
    c = b << 24
    for _ in range(8):
        c = ((c << 1) ^ 0x{kw['poly32']:08X}) & 0xFFFFFFFF if c & 0x80000000 else (c << 1) & 0xFFFFFFFF
    _T.append(c)

def dd_trailer_ok(raw):
    """.dd 트레일러(끝 4B) 체크섬 검증"""
    body = raw[{kw['range_start']}:-4]{transform}
    crc = 0x{kw['init']:08X}
    for byte in body:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ _T[((crc >> 24) ^ byte) & 0xFF]
    crc ^= 0x{kw['xorout']:08X}
    return crc == {t_expr}
''')
    else:  # sum / xor
        op = '+' if kind == 'sum' else '^'
        print(f'''
def dd_trailer_ok(raw):
    """.dd 트레일러(끝 4B) 체크섬 검증 — {kw['fname']} {op} 상수"""
    body = raw[{kw['range_start']}:-4]
    acc = 0
    w, endian = {kw['w']}, '{kw['endian']}'
    n = len(body) - len(body) % w
    for i in range(0, n, w):
        acc = (acc {op} int.from_bytes(body[i:i+w], endian)) & 0xFFFFFFFF
    if n < len(body):
        acc = (acc {op} int.from_bytes(body[n:], endian)) & 0xFFFFFFFF
    acc = (acc {op} 0x{kw['const']:08X}) & 0xFFFFFFFF
    return acc == int.from_bytes(raw[-4:], '{kw['t_endian']}')
''')


def main():
    import argparse
    ap = argparse.ArgumentParser(description='트레일러 체크섬 역산 (CRC/합산형/포렌식)')
    ap.add_argument('paths', nargs='+')
    ap.add_argument('--raw', action='store_true')
    ap.add_argument('--max-pair-size', type=int, default=MAX_PAIR_SIZE)
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args()

    # [로드] 동일 raw dedupe
    uniq = {}
    total_seen = 0
    for name, raw in iter_dd(args.paths, args.raw):
        if len(raw) < 12 or raw[:4] != MAGIC:
            continue
        total_seen += 1
        uniq.setdefault(hashlib.sha1(raw).digest(), (name, raw))
    files = list(uniq.values())
    print(f'[로드] 바이너리 .dd {total_seen}개 → 고유 파일 {len(files)}개')
    if len(files) < 2:
        print('고유 파일이 2개 미만이라 차분 분석 불가')
        return

    # [A] 고유 파일끼리 트레일러 충돌? (고유 파일은 raw 가 다르므로,
    #     트레일러까지 같다면 본문이 다른데 트레일러가 같은 것 → 체크섬 반증)
    by_trailer = defaultdict(list)
    for name, raw in files:
        by_trailer[raw[-4:]].append(name)
    conflicts = {t: ns for t, ns in by_trailer.items() if len(ns) > 1}
    if conflicts:
        print(f'[A] ⚠ 본문이 다른데 트레일러가 같은 충돌 {len(conflicts)}건 — 콘텐츠 체크섬 반증!')
        for t, ns in list(conflicts.items())[:5]:
            print(f'      [{t.hex(" ")}] × {len(ns)}: {ns[:3]}')
    else:
        print('[A] 고유 파일의 트레일러는 전부 고유 — 콘텐츠 체크섬 가설 유지 ✓')

    # [S] 트레일러 바이트 분포
    pos_distinct = [len({raw[-4 + i] for _, raw in files}) for i in range(4)]
    print(f'[S] 트레일러 바이트 위치별 서로 다른 값 개수: {pos_distinct}  (256 에 가까울수록 무작위적)')
    if min(pos_distinct) < 32 and len(files) > 100:
        print(f'    ⚠ 특정 위치의 값 다양성이 낮음 — 그 바이트는 체크섬이 아니라 타입/버전 필드일 수도')

    # [N] 근사-중복 포렌식
    by_len = defaultdict(list)
    for name, raw in files:
        by_len[len(raw)].append((name, raw))
    near = []
    comps = 0
    for L in sorted(by_len):
        g = by_len[L]
        for i in range(len(g)):
            for j in range(i + 1, len(g)):
                comps += 1
                if comps > NEAR_BUDGET:
                    break
                ra, rb = g[i][1], g[j][1]
                xb = bytes(x ^ y for x, y in zip(ra[:-4], rb[:-4]))
                nz = len(xb) - xb.count(0)
                if 0 < nz <= NEAR_MAX_DIFF:
                    near.append((g[i], g[j], [k for k, v in enumerate(xb) if v]))
            if comps > NEAR_BUDGET:
                break
        if len(near) >= 10 or comps > NEAR_BUDGET:
            break
    if near:
        print(f'[N] 근사-중복 쌍 {len(near)}개 발견 — 단서:')
        for (na, ra), (nb, rb), diffs in near[:8]:
            t_xor = bytes(x ^ y for x, y in zip(ra[-4:], rb[-4:]))
            ta_be, tb_be = struct.unpack('>I', ra[-4:])[0], struct.unpack('>I', rb[-4:])[0]
            ta_le, tb_le = struct.unpack('<I', ra[-4:])[0], struct.unpack('<I', rb[-4:])[0]
            dsum = sum(rb[k] - ra[k] for k in diffs)
            print(f'    {Path(na).name} vs {Path(nb).name} (len {len(ra)}) — 상이 {len(diffs)}B @ {diffs}')
            print(f'      바이트 산술차 합={dsum:+d} | 트레일러 xor=[{t_xor.hex(" ")}] '
                  f'산술차 BE={(tb_be - ta_be) & 0xffffffff:#010x} LE={(tb_le - ta_le) & 0xffffffff:#010x}')
            if t_xor == b'\x00' * 4:
                print(f'      → 트레일러 불변! 위 위치들은 체크섬 범위 밖이거나 상쇄됨 (범위 단서!)')
        print('    해석: 산술차가 바이트차 합과 같으면(위치 무관) 합산형,')
        print('          위치마다 xor 패턴이 다르면 CRC 형. 아래 [B]/[D] 가 자동 판정.')
    else:
        print('[N] 근사-중복 쌍 없음 (탐색 예산 내)')

    # [B] CRC 차분 GCD — 여러 길이 그룹에서 앵커 방식으로 쌍 수집
    pairs = []
    for L in sorted(by_len):
        if L > args.max_pair_size:
            continue
        g = by_len[L]
        # 앵커(g[0] vs g[j]) + 교차(g[j] vs g[j+1]) 조합으로 차분 다양성 확보
        combos = [(0, j) for j in range(1, len(g))] + \
                 [(j, j + 1) for j in range(1, len(g) - 1)]
        for i, j in combos[:8]:
            pairs.append((g[i], g[j]))
            if len(pairs) >= MAX_PAIRS:
                break
        if len(pairs) >= MAX_PAIRS:
            break
    if not pairs:
        print(f'[B] {args.max_pair_size}B 이하 같은 길이 쌍 없음 — --max-pair-size 증가 필요')
        return
    print(f'[B] 차분에 사용할 같은 길이 쌍 {len(pairs)}개 '
          f'(길이: {sorted({len(a[1]) for a, _ in pairs})})')

    candidates = []
    for stream in STREAMS:
        for tinterp in TINTERPS:
            for pad in PADS:
                g = 0
                for (na, ra), (nb, rb) in pairs:
                    sa, sb = to_stream(ra[:-4], stream), to_stream(rb[:-4], stream)
                    m_delta = int.from_bytes(bytes(x ^ y for x, y in zip(sa, sb)), 'big')
                    t_delta = read_trailer(ra[-4:], tinterp) ^ read_trailer(rb[-4:], tinterp)
                    D = (m_delta << (32 + 8 * pad)) ^ t_delta
                    if D == 0:
                        continue
                    g = D if g == 0 else poly_gcd(g, D)
                    if g == 1:
                        break
                g = strip_small_factors(g)
                deg = g.bit_length() - 1 if g else -1
                if args.verbose and deg >= 0:
                    print(f'    {stream}/{tinterp}/pad{pad} → GCD 차수 {deg}')
                if deg == 32:
                    candidates.append((stream, tinterp, pad, g))
                    print(f'  ★ CRC 후보: stream={stream}, trailer={tinterp}, pad={pad}, '
                          f'P=0x{g & 0xffffffff:08X}')

    # [C] CRC 후보의 init/xorout 결정 + 전 파일 검증
    for stream, tinterp, pad, poly33 in candidates:
        poly32 = poly33 & 0xffffffff
        table = make_table(poly32)
        for range_start in (0, 4):
            E_by_len = {}
            ok = True
            for name, raw in files:
                body = to_stream(raw[range_start:-4], stream) + b'\x00' * pad
                E = read_trailer(raw[-4:], tinterp) ^ crc_reg(body, table)
                L = len(body)
                if L in E_by_len and E_by_len[L] != E:
                    ok = False
                    break
                E_by_len[L] = E
            if not ok:
                continue
            lens = sorted(E_by_len)
            solution = None
            for I in (0, 0xffffffff):
                X, consistent = None, True
                for L in lens:
                    F = mat_apply(advance_matrix(table, L), I) if I else 0
                    x = E_by_len[L] ^ F
                    if X is None:
                        X = x
                    elif X != x:
                        consistent = False
                        break
                if consistent:
                    solution = (I, X)
                    break
            if solution is None and len(lens) >= 2:
                L0 = lens[0]
                M0 = advance_matrix(table, L0)
                eqs = []
                for L in lens[1:5]:
                    ML = advance_matrix(table, L)
                    eqs.append(([ML[i] ^ M0[i] for i in range(32)],
                                E_by_len[L] ^ E_by_len[L0]))
                I = solve_gf2(eqs)
                if I is not None:
                    solution = (I, E_by_len[L0] ^ mat_apply(M0, I))
            if solution is None:
                continue
            I, X = solution
            good = sum(
                1 for name, raw in files
                if read_trailer(raw[-4:], tinterp)
                == crc_reg(to_stream(raw[range_start:-4], stream) + b'\x00' * pad, table, init=I) ^ X
            )
            print(f'\n[C] stream={stream}, trailer={tinterp}, pad={pad}, range=[{range_start}:n-4], '
                  f'poly=0x{poly32:08X}, init=0x{I:08X}, xorout=0x{X:08X} → {good}/{len(files)}')
            if good == len(files):
                emit_snippet('crc', stream=stream, tinterp=tinterp, pad=pad,
                             range_start=range_start, poly32=poly32, init=I, xorout=X)
                return

    # [D] 합산/XOR 계열 (미지 상수 포함) — 차분으로 검출, 상수 복원
    print('[D] 합산/XOR 계열 차분 테스트...')
    for kind, funcs in (('sum', SUM_FUNCS), ('xor', XOR_FUNCS)):
        for fname, f in funcs:
            for t_endian in ('big', 'little'):
                ok = True
                for (na, ra), (nb, rb) in pairs:
                    ta = int.from_bytes(ra[-4:], t_endian)
                    tb = int.from_bytes(rb[-4:], t_endian)
                    fa, fb = f(ra[:-4]), f(rb[:-4])
                    if kind == 'sum':
                        if (tb - ta) & 0xffffffff != (fb - fa) & 0xffffffff:
                            ok = False
                            break
                    else:
                        if ta ^ tb != fa ^ fb:
                            ok = False
                            break
                if not ok:
                    continue
                # 상수 복원 (모든 길이의 파일에서 일정해야 함)
                for range_start in (0, 4):
                    consts = set()
                    for name, raw in files:
                        t = int.from_bytes(raw[-4:], t_endian)
                        v = f(raw[range_start:-4])
                        consts.add((t - v) & 0xffffffff if kind == 'sum' else t ^ v)
                        if len(consts) > 1:
                            break
                    if len(consts) == 1:
                        c = consts.pop()
                        w = 1 if fname == 'sum8' else int(fname[3:5]) // 8
                        endian = 'big' if fname.endswith('BE') else 'little'
                        print(f'  ★ 확정: {fname} {"＋" if kind == "sum" else "⊕"} 0x{c:08X}, '
                              f'range=[{range_start}:n-4], 트레일러 {t_endian}-endian '
                              f'→ {len(files)}/{len(files)}')
                        emit_snippet(kind, fname=fname, w=w, endian=endian,
                                     range_start=range_start, const=c, t_endian=t_endian)
                        return
    print('  합산/XOR 계열도 아님.')

    print('''
[결론] 트레일러는 본문의 결정적 함수지만, CRC(바이트스왑/패딩 변형 포함)도
합산/XOR+상수 계열도 아님. 남은 가능성:
  1. 암호학적/독자 해시의 절단 (MD5/SHA/FNV/독자 알고리즘의 앞 4B 등)
  2. 다중 필드 (예: 2B 체크섬 + 2B 카운터) — [S] 위치별 분포에서 힌트 확인
  3. 파일명/메타데이터가 계산에 포함되는 변형
다음 수순: [N] 근사-중복 쌍의 트레일러 변화 패턴을 공유해 주면
알고리즘 구조를 더 좁힐 수 있음. -v 로 재실행한 전체 출력을 공유 바람.''')


if __name__ == '__main__':
    main()
