# -*- coding: utf-8 -*-
"""트레일러 체크섬 역산 솔버 — 표준 그리드(trailer_probe.py) 실패 시 2단계.

reveng 없이 미지 파라미터 CRC 를 수학적으로 역산한다. 원리는 CRC 의 선형성:

  [A] 중복 분석
      트레일러가 같은 파일들의 '본문'도 같은지 확인.
      본문이 다른데 트레일러가 같으면 → 체크섬이 아닐 강력한 신호.

  [B] poly 역산 (차분 + 다항식 GCD)
      길이가 같은 두 파일 a,b 에서 t(a)^t(b) 를 만들면 init/xorout 효과가
      완전히 소거되어 crc0(a^b) 만 남는다. CRC 라면 P 가
        D = (a^b)·x^32 ⊕ (t_a ⊕ t_b)
      를 나눈다. 이런 쌍 여러 개의 GF(2) 다항식 GCD = P (커스텀 poly 여도 나옴).
      비트 순서(msb/lsb 스트림)와 트레일러 해석(BE/LE/비트반전) 8조합을 전부 시도.

  [C] init/xorout 결정
      t(m) = crc0(m) ⊕ F(init, len) ⊕ xorout.  E = t ⊕ crc0 를 길이별로 모으면
      E(len) = F(init,len) ⊕ xorout — init 은 GF(2) 32원 연립방정식으로 풀린다.
      (F 는 'init 레지스터를 len 바이트의 0 위로 전진'시키는 선형사상 → 행렬 거듭제곱)

  [D] 전 파일 검증 + dd_main.py 에 붙일 검증 코드 스니펫 출력.

사용:
  python trailer_solve.py dumps/
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
TRAILER_LEN = 4
MAX_PAIR_SIZE = 65536      # GCD 에 쓸 쌍의 최대 크기 (큰 파일은 느려서 제외)
MAX_PAIRS = 6              # combo 당 GCD 에 넣을 쌍 수

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass

BITREV = bytes(int(f'{i:08b}'[::-1], 2) for i in range(256))


def bitrev32(v):
    return (BITREV[v & 0xff] << 24 | BITREV[(v >> 8) & 0xff] << 16
            | BITREV[(v >> 16) & 0xff] << 8 | BITREV[(v >> 24) & 0xff])


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


# ── F(init, L) 선형사상: 0 바이트 L 개 전진 = 행렬 거듭제곱 ─────────
def mat_apply(cols, v):
    r, i = 0, 0
    while v:
        if v & 1:
            r ^= cols[i]
        v >>= 1
        i += 1
    return r


def mat_mul(A, B):          # (A∘B) 의 컬럼들
    return [mat_apply(A, B[i]) for i in range(32)]


def mat_pow(M, e):
    R = [1 << i for i in range(32)]   # 항등
    while e:
        if e & 1:
            R = mat_mul(M, R)
        M = mat_mul(M, M)
        e >>= 1
    return R


def advance_matrix(table, nbytes):
    Z = [crc_reg(b'\x00', table, init=1 << i) for i in range(32)]
    return mat_pow(Z, nbytes) if nbytes != 1 else Z


# ── GF(2) 연립방정식 (32 미지수) ────────────────────────────────────
def solve_gf2(equations):
    """equations: [(cols, target)] — xor_{i: x_i=1} cols[i] == target 를 푼다."""
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
                return None            # 모순 → 해 없음
            continue
        b = mask.bit_length() - 1
        for b2, (pm, pr) in list(piv.items()):
            if (pm >> b) & 1:
                piv[b2] = (pm ^ mask, pr ^ rhs)
        piv[b] = (mask, rhs)
    x = 0
    for b, (m, r) in piv.items():
        if r:
            x |= 1 << b                # 자유변수는 0 으로
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


STREAMS = ('msb', 'lsb')
TINTERPS = ('BE', 'LE', 'BE_rev', 'LE_rev')


def to_stream(body, stream):
    return body if stream == 'msb' else body.translate(BITREV)


def read_trailer(t4, interp):
    be = struct.unpack('>I', t4)[0]
    le = struct.unpack('<I', t4)[0]
    return {'BE': be, 'LE': le, 'BE_rev': bitrev32(be), 'LE_rev': bitrev32(le)}[interp]


def main():
    import argparse
    ap = argparse.ArgumentParser(description='트레일러 체크섬 역산 (poly/init/xorout 미지 CRC)')
    ap.add_argument('paths', nargs='+')
    ap.add_argument('--raw', action='store_true')
    ap.add_argument('--max-pair-size', type=int, default=MAX_PAIR_SIZE)
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args()

    # [로드] 동일 raw 는 1개로 dedupe (통계 왜곡 방지)
    uniq = {}                                # sha1(raw) -> (name, raw)
    total_seen = 0
    for name, raw in iter_dd(args.paths, args.raw):
        if len(raw) < 12 or raw[:4] != MAGIC:
            continue
        total_seen += 1
        h = hashlib.sha1(raw).digest()
        uniq.setdefault(h, (name, raw))
    files = list(uniq.values())
    print(f'[로드] 바이너리 .dd {total_seen}개 → 고유 파일 {len(files)}개')
    if len(files) < 2:
        print('고유 파일이 2개 미만이라 차분 분석 불가')
        return

    # [A] 트레일러 중복 vs 본문 중복
    by_trailer = defaultdict(list)
    for name, raw in files:
        by_trailer[raw[-4:]].append((name, raw))
    conflict = 0
    for t, group in by_trailer.items():
        bodies = {hashlib.sha1(r[:-4]).digest() for _, r in group}
        if len(group) > 1 and len(bodies) > 1:
            conflict += 1
            print(f'  ⚠ 트레일러 [{t.hex(" ")}] 가 서로 다른 본문 {len(bodies)}개에서 반복:')
            for n, _ in group[:4]:
                print(f'      {n}')
    if conflict:
        print(f'[A] 본문이 다른데 트레일러가 같은 충돌 {conflict}건 — 콘텐츠 체크섬이 아닐 수 있음!')
        print('    (트레일러가 ID/시퀀스/타임스탬프일 가능성. 아래 CRC 역산이 실패하면 확정적)')
    else:
        print('[A] 트레일러 중복은 전부 "본문도 동일" — 정상 (같은 파일의 사본). 체크섬 가설 유지 ✓')

    # [B] 같은 길이 & 다른 본문 쌍 수집 → 8조합 GCD
    by_len = defaultdict(list)
    for name, raw in files:
        if len(raw) <= args.max_pair_size:
            by_len[len(raw)].append((name, raw))
    # 앵커 방식(g[0] vs g[j])으로 쌍 구성 — 순차 쌍(g[i],g[i+1])은 파일명 끝자리만
    # 다른 코퍼스에서 모든 차분이 동일해져 GCD 가 안 줄어드는 축퇴가 생길 수 있다.
    pairs = []
    for L in sorted(by_len):
        g = by_len[L]
        for j in range(1, len(g)):
            pairs.append((g[0], g[j]))
            if len(pairs) >= MAX_PAIRS:
                break
        if len(pairs) >= MAX_PAIRS:
            break
    if not pairs:
        print(f'[B] {args.max_pair_size}B 이하에서 같은 길이 쌍이 없음 — --max-pair-size 를 키워볼 것')
        return
    print(f'[B] 차분 GCD 에 사용할 같은 길이 쌍: {len(pairs)}개 '
          f'(크기 {", ".join(str(len(a[1])) for a, _ in pairs)}B)')

    candidates = []                           # (stream, tinterp, poly33)
    for stream in STREAMS:
        for tinterp in TINTERPS:
            g = 0
            for (na, ra), (nb, rb) in pairs:
                sa, sb = to_stream(ra[:-4], stream), to_stream(rb[:-4], stream)
                m_delta = int.from_bytes(bytes(x ^ y for x, y in zip(sa, sb)), 'big')
                t_delta = read_trailer(ra[-4:], tinterp) ^ read_trailer(rb[-4:], tinterp)
                D = (m_delta << 32) ^ t_delta
                if D == 0:
                    continue
                g = D if g == 0 else poly_gcd(g, D)
                if g == 1:
                    break
            while g and not g & 1:           # x 인수 제거
                g >>= 1
            deg = g.bit_length() - 1 if g else -1
            if args.verbose:
                print(f'    {stream}/{tinterp:<7} → GCD 차수 {deg}')
            if deg == 32:
                candidates.append((stream, tinterp, g))
                print(f'  ★ 후보 poly 발견: stream={stream}, trailer={tinterp}, '
                      f'P = 0x{g & 0xffffffff:08X} (x^32 항 별도)')
    if not candidates:
        print('[B] 어느 조합에서도 32차 다항식이 안 나옴 → CRC 계열이 아닐 가능성 높음.')
        print('    남은 가설: 단순합 변형/독자 해시/ID. 트레일러를 파일 생성순으로 정렬해')
        print('    증가 패턴이 있는지 (시퀀스/타임스탬프) 확인해볼 것.')
        return

    # [C] init / xorout 결정  +  [D] 전 파일 검증
    for stream, tinterp, poly33 in candidates:
        poly32 = poly33 & 0xffffffff
        table = make_table(poly32)
        for range_start in (0, 4):            # 매직 포함/제외 두 범위
            E_by_len = {}
            ok = True
            for name, raw in files:
                body = to_stream(raw[range_start:-4], stream)
                E = read_trailer(raw[-4:], tinterp) ^ crc_reg(body, table)
                L = len(body)
                if L in E_by_len and E_by_len[L] != E:
                    ok = False                # 같은 길이인데 E 다름 → 이 범위 아님
                    break
                E_by_len[L] = E
            if not ok:
                continue

            # init 결정: 빠른 경로(0, FFFFFFFF) → 실패 시 연립방정식
            lens = sorted(E_by_len)
            solution = None
            for I in (0, 0xffffffff):
                X = None
                consistent = True
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
                    cols = [ML[i] ^ M0[i] for i in range(32)]
                    eqs.append((cols, E_by_len[L] ^ E_by_len[L0]))
                I = solve_gf2(eqs)
                if I is not None:
                    X = E_by_len[L0] ^ mat_apply(M0, I)
                    solution = (I, X)
            if solution is None:
                continue
            I, X = solution

            # 전 파일 최종 검증
            good = sum(
                1 for name, raw in files
                if read_trailer(raw[-4:], tinterp)
                == crc_reg(to_stream(raw[range_start:-4], stream), table, init=I) ^ X
            )
            print(f'\n[검증] stream={stream}, trailer={tinterp}, range=[{range_start}:n-4], '
                  f'poly=0x{poly32:08X}, init=0x{I:08X}, xorout=0x{X:08X}'
                  f'  →  {good}/{len(files)} 일치')
            if good == len(files):
                t_expr = {
                    'BE': "int.from_bytes(raw[-4:], 'big')",
                    'LE': "int.from_bytes(raw[-4:], 'little')",
                    'BE_rev': "_bitrev32(int.from_bytes(raw[-4:], 'big'))",
                    'LE_rev': "_bitrev32(int.from_bytes(raw[-4:], 'little'))",
                }[tinterp]
                lsb_line = '' if stream == 'msb' else '\n    body = body.translate(BITREV)'
                print('\n' + '=' * 64)
                print('★★ 확정! dd_main.py 에 붙일 검증 함수: ★★')
                print('=' * 64)
                print(f'''
BITREV = bytes(int(f'{{i:08b}}'[::-1], 2) for i in range(256))

def _bitrev32(v):
    return (BITREV[v & 0xff] << 24 | BITREV[(v >> 8) & 0xff] << 16
            | BITREV[(v >> 16) & 0xff] << 8 | BITREV[(v >> 24) & 0xff])

_T = []
for b in range(256):
    c = b << 24
    for _ in range(8):
        c = ((c << 1) ^ 0x{poly32:08X}) & 0xFFFFFFFF if c & 0x80000000 else (c << 1) & 0xFFFFFFFF
    _T.append(c)

def dd_trailer_ok(raw):
    """.dd 트레일러(끝 4B) 체크섬 검증"""
    body = raw[{range_start}:-4]{lsb_line}
    crc = 0x{I:08X}
    for byte in body:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ _T[((crc >> 24) ^ byte) & 0xFF]
    crc ^= 0x{X:08X}
    return crc == {t_expr}
''')
                return
    print('\npoly 는 찾았지만 init/xorout/범위가 안 맞음 — 계산 범위가 [0:n-4]/[4:n-4] 가')
    print('아닐 수 있음 (예: 헤더 일부 제외, 길이 필드 포함 등). -v 로 재실행 후 결과 공유 바람.')


if __name__ == '__main__':
    main()
