# -*- coding: utf-8 -*-
"""엄격(strict) .dd 파서 — 0값 생략/경계 모호성을 백트래킹 + 전역 검증으로 해소.

dd_main.py 의 휴리스틱 파서는 애매한 지점(스칼라 payload 생략 여부)에서
'훔쳐보기'로 한 번 찍고 직진한다. 이 모듈은 다르게 접근한다:

  1. 애매한 지점마다 [payload 있음] / [생략(0)] 양쪽 분기를 모두 탐색
  2. 각 분기를 전역 검증으로 심판:
       · 파싱이 정확히 n-4 경계에서 끝나는가 (END 균형 포함)
       · 미지 태그 0건인가
       · 모든 필드명이 유효 식별자인가
     → 잘못된 분기는 디싱크로 인해 거의 즉시 이 기준을 위반하고 죽는다
  3. 살아남은 해가:
       · 정확히 1개  → 그 파일의 파싱은 '유일해'로 확정 (찍기 없음)
       · 0개        → 구조 오류 (파일 손상 또는 포맷 미지 변형)
       · 2개 이상    → 진짜 모호 → 정직하게 'ambiguous' 보고
  4. 체크섬(h=h*17+b)이 맞는 파일에서 구조 오류가 나면 "파일 탓"이
     원천 배제되므로 포맷 이해의 구멍으로 확정할 수 있다.

CLI 는 전 코퍼스를 돌려 휴리스틱 파서와 대조하고, 둘이 다른 파일
(= 휴리스틱이 틀렸을 파일)을 골라내 보고한다.

사용:
  python dd_strict.py dumps/           # .tdf 폴더 전체 검증
  python dd_strict.py file.tdf -v
  python dd_strict.py raw.dd --raw
"""

import re
import struct
import sys
import zipfile
from pathlib import Path

import dd_main

MAGIC = b'\x17\xfa\xae\x4e'
TRAILER_LEN = 4

TAG_END, TAG_STRING, TAG_ARRAY, TAG_STRUCT = 0x00, 0x09, 0x0a, 0x0b
TAG_BOOL = 0x06

# 스칼라: 태그 -> (struct 포맷, 크기). BOOL 도 고정 4바이트 스칼라로 취급.
SCALARS = {
    0x01: ('>b', 1), 0x02: ('>b', 1), 0x03: ('>B', 1), 0x04: ('>b', 1),
    0x05: ('>h', 2), 0x06: ('>i', 4), 0x07: ('>f', 4), 0x08: ('>d', 8),
}

NAME_RE = re.compile(rb'^[A-Za-z_][A-Za-z0-9_.\-]{0,63}$')

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass


class StrictResult:
    __slots__ = ('status', 'trees', 'visited')

    def __init__(self, status, trees, visited):
        self.status = status      # 'unique' | 'ambiguous' | 'failed' | 'budget'
        self.trees = trees        # 발견된 해들 (최대 2개까지만 수집)
        self.visited = visited


def parse_strict(raw, node_budget=300000):
    """백트래킹 전수 탐색. 경계(n-4)에서 정확히 끝나는 해만 인정."""
    end = len(raw) - TRAILER_LEN
    if raw[:4] != MAGIC or end <= 4:
        return StrictResult('failed', [], 0)
    budget = [node_budget]

    def gen_value(i, subtype, named):
        """(값, 다음 위치) 후보들을 낸다. 유효 분기가 없으면 아무것도 안 냄."""
        if subtype in SCALARS:
            fmt, size = SCALARS[subtype]
            if i + size <= end:                       # 분기 A: payload 존재
                yield struct.unpack(fmt, raw[i:i + size])[0], i + size
            if named:                                 # 분기 B: 생략(값 0/FALSE)
                # 생략은 '이름 있는 필드'에서만 관측됨. 배열의 이름 없는 원소는
                # 생략하면 원소 자체가 사라져 표현 불가이므로 분기하지 않는다.
                yield (False if subtype == TAG_BOOL else 0), i
        elif subtype == TAG_STRING:
            j = raw.find(0, i, end)
            if j != -1:
                yield raw[i:j].decode('utf-8', 'replace'), j + 1
        elif subtype == TAG_STRUCT:
            yield from gen_struct(i)
        elif subtype == TAG_ARRAY:
            yield from gen_array(i)
        # 미지 subtype → 분기 없음(죽음): strict 모드에선 미지 태그 불허

    def gen_struct(i):
        """struct 본문: END 소비까지. (dict, 다음 위치) 후보들."""
        items = []

        def rec(i):
            if budget[0] <= 0:
                return
            budget[0] -= 1
            if i >= end:
                return                                # END 없이 끝 → 실패
            t = raw[i]
            if t == TAG_END:
                yield dict(items), i + 1
                return
            if t != TAG_STRING:
                return                                # 이름 마커 아님 → 실패
            j = raw.find(0, i + 1, end)
            if j == -1:
                return
            nm = raw[i + 1:j]
            if not NAME_RE.match(nm):
                return                                # 쓰레기 이름 → 실패
            k = j + 1
            if k >= end:
                return
            name = nm.decode()
            for val, k2 in gen_value(k + 1, raw[k], named=True):
                items.append((name, val))
                yield from rec(k2)
                items.pop()

        yield from rec(i)

    def gen_array(i):
        items = []

        def rec(i):
            if budget[0] <= 0:
                return
            budget[0] -= 1
            if i >= end:
                return
            t = raw[i]
            if t == TAG_END:
                yield list(items), i + 1
                return
            if t == TAG_STRING:                       # 이름 있는 원소 {name: value}
                j = raw.find(0, i + 1, end)
                if j == -1:
                    return
                nm = raw[i + 1:j]
                if not NAME_RE.match(nm):
                    return
                k = j + 1
                if k >= end:
                    return
                name = nm.decode()
                for val, k2 in gen_value(k + 1, raw[k], named=True):
                    items.append({name: val})
                    yield from rec(k2)
                    items.pop()
            else:                                     # 타입태그 + 값 원소
                for val, k2 in gen_value(i + 1, t, named=False):
                    items.append(val)
                    yield from rec(k2)
                    items.pop()

        yield from rec(i)

    # 최상위: STRUCT(0x0b) 로 열리면 그 본문, 아니면 바로 멤버들(변형 대비)
    start = 5 if raw[4] == TAG_STRUCT else 4
    solutions = []
    for tree, pos in gen_struct(start):
        if pos == end:                                # 전역 기준: 경계 정확 일치
            solutions.append(tree)
            if len(solutions) >= 2:
                break
    visited = 300000 - budget[0] if budget[0] > 0 else node_budget
    if budget[0] <= 0 and not solutions:
        return StrictResult('budget', [], visited)
    if len(solutions) == 1:
        return StrictResult('unique', solutions, visited)
    if len(solutions) >= 2:
        return StrictResult('ambiguous', solutions, visited)
    return StrictResult('failed', [], visited)


# ── CLI: 코퍼스 전수 검증 + 휴리스틱 대조 ──────────────────────────
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


def main():
    import argparse
    ap = argparse.ArgumentParser(
        description='엄격 .dd 파서 — 백트래킹으로 0값 생략 모호성 해소 + 휴리스틱 대조')
    ap.add_argument('paths', nargs='+')
    ap.add_argument('--raw', action='store_true')
    ap.add_argument('-v', '--verbose', action='store_true')
    args = ap.parse_args()

    stats = {'unique': 0, 'ambiguous': 0, 'failed': 0, 'budget': 0}
    checksum_bad = []
    mismatch = []          # 휴리스틱과 유일해가 다른 파일 (휴리스틱 오류!)
    problems = []          # failed / ambiguous / budget

    total = 0
    for name, raw in iter_dd(args.paths, args.raw):
        if len(raw) < 12 or raw[:4] != MAGIC:
            continue
        total += 1
        if not dd_main.dd_trailer_ok(raw):
            checksum_bad.append(name)

        res = parse_strict(raw)
        stats[res.status] += 1
        if res.status == 'unique':
            heur_tree, _, _ = dd_main.parse_tlv(raw)
            if heur_tree != res.trees[0]:
                mismatch.append(name)
                if args.verbose:
                    print(f'✗ 휴리스틱≠유일해: {name}')
        else:
            problems.append((name, res.status))
            if args.verbose:
                print(f'? {res.status}: {name}')

    print(f'\n{"=" * 64}')
    print(f'검사: 바이너리 .dd {total}개')
    print(f'  체크섬 불일치(손상 의심)      : {len(checksum_bad)}개')
    print(f'  구조 유일해 확정 (찍기 없음)   : {stats["unique"]}개')
    print(f'  진짜 모호 (해 2개 이상)       : {stats["ambiguous"]}개')
    print(f'  구조 오류 (해 없음)           : {stats["failed"]}개')
    print(f'  탐색 예산 초과                : {stats["budget"]}개')
    print(f'  휴리스틱 ≠ 유일해 (휴리스틱 오류): {len(mismatch)}개')

    if total and stats['unique'] == total and not mismatch:
        print('\n결론: 전 파일이 유일해로 확정 — 현재 휴리스틱 파서의 출력과 100% 일치.')
        print('      0값 생략/경계 처리가 이 코퍼스에서 증명됨 ✓')
    if mismatch:
        print('\n⚠ 휴리스틱이 잘못 읽은 파일 (strict 유일해와 불일치):')
        for n in mismatch[:10]:
            print(f'    {n}')
    if problems:
        print('\n확인 필요한 파일:')
        for n, s in problems[:10]:
            print(f'    [{s}] {n}')
    if checksum_bad:
        print('\n체크섬 불일치 파일 (추출/전송 중 손상 의심):')
        for n in checksum_bad[:10]:
            print(f'    {n}')


if __name__ == '__main__':
    main()
