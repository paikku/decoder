# -*- coding: utf-8 -*-
"""엄격(strict) .dd 파서 — 0값 생략/경계 모호성을 백트래킹 + 전역 검증으로 해소.

dd_main.py 의 휴리스틱 파서는 애매한 지점(스칼라 payload 생략 여부)에서
'훔쳐보기'로 한 번 찍고 직진한다. 이 모듈은 다르게 접근한다:

  1. 애매한 지점마다 [payload 있음] / [생략(0)] 양쪽 분기를 모두 탐색
  2. 각 분기를 전역 검증으로 심판:
       · 파싱이 정확히 n-4 경계에서 끝나는가 (END 균형 포함)
       · 미지 태그 0건인가
       · 모든 필드명이 유효 식별자인가
  3. 살아남은 해가 1개면 '유일해' 확정, 0개면 구조 오류, 2개+ 면 모호.

단순 합격/불합격 판정을 넘어 **피드백**을 준다:

  · 실패 시  : 탐색이 가장 멀리 도달한 지점(deepest failure)의
               필드 경로 + 오프셋 + hex 문맥 + 죽은 이유 + 행동 가이드
  · 모호 시  : 두 해가 갈라지는 첫 지점의 diff (어떤 규칙이 부족한지 특정)
  · 불일치 시: 휴리스틱 트리와 유일해의 필드 단위 diff
  · 복구    : 실패 지점 이후를 앵커 스캔해 살릴 수 있는 필드 목록(salvage)

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
KEY_ANCHOR = re.compile(rb'\x09([A-Za-z_][A-Za-z0-9_.\-]{0,63})\x00')

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass


class StrictResult:
    __slots__ = ('status', 'trees', 'visited', 'fail_pos', 'fail_reason', 'fail_path')

    def __init__(self, status, trees, visited, fail_pos=-1, fail_reason='', fail_path=()):
        self.status = status          # 'unique' | 'ambiguous' | 'failed' | 'budget'
        self.trees = trees            # 발견된 해들 (최대 2개까지만 수집)
        self.visited = visited
        self.fail_pos = fail_pos      # 탐색이 가장 멀리 도달한 실패 오프셋
        self.fail_reason = fail_reason
        self.fail_path = fail_path    # 그 지점의 필드 경로


def parse_strict(raw, node_budget=300000):
    """백트래킹 전수 탐색. 경계(n-4)에서 정확히 끝나는 해만 인정."""
    end = len(raw) - TRAILER_LEN
    if raw[:4] != MAGIC or end <= 4:
        return StrictResult('failed', [], 0, 0, '매직 없음 또는 파일이 너무 짧음')
    budget = [node_budget]
    path = []                                     # 현재 필드 경로 (진단용)
    deepest = [-1, '', ()]                        # [pos, reason, path 스냅샷]

    def note(pos, reason):
        """분기가 죽을 때 호출 — 가장 멀리 도달한 실패만 기억한다."""
        if pos > deepest[0]:
            deepest[0], deepest[1], deepest[2] = pos, reason, tuple(path)

    def gen_value(i, subtype, named):
        if subtype in SCALARS:
            fmt, size = SCALARS[subtype]
            if i + size <= end:                   # 분기 A: payload 존재
                yield struct.unpack(fmt, raw[i:i + size])[0], i + size
            elif not named:
                note(i, f'payload({size}B)가 경계(n-4)를 넘음')
            if named:                             # 분기 B: 생략(값 0/FALSE)
                yield (False if subtype == TAG_BOOL else 0), i
        elif subtype == TAG_STRING:
            j = raw.find(0, i, end)
            if j != -1:
                yield raw[i:j].decode('utf-8', 'replace'), j + 1
            else:
                note(i, '문자열의 NUL 종결자가 경계 안에 없음')
        elif subtype == TAG_STRUCT:
            yield from gen_struct(i)
        elif subtype == TAG_ARRAY:
            yield from gen_array(i)
        else:
            note(i - 1, f'미지 SubType 0x{subtype:02x}')

    def gen_struct(i):
        items = []

        def rec(i):
            if budget[0] <= 0:
                return
            budget[0] -= 1
            if i >= end:
                note(i, 'END(00) 없이 경계 도달 — 컨테이너 미폐쇄')
                return
            t = raw[i]
            if t == TAG_END:
                yield dict(items), i + 1
                return
            if t != TAG_STRING:
                note(i, f'구조체에서 이름마커(09)/END(00) 기대, 0x{t:02x} 발견')
                return
            j = raw.find(0, i + 1, end)
            if j == -1:
                note(i + 1, '필드명의 NUL 종결자 없음')
                return
            nm = raw[i + 1:j]
            if not NAME_RE.match(nm):
                note(i + 1, f'유효하지 않은 필드명 {nm[:24]!r}')
                return
            k = j + 1
            if k >= end:
                note(k, 'SubType 자리에서 경계 도달')
                return
            name = nm.decode()
            path.append(name)
            for val, k2 in gen_value(k + 1, raw[k], named=True):
                items.append((name, val))
                saved = path.pop()                # 형제 파싱은 부모 경로에서
                yield from rec(k2)
                path.append(saved)
                items.pop()
            path.pop()

        yield from rec(i)

    def gen_array(i):
        items = []

        def rec(i):
            if budget[0] <= 0:
                return
            budget[0] -= 1
            if i >= end:
                note(i, 'END(00) 없이 경계 도달 — 배열 미폐쇄')
                return
            t = raw[i]
            if t == TAG_END:
                yield list(items), i + 1
                return
            path.append(f'[{len(items)}]')
            if t == TAG_STRING:                   # 이름 있는 원소 {name: value}
                j = raw.find(0, i + 1, end)
                if j == -1 or not NAME_RE.match(raw[i + 1:j]):
                    note(i + 1, '배열의 이름있는 원소 이름 불량')
                    path.pop()
                    return
                k = j + 1
                if k >= end:
                    path.pop()
                    return
                name = raw[i + 1:j].decode()
                for val, k2 in gen_value(k + 1, raw[k], named=True):
                    items.append({name: val})
                    saved = path.pop()
                    yield from rec(k2)
                    path.append(saved)
                    items.pop()
            else:                                 # 타입태그 + 값 원소
                for val, k2 in gen_value(i + 1, t, named=False):
                    items.append(val)
                    saved = path.pop()
                    yield from rec(k2)
                    path.append(saved)
                    items.pop()
            path.pop()

        yield from rec(i)

    start = 5 if raw[4] == TAG_STRUCT else 4
    solutions = []
    for tree, pos in gen_struct(start):
        if pos == end:                            # 전역 기준: 경계 정확 일치
            solutions.append(tree)
            if len(solutions) >= 2:
                break
        else:
            note(pos, f'구조는 닫혔지만 경계 전 종료 (남은 {end - pos}B)')
    visited = node_budget - budget[0] if budget[0] > 0 else node_budget
    if budget[0] <= 0 and not solutions:
        return StrictResult('budget', [], visited, deepest[0], deepest[1], deepest[2])
    if len(solutions) == 1:
        return StrictResult('unique', solutions, visited)
    if len(solutions) >= 2:
        return StrictResult('ambiguous', solutions, visited)
    return StrictResult('failed', [], visited, deepest[0], deepest[1], deepest[2])


# ── 피드백/복구 도구 ────────────────────────────────────────────────
def hexdump(raw, pos, radius=24):
    """실패 지점 주변 hex + 마커 줄."""
    lo = max(0, pos - radius)
    hi = min(len(raw), pos + radius)
    lines = []
    for base in range(lo - lo % 16, hi, 16):
        chunk = raw[base:min(base + 16, hi)]
        hx, mark = [], []
        for off, b in enumerate(chunk):
            p = base + off
            hx.append(f'{b:02x}')
            mark.append('^^' if p == pos else '  ')
        asc = ''.join(chr(b) if 0x20 <= b <= 0x7e else '.' for b in chunk)
        lines.append(f'    {base:6d}  {" ".join(hx):<47}  |{asc}|')
        if any(m == '^^' for m in mark):
            lines.append(f'            {" ".join(mark)}')
    return '\n'.join(lines)


def tree_diff(a, b, path=''):
    """두 트리의 차이를 (경로, a값, b값) 리스트로."""
    if type(a) is not type(b):
        return [(path or '(root)', a, b)]
    diffs = []
    if isinstance(a, dict):
        for k in list(a.keys()) + [k for k in b if k not in a]:
            pa = f'{path}.{k}' if path else k
            if k not in a:
                diffs.append((pa, '<없음>', b[k]))
            elif k not in b:
                diffs.append((pa, a[k], '<없음>'))
            else:
                diffs += tree_diff(a[k], b[k], pa)
    elif isinstance(a, list):
        if len(a) != len(b):
            diffs.append((f'{path}[]', f'원소 {len(a)}개', f'원소 {len(b)}개'))
        for idx, (x, y) in enumerate(zip(a, b)):
            diffs += tree_diff(x, y, f'{path}[{idx}]')
    elif a != b:
        diffs.append((path, a, b))
    return diffs


def salvage_scan(raw, from_pos, max_items=200):
    """실패 지점 이후를 앵커 스캔해 복구 가능한 (오프셋, 이름, 타입, 값 미리보기) 수집."""
    end = len(raw) - TRAILER_LEN
    out = []
    for m in KEY_ANCHOR.finditer(raw, max(0, from_pos), end):
        k = m.end()
        if k >= end:
            break
        st = raw[k]
        preview = ''
        if st in SCALARS:
            fmt, size = SCALARS[st]
            if k + 1 + size <= end:
                preview = repr(struct.unpack(fmt, raw[k + 1:k + 1 + size])[0])
        elif st == TAG_STRING:
            j = raw.find(0, k + 1, end)
            if j != -1:
                preview = repr(raw[k + 1:j].decode('utf-8', 'replace'))
        elif st == TAG_STRUCT:
            preview = '{…}'
        elif st == TAG_ARRAY:
            preview = '[…]'
        out.append((m.start(), m.group(1).decode(), f'0x{st:02x}', preview))
        if len(out) >= max_items:
            break
    return out


def advise(res, checksum_ok):
    """실패 유형 + 체크섬 교차 판정 → 행동 가이드 문장들."""
    tips = []
    if res.status == 'failed':
        if not checksum_ok:
            tips.append('체크섬도 불일치 → 파일 손상이 유력. 원본 TDF 재추출 권장.')
            tips.append('손상 확정이면 아래 salvage 목록으로 살릴 수 있는 필드만 부분 복구.')
        else:
            tips.append('체크섬은 일치 → 파일은 멀쩡함. 즉 포맷 이해의 구멍이 확정!')
            if '미지 SubType' in res.fail_reason:
                tips.append('새 타입 태그 발견 — 스펙 §1.3 확장 필요. 아래 hex 문맥에서 '
                            'payload 폭을 추정해 SCALARS 에 추가 후 재검증.')
            elif '이름' in res.fail_reason or '기대' in res.fail_reason:
                tips.append('디싱크 패턴 — 직전 필드의 생략/폭 규칙에 새 변형이 있을 수 있음. '
                            '실패 오프셋 직전 필드(경로 참고)의 hex 를 스펙과 대조.')
            elif '경계' in res.fail_reason:
                tips.append('경계 불일치 — 트레일러가 4B 가 아니거나 파일 뒤에 패딩이 있는 변형 의심. '
                            '파일 끝 8~16B 를 확인.')
            tips.append('이 파일의 hex 문맥을 그대로 공유하면 규칙을 특정할 수 있음.')
    elif res.status == 'ambiguous':
        tips.append('두 해석이 모두 전역 검증을 통과 — 아래 diff 의 첫 분기 필드가 원인.')
        tips.append('같은 타입의 다른 파일들에서 해당 필드의 값 분포를 보면 판별 규칙을 만들 수 있음.')
        tips.append('(예: 항상 0 이면 생략 해석이 맞고, 다양한 값이면 payload 해석이 맞음)')
    elif res.status == 'budget':
        tips.append('탐색 예산 초과 — 모호 지점이 비정상적으로 많음. node_budget 을 키우거나, '
                    '이 파일 hex 를 공유해 구조를 확인.')
    return tips


def diagnose(name, raw, res, verbose=False):
    """문제 파일 하나에 대한 진단 블록 출력."""
    checksum_ok = dd_main.dd_trailer_ok(raw)
    print(f'\n┌─ 진단: {name}')
    print(f'│ 상태: {res.status}   체크섬: {"일치 ✓" if checksum_ok else "불일치 ✗"}   '
          f'크기: {len(raw):,}B   탐색노드: {res.visited}')

    if res.status in ('failed', 'budget') and res.fail_pos >= 0:
        loc = ' > '.join(res.fail_path) if res.fail_path else '(최상위)'
        print(f'│ 최심 실패 지점: 오프셋 {res.fail_pos} / 필드 경로: {loc}')
        print(f'│ 사유: {res.fail_reason}')
        print('│ hex 문맥 (^^ = 실패 바이트):')
        print(hexdump(raw, res.fail_pos))
        sal = salvage_scan(raw, res.fail_pos)
        if sal:
            print(f'│ salvage: 실패 지점 이후 복구 가능해 보이는 필드 {len(sal)}개'
                  f' (앞 {min(len(sal), 6)}개):')
            for off, nm, st, pv in sal[:6]:
                print(f'│     @{off:<7d} {nm} (subtype {st}) = {pv}')

    if res.status == 'ambiguous':
        diffs = tree_diff(res.trees[0], res.trees[1])
        print(f'│ 두 해석의 차이 {len(diffs)}곳 (앞 6곳):')
        for p, va, vb in diffs[:6]:
            print(f'│     {p}:  해석1={va!r}  ↔  해석2={vb!r}')

    for tip in advise(res, checksum_ok):
        print(f'│ ▶ {tip}')
    print('└─')


# ── CLI ─────────────────────────────────────────────────────────────
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
        description='엄격 .dd 파서 — 백트래킹 검증 + 실패 진단/복구 가이드')
    ap.add_argument('paths', nargs='+')
    ap.add_argument('--raw', action='store_true')
    ap.add_argument('-v', '--verbose', action='store_true')
    ap.add_argument('--max-diag', type=int, default=5,
                    help='상세 진단을 출력할 문제 파일 수 (기본 5)')
    args = ap.parse_args()

    stats = {'unique': 0, 'ambiguous': 0, 'failed': 0, 'budget': 0}
    checksum_bad = []
    mismatch = []          # (name, raw, strict_tree)
    problems = []          # (name, raw, res)

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
                mismatch.append((name, heur_tree, res.trees[0]))
        else:
            problems.append((name, raw, res))

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
        print('\n⚠ 휴리스틱이 잘못 읽은 파일 — 필드 단위 diff (휴리스틱 ↔ 유일해):')
        for name, ht, st_tree in mismatch[:args.max_diag]:
            print(f'  {name}')
            for p, va, vb in tree_diff(ht, st_tree)[:6]:
                print(f'      {p}:  휴리스틱={va!r}  ↔  유일해={vb!r}')

    for name, raw, res in problems[:args.max_diag]:
        diagnose(name, raw, res, args.verbose)
    if len(problems) > args.max_diag:
        print(f'\n(문제 파일 {len(problems) - args.max_diag}개 더 있음 — --max-diag 로 조절)')


if __name__ == '__main__':
    main()
