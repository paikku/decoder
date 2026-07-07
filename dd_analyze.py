# -*- coding: utf-8 -*-
"""포맷 태그 의미론 측정기 (읽기 전용) — 하드코딩 대신 코퍼스로 규칙을 정한다.

파일 종류/필드 이름에 의존하지 않고, 태그가 실제로 어떻게 쓰이는지 605개
전체에서 통계로 뽑는다. 특히 핵심 미결 질문에 답한다:

  "배열의 0x02 는 값을 싣는 int8 인가, 순수 0 마커인가?"

  결정적 증거는 **이름 있는 스칼라 필드**(배열이 아니라 모호성이 전혀 없는
  위치)에서의 값 분포다. 어떤 태그가 이름 필드에서 다양한 비영 값을 가지면
  '값 타입', 항상 0/생략이면 '마커/플래그'.

부수적으로 수집:
  - 이름 필드 subtype 히스토그램 + subtype별 값 분포 (0/비영/다양성)
  - 배열 지배 태그 히스토그램
  - 0x02 의 문맥: 비-02 지배 배열 속 고립 마커 vs 전부-02 배열

사용:
  python dd_analyze.py dumps/
  python dd_analyze.py file.tdf
"""

import struct
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path

MAGIC = b'\x17\xfa\xae\x4e'
TRAILER_LEN = 4
TAG_END, TAG_STRING, TAG_ARRAY, TAG_STRUCT = 0x00, 0x09, 0x0a, 0x0b
TAG_INT8_B = 0x02

# 스칼라 태그 → (struct 포맷, 크기). 배열 skip 시 폭 계산에도 사용.
SCALARS = {
    0x01: ('>b', 1), 0x02: ('>b', 1), 0x03: ('>B', 1), 0x04: ('>b', 1),
    0x05: ('>h', 2), 0x06: ('>i', 4), 0x07: ('>f', 4), 0x08: ('>d', 8),
}
TNAME = {0x01: 'int8_a', 0x02: 'int8_b', 0x03: 'uint8', 0x04: 'int8_c',
         0x05: 'enum', 0x06: 'bool', 0x07: 'float32', 0x08: 'float64',
         0x09: 'string', 0x0a: 'array', 0x0b: 'struct'}

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass


class Stats:
    def __init__(self):
        # 이름 필드: subtype -> {'n':개수,'zero':0값수,'vals':값 Counter(상위표본)}
        self.named = defaultdict(lambda: {'n': 0, 'zero': 0, 'nonzero': 0,
                                          'vals': Counter()})
        self.arr_dom = Counter()          # 배열 지배 태그
        self.o2_marker_in_typed = 0       # 비-02 지배 배열 속 02 (마커 확정)
        self.o2_in_all02 = 0              # 전부-02 배열의 02 원소 수
        self.all02_arrays = 0            # 전부-02 배열 개수
        self.parse_errors = 0
        self.files = 0
        self.desync = []                 # 배열 skip 이 깨진 파일 (02=값 증거)


def _walk(raw, st):
    """파일 하나를 바이트 문법으로 순회하며 통계 적재. 실패해도 죽지 않음."""
    end = len(raw) - TRAILER_LEN
    pos = [4 if raw[4] != TAG_STRUCT else 5]

    def read_struct(i):
        while i < end:
            t = raw[i]
            if t == TAG_END:
                return i + 1
            if t != TAG_STRING:
                raise ValueError(f'struct@{i}: 0x{t:02x}')
            j = raw.find(0, i + 1, end)
            if j == -1:
                raise ValueError('name NUL')
            sub = raw[j + 1] if j + 1 < end else TAG_END
            i = read_named_value(j + 2, sub)
        return i

    def read_named_value(i, sub):
        # 이름 있는 스칼라: 0값 생략(다음이 필드앵커/END)이면 payload 없음.
        if sub in SCALARS:
            fmt, size = SCALARS[sub]
            elided = _looks_anchor(raw, i, end) or (i < end and raw[i] == TAG_END)
            if elided:
                _rec_named(st, sub, 0, True)
                return i
            if i + size <= end:
                v = struct.unpack(fmt, raw[i:i + size])[0]
                _rec_named(st, sub, v, False)
                return i + size
            return end
        if sub == TAG_STRING:
            j = raw.find(0, i, end)
            j = end if j == -1 else j
            _rec_named(st, TAG_STRING, raw[i:j], False)
            return j + 1
        if sub == TAG_STRUCT:
            return read_struct(i)
        if sub == TAG_ARRAY:
            return read_array(i)
        raise ValueError(f'named subtype 0x{sub:02x}@{i}')

    def read_array(i):
        """배열 원소를 순회. 02 는 (측정 목적상) 1바이트 마커로 skip —
        전부-02 배열은 두 해석의 종료 위치가 같아 byte-skip 이 안전하다."""
        tags = []
        start = i
        while i < end:
            t = raw[i]
            if t == TAG_END:
                _rec_array(st, tags)
                return i + 1
            if t == TAG_STRING:              # 09 원소: 이형 (post-NUL 판별)
                j = raw.find(0, i + 1, end)
                j = end if j == -1 else j
                nxt = raw[j + 1] if j + 1 < end else None
                tags.append(TAG_STRING)
                if nxt in (TAG_ARRAY, TAG_STRUCT):   # 이름+컨테이너 원소
                    i = (read_struct if nxt == TAG_STRUCT else read_array)(j + 2)
                else:
                    i = j + 1
            elif t == TAG_INT8_B:            # 02 = 마커 (측정 가정), 1바이트
                tags.append(t)
                i += 1
            elif t in SCALARS:
                fmt, size = SCALARS[t]
                tags.append(t)
                i += 1 + size
            elif t in (TAG_STRUCT, TAG_ARRAY):
                tags.append(t)
                i = (read_struct if t == TAG_STRUCT else read_array)(i + 1)
            else:
                raise ValueError(f'array elem 0x{t:02x}@{i}')
        return i

    return read_struct(pos[0])


def _looks_anchor(raw, i, end):
    if i >= end or raw[i] != TAG_STRING:
        return False
    j = i + 1
    while j < end and (65 <= raw[j] <= 90 or 97 <= raw[j] <= 122
                       or 48 <= raw[j] <= 57 or raw[j] in (95, 46, 45)):
        j += 1
    return j > i + 1 and j < end and raw[j] == TAG_END


def _rec_named(st, sub, val, elided):
    d = st.named[sub]
    d['n'] += 1
    is_zero = elided or (isinstance(val, (int, float)) and val == 0) or val == b''
    if is_zero:
        d['zero'] += 1
    else:
        d['nonzero'] += 1
    if isinstance(val, (int, float)) and len(d['vals']) < 5000:
        d['vals'][val] += 1


def _rec_array(st, tags):
    if not tags:
        return
    non02 = [t for t in tags if t != TAG_INT8_B]
    dom = Counter(non02).most_common(1)[0][0] if non02 else TAG_INT8_B
    st.arr_dom[dom] += 1
    n02 = sum(1 for t in tags if t == TAG_INT8_B)
    if non02:                                 # 지배 타입이 02 가 아님
        st.o2_marker_in_typed += n02          # → 이 02 들은 마커 확정
    else:                                     # 전부 02
        st.all02_arrays += 1
        st.o2_in_all02 += n02


def iter_dd(paths):
    for p in paths:
        p = Path(p)
        files = (sorted(set(p.rglob('*.tdf')) | set(p.rglob('*.TDF')) | set(p.rglob('*.dd')))
                 if p.is_dir() else [p])
        for f in files:
            if f.suffix.lower() == '.dd':
                yield str(f), f.read_bytes()
            elif zipfile.is_zipfile(f):
                with zipfile.ZipFile(f) as zf:
                    for n in zf.namelist():
                        if n.endswith('.dd'):
                            yield f'{f.name}::{n}', zf.read(n)


def main():
    import argparse
    ap = argparse.ArgumentParser(description='포맷 태그 의미론 측정 (읽기 전용)')
    ap.add_argument('paths', nargs='+')
    args = ap.parse_args()

    st = Stats()
    for name, raw in iter_dd(args.paths):
        if len(raw) < 12 or raw[:4] != MAGIC:
            continue
        st.files += 1
        try:
            _walk(raw, st)
        except Exception as e:
            st.parse_errors += 1
            if len(st.desync) < 8:
                st.desync.append((name, str(e)))

    print(f'\n{"=" * 66}\n측정 대상: {st.files}개 파일  (walk 실패 {st.parse_errors}개)')

    print('\n[이름 있는 스칼라 필드 — subtype 별 값 분포]  ← 모호성 없는 결정 증거')
    print(f'  {"tag":<10}{"개수":>8}{"0/생략":>9}{"비영":>8}{"고유값":>8}  비영 값 표본')
    for sub in sorted(st.named):
        d = st.named[sub]
        distinct = len(d['vals'])
        sample = ', '.join(str(v) for v, _ in d['vals'].most_common(6)
                           if v != 0)[:48]
        print(f'  0x{sub:02x} {TNAME.get(sub,"?"):<5}{d["n"]:>8}{d["zero"]:>9}'
              f'{d["nonzero"]:>8}{distinct:>8}  {sample}')

    print('\n[배열 지배 태그 히스토그램]')
    for tag, c in st.arr_dom.most_common():
        print(f'  0x{tag:02x} {TNAME.get(tag,"?"):<8} {c}개 배열')

    print('\n[0x02 문맥 분석]  ← 핵심 질문')
    print(f'  · 비-02 지배 배열 속 고립 02 (마커 확정): {st.o2_marker_in_typed}개')
    print(f'  · 전부-02 배열: {st.all02_arrays}개 (원소 02 총 {st.o2_in_all02}개)')

    d02 = st.named.get(0x02)
    print('\n[결론 도출]')
    if d02 and d02['nonzero'] > 0:
        print(f'  ▶ 이름 필드에서 0x02 가 비영 값을 {d02["nonzero"]}회 가짐 '
              f'(고유값 {len(d02["vals"])}종) → 0x02 는 실제 값을 싣는 int8 타입.')
        print('    ⇒ 배열의 전부-02 를 무조건 마커로 볼 수 없음. count 등 다른 판별 필요.')
    elif d02:
        print(f'  ▶ 이름 필드의 0x02 는 전부 0/생략 ({d02["zero"]}/{d02["n"]}) — '
              f'비영 값 0회.')
        print('    ⇒ 0x02 는 값을 싣지 않는 마커/제로 태그. 배열의 02 = 항상 0 마커로')
        print('       일반 규칙화 가능 → count 하드코딩 제거 가능.')
    else:
        print('  ▶ 이름 필드에서 0x02 미관측 — 배열 문맥만 존재.')
        if st.o2_marker_in_typed > 0 and st.o2_in_all02 >= 0:
            print(f'    타입 배열 속 02 가 마커로 {st.o2_marker_in_typed}회 확정 관측 → '
                  '마커 해석 지지.')
    if st.parse_errors:
        print(f'\n  ⚠ walk 실패 {st.parse_errors}개 — 02=마커 가정으로 skip 시 디싱크.')
        print('     (02 가 값을 싣는 배열이 있으면 여기서 터진다 → 그 자체가 증거)')
        for nm, err in st.desync:
            print(f'       {nm}: {err}')


if __name__ == '__main__':
    main()
