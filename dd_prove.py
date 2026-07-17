# -*- coding: utf-8 -*-
"""'.dd 예외 4가지 → 공리 2개' 환원의 증명 러너.

  python dd_prove.py selftest                     # 스펙 실측 예제 + 수작업 케이스
  python dd_prove.py diff   [--files N] [--seed S] [--pure]
                                                  # 생성 코퍼스 차분: dd_main ↔ dd_unified
  python dd_prove.py strict [--files N] [--seed S] [--pure]
                                                  # dd_strict 오라클 교차 (유일해 + 트리 일치)
  python dd_prove.py ambig                        # 모호 반례 2종 → 룰셋별 해 개수 표
  python dd_prove.py hunt   [--rounds N] [--seed S]
                                                  # 변형 퍼즈로 모호 입력 지형 탐사
  python dd_prove.py measure PATH...              # 실코퍼스 pure-A1 판별 측정

용어:
  spec 룰   = 현 스펙 §1.3 그대로 (이름 스칼라: payload/생략 두 분기 허용)
  nowide 룰 = wide(2B+) 생략 분기만 제거
  pure 룰   = 공리 A1 그대로 (0x02/0x03 폭0 전용, 그 외 payload 전용 — 분기 없음)

핵심 주장 (이 러너가 실행으로 보이는 것 — 적대 검증 V1~V4 반영해 정밀화):
  P1. dd_unified(safe) 는 인코더 이미지(A1 을 지키는 인코딩; Enc 가 형식화)
      위에서 dd_main 과 트리가 == 기준 100% 일치한다.
      주의: '규칙이 허용하는 인코딩 전체'와는 다르다 — 스펙 표('0~1B')가
      헷지로 남긴 `02 05`(0x02+비영 payload) 같은 이미지-밖 인코딩에서는
      dd_main({'a':5})과 의도적으로 갈리며(unified 는 {'a':0}), 이 갈림은
      unified.anomalies 로 검출된다. 이때 dd_strict 는 조용히 unique 를
      반환한다(§4 트립와이어 주장의 구멍 — V1 발견).
  P2. pure 룰은 프로덕션당 대안이 최대 1개라 해가 항상 ≤1 (구성적 무모호;
      V2 의 3,198개 변형 퍼즈에서도 모호 0건).
  P3. dd_strict 1차(엄격) pass 문법 안에서 모호성의 원천은 정확히
      '이름 필드'의 두 헷지다: wide 생략(반례 A), 폭1 explicit
      payload(반례 B). 반례는 읽기 방향과 무관하다 — 같은 바이트에 두
      인코딩이 겹치므로 (V4 가 역방향 전수 열거로 해집합 방향 불변 확인).
      스코프 주의: 1차 pass 가 실패한 뒤 도는 loose fallback(이름 스칼라
      원소 허용 등)은 별도의 모호 클래스를 추가로 갖는다 — V2 발견.
  P4. 실코퍼스가 pure 이미지 안인지는 measure 의 카운터 [1]~[5] 가 판별한다.
"""

import argparse
import random
import struct
import sys

import dd_main
import dd_strict
import dd_unified
from dd_unified import MAGIC, NUM, FIELD_ANCHOR

END, STRING, ARRAY, STRUCT = 0x00, 0x09, 0x0a, 0x0b
NAME_RE = dd_strict.NAME_RE

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass


# ────────────────────────────────────────────────────────────────────
# 인코더 = 생성 모델의 형식화
# ────────────────────────────────────────────────────────────────────
def checksum(prefix):
    h = 0
    for b in prefix:
        h = (h * 17 + b) & 0xFFFFFFFF
    return h.to_bytes(4, 'big')


def wrap(member_bytes):
    """멤버 바이트열 → 완전한 .dd 파일 (매직 + 최상위 struct + 트레일러)"""
    raw = MAGIC + bytes([STRUCT]) + member_bytes + b'\x00'
    return raw + checksum(raw)


class Enc:
    """생성 모델. pure=True 면 wide 0값 생략(스펙 §1.3 앵커 케이스)을 안 쓴다.

    공통 원칙(관측 확정):
      · 정수는 값이 태그를 고른다: 0→0x02/0x03(폭0), int8→0x04,
        int16→0x05, int32→0x06.  (explicit '04 00' 같은 폭1 0-payload 는
        규칙계에서 표현 불가 — 다음 바이트가 END 로 읽혀 구조가 바뀐다)
      · 배열 원소는 이름이 없고, {이름: 컨테이너} 원소만 이름을 가진다.
      · 배열은 카테고리 동질 (수치/문자열/이름컨테이너/bare컨테이너).
    """

    def __init__(self, rng, pure=False):
        self.rng, self.pure = rng, pure

    def int_by_value(self, v, widen_ok=True):
        if v == 0:
            return bytes([self.rng.choice((0x02, 0x03))])
        # 가끔 한 단계 넓은 태그로 기록 (스키마-타입 인코더 가능성도 커버 —
        # 파서 동치성은 어느 쪽이든 성립해야 한다)
        widen = widen_ok and self.rng.random() < 0.15
        if -128 <= v <= 127 and not widen:
            return b'\x04' + struct.pack('>b', v)
        if -32768 <= v <= 32767:
            return b'\x05' + struct.pack('>h', v)
        return b'\x06' + struct.pack('>i', v)

    def members(self, d):
        keys = list(d.keys())
        out = b''
        for idx, k in enumerate(keys):
            out += self.member(k, d[k], next_exists=idx + 1 < len(keys))
        return out

    def member(self, name, v, next_exists):
        head = b'\x09' + name.encode() + b'\x00'
        if isinstance(v, dict):
            return head + bytes([STRUCT]) + self.members(v) + b'\x00'
        if isinstance(v, list):
            return head + bytes([ARRAY]) + self.elements(v) + b'\x00'
        if isinstance(v, str):
            return head + bytes([STRING]) + v.encode() + b'\x00'
        if isinstance(v, float):
            if (v == 0.0 and not self.pure and next_exists
                    and self.rng.random() < 0.5):
                return head + b'\x08'          # wide 생략 (§1.3 앵커 케이스)
            if v == 0.0 and self.rng.random() < 0.5:
                return head + bytes([self.rng.choice((0x02, 0x03))])  # by-value 0
            return head + b'\x08' + struct.pack('>d', v)
        # int — 0 은 항상 폭0 태그 (END 직전이든 앵커 앞이든 동일)
        return head + self.int_by_value(v)

    def elements(self, xs):
        out = b''
        for x in xs:
            if isinstance(x, dict):            # {이름: 컨테이너} 원소 (A2)
                (k, v), = x.items()
                if isinstance(v, dict):
                    out += b'\x09' + k.encode() + b'\x00' + bytes([STRUCT]) \
                        + self.members(v) + b'\x00'
                else:
                    out += b'\x09' + k.encode() + b'\x00' + bytes([ARRAY]) \
                        + self.elements(v) + b'\x00'
            elif isinstance(x, str):
                out += b'\x09' + x.encode() + b'\x00'
            elif isinstance(x, list):          # bare 배열 원소
                out += bytes([ARRAY]) + self.elements(x) + b'\x00'
            elif isinstance(x, float):
                if x == 0.0:
                    out += bytes([self.rng.choice((0x02, 0x03))])
                else:
                    out += b'\x08' + struct.pack('>d', x)
            else:                              # int
                out += self.int_by_value(x, widen_ok=False)
        return out


# ────────────────────────────────────────────────────────────────────
# 랜덤 트리 생성 (시드 고정 → 재현 가능)
# ────────────────────────────────────────────────────────────────────
NAMES = ['a', 'b', 'x', 'y', 'p', 'q', 'logn_id', 'phys_id', 'ratio', 'mode',
         'count', 'vals', 'detector', 'cfg', 'item', 'flags', 'level',
         'first_index', 'last_index', 'repeat_count', 'nr_of_used_samples']
STRS = ['TRUE', 'FALSE', 'SIM_DISABLED', 'ok', 'abc', 'v1.2', 'left', 'right']
INTS = [0, 0, 1, -5, 42, 127, 128, 300, -32000, 40000, 129366, 2, 3]
FLTS = [0.0, 0.0, 0.25, -1.5, 3.14159, 1e-12, 2.5e10]


def gen_scalar(rng):
    k = rng.random()
    if k < .45:
        return rng.choice(INTS)
    if k < .75:
        return rng.choice(FLTS)
    return rng.choice(STRS)


def gen_list(rng, depth):
    cat = rng.choice(('num', 'num', 'str', 'map', 'bare'))
    n = rng.randrange(0, 7)
    if cat == 'num':
        base, step = rng.choice(((0, 5), (30, 17), (100, 9), (-60, 4), (9000, -700)))
        vals = [base + step * i for i in range(n)]
        if rng.random() < .4:
            vals = [0] * rng.randrange(1, 4) + vals   # 마커 런 (position_nrs 패턴)
        if rng.random() < .25:
            vals = [float(v) for v in vals]
        return vals
    if cat == 'str':
        return [rng.choice(STRS) for _ in range(n)]
    if cat == 'map' and depth > 0:
        return [{rng.choice(NAMES): gen_dict(rng, depth - 1)}
                for _ in range(max(n, 1))]
    if cat == 'bare':
        return [gen_list(rng, 0) for _ in range(max(n % 3, 1))]
    return [rng.choice(INTS) for _ in range(n)]


def gen_dict(rng, depth):
    ks = rng.sample(NAMES, rng.randrange(1, 6))
    d = {}
    for k in ks:
        r = rng.random()
        if depth > 0 and r < .30:
            d[k] = gen_dict(rng, depth - 1)
        elif depth > 0 and r < .55:
            d[k] = gen_list(rng, depth - 1)
        else:
            d[k] = gen_scalar(rng)
    return d


# ────────────────────────────────────────────────────────────────────
# 미니 전수 열거기 — 룰셋별 '해 개수' 를 센다 (작은 파일 전용)
# ────────────────────────────────────────────────────────────────────
def enum_parses(raw, ruleset='spec', cap=8):
    """boundary(n-4)에서 정확히 끝나는 서로 다른 파스 트리를 최대 cap개 수집.

    dd_strict 의 **1차(엄격) pass** 문법을 미러한다 — loose fallback
    (named_elems=True) 은 모델링하지 않는다 (스코프: P3 참고).

    ruleset='spec'  : 이름 스칼라에 [payload]+[생략] 두 분기
                      (dd_strict.gen_value 116-118행 — 무조건 생성)
    ruleset='nowide': wide(2B+) 태그의 생략 분기 제거 (폭1 payload 분기는 유지)
    ruleset='pure'  : 공리 A1 — 0x02/0x03 은 폭0 전용, 그 외는 payload 전용

    배열 원소는 세 룰셋 공통으로 dd_strict.elem_alts 와 동일:
    0x02/0x03 은 폭0 마커(분기 없음), 그 외 스칼라는 payload 전용,
    dom(카테고리 동질성: NUM / STRING / NAMED / 컨테이너 태그) 게이트 적용.
    ※ 초기 버전에 있던 '배열 1B 태그 생략 분기'는 dd_strict 에 실재하지
      않는 유령 분기였다(gen_value 의 해당 코드는 named=True 로만 호출되는
      죽은 코드 — 적대 검증 V2 발견). 제거함.
    """
    end = len(raw) - 4
    sols = []

    def val_alts(i, sub, named):
        info = NUM.get(sub)
        if info is not None:
            fmt, width = info
            if ruleset == 'pure':
                if width == 0:
                    yield 0, i
                elif i + width <= end:
                    yield struct.unpack(fmt, raw[i:i + width])[0], i + width
                return
            w = width or 1                     # spec/nowide: 폭0 태그도 '폭1+생략' 취급
            f = fmt if width else '>b'
            if i + w <= end:
                yield struct.unpack(f, raw[i:i + w])[0], i + w
            if named and (ruleset == 'spec' or w == 1):
                yield 0, i                     # 생략 분기 (이름 필드 한정)
            return
        if sub == STRING:
            j = raw.find(0, i, end)
            if j != -1:
                yield raw[i:j].decode('utf-8', 'replace'), j + 1
            return
        if sub == STRUCT:
            yield from cont(i, True)
            return
        if sub == ARRAY:
            yield from cont(i, False)

    def elem_alts(i, t, dom):
        """(값, 다음위치, 새 dom). dd_strict.elem_alts 의 엄격 pass 미러."""
        if t == STRING:
            j = raw.find(0, i + 1, end)
            if j == -1:
                return
            nxt = raw[j + 1] if j + 1 < end else None
            named_form = (nxt in (ARRAY, STRUCT)
                          and NAME_RE.match(raw[i + 1:j]) is not None)
            if named_form:
                if dom in (None, 'NAMED'):
                    name = raw[i + 1:j].decode()
                    for v, p in cont(j + 2, nxt == STRUCT):
                        yield {name: v}, p, 'NAMED'
            elif dom in (None, STRING):
                yield raw[i + 1:j].decode('utf-8', 'replace'), j + 1, STRING
            return
        info = NUM.get(t)
        if info is not None:
            fmt, width = info
            if width == 0:                     # 폭0 마커 — dom 불변, 분기 없음
                yield 0, i + 1, dom
                return
            if dom in (None, 'NUM') and i + 1 + width <= end:
                yield (struct.unpack(fmt, raw[i + 1:i + 1 + width])[0],
                       i + 1 + width, 'NUM')
            return
        if t in (STRUCT, ARRAY):
            if dom in (None, t):
                for v, p in cont(i + 1, t == STRUCT):
                    yield v, p, t

    def cont(i, is_struct, acc=(), dom=None):
        if i >= end:
            return
        t = raw[i]
        if t == END:
            yield (dict(acc) if is_struct else list(acc)), i + 1
            return
        if is_struct:
            if t != STRING:
                return
            j = raw.find(0, i + 1, end)
            if j == -1 or not NAME_RE.match(raw[i + 1:j]) or j + 1 >= end:
                return
            name = raw[i + 1:j].decode()
            for v, p in val_alts(j + 2, raw[j + 1], named=True):
                yield from cont(p, True, acc + ((name, v),))
        else:
            for v, p, nd in elem_alts(i, t, dom):
                yield from cont(p, False, acc + (v,), nd)

    start = 5 if raw[4] == STRUCT else 4
    for tree, pos in cont(start, True):
        if pos == end and tree not in sols:
            sols.append(tree)
            if len(sols) >= cap:
                break
    return sols


# ────────────────────────────────────────────────────────────────────
# 모호 반례 2종 (구성적 증명)
# ────────────────────────────────────────────────────────────────────
def build_ambig_wide():
    """반례 A — wide 생략 헷지의 모호성.

    필드 a(float64)의 8바이트 payload 가 우연히 "09 'b' 00 02 09 'c' 00 02"
    (= 폭0 제로 필드 b, c 의 인코딩) 와 동일한 파일. 같은 바이트가
      해석 1: {a: 1.63e-260 근방의 float}          (payload 로 읽음)
      해석 2: {a: 0, b: 0, c: 0}                   (생략으로 읽음)
    두 인코딩의 상(像)이 겹친다 → 인코딩 함수가 비단사 → 어떤 디코더도
    (순방향이든 역방향이든) 원리적으로 못 가른다.
    """
    body = b'\x09a\x00\x08' + b'\x09b\x00\x02\x09c\x00\x02'
    return wrap(body)


def build_ambig_w1():
    """반례 B — 폭1 explicit-payload 헷지의 모호성 (END 시프트).

    바이트: … x:02 [00] y:02 [00] [00]
      해석 1: x=0(생략) → 00 이 내부 struct 닫음 → y 는 바깥 필드(payload 00 소비)
              = {p:{x:0}, y:0}
      해석 2: x 가 00 을 payload 로 소비 → y 가 내부 struct 안으로 들어감
              = {p:{x:0, y:0}}
    'explicit 폭1 0-payload' 를 문법이 허용하는 한 발생. pure 룰(0 은 항상
    폭0)에서는 이 바이트열 자체가 어떤 트리의 인코딩도 아니어서 거부된다.
    """
    body = (b'\x09p\x00' + bytes([STRUCT])
            + b'\x09x\x00\x02' + b'\x00'
            + b'\x09y\x00\x02' + b'\x00')
    return wrap(body)


# ────────────────────────────────────────────────────────────────────
# 서브커맨드
# ────────────────────────────────────────────────────────────────────
def sample_hex(raw, limit=96):
    h = raw.hex(' ')
    return h if len(h) <= limit else h[:limit] + ' …'


def cmd_selftest(_args):
    fails = []

    def check(label, cond, detail=''):
        print(f'  {"✓" if cond else "✗"} {label}' + (f'  {detail}' if detail and not cond else ''))
        if not cond:
            fails.append(label)

    # 1) 스펙 §1.4 실측 예제 — 바이트를 그대로 재구성해 트레일러까지 검증
    body = (b'\x09IFEUCM_machine_configuration_struct\x00' + bytes([STRUCT])
            + b'\x09lens_magnification\x00\x08' + struct.pack('>d', 0.25)
            + b'\x09if_sim_mode\x00\x09SIM_DISABLED\x00'
            + b'\x09hw_timestamp_transmission\x00\x09TRUE\x00'
            + b'\x00')
    raw = wrap(body)
    expected = {'IFEUCM_machine_configuration_struct': {
        'lens_magnification': 0.25,
        'if_sim_mode': 'SIM_DISABLED',
        'hw_timestamp_transmission': 'TRUE'}}
    check('스펙 예제: 트레일러 == bc 94 26 a8 (체크섬 재현)',
          raw[-4:] == bytes.fromhex('bc9426a8'), raw[-4:].hex())
    t_main, unk, _ = dd_main.parse_tlv(raw)
    check('스펙 예제: dd_main == 기대 트리', t_main == expected and not unk)
    check('스펙 예제: unified(safe) == 기대 트리',
          dd_unified.parse(raw, 'safe') == expected)
    check('스펙 예제: unified(pure) == 기대 트리',
          dd_unified.parse(raw, 'pure') == expected)

    # 2) 실측 패턴 수작업 케이스 (모두 dd_main ↔ unified 양쪽 검사)
    cases = [
        ('position_nrs 마커 런',
         b'\x09position_nrs\x00' + bytes([ARRAY])
         + b'\x02\x02\x03' + b'\x04\x02\x04\x02\x04\x03\x04\x03\x04\x04' + b'\x00',
         {'position_nrs': [0, 0, 0, 2, 2, 3, 3, 4]}),
        ('ratios 승격 (int8→int16)',
         b'\x09ratios\x00' + bytes([ARRAY])
         + b'\x04\x22\x04\x27\x04\x7c\x05\x00\x81\x05\x00\x86' + b'\x00',
         {'ratios': [34, 39, 124, 129, 134]}),
        ('es_values 제로 드롭아웃',
         b'\x09es_values\x00' + bytes([ARRAY])
         + b'\x05\x23\x3d\x02\x05\x19\x19\x05\x18\xa8' + b'\x00',
         {'es_values': [9021, 0, 6425, 6312]}),
        ('detector 이름+컨테이너 원소',
         b'\x09detector\x00' + bytes([ARRAY])
         + b'\x09abc\x00' + bytes([STRUCT]) + b'\x09n\x00\x04\x05\x00' + b'\x00',
         {'detector': [{'abc': {'n': 5}}]}),
        ('bare 문자열 배열 (짝수 개 함정)',
         b'\x09valid_values\x00' + bytes([ARRAY])
         + b'\x09TRUE\x00\x09TRUE\x00' + b'\x00',
         {'valid_values': ['TRUE', 'TRUE']}),
        ('전부-02 배열 (빈 logged_errors 패턴)',
         b'\x09logged_errors\x00' + bytes([ARRAY]) + b'\x02\x02\x02\x02' + b'\x00',
         {'logged_errors': [0, 0, 0, 0]}),
        ('END 직전 제로 3연속 (first/last/repeat 패턴)',
         b'\x09s\x00' + bytes([STRUCT])
         + b'\x09first_index\x00\x02\x09last_index\x00\x02\x09repeat_count\x00\x03'
         + b'\x00',
         {'s': {'first_index': 0, 'last_index': 0, 'repeat_count': 0}}),
        ('int32 실측값 (logical_scan_id=129366)',
         b'\x09logical_scan_id\x00\x06' + struct.pack('>i', 129366),
         {'logical_scan_id': 129366}),
    ]
    for label, member_bytes, expected in cases:
        raw = wrap(member_bytes)
        t_main, unk, _ = dd_main.parse_tlv(raw)
        t_safe = dd_unified.parse(raw, 'safe')
        t_pure = dd_unified.parse(raw, 'pure')
        ok = (t_main == expected and t_safe == expected and t_pure == expected
              and not unk)
        check(label, ok, f'main={t_main} safe={t_safe} pure={t_pure}')

    # 3) wide 생략 (safe 전용 — pure 는 이 인코딩을 지원하지 않는 게 정의)
    raw = wrap(b'\x09zero_f\x00\x08' + b'\x09next\x00\x04\x07')
    check('wide 생략(앵커 케이스): dd_main == unified(safe) == {0, 7}',
          dd_main.parse_tlv(raw)[0] == dd_unified.parse(raw, 'safe')
          == {'zero_f': 0, 'next': 7})

    # 4) A1 확정 vs 헷지 — 이미지 밖 인코딩(02+비영 payload)에서의 '의도된 갈림'
    #    dd_main(헷지)은 5 로 읽고, unified(A1 확정)는 0 + anomaly 기록.
    #    dd_strict 는 이 파일을 조용히 unique 로 통과시킨다(V1 발견) —
    #    그래서 anomalies 가 실질 트립와이어다.
    raw = wrap(b'\x09a\x00\x02\x05')
    u = dd_unified.Unified(raw, 'safe')
    check('A1 확정: `02 05` → unified {a:0} + anomaly 1건, dd_main {a:5}',
          u.parse() == {'a': 0} and len(u.anomalies) == 1
          and dd_main.parse_tlv(raw)[0] == {'a': 5}
          and dd_strict.parse_strict(raw).status == 'unique')

    # 5) 유령 분기 제거 검증 — v=[2] ('0a 04 02 00') 는 전 룰셋 1해여야 한다
    #    (초기 enum_parses 는 dd_strict 에 없는 배열 1B 생략 분기 때문에
    #     spec/nowide 에서 2해로 과대집계했다 — V2 발견)
    raw = wrap(b'\x09v\x00' + bytes([ARRAY]) + b'\x04\x02' + b'\x00')
    counts = [len(enum_parses(raw, rs)) for rs in ('spec', 'nowide', 'pure')]
    check('배열 v=[2]: 전 룰셋 1해 (유령 분기 없음) + dd_strict unique',
          counts == [1, 1, 1] and dd_strict.parse_strict(raw).status == 'unique')

    print(f'\nselftest: {"전체 통과 ✓" if not fails else f"{len(fails)}건 실패 ✗"}')
    return 1 if fails else 0


def _gen_file(rng, pure):
    tree = gen_dict(rng, depth=3)
    raw = wrap(Enc(rng, pure=pure).members(tree))
    return tree, raw


def cmd_diff(args):
    rng = random.Random(args.seed)
    n_bad = 0
    for k in range(args.files):
        tree, raw = _gen_file(rng, args.pure)
        t_main, unk, _ = dd_main.parse_tlv(raw)
        t_safe = dd_unified.parse(raw, 'safe')
        pairs = [('main≡intended', t_main == tree),
                 ('main≡unified(safe)', t_main == t_safe),
                 ('미지태그 0건', not unk)]
        if args.pure:
            pairs.append(('main≡unified(pure)',
                          t_main == dd_unified.parse(raw, 'pure')))
        bad = [name for name, ok in pairs if not ok]
        if bad:
            n_bad += 1
            if n_bad <= 5:
                print(f'✗ file#{k}: {bad}')
                print(f'   intended: {tree}')
                print(f'   main    : {t_main}')
                print(f'   safe    : {t_safe}')
                print(f'   hex     : {sample_hex(raw, 240)}')
    mode = 'pure 이미지' if args.pure else 'safe 이미지(wide 생략 포함)'
    print(f'diff({mode}): {args.files}개 생성 파일 중 불일치 {n_bad}개 '
          f'{"✓ 동치" if n_bad == 0 else "✗"}')
    return 1 if n_bad else 0


def cmd_strict(args):
    rng = random.Random(args.seed)
    stats = {'unique': 0, 'ambiguous': 0, 'failed': 0, 'budget': 0}
    tree_mismatch = 0
    ambig_examples = []
    for k in range(args.files):
        tree, raw = _gen_file(rng, args.pure)
        res = dd_strict.parse_strict(raw, node_budget=400_000)
        stats[res.status] = stats.get(res.status, 0) + 1
        if res.status == 'unique':
            if res.trees[0] != dd_main.parse_tlv(raw)[0]:
                tree_mismatch += 1
        elif res.status == 'ambiguous' and len(ambig_examples) < 3:
            ambig_examples.append((k, tree, raw, res))
    print(f'strict 오라클 교차 ({args.files}개, {"pure" if args.pure else "safe"} 이미지):')
    for s, c in stats.items():
        print(f'  {s:<10}: {c}')
    print(f'  유일해 중 dd_main 트리 불일치: {tree_mismatch}')
    for k, tree, raw, res in ambig_examples:
        print(f'\n  [모호 예 file#{k}] — 스펙 룰의 헷지가 만든 모호 '
              f'(pure 룰 해 개수: {len(enum_parses(raw, "pure"))})')
        for d in dd_strict.tree_diff(res.trees[0], res.trees[1])[:4]:
            print(f'    {d[0]}: {d[1]!r} ↔ {d[2]!r}')
    return 0


def cmd_ambig(_args):
    print('반례 2종 — 룰셋별 boundary-정합 해 개수 (enum_parses 전수 열거):\n')
    rows = [('A. wide 생략 반례 (float payload ≡ 제로필드 인코딩)', build_ambig_wide()),
            ('B. 폭1 explicit-payload 반례 (END 시프트)', build_ambig_w1())]
    print(f'  {"반례":<44}{"spec":>6}{"nowide":>8}{"pure":>6}   dd_strict')
    for label, raw in rows:
        counts = [len(enum_parses(raw, rs)) for rs in ('spec', 'nowide', 'pure')]
        res = dd_strict.parse_strict(raw)
        print(f'  {label:<44}{counts[0]:>6}{counts[1]:>8}{counts[2]:>6}   {res.status}')
        sols = enum_parses(raw, 'spec')
        for i, s in enumerate(sols[:2], 1):
            print(f'      해석{i}: {s}')
        print(f'      bytes : {sample_hex(raw, 200)}')
        print()
    print('읽는 법:')
    print('  · spec 룰에서 2해 = 같은 바이트에 두 인코딩이 겹침(인코딩 비단사).')
    print('    이 지점은 순방향/역방향/전역 어떤 알고리즘도 원리적으로 못 가른다 —')
    print('    같은 바이트이므로 읽는 방향은 무관하다 (V4 가 역방향 전수 열거로')
    print('    해집합 방향-불변을 실측 확인). 오라클(dd_strict)의 역할은 "가르기"가')
    print('    아니라 "검출"이고, 그것이 이 포맷의 옳은 아키텍처다.')
    print('  · pure 룰(공리 A1)에서 A는 1해(진짜 float), B는 0해(인코딩 불가 바이트).')
    print('    → dd_strict 엄격-pass 문법 안에서 모호성의 원천은 정확히 이름 필드의')
    print('      두 헷지(wide 생략, 폭1 explicit 0-payload)다. 단, 엄격 pass 실패 시')
    print('      도는 loose fallback 은 별도의 모호 클래스(이름 스칼라 원소 등)를')
    print('      추가로 갖는다 — 혼합 배열 등 문법 밖 입력에서만 발동 (V2 발견).')
    return 0


def cmd_hunt(args):
    """유효 파일에 1~3바이트 변형을 가해 모호 입력의 지형을 훑는다."""
    rng = random.Random(args.seed)
    alphabet = [0x00, 0x02, 0x03, 0x04, 0x05, 0x08, 0x09, 0x0a, 0x0b,
                0x61, 0x62, 0x63]
    tally = {'spec': 0, 'nowide': 0, 'pure': 0}
    checked = 0
    pure_multi = []
    for _ in range(args.rounds):
        tree, raw = _gen_file(rng, pure=False)
        if len(raw) > 120:            # 전수 열거 가능 크기로 제한
            continue
        body = bytearray(raw[:-4])
        for _ in range(rng.randrange(1, 4)):
            body[rng.randrange(5, len(body))] = rng.choice(alphabet)
        mutated = bytes(body) + checksum(bytes(body))
        checked += 1
        for rs in ('spec', 'nowide', 'pure'):
            sols = enum_parses(mutated, rs, cap=3)
            if len(sols) >= 2:
                tally[rs] += 1
                if rs == 'pure':
                    pure_multi.append(mutated)
    print(f'hunt: 변형 파일 {checked}개 검사 — 룰셋별 모호(≥2해) 건수:')
    for rs, c in tally.items():
        print(f'  {rs:<7}: {c}')
    print(f'  pure 룰 모호 {len(pure_multi)}건 '
          f'{"(0 이어야 정상 — pure 는 분기가 없어 구성적으로 ≤1해)" if not pure_multi else "⚠ 반례!"}')
    for m in pure_multi[:3]:
        print(f'    ⚠ {sample_hex(m, 200)}')
    return 1 if pure_multi else 0


# ────────────────────────────────────────────────────────────────────
# measure — 실코퍼스에서 pure-A1 판별 (코퍼스 보유 환경에서 실행)
# ────────────────────────────────────────────────────────────────────
def measure_walk(raw, st):
    end = len(raw) - 4
    i = 5 if raw[4] == STRUCT else 4

    def number(tag, i, pinned):
        fmt, width = NUM[tag]
        if width == 0:
            # 폭0 태그 직후가 '정상 이어짐'(형제/END/원소태그)이 아니면
            # explicit payload 의심 → pure 반례 후보
            if pinned and i < end and raw[i] != END and not FIELD_ANCHOR.match(raw, i):
                st['w0_payloadish'] += 1
            return 0, i
        if pinned and FIELD_ANCHOR.match(raw, i):
            key = 'wide_elide' if width > 1 else 'w1_anchor_elide'
            st[key] += 1
            if width > 1:
                st['wide_elide_tags'][tag] = st['wide_elide_tags'].get(tag, 0) + 1
            return 0, i
        if pinned and width == 1 and i < end and raw[i] == END:
            st['w1_end_elide'] += 1
            return 0, i
        if i + width > end:
            return None, end
        v = struct.unpack(fmt, raw[i:i + width])[0]
        if tag == 0x06 and v == 0:
            st['tag06_zero_explicit'] += 1
        if width == 1 and v == 0:
            st['w1_zero_explicit'] += 1      # '04 00' 류 — pure 반례 후보
        return v, i + width

    def cstr(i):
        j = raw.find(0, i, end)
        j = end if j == -1 else j
        return j + 1

    def walk_struct(i):
        while i < end:
            t = raw[i]
            if t == END:
                return i + 1
            if t != STRING:
                raise ValueError(f'struct@{i}: 0x{t:02x}')
            i = cstr(i + 1)
            if i >= end:
                return end
            sub, i = raw[i], i + 1
            if sub in NUM:
                _, i = number(sub, i, True)
            elif sub == STRING:
                i = cstr(i)
            elif sub == STRUCT:
                i = walk_struct(i)
            elif sub == ARRAY:
                i = walk_array(i)
            else:
                raise ValueError(f'subtype 0x{sub:02x}@{i}')
        return i

    def walk_array(i):
        while i < end:
            t = raw[i]
            if t == END:
                return i + 1
            if t == STRING:
                j = cstr(i + 1)
                nxt = raw[j] if j < end else None
                i = (walk_struct if nxt == STRUCT else walk_array)(j + 1) \
                    if nxt in (ARRAY, STRUCT) else j
            elif t in NUM:
                _, i = number(t, i + 1, False)
            elif t in (STRUCT, ARRAY):
                i = (walk_struct if t == STRUCT else walk_array)(i + 1)
            else:
                raise ValueError(f'array elem 0x{t:02x}@{i}')
        return i

    walk_struct(i)


def cmd_measure(args):
    st = {'wide_elide': 0, 'wide_elide_tags': {}, 'w1_anchor_elide': 0,
          'w1_end_elide': 0, 'w1_zero_explicit': 0, 'w0_payloadish': 0,
          'tag06_zero_explicit': 0, 'files': 0, 'errors': 0}
    for name, raw in dd_strict.iter_dd(args.paths):
        if len(raw) < 12 or raw[:4] != MAGIC:
            continue
        st['files'] += 1
        try:
            measure_walk(raw, st)
        except Exception:
            st['errors'] += 1
    print(f'measure: {st["files"]}개 파일 (walk 실패 {st["errors"]})\n')
    print('pure-A1 판별 카운터 (전부 0 이면 룩어헤드 없는 pure 파서로 충분):')
    print(f'  [1] wide(2B+) 이름 필드의 생략      : {st["wide_elide"]} '
          f'{st["wide_elide_tags"] or ""}')
    print(f'  [2] 폭1 태그(01/04)의 앵커 생략     : {st["w1_anchor_elide"]}')
    print(f'  [3] 폭1 태그(01/04)의 END 생략      : {st["w1_end_elide"]}')
    print(f'  [4] 폭1 explicit 0-payload (04 00)  : {st["w1_zero_explicit"]}')
    print(f'  [5] 폭0 태그 뒤 비정상 이어짐        : {st["w0_payloadish"]}')
    print(f'  (참고) 0x06 explicit 4B 제로        : {st["tag06_zero_explicit"]} '
          f'— 스펙의 "0x06 1개(0)" 의 정체 판별')
    print('\n해석: [1]~[5] 전부 0 → 코퍼스는 pure 이미지 안 → 예외/룩어헤드 전폐 가능.')
    print('      [1] 이 0 이 아니면 wide 생략이 실재 → safe 모드(룩어헤드 1개) 유지.')
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest='cmd', required=True)
    sub.add_parser('selftest')
    p = sub.add_parser('diff')
    p.add_argument('--files', type=int, default=1000)
    p.add_argument('--seed', type=int, default=7)
    p.add_argument('--pure', action='store_true')
    p = sub.add_parser('strict')
    p.add_argument('--files', type=int, default=200)
    p.add_argument('--seed', type=int, default=11)
    p.add_argument('--pure', action='store_true')
    sub.add_parser('ambig')
    p = sub.add_parser('hunt')
    p.add_argument('--rounds', type=int, default=300)
    p.add_argument('--seed', type=int, default=3)
    p = sub.add_parser('measure')
    p.add_argument('paths', nargs='+')
    args = ap.parse_args()
    fn = {'selftest': cmd_selftest, 'diff': cmd_diff, 'strict': cmd_strict,
          'ambig': cmd_ambig, 'hunt': cmd_hunt, 'measure': cmd_measure}[args.cmd]
    sys.exit(fn(args))


if __name__ == '__main__':
    main()
