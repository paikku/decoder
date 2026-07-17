# -*- coding: utf-8 -*-
"""2-공리 파서 — dd_main.py 의 '예외 4가지'를 공리 2개로 환원한 .dd 디코더.

dd_main.py 에는 실측으로 확정한 예외 처리가 4곳에 흩어져 있다:
  ① 이름 필드의 0값 payload 생략 (KEY_ANCHOR / END 룩어헤드)
  ② 배열의 0 은 0x02/0x03 마커 (payload 없음)
  ③ 배열 0x09 원소의 이형 판별 (post-NUL 바이트)
  ④ 수치 배열의 타입 승격 (int8→int16→…)

이 모듈은 그 넷이 서로 다른 규칙이 아니라 다음 두 공리의 발현임을
'구현으로' 보인다 — 아래 파서에는 마커 특수분기도, 승격 로직도,
배열 전용 스칼라 경로도 없다. 이름 필드와 배열 원소가 같은 _number
하나를 쓴다.

공리 A1 (수치 = 최소 폭 인코딩; 태그가 곧 폭이다)
    0x02/0x03 → 0B(값 0)   0x01/0x04 → 1B   0x05 → 2B(int16, 구 'ENUM')
    0x06 → 4B(int32, 구 'BOOL')   0x07 → 4B(f32)   0x08 → 8B(f64)
    인코더는 값이 들어가는 최소 폭 태그를 고른다. 따라서
      · 배열(태그를 값에 맞춰 고르는 문맥)의 0 은 언제나 폭0 태그
        → ②는 폭 테이블의 한 항목(width=0)일 뿐이다.
      · 값이 int8 을 넘으면 태그가 넓어진다 → ④의 '승격'은 개념 불요:
        원소마다 자기 태그가 자기 폭을 정한다.
      · 이름 필드의 '0값 생략'(①) 은 같은 공리("0 은 0바이트")의
        이름-문맥 발현이다.

공리 A2 (배열 원소 문법)
    element := named_container | bare_value
    0x09 원소는 NUL 직후 1바이트가 0x0A/0x0B 면 named_container.
    (③은 이 문법의 LL(1) 룩어헤드일 뿐이다)

mode:
  'safe' : 스펙 §1.3 주의(모든 스칼라의 0값 생략 가능성)를 그대로 수용 —
           이름 필드에서 폭>0 태그도 룩어헤드로 생략을 감지한다.
           실코퍼스에서 dd_main 과 동일 동작.
  'pure' : 생략이라는 개념 자체가 없는 결정적 문법 — 폭 테이블이 전부다.
           룩어헤드/정규식 0회. 인코더가 진짜 최소-폭 원칙(0 은 항상
           폭0 태그)을 지킨다면 이것으로 충분하며, 이 문법은 분기가
           없어 증명적으로 무모호다. 실코퍼스가 pure 이미지 안에 있는지는
           `dd_prove.py measure` 한 번으로 판별된다.

전역 오라클(경계 n-4 정합 + 체크섬 + 유일해 검사)은 dd_strict.py 가
담당한다. 공리가 덮지 못하는 병리적 입력(dd_prove.py ambig 의 반례처럼
같은 바이트에 두 인코딩이 겹치는 파일)은 로컬 규칙이 아니라 오라클이
검출하는 것이 옳다 — 그 지점은 어떤 디코더도 원리적으로 못 가른다.
"""

import re
import struct

MAGIC = bytes([0x17, 0xfa, 0xae, 0x4e])
END, STRING, ARRAY, STRUCT = 0x00, 0x09, 0x0a, 0x0b

# ── 공리 A1: 태그 = 폭 사다리 ────────────────────────────────────────
NUM = {
    0x01: ('>b', 1),   # int8 (희소)
    0x02: ('>b', 0),   # zero(signed 계열)  — 폭 0
    0x03: ('>B', 0),   # zero(unsigned 계열) — 폭 0
    0x04: ('>b', 1),   # int8 값 캐리어 (측정: 이름필드 1087/1087 비영)
    0x05: ('>h', 2),   # int16 (구 'ENUM' — 이름은 유물)
    0x06: ('>i', 4),   # int32 (구 'BOOL' — logical_scan_id=129366 실측)
    0x07: ('>f', 4),   # float32 (미관측)
    0x08: ('>d', 8),   # float64
}

FIELD_ANCHOR = re.compile(rb'\x09[A-Za-z_][A-Za-z0-9_.\-]{0,63}\x00')


class Unified:
    def __init__(self, raw, mode='safe'):
        assert mode in ('safe', 'pure')
        self.raw = raw
        self.n = len(raw)
        self.end = self.n - 4 if self.n > 4 else self.n
        self.mode = mode

    def parse(self):
        i = 4 if self.raw[:4] == MAGIC else 0
        if i < self.end and self.raw[i] == STRUCT:
            i += 1
        tree, _ = self._struct(i)
        return tree

    # ── 공리 A1: 수치 읽기 — 이름 필드/배열 원소가 공유하는 유일한 경로 ──
    def _number(self, tag, i, pinned):
        """pinned=True: 태그가 필드 선언에 고정된 문맥(이름 필드) —
        값 0 이면 payload 가 0바이트로 기록될 수 있다(safe 모드).
        pinned=False: 태그를 값에 맞춰 고르는 문맥(배열 원소) —
        0 은 애초에 폭0 태그로 오므로 '생략' 이란 없다."""
        fmt, width = NUM[tag]
        if width == 0:                       # 폭0 태그 = 0 (②의 정체)
            return 0, i
        if pinned and self.mode == 'safe' and self._zero_elided(i, width):
            return 0, i                      # '0 은 0바이트' 의 이름-필드 발현 (①)
        if i + width > self.n:
            return None, self.n
        return struct.unpack(fmt, self.raw[i:i + width])[0], i + width

    def _zero_elided(self, i, width):
        if FIELD_ANCHOR.match(self.raw, i):  # 형제 필드가 이미 시작되어 있음
            return True
        # END 직전 생략 판정은 폭 1 에서만 — 0x00 payload 로 읽어도 값이
        # 동일하게 0 이라 안전하고, 폭 2+ 는 선두 0x00 이 정상 payload 일 수 있다.
        return width == 1 and i < self.end and self.raw[i] == END

    def _cstr(self, i):
        j = self.raw.find(0, i)
        if j == -1:
            j = self.n
        return self.raw[i:j].decode('utf-8', 'replace'), j + 1

    def _value(self, sub, i, pinned):
        if sub in NUM:
            return self._number(sub, i, pinned)
        if sub == STRING:
            return self._cstr(i)
        if sub == STRUCT:
            return self._struct(i)
        if sub == ARRAY:
            return self._array(i)
        if sub == END:
            return None, i
        return f'<?0x{sub:02x}>', i          # 미지 태그 (정밀 진단은 dd_strict 몫)

    def _struct(self, i):
        obj = {}
        while i < self.end:
            t = self.raw[i]
            if t == END:
                return obj, i + 1
            if t != STRING:                  # 디싱크 — dd_main 과 동일하게 1B 스킵
                i += 1
                continue
            name, i = self._cstr(i + 1)
            if i >= self.end:
                obj[name] = None
                return obj, i
            sub = self.raw[i]
            obj[name], i = self._value(sub, i + 1, pinned=True)
        return obj, i

    def _array(self, i):
        arr = []
        while i < self.end:
            t = self.raw[i]
            if t == END:
                return arr, i + 1
            if t == STRING:                  # 공리 A2: named_container | bare_value
                s, j = self._cstr(i + 1)
                nxt = self.raw[j] if j < self.end else None
                if nxt in (ARRAY, STRUCT):
                    v, i = self._value(nxt, j + 1, pinned=False)
                    arr.append({s: v})
                else:
                    arr.append(s)
                    i = j
                continue
            if t in NUM:
                v, i = self._number(t, i + 1, pinned=False)
                arr.append(v)
                continue
            if t in (STRUCT, ARRAY):
                v, i = self._value(t, i + 1, pinned=False)
                arr.append(v)
                continue
            arr.append(f'<?0x{t:02x}>')      # 미지 태그
            i += 1
        return arr, i


def parse(raw, mode='safe'):
    """.dd 바이트 → 트리 (dd_main.parse_tlv 의 트리와 동일 형태)"""
    return Unified(raw, mode).parse()
