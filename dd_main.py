import io
import sys
import json
import re
import struct
import zipfile
from pathlib import Path

try:
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')
except Exception:
    pass


class Tee:
    """화면(stdout)과 파일에 동시에 출력하는 래퍼"""

    def __init__(self, stream, fileobj):
        self.stream = stream
        self.fileobj = fileobj

    def write(self, data):
        self.stream.write(data)
        self.fileobj.write(data)

    def flush(self):
        self.stream.flush()
        self.fileobj.flush()

MAGIC = bytes([0x17, 0xfa, 0xae, 0x4e])

# ── 공식 스펙 타입 태그 (TLV) ────────────────────────────────────────
#   각 필드: Type(1B) Name(NUL문자열) SubType(1B) Value(가변)
#   컨테이너(ARRAY/STRUCT)는 END(0x00) 로 닫힘
TAG_END     = 0x00  # 블록 종료 (컨테이너 닫기)
TAG_INT8_A  = 0x01  # 8비트 정수 (1B)
TAG_INT8_B  = 0x02  # 8비트 정수 (1B) — 실측 재확인: 과거 INT16(2B) 표기가 오류
TAG_UINT8   = 0x03  # 8비트 부호없는 정수 (1B)
TAG_INT8_C  = 0x04  # 8비트 정수 (1B) — 실측 재확인: 과거 INT32(4B) 표기가 오류
TAG_ENUM    = 0x05  # 열거형 (2B)
TAG_BOOL    = 0x06  # 불리언 (4B, TRUE/FALSE)
TAG_FLOAT32 = 0x07  # 32비트 실수 (4B)
TAG_FLOAT64 = 0x08  # 64비트 실수 (8B)
TAG_STRING  = 0x09  # 문자열 (NUL 종료)
TAG_ARRAY   = 0x0a  # 배열 (가변)
TAG_STRUCT  = 0x0b  # 중첩 구조체 (가변)

# 하위호환용 별칭
TAG_NULL   = TAG_END
TAG_DOUBLE = TAG_FLOAT64
TAG_INT8   = TAG_INT8_A

# 스칼라 타입 → (struct 포맷, 바이트수). big-endian(>) 기준.
SCALAR_FMT = {
    TAG_INT8_A:  ('>b', 1),
    TAG_INT8_B:  ('>b', 1),
    TAG_UINT8:   ('>B', 1),
    TAG_INT8_C:  ('>b', 1),
    TAG_ENUM:    ('>h', 2),  # 실측: 배열 원소로 쓰일 때 2바이트 (DD_FORMAT.md 미해결 참고)
    TAG_FLOAT32: ('>f', 4),
    TAG_FLOAT64: ('>d', 8),
}
TYPE_NAME = {
    TAG_END: 'END', TAG_INT8_A: 'int8_a', TAG_INT8_B: 'int8_b', TAG_UINT8: 'uint8',
    TAG_INT8_C: 'int8_c', TAG_ENUM: 'enum', TAG_BOOL: 'bool', TAG_FLOAT32: 'float32',
    TAG_FLOAT64: 'float64', TAG_STRING: 'string', TAG_ARRAY: 'array', TAG_STRUCT: 'struct',
}

# 키 앵커 패턴: 0x09 + '유효한 식별자' + 0x00
#   식별자를 ASCII 영숫자/._- /공백 으로 제한 → double 데이터 안의 우연한
#   0x09 바이트는 매칭되지 않으므로 '도미노 오정렬' 이 발생하지 않는다.
#   {0,63} → 단일 글자 키(v, a, j 등)도 허용
KEY_ANCHOR = re.compile(rb'\x09([A-Za-z_][A-Za-z0-9_.\-]{0,63})\x00')


def _read_cstr(raw, i):
    """NUL 종료 문자열 읽기 → (문자열, NUL 다음 인덱스)"""
    j = raw.find(0, i)
    if j == -1:
        j = len(raw)
    return raw[i:j].decode('utf-8', errors='replace'), j + 1


# ── 공식 스펙 기반 재귀 TLV 파서 ─────────────────────────────────────
#   필드 = Type(1B) Name(NUL문자열) SubType(1B) Value
#   ARRAY/STRUCT 는 END(0x00) 로 닫힘.  Value 는 SubType 에 따라 재귀.
class TLVParser:
    def __init__(self, raw):
        self.raw = raw
        self.i = 0
        self.n = len(raw)
        self.unknown = []          # (tag, offset) 미지 타입
        # 파일 끝 4바이트 트레일러(체크섬) 제외
        self.end = self.n - 4 if self.n > 4 else self.n
        self.trailer = raw[self.end:] if self.end < self.n else b''
        if raw[:4] == MAGIC:
            self.i = 4

    def parse(self):
        """최상위 = STRUCT 로 가정하고 멤버들을 읽는다."""
        # 최상위가 STRUCT(0x0b) 로 열리면 그 안으로
        if self.i < self.end and self.raw[self.i] == TAG_STRUCT:
            self.i += 1
        return self._read_members()

    def _read_members(self):
        """END(0x00) 또는 끝까지 'Name + SubType + Value' 멤버를 읽어 dict 반환."""
        obj = {}
        while self.i < self.end:
            t = self.raw[self.i]
            if t == TAG_END:            # 블록 종료
                self.i += 1
                break
            if t == TAG_STRING:         # 정상 필드: 이름부터
                self.i += 1
                name, self.i = _read_cstr(self.raw, self.i)
                if self.i >= self.end:
                    obj[name] = None
                    break
                subtype = self.raw[self.i]
                self.i += 1
                obj[name] = self._read_value(subtype)
            else:
                # 이름 없이 값이 오는 경우(배열 원소 등) → 리스트로 처리하려면
                # _read_array 에서 다룸. 여기 오면 미지 → 1바이트 스킵
                self.unknown.append((t, self.i))
                self.i += 1
        return obj

    def _read_value(self, subtype):
        raw, end = self.raw, self.end
        fmt = SCALAR_FMT.get(subtype)
        if fmt:
            f, size = fmt
            # 실측(nr_of_used_samples 등 미사용 detector 슬롯의 0값 필드):
            # payload 가 통째로 생략되고 서브타입 태그 바로 뒤에 다음 필드의
            # 이름(0x09 + 식별자 + NUL)이 곧바로 이어지는 경우가 있다. 이걸
            # 모르고 고정폭 payload 를 그대로 소비하면 다음 필드 이름의 앞
            # 글자를 삼켜 디싱크가 발생한다 → 다음 필드 앵커가 보이면 이
            # 값은 0(생략)으로 보고 바이트를 소비하지 않는다.
            if KEY_ANCHOR.match(raw, self.i):
                return 0
            # 같은 생략이 필드가 컨테이너의 '마지막' 멤버일 때도 일어난다 —
            # 이때는 다음에 형제 필드 앵커가 아니라 그 컨테이너를 닫는
            # END(0x00) 가 곧바로 온다. **0 표기 전용 태그(0x01/0x02/0x03)에
            # 한해서만** 이 검사를 적용한다.
            #   ⚠ 2026-07 정정: 예전엔 size==1 전부(0x04 포함)에 적용했는데,
            #   그건 잠복 버그였다. 0x04(int8_c)는 실제 int8 '값 캐리어'이고
            #   측정상 이름 필드 1087/1087 이 전부 비영이다(0 은 0x02/0x03 로
            #   기록됨). 따라서 0x04 가 0값으로 생략될 일은 없다. 그런데도
            #   0x04 를 이 검사에 포함하면 '명시적 04 00'(int8 값 0) 뒤에
            #   형제 필드가 오는 입력에서 0x00 을 END 로 오인해 컨테이너를
            #   조기 폐쇄하고 뒤 필드를 통째로 잃는다(경계 미도달·무증상).
            #   0x04 를 빼면 이 입력이 {a:0, b:7} 로 올바로 읽히고 경계까지
            #   소비된다. 실코퍼스 동작은 불변(0x04 END-직전 0값이 애초에 없음).
            #   enum/bool/float(폭 2B+)은 선두 0x00 이 실값일 수 있어 원래 제외.
            if (subtype in (TAG_INT8_A, TAG_INT8_B, TAG_UINT8)
                    and self.i < self.end and raw[self.i] == TAG_END):
                return 0
            if self.i + size <= self.n:
                v = struct.unpack(f, raw[self.i:self.i + size])[0]
                self.i += size
                return v
            self.i = self.n
            return None
        if subtype == TAG_BOOL:
            # 실측(IFEUxDATA_ARR_PHYS_SCAN_RAW_DATA_STRUCT.logical_scan_id):
            # 0x06 뒤에 00 01 f9 56 4바이트가 오고 그 직후 다음 필드명(0x09)이
            # 시작한다 — payload 첫 바이트가 0x00 이라 NUL종료 문자열로 읽으면
            # 빈 문자열/False 로 착지하고 남은 3바이트가 디싱크를 유발한다.
            # "TRUE"/"FALSE" 문자열 인코딩은 DD_FORMAT.md 1.4 예시에서도 실제로는
            # STRING(0x09) 태그로 나타났으므로, 0x06 은 고정 4바이트 값으로 처리한다.
            # (위와 동일하게) payload 생략 패턴도 같이 확인한다.
            if KEY_ANCHOR.match(raw, self.i):
                return False
            if self.i + 4 <= self.n:
                v = struct.unpack('>i', raw[self.i:self.i + 4])[0]
                self.i += 4
                return v
            self.i = self.n
            return None
        if subtype == TAG_STRING:
            s, self.i = _read_cstr(raw, self.i)
            return s
        if subtype == TAG_STRUCT:
            return self._read_members()
        if subtype == TAG_ARRAY:
            return self._read_array()
        if subtype == TAG_END:
            return None
        # 미지 subtype
        self.unknown.append((subtype, self.i))
        return f'<?0x{subtype:02x}>'

    def _read_array(self):
        """배열: END(0x00) 까지 'SubType + Value' 원소들을 읽는다.

        실측 정정 (DD_FORMAT_SPEC.md §1.6):
          - 0x09 원소는 이형: 이름 NUL 직후가 컨테이너(0a/0b)면 {이름: 컨테이너},
            아니면 bare 문자열 값. (둘씩 짝지어 먹던 과거 오독 차단)
          - 0x02 는 배열의 순수 0 마커다 (측정 확정: 이름필드 602/602 이 0,
            진짜 int8 값은 0x04). payload 없이 1바이트만 소비하고 값 0.
          - 그 외 스칼라는 값을 싣는다 (0 은 0x02 로 기록되므로 마커 판정 불필요).
        """
        arr = []
        dom = None                # 배열 지배 태그 (§1.6 동질성 규칙)
        while self.i < self.end:
            t = self.raw[self.i]
            if t == TAG_END:
                self.i += 1
                break
            if t == TAG_STRING:
                # 09 원소는 이형(§1.6): 이름 NUL 직후가 컨테이너 태그(0a/0b)면
                # '이름있는 컨테이너 원소' {name: container} (detector 맵 실측),
                # 아니면 bare 문자열 값.
                self.i += 1
                s, self.i = _read_cstr(self.raw, self.i)
                nxt = self.raw[self.i] if self.i < self.end else None
                if nxt in (TAG_ARRAY, TAG_STRUCT):
                    self.i += 1
                    arr.append({s: self._read_value(nxt)})
                    dom = dom or 'NAMED'
                else:
                    arr.append(s)
                    dom = dom or TAG_STRING
                continue
            # 0x02/0x03 은 배열의 payload 없는 0 마커 (측정 확정, §1.6): 이름
            # 필드에서 0x02 는 602/602, 0x03 은 50/50 이 값 0. 진짜 int8 값은
            # 0x04(int8_c). 1바이트만 소비하고 0 을 낸다.
            if t in (TAG_INT8_B, TAG_UINT8):
                self.i += 1
                arr.append(0)
                continue
            # 그 외 스칼라 + 값. 0 은 0x02 로 기록되므로 여기선 마커 판정 불필요,
            # 고정폭 payload 만 읽는다.
            self.i += 1
            if t in SCALAR_FMT:
                f, size = SCALAR_FMT[t]
                if self.i + size <= self.n:
                    arr.append(struct.unpack(f, self.raw[self.i:self.i + size])[0])
                    self.i += size
                    dom = dom or t
                else:
                    self.i = self.n
                    arr.append(None)
                continue
            if t == TAG_BOOL:
                if self.i + 4 <= self.n:
                    arr.append(struct.unpack('>i', self.raw[self.i:self.i + 4])[0])
                    self.i += 4
                    dom = dom or t
                else:
                    self.i = self.n
                    arr.append(None)
                continue
            arr.append(self._read_value(t))
            dom = dom or t
        return arr


def parse_tlv(raw):
    """재귀 TLV 파싱 → (tree dict, unknown list, trailer bytes)"""
    p = TLVParser(raw)
    tree = p.parse()
    return tree, p.unknown, p.trailer


# ---------------------------------------------------------------------------
# 스켈레톤 추출 : 구조( { [ , key )만 복원하고 값은 placeholder 로 남김
# ---------------------------------------------------------------------------

VALUE_PLACEHOLDER = {
    TAG_NULL:   '<null>',
    TAG_INT8:   '<int8>',
    TAG_DOUBLE: '<double>',
    TAG_STRING: '<string>',
}


def _placeholder(tag):
    """값 태그를 사람이 읽는 placeholder 문자열로"""
    if tag is None:
        return '<empty>'          # 키 뒤에 값 바이트가 없는 경우
    if tag in VALUE_PLACEHOLDER:
        return VALUE_PLACEHOLDER[tag]
    return f'<?0x{tag:02x}>'


def value_span(raw, i):
    """raw[i] 가 값 태그라고 보고, 그 값이 차지하는 바이트 수를 반환.

    반환: (consumed, tag)  consumed = 태그+payload 총 바이트 수
      규칙이 확정된 스칼라만 정확히 소비한다.
      컨테이너(0x0a/0x0b)와 미지 태그는 태그 1바이트만 소비(payload 모름).
    """
    if i >= len(raw):
        return 0, None
    tag = raw[i]
    if tag == TAG_NULL:
        return 1, tag                       # 값 없음
    if tag == TAG_INT8:
        return 2, tag                       # 태그 + 1바이트
    if tag == TAG_DOUBLE:
        return 9, tag                       # 태그 + 8바이트
    if tag == TAG_STRING:
        j = raw.find(0, i + 1)              # NUL 종료
        end = (j + 1) if j != -1 else len(raw)
        return end - i, tag
    # 컨테이너/미지: payload 길이 미확정 → 태그 1바이트만
    return 1, tag


def find_closers(raw):
    """닫는 마커 후보를 자동 탐지.

    스칼라 값을 '정확한 길이' 만큼 소비한 뒤, 값의 끝과 다음 키(0x09) 시작
    사이에 남는 바이트를 모은다. 이 '사이 바이트' 가 닫는 마커/구분자다.
    구조체가 닫히는 곳(다음 형제로 넘어가기 전)에서 특히 나타난다.

    반환: (gap_counter, samples)
      gap_counter: 사이 바이트 시퀀스별 출현 횟수
      samples: (offset, prev_key_끝, gap_hex, 다음키) 예시
    """
    from collections import Counter

    anchors = [(m.start(), m.end(), m.group(1).decode('ascii'))
               for m in KEY_ANCHOR.finditer(raw)]
    gap_counter = Counter()
    single_byte = Counter()
    samples = []

    for idx in range(len(anchors)):
        ks, ke, key = anchors[idx]
        # 이 키의 값이 시작되는 위치 = ke
        consumed, vtag = value_span(raw, ke)
        val_end = ke + consumed
        # 다음 키 시작
        nxt_start = anchors[idx + 1][0] if idx + 1 < len(anchors) else len(raw)

        # 값 끝 ~ 다음 키 사이의 '갭' = 닫는 마커/구분자 후보
        if vtag in (TAG_ARRAY, TAG_STRUCT):
            continue  # 컨테이너는 payload 길이를 몰라 갭 계산 부정확 → 제외
        gap = raw[val_end:nxt_start]
        if gap:
            gap_counter[gap.hex(' ')] += 1
            for b in gap:
                single_byte[f'0x{b:02x}'] += 1
            if len(samples) < 20:
                samples.append({
                    'offset': val_end,
                    'after_key': key,
                    'val_tag': f'0x{vtag:02x}' if vtag is not None else None,
                    'gap_hex': gap.hex(' '),
                    'next_key': anchors[idx + 1][2] if idx + 1 < len(anchors) else '(EOF)',
                })

    return gap_counter, single_byte, samples


def print_closers(raw, name=''):
    gap_counter, single_byte, samples = find_closers(raw)
    print(f"\n{'='*60}\n닫는 마커 후보 탐지: {name}\n{'='*60}")
    print("\n[값 끝 ~ 다음 키 사이의 갭 바이트 분포]")
    print("  = 닫는 마커/구분자 후보 (스칼라 값 뒤에서 관찰)\n")
    print("  ● 갭 시퀀스별 빈도:")
    for gap, cnt in gap_counter.most_common(15):
        print(f"      {cnt:>5}회  [{gap}]")
    print("\n  ● 갭에 등장한 개별 바이트 빈도:")
    for b, cnt in single_byte.most_common(15):
        print(f"      {cnt:>5}회  {b}")
    print("\n  [샘플: 어떤 키 뒤에서 어떤 갭이 나오고 다음 키로 가는지]")
    for s in samples[:12]:
        print(f"      after {s['after_key']!r}({s['val_tag']}) "
              f"-> gap [{s['gap_hex']}] -> next {s['next_key']!r}")
    print("\n  해석: 갭이 0바이트면 값이 곧바로 다음 키로 이어진 것(닫힘 없음).")
    print("        특정 바이트(예: 0x0c/0x0d)가 struct 끝마다 반복되면 그게 닫는 마커.")
    print("        갭 길이가 '중첩을 몇 단계 빠져나오는지'(닫기 횟수)와 대응될 수 있음.")


def _read_key_at(raw, i):
    """raw[i] 가 0x09(키/문자열) 일 때 (문자열, NUL 다음 인덱스) 반환."""
    j = raw.find(0, i + 1)
    if j == -1:
        j = len(raw)
    return raw[i + 1:j].decode('utf-8', errors='replace'), j + 1


# 트레일러(체크섬) 크기: 파일 끝 고정 4바이트 (magic 과 짝)
TRAILER_LEN = 4


def trailer_checksum(raw):
    """트레일러 체크섬 계산 (2026-07-06 실측 확정, DD_FORMAT_SPEC.md §1.5).

    base-17 곱셈 롤링 해시: h = h*17 + byte (mod 2^32).
    범위는 매직 포함 raw[0:n-4], big-endian 4바이트로 저장된다.
    (표준 CRC 계열이 아님 — trailer_solve.py 로 역산)
    """
    h = 0
    for byte in raw[:-TRAILER_LEN]:
        h = (h * 17 + byte) & 0xFFFFFFFF
    return h


def dd_trailer_ok(raw):
    """.dd 끝 4바이트가 본문 체크섬과 일치하는지 검증"""
    if len(raw) <= TRAILER_LEN:
        return False
    return trailer_checksum(raw) == int.from_bytes(raw[-TRAILER_LEN:], 'big')


def extract_skeleton(raw):
    """스펙 기반 재귀 TLV 파서 결과를 '구조 + 실제 값' 텍스트로 렌더.

    값 타입은 스펙(0x01~0x0b)대로 정확히 해석되며, 중첩 struct/array 는
    재귀적으로 { } / [ ] 로 표시된다.
    """
    tree, unknown, trailer = parse_tlv(raw)
    lines = ['{']
    for ln in _render_tree(tree, indent=1, max_lines=100000):
        lines.append(ln)
    lines.append('}')
    if trailer:
        mark = '일치' if dd_trailer_ok(raw) else '불일치!'
        lines.append(f'// trailer(체크섬 h=h*17+b): {trailer.hex(" ")}  ← {mark}')
    if unknown:
        u = ', '.join(sorted({f'0x{t:02x}' for t, _ in unknown}))
        lines.append(f'// ⚠ 미지/오정렬 태그: {u}')
    return '\n'.join(lines)


def _count_leaves(tree):
    """중첩 트리의 리프(실제 값) 개수를 재귀 집계"""
    if isinstance(tree, dict):
        return sum(_count_leaves(v) for v in tree.values()) or (0 if tree else 0)
    if isinstance(tree, list):
        return sum(_count_leaves(v) for v in tree)
    return 1


def parse_bytes(raw, name=''):
    """단일 .dd 바이트를 스펙 기반 재귀 TLV 로 파싱해 dict 반환"""
    from collections import Counter
    # parse_tlv 대신 파서를 직접 들어 최종 커서 위치(경계 도달 여부)를 읽는다.
    p = TLVParser(raw)
    tree = p.parse()
    unknown, trailer = p.unknown, p.trailer
    # 경계(n-4) 미도달 = 파싱이 도중에 멈췄다는 신호. 단일 pass 휴리스틱은
    # 예전엔 이를 조용히 흘려 뒤 필드를 잃어도 티가 안 났다(예: 명시적
    # '04 00'). 남은 바이트 수를 리포트해 무증상 절단을 드러낸다.
    trailing = max(0, p.end - p.i) if raw[:4] == MAGIC else 0

    unk_tags = Counter(t for t, _ in unknown)
    samples = []
    for tag, off in unknown[:8]:
        ctx = raw[max(0, off - 12):off + 8]
        samples.append({
            'tag': tag, 'offset': off,
            'context_hex': ctx.hex(' '),
        })

    return {
        'name': name,
        'size': len(raw),
        'magic_ok': raw[:4] == MAGIC,
        'fields': tree,
        'field_count': _count_leaves(tree),
        'trailer': trailer.hex(' ') if trailer else '',
        'trailer_ok': dd_trailer_ok(raw) if raw[:4] == MAGIC else None,
        'boundary_ok': trailing == 0,
        'trailing_bytes': trailing,
        'unknown_tags': {f'0x{k:02x}': v for k, v in unk_tags.items()},
        'unknown_samples': samples,
    }


def _render_tree(tree, indent=1, max_lines=40, _lines=None):
    """중첩 트리를 들여쓰기 텍스트 줄 리스트로 렌더"""
    if _lines is None:
        _lines = []
    pad = '  ' * indent
    if isinstance(tree, dict):
        for k, v in tree.items():
            if len(_lines) >= max_lines:
                _lines.append(pad + '...')
                return _lines
            if isinstance(v, dict):
                _lines.append(f'{pad}{k} = {{')
                _render_tree(v, indent + 1, max_lines, _lines)
                _lines.append(pad + '}')
            elif isinstance(v, list):
                _lines.append(f'{pad}{k} = [')
                _render_tree(v, indent + 1, max_lines, _lines)
                _lines.append(pad + ']')
            elif isinstance(v, float):
                _lines.append(f'{pad}{k} = {v:.6g}')
            elif isinstance(v, str):
                _lines.append(f'{pad}{k} = "{v}"')
            else:
                _lines.append(f'{pad}{k} = {v}')
    elif isinstance(tree, list):
        for v in tree:
            if isinstance(v, (dict, list)):
                _render_tree(v, indent, max_lines, _lines)
            else:
                _lines.append(f'{pad}- {v}')
    return _lines


def print_result(res, preview=40):
    print(f"\n📄 {res['name']}  ({res['size']:,}B)  "
          f"magic={'OK' if res['magic_ok'] else 'X'}  필드 {res['field_count']}개")
    for line in _render_tree(res['fields'], max_lines=preview):
        print('  ' + line)
    if res.get('trailer'):
        mark = {True: '✓ 체크섬 일치', False: '✗ 체크섬 불일치!', None: ''}[res.get('trailer_ok')]
        print(f"    // trailer(h=h*17+b): {res['trailer']}  {mark}")
    if res.get('trailing_bytes'):
        print(f"    ⚠ 경계 미도달: 파싱이 {res['trailing_bytes']}B 를 남기고 멈춤 "
              f"(무증상 절단 가능 — dd_strict 로 확인 권장)")
    if res['unknown_tags']:
        print(f"    ⚠ 미지 태그: {res['unknown_tags']}")
        for s in res.get('unknown_samples', [])[:3]:
            print(f"       - 0x{s['tag']:02x} @off {s['offset']}  ctx: {s['context_hex']}")


def find_tdf_files(path):
    """경로에서 TDF 목록 수집. 파일이면 그 파일, 폴더면 하위까지 재귀."""
    p = Path(path)
    if p.is_file():
        return [p]
    if p.is_dir():
        return sorted(set(p.rglob('*.tdf')) | set(p.rglob('*.TDF')))
    return []


def process_tdf(tdf_path, dd_filter=None, verbose=True):
    """단일 TDF 안의 (필터에 맞는) 모든 .dd 를 파싱해 결과 리스트 반환"""
    results = []
    if not zipfile.is_zipfile(tdf_path):
        print(f"  ❌ ZIP(TDF) 형식 아님, 건너뜀: {tdf_path}")
        return results

    with zipfile.ZipFile(tdf_path, 'r') as zf:
        dd_files = [n for n in zf.namelist() if n.endswith('.dd')]
        if dd_filter:
            dd_files = [n for n in dd_files if dd_filter in n]

        for n in dd_files:
            raw = zf.read(n)
            res = parse_bytes(raw, name=n)
            res['tdf'] = str(tdf_path)
            results.append(res)
            if verbose:
                print_result(res)

    return results


def interpret_payload(hexstr):
    """payload hex 문자열을 여러 타입으로 해석해 '그럴듯한' 후보를 반환.

    미지 태그의 실제 타입을 역추적하기 위한 힌트 생성기.
    """
    import math
    b = bytes.fromhex(hexstr) if hexstr else b''
    out = {}
    if len(b) >= 1:
        out['int8'] = b[0]
        out['ascii1'] = chr(b[0]) if 0x20 <= b[0] <= 0x7e else None
    if len(b) >= 2:
        out['int16_le'] = struct.unpack('<h', b[:2])[0]
        out['int16_be'] = struct.unpack('>h', b[:2])[0]
    if len(b) >= 4:
        out['int32_le'] = struct.unpack('<i', b[:4])[0]
        out['int32_be'] = struct.unpack('>i', b[:4])[0]
        f = struct.unpack('>f', b[:4])[0]
        out['float32_be'] = f if math.isfinite(f) else None
    if len(b) >= 8:
        d = struct.unpack('>d', b[:8])[0]
        out['float64_be'] = d if math.isfinite(d) else None
    # ASCII 문자열로 보이는지
    printable = all(0x20 <= c <= 0x7e or c == 0 for c in b)
    if b and printable:
        out['as_string'] = b.split(b'\x00')[0].decode('ascii', 'replace')
    return {k: v for k, v in out.items() if v is not None}


def build_discovery_report(all_results):
    """전체 결과에서 미지 태그를 발굴 분석한 리포트(dict) 생성.

    태그별로:
      - 출현 횟수, payload 길이 분포(고정폭 여부 판단)
      - 직전 키 이름 예시(의미 힌트)
      - payload 를 여러 타입으로 해석한 후보
    """
    from collections import Counter, defaultdict

    tag_count = Counter()
    tag_lens = defaultdict(Counter)      # tag -> payload_len 분포
    tag_keys = defaultdict(list)         # tag -> 직전 키 예시
    tag_samples = defaultdict(list)      # tag -> payload_hex 예시

    tag_ctx = defaultdict(list)          # tag -> context_hex 예시
    for r in all_results:
        for tag_hex, cnt in r['unknown_tags'].items():
            tag = int(tag_hex, 16)
            tag_count[tag] += cnt
        for s in r.get('unknown_samples', []):
            tag = s['tag']
            if len(tag_ctx[tag]) < 6:
                tag_ctx[tag].append(s.get('context_hex', ''))

    report = {}
    for tag, cnt in tag_count.most_common():
        report[f'0x{tag:02x}'] = {
            'count': cnt,
            'context_samples_hex': tag_ctx[tag],
            'note': '스펙 미정의 또는 파싱 오정렬 위치 — context_hex 로 확인',
        }
    return report


def _guess_type(fixed, common_len, samples):
    """길이/샘플로 타입 1차 추정 (사람이 최종 확인용)"""
    if common_len == 0:
        return 'null 또는 마커(payload 없음)'
    if fixed and common_len == 1:
        return 'int8 / bool (1바이트 고정)'
    if fixed and common_len == 2:
        return 'int16 (2바이트 고정)'
    if fixed and common_len == 4:
        return 'int32 또는 float32 (4바이트 고정)'
    if fixed and common_len == 8:
        return 'int64 또는 float64 (8바이트 고정)'
    if not fixed:
        return '가변 길이 → 문자열/배열/구조체 가능성'
    return f'{common_len}바이트 고정 타입'


def print_discovery_report(report):
    print(f"\n{'='*70}")
    print("🔬 미지 타입 발굴 리포트")
    print(f"{'='*70}")
    if not report:
        print("미지 태그 없음 — 모든 바이트가 알려진 태그로 해석됨 🎉")
        return
    for tag_hex, info in report.items():
        print(f"\n● 태그 {tag_hex}  (총 {info['count']}회)  {info['note']}")
        for hx in info['context_samples_hex']:
            print(f"    ctx: {hx}")


def detect_format(raw):
    """`.dd` 형식 자동 감지 (스펙 §3). 반환: 'binary' | 'text'.

    1. 앞 4바이트가 매직(17 FA AE 4E) → binary
    2. NUL 바이트가 있고 출력가능문자 비율 < 85% → binary (매직 없는 변형 대비)
    3. 그 외 → text
    """
    if raw[:4] == MAGIC:
        return 'binary'
    if not raw:
        return 'text'
    if 0 in raw:
        printable = sum(1 for b in raw if 0x20 <= b <= 0x7e or b in (9, 10, 13))
        if printable / len(raw) < 0.85:
            return 'binary'
    return 'text'


def _run(args):
    """main() 의 실제 처리부 — 모드별 분기 (--raw / TDF 경로 / 스켈레톤 등)."""
    import json

    # ── 원시 .dd 하나를 직접 파싱 ──
    if args.raw:
        raw = Path(args.raw).read_bytes()
        fmt = detect_format(raw)
        print(f"[형식 감지: {fmt}]  {args.raw}")
        if fmt == 'text':
            print("  (텍스트 형식 — 바이너리 TLV 파서 대상 아님. 메모장 구조 그대로)")
            return
        if args.skeleton:
            print(extract_skeleton(raw))
            return
        if args.closers:
            print_closers(raw, name=args.raw)
            return
        res = parse_bytes(raw, name=args.raw)
        print_result(res)
        if args.output:
            Path(args.output).write_text(
                json.dumps(res, ensure_ascii=False, indent=2, default=str),
                encoding='utf-8')
            print(f"[JSON 저장: {args.output}]")
        return

    # ── 폴더/파일의 모든 TDF 처리 ──
    tdfs = find_tdf_files(args.path)
    if not tdfs:
        print(f"TDF(.tdf) 를 찾지 못함: {args.path}")
        return

    all_results = []
    for tdf in tdfs:
        results = process_tdf(tdf, dd_filter=args.dd, verbose=not args.quiet
                              and not args.discover)
        all_results.extend(results)
        if args.per_tdf_json:
            out = Path(tdf).with_suffix('.json')
            out.write_text(json.dumps(results, ensure_ascii=False, indent=2,
                                      default=str), encoding='utf-8')
            print(f"[JSON 저장: {out}]")

    if args.discover:
        report = build_discovery_report(all_results)
        print_discovery_report(report)
        if args.discover_json:
            Path(args.discover_json).write_text(
                json.dumps(report, ensure_ascii=False, indent=2, default=str),
                encoding='utf-8')
            print(f"[발굴 리포트 저장: {args.discover_json}]")

    if args.output:
        Path(args.output).write_text(
            json.dumps(all_results, ensure_ascii=False, indent=2, default=str),
            encoding='utf-8')
        print(f"\n[통합 JSON 저장: {args.output}  ({len(all_results)}개 .dd)]")


def main():
    import argparse
    ap = argparse.ArgumentParser(
        description='.dd 태그 기반 바이너리 파서 (폴더 내 모든 TDF 처리)')
    ap.add_argument('path', nargs='?', default='.',
                    help='TDF 파일 또는 폴더 경로 (기본: 현재 폴더의 모든 .tdf)')
    ap.add_argument('--dd', help='파싱할 .dd 이름 필터(부분일치)')
    ap.add_argument('--raw', help='압축 해제된 원시 .dd 파일 하나를 직접 파싱')
    ap.add_argument('-o', '--output', help='통합 결과 JSON 저장 경로')
    ap.add_argument('--per-tdf-json', action='store_true',
                    help='TDF 별로 <tdf이름>.json 을 각각 저장')
    ap.add_argument('-q', '--quiet', action='store_true',
                    help='필드 상세 출력 생략(요약만)')
    ap.add_argument('--discover', action='store_true',
                    help='미지 타입 발굴 리포트만 집중 출력(파일별 상세 생략)')
    ap.add_argument('--discover-json', help='발굴 리포트를 JSON 으로 저장할 경로')
    ap.add_argument('--skeleton', action='store_true',
                    help='구조({ [ , key)만 복원하고 값은 placeholder 로 남긴 스켈레톤 출력')
    ap.add_argument('--closers', action='store_true',
                    help='닫는 마커 후보 탐지(값 끝~다음 키 사이 갭 바이트 분포)')
    ap.add_argument('-s', '--save',
                    help='화면 출력 전체를 텍스트 파일로도 저장(스켈레톤/닫는마커 결과 포함)')
    args = ap.parse_args()

    # -s/--save 지정 시 화면+파일 동시 출력(Tee). 모든 모드의 출력을 파일로 남김.
    _logfile = None
    if args.save:
        _logfile = open(args.save, 'w', encoding='utf-8')
        sys.stdout = Tee(sys.stdout, _logfile)
        print(f"[출력 저장: {Path(args.save).resolve()}]")

    try:
        _run(args)
    finally:
        if _logfile:
            print(f"\n출력 저장 완료: {Path(args.save).resolve()}")
            sys.stdout = sys.stdout.stream
            _logfile.close()


if __name__ == '__main__':
    main()
