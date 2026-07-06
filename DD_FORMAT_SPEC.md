# .dd 파일 포맷 명세 (rule)

ASML ID dump(`.tdf`) 안에 들어있는 `.dd` 파일의 구조 규칙 정리.
`.tdf` 는 **ZIP 아카이브**이며 그 안에 다수의 `.dd` 파일이 들어있다.

`.dd` 는 **두 가지 형식**이 섞여 존재한다.

---

## 1. 바이너리 TLV 형식

### 1.1 전체 레이아웃

```
+------------------+
| MAGIC (4 bytes)  |  17 FA AE 4E
+------------------+
| STRUCT (0x0B)    |  최상위 구조체 시작
|   ...필드들...    |
| END (0x00)       |  최상위 구조체 종료
+------------------+
| TRAILER (4 bytes)|  체크섬 추정 (예: BC 94 26 A8)
+------------------+
```

- 파일은 `17 FA AE 4E` 매직으로 시작한다.
- 파일 끝 **4바이트는 트레일러(체크섬 추정)** 이며 구조에서 제외한다.

### 1.2 TLV 필드 구조

각 필드는 다음 순서로 구성된다:

```
+----------+-----------------+----------+------------+
|  Type    |  Name           |  SubType |  Value     |
| (1 byte) | (string, NUL종료)| (1 byte) | (가변)      |
+----------+-----------------+----------+------------+
```

- **Type** = `0x09`(STRING) : 필드가 "이름"으로 시작함을 의미
- **Name** = NUL(`0x00`) 종료 ASCII 문자열 (필드명)
- **SubType** = 값의 타입 (아래 타입 표)
- **Value** = SubType 에 따른 값 (스칼라/문자열/컨테이너)

컨테이너(ARRAY/STRUCT)는 자식 필드들을 담고 **END(`0x00`)** 로 닫힌다.

### 1.3 타입 태그 표

| 태그 | 이름 | 크기 | 값 인코딩 |
|------|------|------|-----------|
| `0x00` | END | - | 블록(컨테이너) 종료 |
| `0x01` | INT8_A | 1B | 부호있는 8비트 정수 |
| `0x02` | INT8_B | 1B | 부호있는 8비트 정수 (실측 재확인: 기존 INT16/2B 표기가 오류, 1B) |
| `0x03` | UINT8 | 1B | 부호없는 8비트 정수 |
| `0x04` | INT8_C | 1B | 부호있는 8비트 정수 (실측 재확인: 기존 INT32/4B 표기가 오류, 1B) |
| `0x05` | ENUM | 2B | 열거형 (int16 로 저장, big-endian) — 배열 원소로 반복 관측 |
| `0x06` | BOOL | 4B | 고정 4바이트 값(int32) — `"TRUE"`/`"FALSE"` 문자열이 아님 |
| `0x07` | FLOAT32 | 4B | IEEE754 단정도 (big-endian) |
| `0x08` | FLOAT64 | 8B | IEEE754 배정도 (big-endian) |
| `0x09` | STRING | 가변 | NUL 종료 문자열 |
| `0x0A` | ARRAY | 가변 | 배열, END 로 닫힘 |
| `0x0B` | STRUCT | 가변 | 중첩 구조체, END 로 닫힘 |

> **주의(2026-07-07 정정)**: `0x02`/`0x04`는 과거 INT16(2B)/INT32(4B)로 문서화됐으나
> 실측 재확인 결과 각각 **1바이트** 정수다. 태그 이름을 크기에 맞춰
> `INT8_B`/`INT8_C`로 변경했다 — 셋 다 8비트 정수라는 뜻이며, `0x01`과의 의미
> 차이(왜 세 개나 있는지)는 아직 불명확하다(§4 참고).

> **주의**: 모든 다바이트 수치는 **big-endian** 이다.

> **주의(실측 확인)**: 스칼라 SubType(`0x01~0x08`) 뒤에 고정폭 payload가 항상
> 오는 건 아니다. 값이 `0`/`FALSE`(예: 미사용 detector 슬롯의
> `nr_of_used_samples` 등)일 때는 **payload 전체가 생략**되고, SubType 태그
> 바로 뒤에 다음 필드의 `Name`(`0x09` + 식별자 + NUL)이 곧바로 이어진다.
> 이걸 모르고 고정폭을 그대로 소비하면 다음 필드 이름을 삼켜 디싱크가
> 발생한다. 파서는 SubType 뒤에 다음 필드 앵커(`0x09`+식별자+NUL)가 바로
> 보이면 payload를 소비하지 않고 값 `0`으로 처리한다 (자세한 내용은
> §4 참고).

### 1.4 예시 (실측)

hex:
```
17 fa ae 4e 0b 09 "IFEUCM_machine_configuration_struct" 00
   0b 09 "lens_magnification" 00 08 3f d0 00 00 00 00 00 00
      09 "if_sim_mode" 00 09 "SIM_DISABLED" 00
      09 "hw_timestamp_transmission" 00 09 "TRUE" 00
   00 00
bc 94 26 a8
```

파싱 결과:
```json
{
  "IFEUCM_machine_configuration_struct": {
    "lens_magnification": 0.25,
    "if_sim_mode": "SIM_DISABLED",
    "hw_timestamp_transmission": "TRUE"
  }
}
```

---

## 2. 텍스트 형식

메모장으로 열면 사람이 읽을 수 있는 중첩 구조 텍스트.

```
{
  IFXATA_STRUCT = {
    logn_id = 2,
    phys_id = 5,
    detector = [
      { name = TRUE, intensities = [1, 2, 3] },
      { name = FALSE, vals = [] }
    ],
    empty = {}
  }
}
```

### 문법 (BNF 유사)

```
value  := struct | array | scalar
struct := '{' ( member (',' member)* )? ','? '}'
member := KEY '=' value
array  := '[' ( value (',' value)* )? ']'
scalar := number | TRUE | FALSE | <undef> | "quoted" | bareword
```

- `=` 앞뒤 공백은 무관 (`phys_id =5` 도 허용)
- 스칼라 타입 변환: 정수/실수(1.0e-3 포함)/불리언/`<undef>`→null/문자열
- 빈 구조체 `{}`, 빈 배열 `[]` 허용
- 배열 원소로 구조체 가능

---

## 3. 형식 자동 감지 규칙

`dd_main.py` 의 `detect_format()` 판정:

1. 앞 4바이트가 매직(`17 FA AE 4E`) → **바이너리**
2. NUL 바이트가 있고 출력가능문자 비율 < 85% → **바이너리** (매직 없는 변형 대비)
3. 그 외 → **텍스트**

---
