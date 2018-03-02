
; SHA256.asm

.DATA?

.CONST
SHUFFLE_BYTE_FLIP_MASK DD 0C0D0E0FH, 08090A0BH, 04050607H, 00010203H
; SHA256 constants
K256    DD   428A2F98H,  71374491H, 0B5C0FBCFH, 0E9B5DBA5H,  3956C25BH,  59F111F1H,  923F82A4H, 0AB1C5ED5H
        DD  0D807AA98H,  12835B01H,  243185BEH,  550C7DC3H,  72BE5D74H,  80DEB1FEH,  9BDC06A7H, 0C19BF174H
        DD  0E49B69C1H, 0EFBE4786H,  0FC19DC6H,  240CA1CCH,  2DE92C6FH,  4A7484AAH,  5CB0A9DCH,  76F988DAH
        DD   983E5152H, 0A831C66DH, 0B00327C8H, 0BF597FC7H, 0C6E00BF3H, 0D5A79147H,  06CA6351H,  14292967H
        DD   27B70A85H,  2E1B2138H,  4D2C6DFCH,  53380D13H,  650A7354H,  766A0ABBH,  81C2C92EH,  92722C85H
        DD  0A2BFE8A1H, 0A81A664BH, 0C24B8B70H, 0C76C51A3H, 0D192E819H, 0D6990624H, 0F40E3585H,  106AA070H
        DD   19A4C116H,  1E376C08H,  2748774CH,  34B0BCB5H,  391C0CB3H,  4ED8AA4AH,  5B9CCA4FH,  682E6FF3H
        DD   748F82EEH,  78A5636FH,  84C87814H,  8CC70208H,  90BEFFFAH, 0A4506CEBH, 0BEF9A3F7H, 0C67178F2H

MSG_SEG SEGMENT ALIGN(32) 'DATA'
MSG DD 61626380H ; 0
    DD 00000000H ; 1
    DD 00000000H ; 2
    DD 00000000H ; 3
    DD 00000000H ; 4
    DD 00000000H ; 5
    DD 00000000H ; 6
    DD 00000000H ; 7
    DD 00000000H ; 8
    DD 00000000H ; 9
    DD 00000000H ; 10
    DD 00000000H ; 11
    DD 00000000H ; 12
    DD 00000000H ; 13
    DD 00000000H ; 14
    DD 00000018H ; 15
MSG_SEG ENDS

.code
; initial hash value
H0      EQU     6A09E667H
H1      EQU    0BB67AE85H
H2      EQU     3C6EF372H
H3      EQU    0A54FF53AH
H4      EQU     510E527FH
H5      EQU     9B05688CH
H6      EQU     1F83D9ABH
H7      EQU     5BE0CD19H

; Perform the SHA-256 Ch calculation:
;   Ch(e, f, g) = (e(f^g))^g
CHO MACRO e, f, g
    MOV EDX, f
    XOR EDX, g
    AND e, EDX
    XOR e, g
ENDM

; Performs the SHA-256 Maj calculation
; Maj = a(b^c)+bc


; Performs the SHA-256 Sigma0 calculation
; Sigma0 = ROTR2^ROTR13^ROTR22
SIGMA0 MACRO
    MOV ECX, EAX
    ROR ECX, 2
    MOV EDX, ECX
    ROR ECX, 11 ; 13 - 2
    XOR EDX, ECX
    ROR ECX, 9 ; 22 - 13
    XOR ECX, EDX
ENDM

; Performs the SHA-256 Sigma1 calculation
; Sigma1 = ROTR6^ROTR11^ROTR25
SIGMA1 MACRO
    MOV ECX, EBX
    ROR ECX, 6
    MOV EDX, ECX
    ROR ECX, 5 ; 11 - 6
    XOR EDX, ECX
    ROR ECX, 14 ; 25 - 11
    XOR ECX, EDX
ENDM

UPDATE_T1 MACRO h, Sigma1, Ch, K, W
    ADD Sigma1, h
    ADD Sigma1, K
    ADD Sigma1, Ch
    ADD Sigma1, W
ENDM

UPDATE_T2 MACRO Sigma0, Maj
    ADD Maj, Sigma0
ENDM

UPDATE_E MACRO d, T1
    MOV EBX, d
    ADD EBX, T1
    MOV d, EBX
ENDM

UPDATE_A MACRO T1, T2, a
    ADD T2, T1
    MOV a, T2
ENDM

; Function sigma_0
; Performs the SHA-256 sigma 0 calculation

SCHEDULE MACRO W0, W1, W9, W14
    ; sigma_0
    MOV ECX, W1
    MOV EDX, ECX
    SHR ECX, 3
    ROR EDX, 7
    XOR ECX, EDX
    ROR EDX, 11 ; 18 - 7
    XOR ECX, EDX
    ; sigma_1
    MOV EDX, W14
    MOV ESI, EDX
    SHR EDX, 10
    ROR ESI, 17
    XOR EDX, ESI
    ROR ESI, 2 ; 19 - 17
    XOR EDX, ESI
    ; sum
    ADD ECX, W0
    ADD ECX, W9
    ADD ECX, EDX
    MOV W0, ECX
ENDM


ROUND_AND_KW MACRO a, b, c, d, e, f, g, h, r
    VMOVDQA X0, YMMWORD PTR [MSG + 0 * 32]
    RORX    S1, e, 6                ; S1 = e>>>6
    RORX    S1T, e, 11              ; S1T = e>>>11
    RORX    S0, a, 2                ; S0 = a>>>2
    RORX    S0T, a, 13              ; S0T = a>>>13
    MOV     CHS, f                  ; CHS = f
    MOV     MAJ, a                  ; MAJ = a
    MOV     MAJT, a                 ; MAJT = a
    
    VPADDD  X0, X0, YMMWORD PTR [K256 + 0 * 32]
    XOR     S1, S1T                 ; S1 = (e>>>6) ^ (e>>>11)
    XOR     S0, S0T                 ; S0 = (a>>>2) ^ (a>>>13)
    XOR     CHS, g                  ; CHS = f^g
    OR      MAJ, b                  ; MAJ = a|b
    AND     MAJT, b                 ; MAJT = a&b

    VMOVDQA YMMWORD PTR [MSG + 0 * 32], X0
    RORX    S1T, e, 25              ; S1T = e>>>25
    RORX    S0T, a, 22              ; S0T = a>>>22
    AND     CHS, e                  ; CHS = (f^g)&e
    AND     MAJ, c                  ; MAJ = (a|b)&c
    
    ADD     h, [MSG + r * 4]        ; a := h = h + K + W
    XOR     S1, S1T                 ; S1 = (e>>>6) ^ (e>>>11) ^ (e>>>25)
    XOR     CHS, g                  ; CHS = ((f^g)&e)^g
    XOR     S0, S0T                 ; S0 = (a>>>2) ^ (a>>>13) ^ (a>>>22)
    OR      MAJ, MAJT               ; MAJ = ((a|b)&c)|(a&b)
    
    ADD     S1, CHS                 ; S1 = Sigma1 + Ch
    ADD     S0, MAJ                 ; S0 = Sigma0 + Maj

    ADD     h, S1                   ; a := h = h + Sigma1 + Ch + K + W
    
    ADD     d, h                    ; d := d = d + (h + Sigma1 + Ch + K + W)
    ADD     h, S0                   ; a := h = (h + Sigma1 + Ch + K + W) + (Sigma0 + Maj)
ENDM

ROUND MACRO a, b, c, d, e, f, g, h, r
    RORX    S1, e, 6                ; S1 = e>>>6
    RORX    S1T, e, 11              ; S1T = e>>>11
    RORX    S0, a, 2                ; S0 = a>>>2
    RORX    S0T, a, 13              ; S0T = a>>>13
    MOV     CHS, f                  ; CHS = f
    MOV     MAJ, a                  ; MAJ = a
    MOV     MAJT, a                 ; MAJT = a
    
    XOR     S1, S1T                 ; S1 = (e>>>6) ^ (e>>>11)
    XOR     S0, S0T                 ; S0 = (a>>>2) ^ (a>>>13)
    XOR     CHS, g                  ; CHS = f^g
    OR      MAJ, b                  ; MAJ = a|b
    AND     MAJT, b                 ; MAJT = a&b

    RORX    S1T, e, 25              ; S1T = e>>>25
    RORX    S0T, a, 22              ; S0T = a>>>22
    AND     CHS, e                  ; CHS = (f^g)&e
    AND     MAJ, c                  ; MAJ = (a|b)&c
    
    ADD     h, [MSG + r * 4]        ; a := h = h + K + W
    XOR     S1, S1T                 ; S1 = (e>>>6) ^ (e>>>11) ^ (e>>>25)
    XOR     CHS, g                  ; CHS = ((f^g)&e)^g
    XOR     S0, S0T                 ; S0 = (a>>>2) ^ (a>>>13) ^ (a>>>22)
    OR      MAJ, MAJT               ; MAJ = ((a|b)&c)|(a&b)
    
    ADD     S1, CHS                 ; S1 = Sigma1 + Ch
    ADD     S0, MAJ                 ; S0 = Sigma0 + Maj

    ADD     h, S1                   ; a := h = h + Sigma1 + Ch + K + W
    
    ADD     d, h                    ; d := d = d + (h + Sigma1 + Ch + K + W)
    ADD     h, S0                   ; a := h = (h + Sigma1 + Ch + K + W) + (Sigma0 + Maj)
ENDM

a   EQU     EAX
b   EQU     EBX
c   EQU     ECX
d   EQU     EDX
e   EQU     ESI
f   EQU     EDI
g   EQU     R8D
h   EQU     R9D

X0  EQU     YMM0
X1  EQU     YMM1
X2  EQU     YMM2
X3  EQU     YMM3

Y0  EQU     YMM4
Y1  EQU     YMM5
Y2  EQU     YMM6
Y3  EQU     YMM7

T0  EQU     R10D
T1  EQU     R11D
T2  EQU     R12D
T3  EQU     R13D
T4  EQU     R14D
T5  EQU     R15D

S0      EQU     R10D    ; Sigma0
S0T     EQU     R11D    ; Sigma0
S1      EQU     R12D    ; Sigma1
S1T     EQU     R13D    ; Sigma1
CHS     EQU     R14D    ; Ch
MAJ     EQU     R15D
MAJT    EQU     EBP

SHA256D PROC

    ;;MOV EAX, SHUFFLE_BYTE_FLIP_MASK
    ;MOVDQA   XMM1, XMMWORD PTR [SHUFFLE_BYTE_FLIP_MASK]
    ;VPALIGNR     YMM1, YMM7, YMM6, 4
    ;PSHUFB XMM3, XMM2
    ;;PUSHAD
    ;RDTSC
    ;;PUSH EAX
    ;;PUSH EDX
    ; t = 0, a0 := a(H0), b0 := b(H1), c0 := c(H2), d0 := d(H3), e0 := e(H4), f0 := f(H5), g0 := g(H6), h0 := h(H7)
    a0  EQU     H0
    b0  EQU     H1
    c0  EQU     H2
    d0  EQU     H3
    e0  EQU     H4
    f0  EQU     H5
    g0  EQU     H6
    h0_ EQU     H7
    Sigma00 = ((a0 SHR 2) OR (a0 SHL 30)) XOR ((a0 SHR 13) OR (a0 SHL 19)) XOR ((a0 SHR 22) OR (a0 SHL 10))
    Sigma10 = ((e0 SHR 6) OR (e0 SHL 26)) XOR ((e0 SHR 11) OR (e0 SHL 21)) XOR ((e0 SHR 25) OR (e0 SHL 7))
    Ch0 = ((f0 XOR g0) AND e0) XOR g0   ; CHS = ((f^g)&e)^g
    Maj0 = ((a0 OR b0) AND c0) OR (a0 AND b0)    ; MAJ = ((a|b)&c)|(a&b)
    
    VMOVDQA X0, YMMWORD PTR [MSG + 0 * 32]

    MOV     d, LOW32(d0 + h0_ + Sigma10 + Ch0)    ; e := d = d + (h + Sigma1 + Ch)
    
    VPADDD  X0, X0, YMMWORD PTR [K256 + 0 * 32]

    MOV     h, LOW32(h0_ + Sigma10 + Ch0 + Sigma00 + Maj0)   ; a := h = (h + Sigma1 + Ch) + (Sigma0 + Maj)

    VMOVDQA YMMWORD PTR [MSG + 0 * 32], X0

    ADD     d, [MSG + 0 * 4]    ; e := d = d + (K + W + h + Sigma1 + Ch)
    ADD     h, [MSG + 0 * 4]    ; a := h = (K + W + h + Sigma1 + Ch) + (Sigma0 + Maj)

    ; t = 1, a1 := h, b1 := a(H0), c1 := b(H1), d1 := c(H2), e1 := d, f1 := e(H4), g1 := f(H5), h1 := g(H6)
    a1  EQU     h
    b1  EQU     H0
    c1  EQU     H1
    d1  EQU     H2
    e1  EQU     d
    f1  EQU     H4
    g1  EQU     H5
    h1_ EQU     H6
    RORX    S1, e1, 6               ; S1 = e>>>6
    RORX    S1T, e1, 11             ; S1T = e>>>11
    RORX    S0, a1, 2               ; S0 = a>>>2
    RORX    S0T, a1, 13             ; S0T = a>>>13
    MOV     CHS, f1 XOR g1          ; CHS = f^g
    MOV     MAJ, b1 OR c1           ; MAJ = b|c
    MOV     MAJT, b1 AND c1         ; MAJT = b&c

    MOV     g, [MSG + 1 * 4]        ; a := g = K + W
    XOR     S1, S1T                 ; S1 = (e>>>6) ^ (e>>>11)
    XOR     S0, S0T                 ; S0 = (a>>>2) ^ (a>>>13)
    AND     CHS, e                  ; CHS = (f^g)&e
    AND     MAJ, a                  ; MAJ = (b|c)&a

    MOV     b, LOW32(d1 + h1_)      ; d := b = d + h
    RORX    S1T, e1, 25             ; S1T = e>>>25
    RORX    S0T, a1, 22             ; S0T = a>>>22
    XOR     CHS, g1                 ; CHS = ((f^g)&e)^g
    OR      MAJ, MAJT               ; MAJ = ((b|c)&a)|(b&c)
    
    XOR     S1, S1T                 ; S1 = (e>>>6) ^ (e>>>11) ^ (e>>>25)
    XOR     S0, S0T                 ; S0 = (a>>>2) ^ (a>>>13) ^ (a>>>22)
    
    ADD     S1, CHS                 ; S1 = Sigma1 + Ch
    ADD     S0, MAJ                 ; S0 = Sigma0 + Maj

    ADD     g, S1                   ; a := g = Sigma1 + Ch + K + W
    ADD     S0, h1_                 ; S0 = h + Sigma0 + Maj

    ADD     b, g                    ; d := b = d + (h + Sigma1 + Ch + K + W)
    ADD     g, S0                   ; a := g = (h + Sigma1 + Ch + K + W) + (Sigma0 + Maj)
NOP
    ; t = 2, a2 := g, b2 := h, c2 := a(H0), d2 := b(H1), e2 := c, f2 := d, g2 := e(H4), h2 := f(H5)
    a2  EQU     g
    b2  EQU     h
    c2  EQU     H0
    d2  EQU     H1
    e2  EQU     c
    f2  EQU     d
    g2  EQU     H4
    h2_ EQU     H5
    RORX    S1, e, 6                ; S1 = e>>>6
    RORX    S1T, e, 11              ; S1T = e>>>11
    RORX    S0, a, 2                ; S0 = a>>>2
    RORX    S0T, a, 13              ; S0T = a>>>13
    MOV     CHS, f                  ; CHS = f
    MOV     MAJ, a                  ; MAJ = a
    MOV     MAJT, a                 ; MAJT = a

    MOV     f, [MSG + 2 * 4]        ; a := f = K + W
    XOR     S1, S1T                 ; S1 = (e>>>6) ^ (e>>>11)
    XOR     S0, S0T                 ; S0 = (a>>>2) ^ (a>>>13)
    XOR     CHS, g2                 ; CHS = f^g
    OR      MAJ, b                  ; MAJ = a|b
    AND     MAJT, b                 ; MAJT = a&b

    MOV     a, LOW32(d2 + h2_)      ; d := a = d + h
    RORX    S1T, e, 25              ; S1T = e>>>25
    RORX    S0T, a, 22              ; S0T = a>>>22
    AND     CHS, e                  ; CHS = (f^g)&e
    AND     MAJ, c2                 ; MAJ = (a|b)&c

    XOR     S1, S1T                 ; S1 = (e>>>6) ^ (e>>>11) ^ (e>>>25)
    XOR     S0, S0T                 ; S0 = (a>>>2) ^ (a>>>13) ^ (a>>>22)
    XOR     CHS, g2                 ; CHS = ((f^g)&e)^g
    OR      MAJ, MAJT               ; MAJ = ((a|b)&c)|(a&b)

    ADD     S1, CHS                 ; S1 = Sigma1 + Ch
    ADD     S0, MAJ                 ; S0 = Sigma0 + Maj

    ADD     f, S1                   ; a := f = Sigma1 + Ch + K + W
    ADD     S0, h2_                 ; S0 = h + Sigma0 + Maj

    ADD     a, f                    ; d := a = d + (h + Sigma1 + Ch + K + W)
    ADD     f, S0                   ; a := f = (h + Sigma1 + Ch + K + W) + (Sigma0 + Maj)
NOP
    ; t = 3, a3 := f, b3 := g, c3 := h, d3 := a(H0), e3 := b, f3 := c, g3 := d, h3 := e(H4)
    a3  EQU     f
    b3  EQU     g
    c3  EQU     h
    d3  EQU     H0
    e3  EQU     b
    f3  EQU     c
    g3  EQU     d
    h3_ EQU     H4
    RORX    S1, e3, 6               ; S1 = e>>>6
    RORX    S1T, e3, 11             ; S1T = e>>>11
    RORX    S0, a3, 2               ; S0 = a>>>2
    RORX    S0T, a3, 13             ; S0T = a>>>13
    MOV     CHS, f3                 ; CHS = f
    MOV     MAJ, a3                 ; MAJ = a
    MOV     MAJT, a3                ; MAJT = a

    MOV     e, [MSG + 2 * 4]        ; a := e = K + W
    XOR     S1, S1T                 ; S1 = (e>>>6) ^ (e>>>11)
    XOR     S0, S0T                 ; S0 = (a>>>2) ^ (a>>>13)
    XOR     CHS, g3                 ; CHS = f^g
    OR      MAJ, b3                 ; MAJ = a|b
    AND     MAJT, b3                ; MAJT = a&b
    
    MOV     h, LOW32(d3 + h3_)      ; d := h = d + h
    RORX    S1T, e3, 25             ; S1T = e>>>25
    RORX    S0T, a3, 22             ; S0T = a>>>22
    AND     CHS, e3                 ; CHS = (f^g)&e
    AND     MAJ, c3                 ; MAJ = (a|b)&c

    XOR     S1, S1T                 ; S1 = (e>>>6) ^ (e>>>11) ^ (e>>>25)
    XOR     S0, S0T                 ; S0 = (a>>>2) ^ (a>>>13) ^ (a>>>22)
    XOR     CHS, g3                 ; CHS = ((f^g)&e)^g
    OR      MAJ, MAJT               ; MAJ = ((a|b)&c)|(a&b)

    ADD     S1, CHS                 ; S1 = Sigma1 + Ch
    ADD     S0, MAJ                 ; S0 = Sigma0 + Maj

    ADD     e, S1                   ; a := e = Sigma1 + Ch + K + W
    ADD     S0, h3_                 ; S0 = h + Sigma0 + Maj

    ADD     h, e                    ; d := h = d + (h + Sigma1 + Ch + K + W)
    ADD     e, S0                   ; a := e = (h + Sigma1 + Ch + K + W) + (Sigma0 + Maj)
NOP

    ; t = 4, a4 := e, b4 := f, c4 := g, d4 := h, e4 := a, f4 := b, g4 := c, h4 := d
    
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SF, SG
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SB, SC
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SD, ECX, EBX, K4, W4
    ;; e = d + T1
    ;UPDATE_E SH, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SD

    ;; t = 5, a5 := d, b5 := e, c5 := f, d5 := g, e5 := h, f5 := a, g5 := b, h5 := c
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SE, SF
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SA, SB
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SC, ECX, EBX, K5, W5
    ;; e = d + T1
    ;UPDATE_E SG, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SC
;
    ;; t = 6, a6 := c, b6 := d, c6 := e, d6 := f, e6 := g, f6 := h, g6 := a, h6 := b
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SD, SE
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SH, SA
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SB, ECX, EBX, K6, W6
    ;; e = d + T1
    ;UPDATE_E SF, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SB
;
    ;; t = 7, a7 := b, b7 := c, c7 := d, d7 := e, e7 := f, f7 := g, g7 := h, h7 := a
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SC, SD
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SG, SH
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SA, ECX, EBX, K7, W7
    ;; e = d + T1
    ;UPDATE_E SE, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SA
;
    ; t = 8, a8 := a, b7 := b, c8 := c, d8 := d, e8 := e, f8 := f, g8 := g, h8 := h
    
    ;
    ;
;START_MARKER
MOV EBX, 111
DB 64H, 67H, 90H

    VMOVDQA X0, YMMWORD PTR [MSG + 0 * 32]
    RORX    S1, e, 6                ; S1 = e>>>6
    RORX    S1T, e, 11              ; S1T = e>>>11
    RORX    S0, a, 2                ; S0 = a>>>2
    RORX    S0T, a, 13              ; S0T = a>>>13
    MOV     CHS, f                  ; CHS = f
    MOV     MAJ, a                  ; MAJ = a
    MOV     MAJT, a                 ; MAJT = a
    
    VPADDD  X0, X0, YMMWORD PTR [K256 + 0 * 32]
    XOR     S1, S1T                 ; S1 = (e>>>6)^(e>>>11)
    XOR     S0, S0T                 ; S0 = (a>>>2)^(a>>>13)
    XOR     CHS, g                  ; CHS = f^g
    OR      MAJ, b                  ; MAJ = a|b
    AND     MAJT, b                 ; MAJT = a&b

    VMOVDQA YMMWORD PTR [MSG + 0 * 32], X0
    RORX    S1T, e, 25              ; S1T = e>>>25
    RORX    S0T, a, 22              ; S0T = a>>>22
    AND     CHS, e                  ; CHS = (f^g)&e
    AND     MAJ, c                  ; MAJ = (a|b)&c
    
    ADD     h, [MSG + 4 * 4]        ; h = K+W+h
    XOR     S1, S1T                 ; S1 = (e>>>6)^(e>>>11)^(e>>>25)
    XOR     CHS, g                  ; CHS = ((f^g)&e)^g
    XOR     S0, S0T                 ; S0 = (a>>>2)^(a>>>13)^(a>>>22)
    OR      MAJ, MAJT               ; MAJ = ((a|b)&c)|(a&b)
    
    ADD     S1, CHS                 ; S1 = Sigma1+Ch
    ADD     S0, MAJ                 ; S0 = Sigma0+Maj

    ADD     h, S1                   ; h = K+W+h+Sigma1+Ch
    
    ADD     d, h                    ; d = d+(K+W+h+Sigma1+Ch)
    ADD     h, S0                   ; h = (K+W+h+Sigma1+Ch)+Sigma0+Maj
;END_MARKER
MOV EBX, 222
DB 64H, 67H, 90H
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SB, SC
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SF, SG
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SH, ECX, EBX, K8, W8
    ;; e = d + T1
    ;UPDATE_E SD, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SH
;
    ;; t = 9, a9 := h, b9 := a, c9 := b, d9 := c, e9 := d, f9 := e, g9 := f, h9 := g
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SA, SB
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SE, SF
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SG, ECX, EBX, K9, W9
    ;; e = d + T1
    ;UPDATE_E SC, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SG
;
    ;; t = 10, a10 := g, b10 := h, c10 := a, d10 := b, e10 := c, f10 := d, g10 := e, h10 := f
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SH, SA
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SD, SE
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SF, ECX, EBX, K10, W10
    ;; e = d + T1
    ;UPDATE_E SB, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SF
;
    ;; t = 11, a11 := f, b11 := g, c11 := h, d11 := a, e11 := b, f11 := c, g11 := d, h11 := e
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SG, SH
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SC, SD
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SE, ECX, EBX, K11, W11
    ;; e = d + T1
    ;UPDATE_E SA, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SE
;
    ;; t = 12, a12 := e, b12 := f, c12 := g, d12 := h, e12 := a, f12 := b, g12 := c, h12 := d
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SF, SG
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SB, SC
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SD, ECX, EBX, K12, W12
    ;; e = d + T1
    ;UPDATE_E SH, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SD
;
    ;; t = 13, a13 := d, b13 := e, c13 := f, d13 := g, e13 := h, f13 := a, g13 := b, h13 := c
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SE, SF
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SA, SB
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SC, ECX, EBX, K13, W13
    ;; e = d + T1
    ;UPDATE_E SG, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SC
;
    ;; t = 14, a14 := c, b14 := d, c14 := e, d14 := f, e14 := g, f14 := h, g14 := a, h14 := b
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SD, SE
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SH, SA
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SB, ECX, EBX, K14, W14
    ;; e = d + T1
    ;UPDATE_E SF, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SB
;
    ;; t = 15, a15 := b, b15 := c, c15 := d, d15 := e, e15 := f, f15 := g, g15 := h, h15 := a
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SC, SD
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SG, SH
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SA, ECX, EBX, K15, W15
    ;; e = d + T1
    ;UPDATE_E SE, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SA
;
    ;; t = 16, a16 := a, b7 := b, c16 := c, d16 := d, e16 := e, f16 := f, g16 := g, h16 := h
    ;SCHEDULE W0, W1, W9, W14
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SB, SC
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SF, SG
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SH, ECX, EBX, K16, W0
    ;; e = d + T1
    ;UPDATE_E SD, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SH
    ;
    ;; t = 17, a17 := h, b17 := a, c17 := b, d17 := c, e17 := d, f17 := e, g17 := f, h17 := g
    ;SCHEDULE W1, W2, W10, W15
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SA, SB
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SE, SF
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SG, ECX, EBX, K17, W1
    ;; e = d + T1
    ;UPDATE_E SC, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SG
;
    ;; t = 18, a18 := g, b18 := h, c18 := a, d18 := b, e18 := c, f18 := d, g18 := e, h18 := f
    ;SCHEDULE W2, W3, W11, W0
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SH, SA
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SD, SE
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SF, ECX, EBX, K18, W2
    ;; e = d + T1
    ;UPDATE_E SB, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SF
;
    ;; t = 19, a19 := f, b19 := g, c19 := h, d19 := a, e19 := b, f19 := c, g19 := d, h19 := e
    ;SCHEDULE W3, W4, W12, W1
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SG, SH
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SC, SD
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SE, ECX, EBX, K19, W3
    ;; e = d + T1
    ;UPDATE_E SA, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SE
;
    ;; t = 20, a20 := e, b20 := f, c20 := g, d20 := h, e20 := a, f20 := b, g20 := c, h20 := d
    ;SCHEDULE W4, W5, W13, W2
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SF, SG
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SB, SC
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SD, ECX, EBX, K20, W4
    ;; e = d + T1
    ;UPDATE_E SH, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SD
;
    ;; t = 21, a21 := d, b21 := e, c21 := f, d21 := g, e21 := h, f21 := a, g21 := b, h21 := c
    ;SCHEDULE W5, W6, W14, W3
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SE, SF
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SA, SB
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SC, ECX, EBX, K21, W5
    ;; e = d + T1
    ;UPDATE_E SG, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SC
;
    ;; t = 22, a22 := c, b22 := d, c22 := e, d22 := f, e22 := g, f22 := h, g22 := a, h22 := b
    ;SCHEDULE W6, W7, W15, W4
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SD, SE
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SH, SA
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SB, ECX, EBX, K22, W6
    ;; e = d + T1
    ;UPDATE_E SF, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SB
;
    ;; t = 23, a23 := b, b23 := c, c23 := d, d23 := e, e23 := f, f23 := g, g23 := h, h23 := a
    ;SCHEDULE W7, W8, W0, W5
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SC, SD
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SG, SH
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SA, ECX, EBX, K23, W7
    ;; e = d + T1
    ;UPDATE_E SE, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SA
;
    ;; t = 24, a24 := a, b7 := b, c24 := c, d24 := d, e24 := e, f24 := f, g24 := g, h24 := h
    ;SCHEDULE W8, W9, W1, W6
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SB, SC
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SF, SG
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SH, ECX, EBX, K24, W8
    ;; e = d + T1
    ;UPDATE_E SD, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SH
;
    ;; t = 25, a25 := h, b25 := a, c25 := b, d25 := c, e25 := d, f25 := e, g25 := f, h25 := g
    ;SCHEDULE W9, W10, W2, W7
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SA, SB
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SE, SF
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SG, ECX, EBX, K25, W9
    ;; e = d + T1
    ;UPDATE_E SC, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SG
;
    ;; t = 26, a26 := g, b26 := h, c26 := a, d26 := b, e26 := c, f26 := d, g26 := e, h26 := f
    ;SCHEDULE W10, W11, W3, W8
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SH, SA
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SD, SE
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SF, ECX, EBX, K26, W10
    ;; e = d + T1
    ;UPDATE_E SB, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SF
;
    ;; t = 27, a27 := f, b27 := g, c27 := h, d27 := a, e27 := b, f27 := c, g27 := d, h27 := e
    ;SCHEDULE W11, W12, W4, W9
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SG, SH
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SC, SD
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SE, ECX, EBX, K27, W11
    ;; e = d + T1
    ;UPDATE_E SA, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SE
;
    ;; t = 28, a28 := e, b28 := f, c28 := g, d28 := h, e28 := a, f28 := b, g28 := c, h28 := d
    ;SCHEDULE W12, W13, W5, W10
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SF, SG
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SB, SC
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SD, ECX, EBX, K28, W12
    ;; e = d + T1
    ;UPDATE_E SH, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SD
;
    ;; t = 29, a29 := d, b29 := e, c29 := f, d29 := g, e29 := h, f29 := a, g29 := b, h29 := c
    ;SCHEDULE W13, W14, W6, W11
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SE, SF
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SA, SB
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SC, ECX, EBX, K29, W13
    ;; e = d + T1
    ;UPDATE_E SG, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SC
;
    ;; t = 30, a30 := c, b30 := d, c30 := e, d30 := f, e30 := g, f30 := h, g30 := a, h30 := b
    ;SCHEDULE W14, W15, W7, W12
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SD, SE
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SH, SA
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SB, ECX, EBX, K30, W14
    ;; e = d + T1
    ;UPDATE_E SF, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SB
;
    ;; t = 31, a31 := b, b31 := c, c31 := d, d31 := e, e31 := f, f31 := g, g31 := h, h31 := a
    ;SCHEDULE W15, W0, W8, W13
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SC, SD
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SG, SH
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SA, ECX, EBX, K31, W15
    ;; e = d + T1
    ;UPDATE_E SE, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SA
;
    ;; t = 32, a32 := a, b7 := b, c32 := c, d32 := d, e32 := e, f32 := f, g32 := g, h32 := h
    ;SCHEDULE W0, W1, W9, W14
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SB, SC
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SF, SG
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SH, ECX, EBX, K32, W0
    ;; e = d + T1
    ;UPDATE_E SD, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SH
;
    ;; t = 33, a33 := h, b33 := a, c33 := b, d33 := c, e33 := d, f33 := e, g33 := f, h33 := g
    ;SCHEDULE W1, W2, W10, W15
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SA, SB
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SE, SF
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SG, ECX, EBX, K33, W1
    ;; e = d + T1
    ;UPDATE_E SC, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SG
;
    ;; t = 34, a34 := g, b34 := h, c34 := a, d34 := b, e34 := c, f34 := d, g34 := e, h34 := f
    ;SCHEDULE W2, W3, W11, W0
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SH, SA
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SD, SE
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SF, ECX, EBX, K34, W2
    ;; e = d + T1
    ;UPDATE_E SB, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SF
;
    ;; t = 35, a35 := f, b35 := g, c35 := h, d35 := a, e35 := b, f35 := c, g35 := d, h35 := e
    ;SCHEDULE W3, W4, W12, W1
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SG, SH
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SC, SD
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SE, ECX, EBX, K35, W3
    ;; e = d + T1
    ;UPDATE_E SA, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SE
;
    ;; t = 36, a36 := e, b36 := f, c36 := g, d36 := h, e36 := a, f36 := b, g36 := c, h36 := d
    ;SCHEDULE W4, W5, W13, W2
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SF, SG
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SB, SC
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SD, ECX, EBX, K36, W4
    ;; e = d + T1
    ;UPDATE_E SH, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SD
;
    ;; t = 37, a37 := d, b37 := e, c37 := f, d37 := g, e37 := h, f37 := a, g37 := b, h37 := c
    ;SCHEDULE W5, W6, W14, W3
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SE, SF
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SA, SB
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SC, ECX, EBX, K37, W5
    ;; e = d + T1
    ;UPDATE_E SG, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SC
;
    ;; t = 38, a38 := c, b38 := d, c38 := e, d38 := f, e38 := g, f38 := h, g38 := a, h38 := b
    ;SCHEDULE W6, W7, W15, W4
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SD, SE
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SH, SA
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SB, ECX, EBX, K38, W6
    ;; e = d + T1
    ;UPDATE_E SF, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SB
;
    ;; t = 39, a39 := b, b39 := c, c39 := d, d39 := e, e39 := f, f39 := g, g39 := h, h39 := a
    ;SCHEDULE W7, W8, W0, W5
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SC, SD
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SG, SH
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SA, ECX, EBX, K39, W7
    ;; e = d + T1
    ;UPDATE_E SE, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SA
;
    ;; t = 40, a40 := a, b7 := b, c40 := c, d40 := d, e40 := e, f40 := f, g40 := g, h40 := h
    ;SCHEDULE W8, W9, W1, W6
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SB, SC
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SF, SG
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SH, ECX, EBX, K40, W8
    ;; e = d + T1
    ;UPDATE_E SD, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SH
;
    ;; t = 41, a41 := h, b41 := a, c41 := b, d41 := c, e41 := d, f41 := e, g41 := f, h41 := g
    ;SCHEDULE W9, W10, W2, W7
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SA, SB
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SE, SF
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SG, ECX, EBX, K41, W9
    ;; e = d + T1
    ;UPDATE_E SC, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SG
;
    ;; t = 42, a42 := g, b42 := h, c42 := a, d42 := b, e42 := c, f42 := d, g42 := e, h42 := f
    ;SCHEDULE W10, W11, W3, W8
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SH, SA
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SD, SE
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SF, ECX, EBX, K42, W10
    ;; e = d + T1
    ;UPDATE_E SB, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SF
;
    ;; t = 43, a43 := f, b43 := g, c43 := h, d43 := a, e43 := b, f43 := c, g43 := d, h43 := e
    ;SCHEDULE W11, W12, W4, W9
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SG, SH
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SC, SD
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SE, ECX, EBX, K43, W11
    ;; e = d + T1
    ;UPDATE_E SA, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SE
;
    ;; t = 44, a44 := e, b44 := f, c44 := g, d44 := h, e44 := a, f44 := b, g44 := c, h44 := d
    ;SCHEDULE W12, W13, W5, W10
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SF, SG
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SB, SC
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SD, ECX, EBX, K44, W12
    ;; e = d + T1
    ;UPDATE_E SH, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SD
;
    ;; t = 45, a45 := d, b45 := e, c45 := f, d45 := g, e45 := h, f45 := a, g45 := b, h45 := c
    ;SCHEDULE W13, W14, W6, W11
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SE, SF
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SA, SB
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SC, ECX, EBX, K45, W13
    ;; e = d + T1
    ;UPDATE_E SG, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SC
;
    ;; t = 46, a46 := c, b46 := d, c46 := e, d46 := f, e46 := g, f46 := h, g46 := a, h46 := b
    ;SCHEDULE W14, W15, W7, W12
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SD, SE
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SH, SA
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SB, ECX, EBX, K46, W14
    ;; e = d + T1
    ;UPDATE_E SF, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SB
;
    ;; t = 47, a47 := b, b47 := c, c47 := d, d47 := e, e47 := f, f47 := g, g47 := h, h47 := a
    ;SCHEDULE W15, W0, W8, W13
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SC, SD
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SG, SH
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SA, ECX, EBX, K47, W15
    ;; e = d + T1
    ;UPDATE_E SE, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SA
;
    ;; t = 48, a48 := a, b7 := b, c48 := c, d48 := d, e48 := e, f48 := f, g48 := g, h48 := h
    ;SCHEDULE W0, W1, W9, W14
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SB, SC
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SF, SG
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SH, ECX, EBX, K48, W0
    ;; e = d + T1
    ;UPDATE_E SD, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SH
;
    ;; t = 49, a49 := h, b49 := a, c49 := b, d49 := c, e49 := d, f49 := e, g49 := f, h49 := g
    ;SCHEDULE W1, W2, W10, W15
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SA, SB
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SE, SF
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SG, ECX, EBX, K49, W1
    ;; e = d + T1
    ;UPDATE_E SC, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SG
;
    ;; t = 50, a50 := g, b50 := h, c50 := a, d50 := b, e50 := c, f50 := d, g50 := e, h50 := f
    ;SCHEDULE W2, W3, W11, W0
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SH, SA
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SD, SE
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SF, ECX, EBX, K50, W2
    ;; e = d + T1
    ;UPDATE_E SB, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SF
;
    ;; t = 51, a51 := f, b51 := g, c51 := h, d51 := a, e51 := b, f51 := c, g51 := d, h51 := e
    ;SCHEDULE W3, W4, W12, W1
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SG, SH
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SC, SD
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SE, ECX, EBX, K51, W3
    ;; e = d + T1
    ;UPDATE_E SA, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SE
;
    ;; t = 52, a52 := e, b52 := f, c52 := g, d52 := h, e52 := a, f52 := b, g52 := c, h52 := d
    ;SCHEDULE W4, W5, W13, W2
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SF, SG
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SB, SC
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SD, ECX, EBX, K52, W4
    ;; e = d + T1
    ;UPDATE_E SH, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SD
;
    ;; t = 53, a53 := d, b53 := e, c53 := f, d53 := g, e53 := h, f53 := a, g53 := b, h53 := c
    ;SCHEDULE W5, W6, W14, W3
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SE, SF
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SA, SB
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SC, ECX, EBX, K53, W5
    ;; e = d + T1
    ;UPDATE_E SG, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SC
;
    ;; t = 54, a54 := c, b54 := d, c54 := e, d54 := f, e54 := g, f54 := h, g54 := a, h54 := b
    ;SCHEDULE W6, W7, W15, W4
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SD, SE
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SH, SA
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SB, ECX, EBX, K54, W6
    ;; e = d + T1
    ;UPDATE_E SF, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SB
;
    ;; t = 55, a55 := b, b55 := c, c55 := d, d55 := e, e55 := f, f55 := g, g55 := h, h55 := a
    ;SCHEDULE W7, W8, W0, W5
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SC, SD
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SG, SH
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SA, ECX, EBX, K55, W7
    ;; e = d + T1
    ;UPDATE_E SE, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SA
;
    ;; t = 56, a56 := a, b7 := b, c56 := c, d56 := d, e56 := e, f56 := f, g56 := g, h56 := h
    ;SCHEDULE W8, W9, W1, W6
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SB, SC
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SF, SG
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SH, ECX, EBX, K56, W8
    ;; e = d + T1
    ;UPDATE_E SD, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SH
;
    ;; t = 57, a57 := h, b57 := a, c57 := b, d57 := c, e57 := d, f57 := e, g57 := f, h57 := g
    ;SCHEDULE W9, W10, W2, W7
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SA, SB
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SE, SF
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SG, ECX, EBX, K57, W9
    ;; e = d + T1
    ;UPDATE_E SC, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SG
;
    ;; t = 58, a58 := g, b58 := h, c58 := a, d58 := b, e58 := c, f58 := d, g58 := e, h58 := f
    ;SCHEDULE W10, W11, W3, W8
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SH, SA
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SD, SE
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SF, ECX, EBX, K58, W10
    ;; e = d + T1
    ;UPDATE_E SB, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SF
;
    ;; t = 59, a59 := f, b59 := g, c59 := h, d59 := a, e59 := b, f59 := c, g59 := d, h59 := e
    ;SCHEDULE W11, W12, W4, W9
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SG, SH
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SC, SD
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SE, ECX, EBX, K59, W11
    ;; e = d + T1
    ;UPDATE_E SA, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SE
;
    ;; t = 60, a60 := e, b60 := f, c60 := g, d60 := h, e60 := a, f60 := b, g60 := c, h60 := d
    ;SCHEDULE W12, W13, W5, W10
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SF, SG
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SB, SC
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SD, ECX, EBX, K60, W12
    ;; e = d + T1
    ;UPDATE_E SH, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SD
;
    ;; t = 61, a61 := d, b61 := e, c61 := f, d61 := g, e61 := h, f61 := a, g61 := b, h61 := c
    ;SCHEDULE W13, W14, W6, W11
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SE, SF
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SA, SB
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SC, ECX, EBX, K61, W13
    ;; e = d + T1
    ;UPDATE_E SG, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SC
;
    ;; t = 62, a62 := c, b62 := d, c62 := e, d62 := f, e62 := g, f62 := h, g62 := a, h62 := b
    ;SCHEDULE W14, W15, W7, W12
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SD, SE
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SH, SA
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SB, ECX, EBX, K62, W14
    ;; e = d + T1
    ;UPDATE_E SF, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SB
;
    ;; t = 63, a63 := b, b63 := c, c63 := d, d63 := e, e63 := f, f63 := g, g63 := h, h63 := a
    ;SCHEDULE W15, W0, W8, W13
    ;; Sigma0
    ;SIGMA0
    ;; Maj
    ;MAJ EAX, SC, SD
    ;; T2 = Sigma0 + Maj
    ;UPDATE_T2 ECX, EAX
    ;; Sigma1
    ;SIGMA1
    ;; Ch
    ;CHO EBX, SG, SH
    ;; T1 = h + Sigma1 + Ch + K + W;
    ;UPDATE_T1 SA, ECX, EBX, K63, W15
    ;; e = d + T1
    ;UPDATE_E SE, ECX
    ;; a = T1 + T2
    ;UPDATE_A ECX, EAX, SA
;
    ;RDTSC
    ;;POP ECX
    ;;POP EBX
    ;SUB EAX, EBX ; 35442
;
;
    ;;POPAD
    RET
SHA256D ENDP
;
;x = 0
    ;ROTR7 = (x SHR 7) OR ((x SHL 25) AND 0FFFFFFFFH)
    ;ROTR17 = (x SHR 17) OR ((x SHL 15) AND 0FFFFFFFFH)
    ;ROTR18 = (x SHR 18) OR ((x SHL 14) AND 0FFFFFFFFH)
    ;ROTR19 = (x SHR 19) OR ((x SHL 13) AND 0FFFFFFFFH)
    ;SHR3 = x SHR 3
    ;SHR10 = x SHR 10
END
