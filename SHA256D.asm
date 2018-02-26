
; SHA256.asm

.686p
.model flat

.DATA?
SA      DD ?
SB      DD ?
SC      DD ?
SD      DD ?
SE      DD ?
SF      DD ?
SG      DD ?
SH      DD ?

W0      DD ?
W1      DD ?
W2      DD ?
W3      DD ?
W4      DD ?
W5      DD ?
W6      DD ?
W7      DD ?
W8      DD ?
W9      DD ?
W10     DD ?
W11     DD ?
W12     DD ?
W13     DD ?
W14     DD ?
W15     DD ?

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
; SHA256 constants
K0      EQU     428A2F98H
K1      EQU     71374491H
K2      EQU    0B5C0FBCFH
K3      EQU    0E9B5DBA5H
K4      EQU     3956C25BH
K5      EQU     59F111F1H
K6      EQU     923F82A4H
K7      EQU    0AB1C5ED5H
K8      EQU    0D807AA98H
K9      EQU     12835B01H
K10     EQU     243185BEH
K11     EQU     550C7DC3H
K12     EQU     72BE5D74H
K13     EQU     80DEB1FEH
K14     EQU     9BDC06A7H
K15     EQU    0C19BF174H
K16     EQU    0E49B69C1H
K17     EQU    0EFBE4786H
K18     EQU     0FC19DC6H
K19     EQU     240CA1CCH
K20     EQU     2DE92C6FH
K21     EQU     4A7484AAH
K22     EQU     5CB0A9DCH
K23     EQU     76F988DAH
K24     EQU     983E5152H
K25     EQU    0A831C66DH
K26     EQU    0B00327C8H
K27     EQU    0BF597FC7H
K28     EQU    0C6E00BF3H
K29     EQU    0D5A79147H
K30     EQU     06CA6351H
K31     EQU     14292967H
K32     EQU     27B70A85H
K33     EQU     2E1B2138H
K34     EQU     4D2C6DFCH
K35     EQU     53380D13H
K36     EQU     650A7354H
K37     EQU     766A0ABBH
K38     EQU     81C2C92EH
K39     EQU     92722C85H
K40     EQU    0A2BFE8A1H
K41     EQU    0A81A664BH
K42     EQU    0C24B8B70H
K43     EQU    0C76C51A3H
K44     EQU    0D192E819H
K45     EQU    0D6990624H
K46     EQU    0F40E3585H
K47     EQU     106AA070H
K48     EQU     19A4C116H
K49     EQU     1E376C08H
K50     EQU     2748774CH
K51     EQU     34B0BCB5H
K52     EQU     391C0CB3H
K53     EQU     4ED8AA4AH
K54     EQU     5B9CCA4FH
K55     EQU     682E6FF3H
K56     EQU     748F82EEH
K57     EQU     78A5636FH
K58     EQU     84C87814H
K59     EQU     8CC70208H
K60     EQU     90BEFFFAH
K61     EQU    0A4506CEBH
K62     EQU    0BEF9A3F7H
K63     EQU    0C67178F2H

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
MAJ MACRO a, b, c
    MOV EDX, b
    MOV ESI, EDX
    XOR EDX, c
    AND EAX, EDX
    AND ESI, c
    OR  EAX, ESI
ENDM

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

SHA256D PROC C
    MOV W0, 61626380H ; abc
    MOV W1, 0
    MOV W2, 0
    MOV W3, 0
    MOV W4, 0
    MOV W5, 0
    MOV W6, 0
    MOV W7, 0
    MOV W8, 0
    MOV W9, 0
    MOV W10, 0
    MOV W11, 0
    MOV W12, 0
    MOV W13, 0
    MOV W14, 0
    MOV W15, 18H

    PUSHAD
    RDTSC
    PUSH EAX
    PUSH EDX
    ; t = 0, a0 := H0, b0 := H1, c0 := H2, d0 := H3, e0 := H4, f0 := H5, g0 := H6, h0 := H7
    x0 = H4
    y0 = H5
    z0 = H6
    CH0 = (x0 AND y0) XOR ((NOT x0) AND z0)
    
    x1 = H0
    y1 = H1
    z1 = H2
    MAJ0 = (x1 AND y1) XOR (x1 AND z1) XOR (y1 AND z1)

    x2 = H0
    ROTR2 = (x2 SHR 2) OR ((x2 SHL 30) AND 0FFFFFFFFH)
    ROTR13 = (x2 SHR 13) OR ((x2 SHL 19) AND 0FFFFFFFFH)
    ROTR22 = (x2 SHR 22) OR ((x2 SHL 10) AND 0FFFFFFFFH)
    SIGMA00 = ROTR2 XOR ROTR13 XOR ROTR22

    x3 = H4
    ROTR6 = (x3 SHR 6) OR ((x3 SHL 26) AND 0FFFFFFFFH)
    ROTR11 = (x3 SHR 11) OR ((x3 SHL 21) AND 0FFFFFFFFH)
    ROTR25 = (x3 SHR 25) OR ((x3 SHL 7) AND 0FFFFFFFFH)
    SIGMA10 = ROTR6 XOR ROTR11 XOR ROTR25

    T10 = (H7 + SIGMA10 + CH0 + K0) AND 0FFFFFFFFH ; except W
    T20 = (SIGMA00 + MAJ0) AND 0FFFFFFFFH
    ; a = T1 + T2
    MOV EAX, T10 + T20
    ADD EAX, W0
    MOV SH, EAX
    ; e = d + T1
    MOV EBX, (H3 + T10) AND 0FFFFFFFFH
    ADD EBX, W0
    MOV SD, EBX

    ; t = 1, a1 := h, b1 := H0, c1 := H1, d1 := H2, e1 := d, f1 := H4, g1 := H5, h1 := H6
    ; Sigma0
    SIGMA0
    ; Maj = a(b^c)+bc
    AND EAX, H0 XOR H1
    OR  EAX, H0 AND H1
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1 = ROTR6^ROTR11^ROTR25
    SIGMA1
    ; Ch = e(f^g)^g
    AND EBX, H4 XOR H5
    XOR EBX, H5
    ; T1 = h + Sigma1 + Ch + K + W;
    ADD ECX, (H6 + K1) AND 0FFFFFFFFH
    ADD ECX, EBX
    ADD ECX, W1
    ; e = d + T1
    MOV EBX, H2
    ADD EBX, ECX
    MOV SC, EBX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SG

    ; t = 2, a2 := g, b2 := h, c2 := H0, d2 := H1, e2 := c, f2 := d, g2 := H4, h2 := H5
    ; Sigma0
    SIGMA0
    ; Maj = a(b^c)+bc
    MAJ EAX, SH, H0
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1 = ROTR6 XOR ROTR11 XOR ROTR25
    SIGMA1
    ; Ch = e(f^g)^g
    CHO EBX, SD, H4
    ; T1 = h + Sigma1 + Ch + K + W;
    ADD ECX, (H5 + K2) AND 0FFFFFFFFH
    ADD ECX, EBX
    ADD ECX, W2
    ; e = d + T1
    MOV EBX, H1
    ADD EBX, ECX
    MOV SB, EBX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SF

    ; t = 3, a3 := f, b3 := g, c3 := h, d3 := H0, e3 := b, f3 := c, g3 := d, h3 := H4
    ; Sigma0
    SIGMA0
    ; Maj = a(b^c)+bc
    MAJ EAX, SG, SH
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1 = ROTR6 XOR ROTR11 XOR ROTR25
    SIGMA1
    ; Ch = e(f^g)^g
    CHO EBX, SC, SD
    ; T1 = h + Sigma1 + Ch + K + W;
    ADD ECX, (H4 + K3) AND 0FFFFFFFFH
    ADD ECX, EBX
    ADD ECX, W3
    ; e = d + T1
    MOV EBX, H0
    ADD EBX, ECX
    MOV SA, EBX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SE

    ; t = 4, a4 := e, b4 := f, c4 := g, d4 := h, e4 := a, f4 := b, g4 := c, h4 := d
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SF, SG
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SB, SC
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SD, ECX, EBX, K4, W4
    ; e = d + T1
    UPDATE_E SH, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SD

    ; t = 5, a5 := d, b5 := e, c5 := f, d5 := g, e5 := h, f5 := a, g5 := b, h5 := c
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SE, SF
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SA, SB
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SC, ECX, EBX, K5, W5
    ; e = d + T1
    UPDATE_E SG, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SC

    ; t = 6, a6 := c, b6 := d, c6 := e, d6 := f, e6 := g, f6 := h, g6 := a, h6 := b
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SD, SE
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SH, SA
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SB, ECX, EBX, K6, W6
    ; e = d + T1
    UPDATE_E SF, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SB

    ; t = 7, a7 := b, b7 := c, c7 := d, d7 := e, e7 := f, f7 := g, g7 := h, h7 := a
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SC, SD
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SG, SH
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SA, ECX, EBX, K7, W7
    ; e = d + T1
    UPDATE_E SE, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SA

    ; t = 8, a8 := a, b7 := b, c8 := c, d8 := d, e8 := e, f8 := f, g8 := g, h8 := h
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SB, SC
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SF, SG
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SH, ECX, EBX, K8, W8
    ; e = d + T1
    UPDATE_E SD, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SH

    ; t = 9, a9 := h, b9 := a, c9 := b, d9 := c, e9 := d, f9 := e, g9 := f, h9 := g
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SA, SB
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SE, SF
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SG, ECX, EBX, K9, W9
    ; e = d + T1
    UPDATE_E SC, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SG

    ; t = 10, a10 := g, b10 := h, c10 := a, d10 := b, e10 := c, f10 := d, g10 := e, h10 := f
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SH, SA
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SD, SE
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SF, ECX, EBX, K10, W10
    ; e = d + T1
    UPDATE_E SB, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SF

    ; t = 11, a11 := f, b11 := g, c11 := h, d11 := a, e11 := b, f11 := c, g11 := d, h11 := e
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SG, SH
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SC, SD
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SE, ECX, EBX, K11, W11
    ; e = d + T1
    UPDATE_E SA, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SE

    ; t = 12, a12 := e, b12 := f, c12 := g, d12 := h, e12 := a, f12 := b, g12 := c, h12 := d
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SF, SG
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SB, SC
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SD, ECX, EBX, K12, W12
    ; e = d + T1
    UPDATE_E SH, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SD

    ; t = 13, a13 := d, b13 := e, c13 := f, d13 := g, e13 := h, f13 := a, g13 := b, h13 := c
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SE, SF
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SA, SB
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SC, ECX, EBX, K13, W13
    ; e = d + T1
    UPDATE_E SG, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SC

    ; t = 14, a14 := c, b14 := d, c14 := e, d14 := f, e14 := g, f14 := h, g14 := a, h14 := b
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SD, SE
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SH, SA
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SB, ECX, EBX, K14, W14
    ; e = d + T1
    UPDATE_E SF, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SB

    ; t = 15, a15 := b, b15 := c, c15 := d, d15 := e, e15 := f, f15 := g, g15 := h, h15 := a
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SC, SD
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SG, SH
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SA, ECX, EBX, K15, W15
    ; e = d + T1
    UPDATE_E SE, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SA

    ; t = 16, a16 := a, b7 := b, c16 := c, d16 := d, e16 := e, f16 := f, g16 := g, h16 := h
    SCHEDULE W0, W1, W9, W14
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SB, SC
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SF, SG
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SH, ECX, EBX, K16, W0
    ; e = d + T1
    UPDATE_E SD, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SH
    
    ; t = 17, a17 := h, b17 := a, c17 := b, d17 := c, e17 := d, f17 := e, g17 := f, h17 := g
    SCHEDULE W1, W2, W10, W15
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SA, SB
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SE, SF
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SG, ECX, EBX, K17, W1
    ; e = d + T1
    UPDATE_E SC, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SG

    ; t = 18, a18 := g, b18 := h, c18 := a, d18 := b, e18 := c, f18 := d, g18 := e, h18 := f
    SCHEDULE W2, W3, W11, W0
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SH, SA
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SD, SE
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SF, ECX, EBX, K18, W2
    ; e = d + T1
    UPDATE_E SB, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SF

    ; t = 19, a19 := f, b19 := g, c19 := h, d19 := a, e19 := b, f19 := c, g19 := d, h19 := e
    SCHEDULE W3, W4, W12, W1
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SG, SH
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SC, SD
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SE, ECX, EBX, K19, W3
    ; e = d + T1
    UPDATE_E SA, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SE

    ; t = 20, a20 := e, b20 := f, c20 := g, d20 := h, e20 := a, f20 := b, g20 := c, h20 := d
    SCHEDULE W4, W5, W13, W2
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SF, SG
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SB, SC
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SD, ECX, EBX, K20, W4
    ; e = d + T1
    UPDATE_E SH, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SD

    ; t = 21, a21 := d, b21 := e, c21 := f, d21 := g, e21 := h, f21 := a, g21 := b, h21 := c
    SCHEDULE W5, W6, W14, W3
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SE, SF
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SA, SB
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SC, ECX, EBX, K21, W5
    ; e = d + T1
    UPDATE_E SG, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SC

    ; t = 22, a22 := c, b22 := d, c22 := e, d22 := f, e22 := g, f22 := h, g22 := a, h22 := b
    SCHEDULE W6, W7, W15, W4
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SD, SE
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SH, SA
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SB, ECX, EBX, K22, W6
    ; e = d + T1
    UPDATE_E SF, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SB

    ; t = 23, a23 := b, b23 := c, c23 := d, d23 := e, e23 := f, f23 := g, g23 := h, h23 := a
    SCHEDULE W7, W8, W0, W5
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SC, SD
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SG, SH
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SA, ECX, EBX, K23, W7
    ; e = d + T1
    UPDATE_E SE, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SA

    ; t = 24, a24 := a, b7 := b, c24 := c, d24 := d, e24 := e, f24 := f, g24 := g, h24 := h
    SCHEDULE W8, W9, W1, W6
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SB, SC
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SF, SG
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SH, ECX, EBX, K24, W8
    ; e = d + T1
    UPDATE_E SD, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SH

    ; t = 25, a25 := h, b25 := a, c25 := b, d25 := c, e25 := d, f25 := e, g25 := f, h25 := g
    SCHEDULE W9, W10, W2, W7
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SA, SB
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SE, SF
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SG, ECX, EBX, K25, W9
    ; e = d + T1
    UPDATE_E SC, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SG

    ; t = 26, a26 := g, b26 := h, c26 := a, d26 := b, e26 := c, f26 := d, g26 := e, h26 := f
    SCHEDULE W10, W11, W3, W8
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SH, SA
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SD, SE
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SF, ECX, EBX, K26, W10
    ; e = d + T1
    UPDATE_E SB, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SF

    ; t = 27, a27 := f, b27 := g, c27 := h, d27 := a, e27 := b, f27 := c, g27 := d, h27 := e
    SCHEDULE W11, W12, W4, W9
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SG, SH
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SC, SD
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SE, ECX, EBX, K27, W11
    ; e = d + T1
    UPDATE_E SA, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SE

    ; t = 28, a28 := e, b28 := f, c28 := g, d28 := h, e28 := a, f28 := b, g28 := c, h28 := d
    SCHEDULE W12, W13, W5, W10
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SF, SG
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SB, SC
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SD, ECX, EBX, K28, W12
    ; e = d + T1
    UPDATE_E SH, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SD

    ; t = 29, a29 := d, b29 := e, c29 := f, d29 := g, e29 := h, f29 := a, g29 := b, h29 := c
    SCHEDULE W13, W14, W6, W11
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SE, SF
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SA, SB
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SC, ECX, EBX, K29, W13
    ; e = d + T1
    UPDATE_E SG, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SC

    ; t = 30, a30 := c, b30 := d, c30 := e, d30 := f, e30 := g, f30 := h, g30 := a, h30 := b
    SCHEDULE W14, W15, W7, W12
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SD, SE
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SH, SA
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SB, ECX, EBX, K30, W14
    ; e = d + T1
    UPDATE_E SF, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SB

    ; t = 31, a31 := b, b31 := c, c31 := d, d31 := e, e31 := f, f31 := g, g31 := h, h31 := a
    SCHEDULE W15, W0, W8, W13
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SC, SD
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SG, SH
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SA, ECX, EBX, K31, W15
    ; e = d + T1
    UPDATE_E SE, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SA

    ; t = 32, a32 := a, b7 := b, c32 := c, d32 := d, e32 := e, f32 := f, g32 := g, h32 := h
    SCHEDULE W0, W1, W9, W14
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SB, SC
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SF, SG
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SH, ECX, EBX, K32, W0
    ; e = d + T1
    UPDATE_E SD, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SH

    ; t = 33, a33 := h, b33 := a, c33 := b, d33 := c, e33 := d, f33 := e, g33 := f, h33 := g
    SCHEDULE W1, W2, W10, W15
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SA, SB
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SE, SF
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SG, ECX, EBX, K33, W1
    ; e = d + T1
    UPDATE_E SC, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SG

    ; t = 34, a34 := g, b34 := h, c34 := a, d34 := b, e34 := c, f34 := d, g34 := e, h34 := f
    SCHEDULE W2, W3, W11, W0
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SH, SA
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SD, SE
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SF, ECX, EBX, K34, W2
    ; e = d + T1
    UPDATE_E SB, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SF

    ; t = 35, a35 := f, b35 := g, c35 := h, d35 := a, e35 := b, f35 := c, g35 := d, h35 := e
    SCHEDULE W3, W4, W12, W1
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SG, SH
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SC, SD
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SE, ECX, EBX, K35, W3
    ; e = d + T1
    UPDATE_E SA, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SE

    ; t = 36, a36 := e, b36 := f, c36 := g, d36 := h, e36 := a, f36 := b, g36 := c, h36 := d
    SCHEDULE W4, W5, W13, W2
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SF, SG
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SB, SC
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SD, ECX, EBX, K36, W4
    ; e = d + T1
    UPDATE_E SH, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SD

    ; t = 37, a37 := d, b37 := e, c37 := f, d37 := g, e37 := h, f37 := a, g37 := b, h37 := c
    SCHEDULE W5, W6, W14, W3
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SE, SF
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SA, SB
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SC, ECX, EBX, K37, W5
    ; e = d + T1
    UPDATE_E SG, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SC

    ; t = 38, a38 := c, b38 := d, c38 := e, d38 := f, e38 := g, f38 := h, g38 := a, h38 := b
    SCHEDULE W6, W7, W15, W4
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SD, SE
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SH, SA
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SB, ECX, EBX, K38, W6
    ; e = d + T1
    UPDATE_E SF, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SB

    ; t = 39, a39 := b, b39 := c, c39 := d, d39 := e, e39 := f, f39 := g, g39 := h, h39 := a
    SCHEDULE W7, W8, W0, W5
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SC, SD
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SG, SH
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SA, ECX, EBX, K39, W7
    ; e = d + T1
    UPDATE_E SE, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SA

    ; t = 40, a40 := a, b7 := b, c40 := c, d40 := d, e40 := e, f40 := f, g40 := g, h40 := h
    SCHEDULE W8, W9, W1, W6
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SB, SC
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SF, SG
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SH, ECX, EBX, K40, W8
    ; e = d + T1
    UPDATE_E SD, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SH

    ; t = 41, a41 := h, b41 := a, c41 := b, d41 := c, e41 := d, f41 := e, g41 := f, h41 := g
    SCHEDULE W9, W10, W2, W7
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SA, SB
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SE, SF
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SG, ECX, EBX, K41, W9
    ; e = d + T1
    UPDATE_E SC, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SG

    ; t = 42, a42 := g, b42 := h, c42 := a, d42 := b, e42 := c, f42 := d, g42 := e, h42 := f
    SCHEDULE W10, W11, W3, W8
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SH, SA
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SD, SE
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SF, ECX, EBX, K42, W10
    ; e = d + T1
    UPDATE_E SB, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SF

    ; t = 43, a43 := f, b43 := g, c43 := h, d43 := a, e43 := b, f43 := c, g43 := d, h43 := e
    SCHEDULE W11, W12, W4, W9
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SG, SH
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SC, SD
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SE, ECX, EBX, K43, W11
    ; e = d + T1
    UPDATE_E SA, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SE

    ; t = 44, a44 := e, b44 := f, c44 := g, d44 := h, e44 := a, f44 := b, g44 := c, h44 := d
    SCHEDULE W12, W13, W5, W10
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SF, SG
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SB, SC
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SD, ECX, EBX, K44, W12
    ; e = d + T1
    UPDATE_E SH, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SD

    ; t = 45, a45 := d, b45 := e, c45 := f, d45 := g, e45 := h, f45 := a, g45 := b, h45 := c
    SCHEDULE W13, W14, W6, W11
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SE, SF
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SA, SB
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SC, ECX, EBX, K45, W13
    ; e = d + T1
    UPDATE_E SG, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SC

    ; t = 46, a46 := c, b46 := d, c46 := e, d46 := f, e46 := g, f46 := h, g46 := a, h46 := b
    SCHEDULE W14, W15, W7, W12
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SD, SE
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SH, SA
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SB, ECX, EBX, K46, W14
    ; e = d + T1
    UPDATE_E SF, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SB

    ; t = 47, a47 := b, b47 := c, c47 := d, d47 := e, e47 := f, f47 := g, g47 := h, h47 := a
    SCHEDULE W15, W0, W8, W13
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SC, SD
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SG, SH
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SA, ECX, EBX, K47, W15
    ; e = d + T1
    UPDATE_E SE, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SA

    ; t = 48, a48 := a, b7 := b, c48 := c, d48 := d, e48 := e, f48 := f, g48 := g, h48 := h
    SCHEDULE W0, W1, W9, W14
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SB, SC
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SF, SG
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SH, ECX, EBX, K48, W0
    ; e = d + T1
    UPDATE_E SD, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SH

    ; t = 49, a49 := h, b49 := a, c49 := b, d49 := c, e49 := d, f49 := e, g49 := f, h49 := g
    SCHEDULE W1, W2, W10, W15
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SA, SB
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SE, SF
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SG, ECX, EBX, K49, W1
    ; e = d + T1
    UPDATE_E SC, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SG

    ; t = 50, a50 := g, b50 := h, c50 := a, d50 := b, e50 := c, f50 := d, g50 := e, h50 := f
    SCHEDULE W2, W3, W11, W0
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SH, SA
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SD, SE
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SF, ECX, EBX, K50, W2
    ; e = d + T1
    UPDATE_E SB, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SF

    ; t = 51, a51 := f, b51 := g, c51 := h, d51 := a, e51 := b, f51 := c, g51 := d, h51 := e
    SCHEDULE W3, W4, W12, W1
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SG, SH
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SC, SD
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SE, ECX, EBX, K51, W3
    ; e = d + T1
    UPDATE_E SA, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SE

    ; t = 52, a52 := e, b52 := f, c52 := g, d52 := h, e52 := a, f52 := b, g52 := c, h52 := d
    SCHEDULE W4, W5, W13, W2
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SF, SG
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SB, SC
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SD, ECX, EBX, K52, W4
    ; e = d + T1
    UPDATE_E SH, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SD

    ; t = 53, a53 := d, b53 := e, c53 := f, d53 := g, e53 := h, f53 := a, g53 := b, h53 := c
    SCHEDULE W5, W6, W14, W3
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SE, SF
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SA, SB
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SC, ECX, EBX, K53, W5
    ; e = d + T1
    UPDATE_E SG, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SC

    ; t = 54, a54 := c, b54 := d, c54 := e, d54 := f, e54 := g, f54 := h, g54 := a, h54 := b
    SCHEDULE W6, W7, W15, W4
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SD, SE
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SH, SA
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SB, ECX, EBX, K54, W6
    ; e = d + T1
    UPDATE_E SF, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SB

    ; t = 55, a55 := b, b55 := c, c55 := d, d55 := e, e55 := f, f55 := g, g55 := h, h55 := a
    SCHEDULE W7, W8, W0, W5
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SC, SD
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SG, SH
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SA, ECX, EBX, K55, W7
    ; e = d + T1
    UPDATE_E SE, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SA

    ; t = 56, a56 := a, b7 := b, c56 := c, d56 := d, e56 := e, f56 := f, g56 := g, h56 := h
    SCHEDULE W8, W9, W1, W6
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SB, SC
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SF, SG
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SH, ECX, EBX, K56, W8
    ; e = d + T1
    UPDATE_E SD, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SH

    ; t = 57, a57 := h, b57 := a, c57 := b, d57 := c, e57 := d, f57 := e, g57 := f, h57 := g
    SCHEDULE W9, W10, W2, W7
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SA, SB
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SE, SF
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SG, ECX, EBX, K57, W9
    ; e = d + T1
    UPDATE_E SC, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SG

    ; t = 58, a58 := g, b58 := h, c58 := a, d58 := b, e58 := c, f58 := d, g58 := e, h58 := f
    SCHEDULE W10, W11, W3, W8
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SH, SA
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SD, SE
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SF, ECX, EBX, K58, W10
    ; e = d + T1
    UPDATE_E SB, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SF

    ; t = 59, a59 := f, b59 := g, c59 := h, d59 := a, e59 := b, f59 := c, g59 := d, h59 := e
    SCHEDULE W11, W12, W4, W9
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SG, SH
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SC, SD
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SE, ECX, EBX, K59, W11
    ; e = d + T1
    UPDATE_E SA, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SE

    ; t = 60, a60 := e, b60 := f, c60 := g, d60 := h, e60 := a, f60 := b, g60 := c, h60 := d
    SCHEDULE W12, W13, W5, W10
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SF, SG
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SB, SC
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SD, ECX, EBX, K60, W12
    ; e = d + T1
    UPDATE_E SH, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SD

    ; t = 61, a61 := d, b61 := e, c61 := f, d61 := g, e61 := h, f61 := a, g61 := b, h61 := c
    SCHEDULE W13, W14, W6, W11
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SE, SF
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SA, SB
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SC, ECX, EBX, K61, W13
    ; e = d + T1
    UPDATE_E SG, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SC

    ; t = 62, a62 := c, b62 := d, c62 := e, d62 := f, e62 := g, f62 := h, g62 := a, h62 := b
    SCHEDULE W14, W15, W7, W12
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SD, SE
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SH, SA
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SB, ECX, EBX, K62, W14
    ; e = d + T1
    UPDATE_E SF, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SB

    ; t = 63, a63 := b, b63 := c, c63 := d, d63 := e, e63 := f, f63 := g, g63 := h, h63 := a
    SCHEDULE W15, W0, W8, W13
    ; Sigma0
    SIGMA0
    ; Maj
    MAJ EAX, SC, SD
    ; T2 = Sigma0 + Maj
    UPDATE_T2 ECX, EAX
    ; Sigma1
    SIGMA1
    ; Ch
    CHO EBX, SG, SH
    ; T1 = h + Sigma1 + Ch + K + W;
    UPDATE_T1 SA, ECX, EBX, K63, W15
    ; e = d + T1
    UPDATE_E SE, ECX
    ; a = T1 + T2
    UPDATE_A ECX, EAX, SA

    RDTSC
    POP ECX
    POP EBX
    SUB EAX, EBX ; 35442


    POPAD
    RET
SHA256D ENDP

x = 0
    ROTR7 = (x SHR 7) OR ((x SHL 25) AND 0FFFFFFFFH)
    ROTR17 = (x SHR 17) OR ((x SHL 15) AND 0FFFFFFFFH)
    ROTR18 = (x SHR 18) OR ((x SHL 14) AND 0FFFFFFFFH)
    ROTR19 = (x SHR 19) OR ((x SHL 13) AND 0FFFFFFFFH)
    SHR3 = x SHR 3
    SHR10 = x SHR 10
END
