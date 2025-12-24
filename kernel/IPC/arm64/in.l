entry:

    ldp (^@r11+1) ^u8 M <M>
    mov @r8 @r2 @r4 @r2 ^@r7
    movk ^*main @r7 u64 @r8 M ^@r1 (^u16+1)
    ldp (@r9/0_2) && ^u16 ^@r6 @r1

    mov ^u8 @r7

    jmp M (^u32/0_1) @r3 *main <M> @r11 ^@r11

    movk @r1 *main (u64+1) ^*block ^@r9 (^M+3)
    jmp u64 @r6 (@r9/1)

    cmp ^@r7 @r12 u64 @r12 @r11
    @r9 u8 @r5 *main

    lsl @r10 @r5 @r9 @r2
    movk (<M>/0_1) @r4 M (M+0_1) (@r3+3)
    cmp @r9 (@r4+3) @r3 *block
    movk @r9 ^@r3 @r9

    push (*block+0_1) @r4 @r8

    dw u8 ^M




















