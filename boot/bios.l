entry:    
    movk <M> (@r1+2)

    cmp (^@r7+3) M ^M
    @r2 @r5 <M>

    jmk (@r5/2) *block
    dw @r7 M
    mov ^*block ^@r4
    jmp (u32+1) @r9
    mov @r1 u32
    @r11 (@r10/1) ^u16 &&
    dw M @r7
    @r8 <> ^@r4

    jmp @r10 @r9 *main
    @r8 ^@r5 @r5

    jmk <> @r12 @r5
    jmp @r5 ^@r9
    movk (@r9/0_2) <>

    movk ^@r1 ^@r9
    @r11 ^@r1 (@r2+1)
    mov @r3 u64
    push @r4 <M>

    mov (@r6/0_1) (u32/0_2) u64
    jmp (@r11/0_2) u16 (&&+2)

    jmk u64 <M>

    movk u32 (@r12+3)
    push (u64+0_2) u8 ^@r1

    jmk ^u32 ^u8

    cmp u16 <M> ^@r5

    jmk (^@r7+2) (u32/3)

    cmp @r10 ^@r6 ^&&

    @r12 (@r12+0_2) (*main+0_2) @r2
    @r2 @r2 &&

    @r9 u8 ^@r9

    jmp @r1 *main
    movk u32 (^@r11+2)
    movk ^*block M M
    jmp @r1 (^@r8/3)
    mov (^@r5+2) (@r4+0_2) (^*main/3)

