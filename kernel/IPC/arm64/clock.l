entry:
//    @r5 @r3 ^@r2 (u16/1)
    @r5 @r3 u64 (@r2/1)
    lpd @r1 @r4 u32 <M> @r3 ^@r5
    lsl u32 (&&/2) ^*block (*main+0_1)
    @r9 M ^*main @r2 ^@r11

    dw @r2 *block @r3

    movk @r3 ^*main (@r3/3) @r10 u32 (@r10/2) (^@r5+1)
//    @r10 *main ^@r5 @r9 ^<> @r6
//    dw M ^@r12 (<M>+1)
    @r12 *main @r1 u32 <M> &&
    dw ^@r12 (<M>+2) @r1 @r8    

    dw @r8 (<>+2)
    @r1 u64 ^u16 @r9 @r10 (@r5+2) *main ^@r7
    lsl @r9 @r10 u64 @r1 ^@r7 <M> @r1
    movk @r1 @r11 u32 (*main/2) <> *block
    @r1 @r2 @r9 u64

//    @r7 u32 @r2 ^<> *main u64
//    @r2 @r8 <> (u16+0_2)
    @r4 @r2 @r7 u64 <M> ^*main @r1 u16
    jmk @r7 @r1 *main @r4 <> u16
    jmk @r2 (^@r1+0_1) ^@r4 u8
    lsl u16 u8

    movk (<M>+1) ^M @r2 @r2 @r10 ^*main

    @r4 @r6 ^@r7
    jmk (@r7/2) && @r10
    dw @r4 ^@r10 <M>
    movk @r6 @r6
    push (u8+1) @r9 *main u16 @r9
    @r7 *main (u32/1) @r5 @r7 @r4 u8 u16
    ldp @r1 <> @r4 (<>+3) @r11 u32 (@r9/1)
    mov @r12 u8 @r5 (@r1+0_2) ^u64 <> (^@r8+1)
    lsl @r10 @r4 (*block/0_2)
    @r5 ^@r12 @r4
    dw (@r10+3) && u32 @r1
    @r9 ^u64 @r7 *block (^<M>+2)
    push (^@r3/0_1) u8 @r10 @r2 u64

    @r11 @r9 @r11 <M> M ^u64 M @r5

    jmk @r6 && @r6 ^*main @r5 @r4 @r11
    mov @r4 @r8 ^&&

    @r9 @r4 @r9 @r6
    jmp ^<M> ^@r4 (@r9+0_1) <M>
    push @r11 u8 @r11 @r2 (*block/0_1) @r7 u8


    ldp @r11 ^<> (u64/2) (@r11+0_1) @r6

    jmk (&&+1) *main @r1 ^@r7 && *main
    dw @r3 u32 u16 @r12 @r1 <M> *main
    mov (*main/1) (u32+3) u64
    push M <> u16 @r1 u8 M

    mov @r4 (@r9/2) u64 (<>+3) (u16+1)

    dw @r1 u32 &&
    jmp ^@r12 u8 (@r8+3)

    jmp @r1 @r12 u8
    dw ^@r2 @r12 (^@r9+1) @r6 @r9 @r2

    cmp (@r1+2) @r1 ^u64 <> (@r3+0_2) <M>
    @r12 && && && (^<>/0_1) *main

    cmp @r9 (@r1/2) <> *main
    dw ^@r2 @r7 (^@r2+0_2) u16 u8

    jmk <> ^@r1 ^@r7 @r5 @r4 u8 ^@r10
    jmp ^@r3 @r7 (^@r3/3) @r10 @r1
    cmp @r11 @r11

    jmp && @r5 @r3 (M/0_2) ^u32 ^*main u64

    push *block u16 u16 (^u16+0_1) @r2
    jmp @r9 @r6 (u8+2) u32 *block @r7
    push @r12 *main @r4 @r9 @r6 (@r8+3)
    dw *block @r8 ^@r3 u16 (^@r11/3) @r5 ^@r1
    push @r2 u16 ^u64 ^@r11 (@r6/0_1) @r6 @r8
    cmp (u16+0_2) ^@r12 @r12 *main *block (@r12/0_1) (@r6/0_1)
    push M (^u32+2) ^@r5
    ldp (@r6/0_2) *main ^*block *main
    jmp u64 u32 (@r9/3) @r2 (@r12+3) @r12

    @r7 (^*main/1) ^@r1 ^*block

    jmk @r8 ^u16
    lsl (^M/0_2) @r1 ^*main

    lsl (@r4/2) ^@r10 (@r12+0_1) @r6 u32 ^@r7 @r7

    cmp ^@r10 @r6

    movk ^u8 (<>/0_1)

    @r12 @r4 @r5
    jmp u64 u8 @r1 @r8 (@r12/2) u64 u64

    mov @r12 @r11 u8 *main

    @r1 @r9 *block

