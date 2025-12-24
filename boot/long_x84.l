entry:
    mov @r1 <M> u64 (^*main/3) @r4 @r3 ^@r2
    mov @r4 *main u64
    @r4 @r2 ^@r3 @r1 
    mov @r4 @r1 
    @r7 @r4 <M> u64 @r3 @r8
    @r1 ^@r1 @r10 *main u64

    push @r1 @r2 @r3 @r4 @r5 @r6 @r7 @r8 @r9 @r10 @r11 @r12 u64 <> <> *main
    mov ^@r8 @r9 @r12

    @r9 (^@r8+1) u64 @r11

    jmp (u64+3) @r11 @r7
    push (@r10/0_2) (@r11+0_1)
    jmp (@r10+0_1) ^@r7 @r3
    push @r4 (@r10/2) ^@r11

    movk @r2 ^@r11 @r6
    movk @r4 @r8 ^u64
    push *main @r4

    movk (*main+1) ^@r5 ^@r4
    push ^@r11 @r2 @r4
    mov ^@r4 ^@r4 @r9

    movk @r1 u64 <M>
    @r11 @r5 ^@r11 <M>
    movk @r3 ^*main ^@r6

    push @r4 <M>

    push *main *block
    movk u64 <M>
    @r12 (^@r1/2) @r3 @r12

    @r8 ^@r9 (<M>/2)

    mov @r6 u32
    push u32 @r3 <M>

    movk @r6 @r1 u64
    mov @r9 @r6

    dw <M> *main @r5
    mov @r11 (@r5/0_2)

    jmp @r9 ^@r9 @r2
    @r12 ^u64 u64
    movk @r2 @r9
    dw @r11 ^@r9 ^@r7
    dw @r4 @r10

    dw @r6 u16 @r9

    @r4 ^M @r1

    push (@r10/2) <>
    movk ^@r12 &&
    jmk <M> <M>
    push u8 &&
    movk @r12 (*block+0_2)
    @r2 @r2 @r7
    cmp <> u16

    movk *main @r8 *block

    @r9 @r2 u64
    movk (*main+0_2) @r10 *block

    @r6 @r11 @r2 @r7

    push @r10 @r7 &&
    @r2 u8 u16
    push *block <M>
    jmk @r9 @r9
    jmp ^@r8 ^@r2

    cmp M ^*main
    dw <> @r12
    movk ^@r3 ^@r10
    @r6 ^*main ^@r10

    mov @r11 (u32+0_1) u16
    jmk (^*main+3) ^M

    dw @r6 (^@r10+0_2)
    mov u16 @r6 (u16+1)
    jmk (@r8+0_1) @r4
    jmk ^@r7 u8 ^@r2
    cmp @r8 @r5 (u64+1)

    @r5 @r4 *main
    dw @r12 @r7

    jmk @r1 @r1
    push u16 @r9

    jmp @r3 u32

    dw <M> u64

    @r5 u16 ^*main
    jmp (^*block+2) @r3 (^u32/0_1)
    mov @r8 @r8
    mov ^@r4 @r8
    cmp @r10 @r7
    @r12 @r10 @r4
    push (*block/3) @r5
    @r4 <M> @r2
    mov ^@r1 u64
    @r6 @r3 ^<>
    push ^&& *main

    jmk @r1 @r3

    dw (@r8/0_1) &&
    cmp <M> (@r4+2) (@r6+0_2)
    mov M @r7 @r2
    @r1 @r10 @r1
    @r10 @r6 @r9
    dw @r7 @r5
    mov @r11 @r1 @r9

    dw <> @r12 &&

    jmp <M> ^*main
    mov @r11 ^@r8
    jmp @r3 ^*main
    cmp @r9 @r12

    cmp u16 @r9

    jmk @r11 *main

    mov && ^u16
    cmp (<>+0_1) @r4
    dw @r1 (@r6+1)
    jmk u64 (<>/0_2) ^@r1
    jmk u32 &&

    cmp ^@r7 u8

    movk @r1 ^u64 @r10
    dw u8 u32 @r9
    movk @r9 (@r11+3)
    @r7 u64 @r4
    movk u8 @r1

    push (@r10+3) @r4
    @r1 <M> @r11

    dw @r11 u16
    push @r10 @r1 <>
    jmk ^@r1 &&

    cmp ^u8 @r7

    jmk u32 (^u8+1)
    push (@r7/0_1) @r8
    jmp ^u32 (@r12/2)
    jmk (*block/0_2) ^u16

    @r11 @r7 ^&&

    cmp @r3 u64 u8
    push @r9 @r12 (@r1/1)
    cmp @r7 ^@r8

    movk ^u16 u64
    jmp u32 ^@r10
    movk ^@r6 ^@r10
    jmp ^*block @r10 &&
    jmk @r5 (@r8+0_2) *main

    @r4 ^*block <>
    cmp u8 (*block/0_2)
    cmp (&&/0_2) (u64/2)

    push (@r8/0_1) u8

    push @r11 (M/2)
    jmk @r6 @r3

    cmp @r7 @r1
    cmp (^@r5+0_2) @r8

    dw @r11 @r1
    jmp (@r12/2) u32

    movk @r3 <M> (@r1/0_1)

    movk u32 u16
    cmp ^&& @r1
    jmp ^@r5 @r4 ^<M>

    cmp (@r5+0_2) u16

    mov (M/2) &&

    jmk @r6 *block

    @r4 ^u32 *main u8
    mov @r6 @r4
    cmp u16 ^*block *block
    @r5 *main @r7 @r9
    jmp (^@r7/3) @r1
    jmp <M> M M
    jmp @r3 ^u32

    cmp @r6 @r12
    @r5 @r4 u8
    mov u16 (^@r2/0_1) &&
    push @r7 (&&/0_2)
    @r3 u64 u8
    jmp (@r11/0_2) <M>
    jmp (<M>+1) u16
    movk <M> u32
    @r12 && (u32+1) (@r4+1)

    movk u8 @r8
    mov @r3 @r3

    cmp u32 ^*main
    mov @r10 (^*block/2)
    @r8 @r3 (@r6+0_1)
    cmp <> (@r9+3) u8
    movk (^<>+3) (*main+0_1)

    jmp @r9 @r10

    push u8 <M>
    @r12 @r7 @r7
    dw ^u16 (u32/0_1)
    cmp ^*main u8

    push @r7 *block
    mov (@r10+2) M @r6
    @r7 (u8+2) u8 *main

    dw ^@r10 *main
    movk @r10 <M>

    jmk *block @r8
    push @r5 *main
    mov @r10 &&
    dw u64 @r7
    dw ^&& @r11

    push ^@r4 u8
    cmp (^u16/2) <> (^@r9+1)
    jmp (^u16+3) @r9
    push ^u16 <M>

    dw (@r8+3) u8 ^M
    push @r2 ^<M>

    movk @r11 @r9
    mov ^M *main
    mov ^@r9 <M> @r3

    jmk *main &&
    dw u32 @r3 (@r7/3)

    @r12 @r11 (<M>+3) (@r3/3)

    mov M ^u64
    @r11 && (u8+0_1)
    jmp ^<> ^@r11
    jmk @r7 *block ^u16
    jmp @r3 ^@r5
    movk @r9 u16
    dw (@r10/0_2) @r4

    dw ^@r5 @r6 ^&&

    @r2 @r6 ^M @r9
    mov @r1 (@r8/0_2) @r6

    jmp @r4 ^@r3
    push u32 ^u64

    mov && <> &&
    mov ^<> @r10
    push @r3 @r10
    dw @r1 @r6

    cmp (&&/0_1) M

    mov (&&/3) @r6

    jmk (@r2/0_1) &&
    cmp <> *block

    movk u16 @r3
    jmp @r7 @r11
    cmp @r8 @r11
    movk ^&& @r12

