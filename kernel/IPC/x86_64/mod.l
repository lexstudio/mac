entry:
    @r3 ^u16 @r7 (u8+1) @r1 @r9
    dw ^@r11 <M> @r4 ^u16 u32
    movk @r3 ^@r2 <>
    lsl (M+2) @r2 @r4 ^@r2
    lsl && ^@r11
    movk (^u64+0_2) u32 u32 @r4 @r9
    lsl @r9 @r4

    cmp u16 @r4
    jmk <> @r2 (@r6/1) ^@r4
    dw ^M @r8 @r12 @r12 @r2 M

    ldp ^@r3 @r2 ^@r2
    movk @r11 @r8
    ldp (*main/3) @r7

    jmp ^<M> ^u32 ^@r11 (u64/1) <> ^u32
    @r10 @r7 && u64
    movk ^@r8 <> && @r4
    dw (@r1/3) @r1 @r1 ^&& *block @r1

    cmp <M> ^@r4
    jmk @r11 @r11 (@r5/3) ^<M> ^<M>
    push @r8 M @r11 @r7 @r1
    movk (@r7+2) ^@r9 u64 u32 ^@r12
    cmp @r6 (M+3) ^@r1 (@r7/2) @r7 @r3 ^@r1
    mov <> ^@r5 @r5 @r4 ^@r3
    ldp (u32+2) @r11
    jmk @r10 ^*block
    mov @r7 @r8 @r12 @r5 @r4 u32 (u32/3)
    cmp @r9 @r12 @r3 *main (@r10/0_2)
    jmp @r11 ^u64 u16 @r3 u32

    dw u16 u8 (u64/2) @r1 u32 u32
    ldp @r1 u32 ^u8 <M> ^@r12

    push && @r9 u16 (@r11/3)
    ldp @r2 @r5
    jmp (@r3+0_2) @r5 @r9 @r1
    lsl @r2 @r7 (*main/0_2) (u16/0_2) u16 ^*block M
    @r2 @r9 *main u32 u16 @r6
    mov <M> @r8
    @r9 @r5 @r4
    mov (u8+0_1) @r1 *block ^*main
    @r2 @r6 @r4 u64 @r8 u64
    jmp (@r4+2) ^@r8 ^@r12 ^@r8 <M>
    dw ^*block ^@r9 @r2 <M> u64

    ldp u8 ^@r7 *main u16
    jmp u32 @r12 <> @r2 u64 @r10 @r6
    dw <> ^@r9 @r4 @r4
    @r9 @r2 @r12 ^@r5 &&
    jmp @r8 @r10 @r9 u64 ^M <M>
    jmk @r9 <> @r10
    @r10 M @r10 @r7 @r8 <M> @r12
    ldp u8 @r8 @r6 @r9
    mov ^u16 @r5 *block ^@r2 (@r6/0_2) @r10 ^@r8

    jmp ^@r11 @r12 @r5
    lsl u64 (@r4+0_1) ^*block
    jmk ^@r8 ^@r11 @r12 u8 @r3 ^@r7 @r11
    cmp *main @r9 (<>+2) @r1 M @r2
    lsl @r9 @r3 <M> @r2
    jmk && @r4 *main @r4 (@r6+0_1) ^M ^&&

    mov *block ^@r11 M
    ldp u8 (^u16/2) (@r6/2) (u8+0_1) ^*main
    cmp u16 *main @r1 u8 @r6 @r12 &&
    push ^M @r1 @r1 @r2 ^@r3
    jmk @r7 (@r1+0_2) @r3 @r5

    push ^@r10 @r9 *block @r5 @r4
    dw @r4 ^<>

    @r2 (u16/2) (^@r4+0_2) @r4 *main
    cmp @r10 (@r11/2)

    jmk @r1 @r11 @r5 u32 u32 (*block/0_2)
    push ^*main ^&& u32 @r3 <M> u32

    mov (<>/2) M ^@r6 u8 (u8/0_1)

    ldp ^@r12 <M> @r9 u8 <M>
    push @r6 @r6 ^@r9 @r1 @r8
    dw (u8+2) (@r5+0_1) (@r11/0_2)
    @r9 ^@r10 ^@r4 ^&& @r3
    ldp @r1 (u64/3) (@r12/0_2) @r6 @r8

    lsl *main <> (@r2+1) @r4 @r6 @r11 ^*block

    push (@r8/0_2) *block
    push *main @r5 @r12 u16

    @r5 <M> (@r5/0_1) *block <M> u32 @r7
    @r6 @r6 (@r5/3) (*block/0_2) @r4 (@r4/0_1) @r8
    jmp <M> ^u32 (u8+1) (@r12/3) (u16+3) @r10 &&
    dw @r2 *block
    ldp @r2 @r4
    jmp @r7 (u64+0_1)
    cmp @r9 @r5 ^@r3 ^@r1 @r8 @r2 ^&&
    ldp @r11 @r3 (^@r1+3) ^@r2 u8
    jmk <M> u8 u8
    jmk u8 *block u8
    mov @r8 *block @r8
    @r7 (@r1/2) M u64 ^@r9 ^&& @r10 @r5
    dw u64 ^*main @r12 ^u64
    push ^@r3 (@r6/2) ^@r9 u8 @r7 @r4
    dw *main (^@r11/0_2) @r3 (@r5+1)
    lsl (@r8+0_2) <> (u32+0_1) ^M
    @r12 @r1 <M>
    @r9 @r1 @r4 @r5 *main
    ldp <> @r1 @r1
    lsl *block ^@r10 (@r9+1)
    push @r12 *block ^u8 @r4

    @r1 (@r11+2) @r2 *block
    push <M> @r5 ^@r10
    jmk ^@r4 && @r3 ^*main

    @r5 @r3 (@r8/2)
    movk @r4 <> @r6 @r5
    @r1 @r4 @r2 u64 u16
    @r2 @r4 @r3 (^@r7/0_2)
    jmp ^<> (^@r2/0_2) u16
    mov (^u8/2) @r2 ^@r11
    @r5 @r2 *main @r4

    mov ^@r2 (@r12/1) u32
    lsl ^&& M @r7

    cmp u32 @r11 ^<M> @r8 @r1 @r10

    movk @r5 (@r8/0_1)
    @r9 @r8 && ^@r4 @r6 (@r9+3)
    jmp @r5 @r10 @r1
    lsl @r3 <> @r7 (^@r2+0_1) @r1 @r10 @r1
    ldp ^&& u8 @r10 (<M>+0_1)

    jmp (<M>/0_2) ^@r4 M @r5 u32 ^@r5 u16
    mov && (@r1+1) ^*main @r7 @r7 @r9 @r2
    push @r3 ^@r12 (*block+0_2) ^u16 @r4 @r9 &&
    lsl ^@r6 @r11
    lsl *main @r2 <M> <M> ^@r11
    @r7 *main @r4 && @r10 @r7 @r4 @r4

    ldp ^u64 ^@r8 @r2 @r6
    mov @r11 *block <>
    jmp ^@r8 <M> @r10 @r11 *main
    movk ^*main (^@r10/1) ^u16 (@r6+2)
    push *main (@r4+2) ^@r1 (@r8+0_1)

    @r3 @r11 @r11 @r5 (u32/2)

    dw @r2 <M> u32 ^*main @r6 @r9
    cmp M <> @r4 @r4 @r9 ^@r7 u32
    ldp @r5 ^u64 M @r10 *block *block
    movk u64 @r10 ^@r10 (u32+2) @r10 @r1

    jmp @r7 ^@r8 ^&& @r4
    @r1 u16 @r10 @r5 @r3
    push @r1 ^u32 (^@r6/0_2) @r7
    jmp @r5 <M> (@r6+0_1)
    @r4 ^u64 *block <M> @r1 @r11 @r6

    jmp <M> @r4
    push (^@r3/2) (<>/1) @r11

    jmp u8 (@r10/0_1) ^@r12

    cmp u8 ^u64 <M> ^@r9 u8 @r4

    ldp @r9 (^u8+1) *block
    lsl @r12 @r9 @r2 <>
    mov ^*main @r9 (M/0_2) @r3 ^<M> u32 u32
    @r3 @r5 @r12 @r5

    mov @r10 @r8 ^M
    jmp @r5 u16

    @r3 @r7 @r7 (@r4+3)

    jmk && *main ^@r3 u8 u16 ^@r10
    push (^*block/0_1) u16 @r6 @r6 @r5
    push *main *main @r7 @r8 ^*block @r3

    lsl *main @r11 @r1 u16 ^@r9 @r9
    @r4 @r10 @r3
    jmp @r1 @r3 @r10 @r1
    movk u8 <M> @r5
    mov @r5 @r4 u32

    @r6 @r10 ^@r12 @r11 @r1

    ldp u8 <M> @r10 *block && M ^<M>
    push u32 @r3 @r5 @r10 u8
    @r9 @r6 @r2 @r6 @r12 ^u16 <M> @r2
    push (^u8+0_2) @r6 (@r8+0_1) @r10 @r12 &&

    @r10 *main <> @r5 u8 @r7

    @r2 (*block/1) @r11
    @r5 u64 (@r7/3)

    jmp ^M @r8 @r3 @r4 ^@r6 (@r8/0_1)
    jmp *block ^u16 u8 *main @r2 && <M>
    lsl <M> @r1
    movk @r1 ^@r3 @r3 ^@r6 @r5
    jmp ^@r9 <M> u32 ^u8 @r2
    dw @r2 ^u32 ^u32 @r12 (@r8/1)
    mov @r4 (*main+3) <> M (@r7/0_2) (@r6+2) (^<>+0_2)

    movk @r9 @r1 ^u64 u8 @r10 u64
    jmk ^@r3 <M> @r8 u32 (@r2/0_2)
    jmk ^@r7 @r4 (&&+3) ^*block
    @r3 (u8/2) u8 u16
    @r4 @r3 ^@r4
    lsl @r10 @r6

    @r3 @r2 <> (@r7+0_2) (@r11+0_1) @r12 (@r1/0_2) ^*main
    movk ^*block @r1
    @r5 (*main+2) @r9 ^M @r3 (^M+2) (^@r10+1) <>
    ldp ^@r3 ^@r11 ^@r10 ^@r5

    push u64 ^@r3 *main <> <>
    mov @r6 @r9 ^@r12 *block <M> @r11
    @r1 (@r11+0_1) u8 ^@r10

    @r8 <> M u16
    jmp && (<>/2) ^@r1 @r6 ^@r8 @r8 @r9

    mov @r2 (*main+1)
    lsl u64 *block @r1 @r1 *main <>

    jmp @r11 ^@r4 ^@r10
    @r5 @r4 <M> @r10 <> u8

    @r11 (u32/0_2) @r4 @r12 @r1 M *main

    dw u32 @r4 (@r11/1) @r2 (^@r1+1) @r3
    lsl (u16+2) u16

    movk *main ^@r10 (@r3/0_2) <>
    dw && (^u32+0_1) ^@r6
    lsl @r9 u8 u8 (<M>+2) M <> M

    movk u32 @r1 ^@r6 @r5 @r2 u64
    push <> @r7 @r10 @r10 <>
    @r10 @r10 @r12 @r6 @r8 ^@r9 @r5 (@r8+2)

    ldp (@r7/1) @r9 (@r3+1) @r11 @r1 <>

    @r6 (@r4/1) ^@r5
    mov (^*block+0_1) u32 @r7
    movk (^@r2+0_2) u64 ^@r10 M @r4 u8
    @r10 ^<M> u64 (&&/2) @r4 *block
    mov ^@r11 @r11 ^u64 (^<>/0_1) u8 <M>
    dw @r12 u16 (@r9/3) ^@r8
    @r4 && @r7 ^@r8 ^@r1 @r2 ^@r11
    push <M> @r8 ^@r7 @r7
    lsl *main *main && M @r10 u8 (^M/3)
    jmp ^@r10 @r12 <M> @r6 *block @r10

    @r3 u32 (^*block/3) @r6

    ldp (*main+0_2) (&&+3) ^@r11 u32
    @r10 ^@r2 &&
    cmp ^@r2 *main ^@r10 *block <>

    cmp M (u32+0_2)
    @r8 *main ^@r10 ^@r5 u64 <M>
    cmp (^@r6/2) *main @r1 <> M ^@r6
    ldp @r7 u64 M
    jmk ^@r6 ^&& @r3 (^M+3) @r2 && @r9

    movk @r3 @r8 M ^@r7 @r6

    mov *main M @r10 (@r7+0_1)

    lsl (^@r8/3) u8 @r2 @r11 u16 @r2

    @r3 (@r1+3) @r12

    mov @r9 (^@r10+2) @r4 @r10 *block

    ldp ^<> @r5 @r10 u64 @r2
    mov M *main @r10 *main @r5 (@r5/2) <M>

    ldp @r2 <M> u32

    @r2 (@r5/3) (@r12/1) (^@r7+0_2) ^@r8 u64 @r5
    @r5 (@r12/0_1) ^u32 (u64+3) *block @r5 ^@r10 &&

    @r10 ^@r5 <> && ^@r9 @r7 u32 (@r1+3)
    ldp (^@r12/0_2) @r8 (^@r9/0_1) (M/3) @r3 @r4
    cmp *block ^u32 @r1 u16 @r7 @r12

    dw (*main+1) ^*main ^@r6 (*main+2)
    lsl M M
    push @r3 @r5 @r9 @r5 ^@r2
    @r5 u64 ^M

    @r12 u8 @r12 @r9 @r7

    jmk *block ^@r12 @r10 @r8 ^<M>

    jmp @r12 @r8 (<M>/2) ^<M> ^u32
    jmk (@r10/0_2) u64
    ldp @r5 @r8 ^@r6 *main @r4

    ldp <> u16 && @r4

    @r6 <M> @r7 @r8 @r11 ^@r1 @r10
    movk u32 @r10 @r11 @r3 @r5 @r5 ^&&
    cmp @r9 ^*main @r3
    dw *main @r4 <M> (@r4+0_1) M
    cmp ^<> (^@r5/1) ^u16 ^@r12 @r4
    dw (u64+2) && @r8

    movk @r2 *block @r6
    push ^*block u64 @r12 @r12

    @r12 *main && ^@r9 *main
    dw @r6 <M>
    jmp @r4 (^*main/3) u32 u32
    dw @r12 @r12 (&&/0_2) (@r8+2) @r4 @r10

    ldp @r7 u32 @r7
    jmk (@r3+0_1) @r3 <> && u16

    @r9 && @r11 ^u64 (@r6+0_1) @r8
    ldp ^*main @r8

    movk u16 @r11 *block
    push (^@r7+0_2) (^*main+0_2) @r2 *main *block (u8/2)
    @r3 u16 @r3

    @r11 <M> @r3 @r10 @r11 @r3 u16
    @r12 u8 @r2 @r6 ^*main @r7 @r10
    @r12 @r8 ^@r5

    ldp @r3 @r3 ^@r1 (@r6/3) (*main/0_2)
    jmk && && (^*main+0_1)

    jmk @r11 u32 (@r5+2) *main (M/3) u32 (@r2+3)

    mov && M @r11 ^@r9 (u64/0_1)

    mov @r9 u64 u64 @r2 u8 @r4
    lsl (<M>/0_2) @r3 ^*block ^@r7 @r3 @r12 (@r5/0_2)
    movk <M> @r10 @r3
    jmp @r4 @r4 @r8
    @r4 ^M u32 @r7 M u8 @r1

    ldp ^@r1 ^@r4 (@r10/3) ^@r8 (^@r1+1) @r8

    @r7 ^@r4 u64 <M> ^@r1 (<>/0_1)
    jmp u32 @r6 @r2 @r7
    @r11 (@r8/0_2) @r4 @r6 u16 (u64/3)
    dw @r8 @r2 ^@r6 (^@r2+0_2)
    push ^@r2 @r1 @r12 (@r5+1) ^u64 @r12 (@r2/3)
    @r5 @r4 ^&& u32 M u64 <M> @r7

    jmk @r5 ^@r4 (^u64+0_2) u32 (<M>+3)

    dw @r6 @r4 M ^@r4 u16 @r11 ^@r10

    mov u8 && (u64+2) u16 *main @r8 ^@r12
    movk ^@r1 (@r12+0_1) ^*main ^@r10 @r12 @r11
    movk @r4 u32 @r1
    dw @r7 ^*block (<>+0_2) @r12 @r4 <M>
    @r9 M @r11 @r12

    @r6 M ^M

    dw ^@r5 @r5 (^*main/3) (@r11/2) u16 @r11 @r10
    jmp ^@r10 @r5 @r12 u32 @r12 (@r1/3)
    cmp ^u8 @r9
    lsl @r6 (^*main/0_1)

    @r12 @r5 @r6 @r5
    jmk u32 @r7
    cmp u16 (@r7+3) (@r3/0_2) (&&+0_1) (@r9/0_2) M
    @r1 @r3 <M>
    jmp ^u64 (u64+2) (@r9+1) (@r3/3) ^@r1 u32 (u64+0_1) u64 ^@r10 @r3 *main
    jmp @r1 @r9 (@r1+0_1) @r11 M @r8 *main u16 ^u8 (*main/0_1) ^@r3 @r11
    con @r10 u16 u64 @r2 <M> @r4 u8 (^@r3+0_2) ^@r12 u8
    jmk ^@r2 @r12 ^@r10 ^&& (^@r8/2) *block @r12
    xt @r2 *main ^@r6 (@r5/0_2) @r1 (^@r3/1) @r6 @r7 @r8 <> (u16/0_1) (u16/0_1)

    mov @r1 @r2 @r4

    push ^@r12 @r12
    movk @r9 <> (^@r6/1) ^*main ^*block (@r7+0_2) ^@r9 @r6 @r11 (<>/1)

    xt @r10 ^@r3 <> *block ^@r2 @r6 ^@r9 @r6 (&&+2) (^@r8/0_2)
    ldp @r10 @r1 @r8
    dw ^@r6 @r8

    ldp *block (u8+0_2) ^&& M @r2 @r3
    @r10 @r8 (@r12/1) @r2 @r9 @r10
    @r10 ^@r4 <M> M (*block/1) @r9 && (u16+3) @r5 (@r2/0_1) @r3
    push @r1 (u64+1) && (@r12/2)
    lsl M && @r3 @r10 (^u32+0_1) @r6 @r8 ^<M> (u8/3) @r6 <>
    jmp u16 (&&/0_1) @r11 <M>
    jmk ^*main ^<M> ^@r8 @r1 @r12
    ldp ^@r5 <M> @r2
    mov u8 @r10 u8 @r12 @r8
    ldp u32 ^@r11 @r4 @r2
    dw (*main/0_2) ^@r2 @r11 @r8 ^@r9
    ldp <> ^u16 @r3 @r11
    dw u32 @r11 M ^u8 && ^@r9 u32 @r6 u8 u16 ^*block @r4
    @r4 @r8 <> u64 @r8
    cmp (^@r9+2) @r9 (@r12+0_2) (^M+3) @r10 && ^@r3 ^@r5 ^@r4 @r3
    cmp *block M
    mov (^@r5+3) @r9 (^@r12/2) M

    dw (@r10+3) ^@r2 u64 ^@r12 ^@r4 @r4 ^u64 @r5 @r10 ^*main @r7

    mov <M> u32 u8 ^u32 @r2 @r8 (@r11+1) ^@r8 ^u8

    @r11 <> u8 (^@r5/2) @r7

    con u64 ^u64 <M> @r5 @r7 *main (^@r12+3) @r1 M

    ldp @r9 ^M (@r7/0_1) u32 @r2 ^M @r11 ^@r9 (^@r12+2) ^@r10
    lsl u32 @r4 u16 u64 (M+0_1) @r6 @r7
    @r4 *block && @r10
    xt *main *block u32 @r8 @r9 ^@r6 M @r3 @r5 @r12 @r7 ^u16
    cmp u32 @r4

    @r6 M <>
    jmk ^@r8 @r5 u8 *block (u32/2) && ^u16 @r1 @r12 u64 @r5
    jmk (^u8+2) u16 u32 @r4 u16 @r5 @r11 @r4 @r10 (u16+2) @r3 ^@r4
    lsl @r1 <M> @r2 ^u32 (<>/1) ^@r2 *main <M> ^u32 (@r1/2) ^@r6
    con (@r5+0_2) @r1 (u64/1) (*block+2) @r9 @r3 M @r12 u16 @r7 M u8

    lsl ^@r4 @r6 @r8 (<M>+0_2) (@r5+3) ^@r10 ^@r10 u32 <> @r4 u32
    dw (@r5+1) && <> (<M>/2) (@r9/0_2) @r6 (@r5/0_2) @r5 <>
    mov @r7 ^u32 *main @r8

    con && && ^u16

    movk @r6 *block @r12 ^&& M u64 @r1 @r10 @r3
    ldp (u8+0_1) (M+2) @r5 @r4 @r12 @r3 <> ^M (@r10/0_2) @r8 M
    jmk u64 @r3 <> @r7 u8 &&
    jmp @r10 *main u32 (M/0_1) ^@r1 @r2 @r4 *block (@r4+1) (u64+3) @r11
    dw (@r8/2) ^&& @r3 ^u64 ^u16 u8 u64 @r11 && && <> ^@r1
    @r3 @r1 (^@r7/1) ^@r12 @r7 (@r6+0_2)
    @r6 *block ^@r12 ^&& *block @r8 @r7 ^@r7 @r7 ^@r12 u32
    dw <> @r7 (@r2/0_1) (@r9/0_2) (^<M>+1) @r10 u32 @r10 <M> (u16/1)
    jmp @r12 (*main+3) *main *block u16 @r11 ^&& @r7 M u8 ^*main @r2

    @r10 ^u16 @r9
    movk ^u8 &&
    dw @r5 ^u16 (u16+0_2)
    @r9 ^*main u8 @r1 <M> M @r2 @r12
    jmk @r1 u64

    ldp u8 @r6 @r7 (@r9/2) (@r11/0_2) (@r2+0_1) <M>
    dw ^@r5 <> u8 <M> @r11 ^@r3
    jmk @r10 @r5 ^u8 ^&& @r4 u16 @r12
    push u32 @r7
    xt (@r7/0_1) @r7 @r5 (u8/0_1)
    push @r8 ^@r3 @r12 @r11 @r11 *block u16

    cmp ^@r5 @r3 <M> ^@r5 M
    push && @r9 @r5 *block u8

    push ^*main u32 <M> @r1 @r8 *main
    movk @r1 @r2 (u64+0_1) M (&&/1) (^@r6/0_1) ^@r9 ^@r10 @r11 <>

    cmp (@r4/1) @r5 ^@r7
    con (@r10/3) ^*main @r4 ^*main (@r4+2) @r10 <M>

    lsl @r7 (<>/0_1) ^@r12 u32 (<M>+3) M @r4 @r10 u8 @r4 @r4
    @r7 *main ^*main @r11 *main ^@r10 *main
    dw ^<> @r9 ^u32 M u64 (@r3+2) ^@r7 @r2 (M/0_1) ^@r5

    xt *main <> @r5

    jmp (@r11+1) @r3 @r8 (@r1/3)
    con ^@r1 <> &&

    movk ^@r12 (&&+1) @r12 && u32
    con (&&+0_1) && @r1

    jmp <M> ^@r10
    push (u64+0_1) @r9

    @r6 @r5 u16
    @r5 @r8 (@r1+2) u32 @r3 u8 (@r9+0_2)
    jmk (@r9+1) @r10

    ldp @r4 M ^@r10 @r5 (@r3/2) (@r1+0_1) @r11 @r3 (*main+0_1)
    jmk <> u8 @r6 *block (^@r1/2) *main
    dw u32 @r10 @r8 @r2 ^@r8 ^@r10 (^@r7/0_1) @r7 u64

    con ^u32 @r11 ^@r1 ^@r12 (@r5/1) u8 (@r7/0_1) @r9 @r1 *main @r12
    cmp u32 ^M M @r5 u8 u64 @r4 @r1 @r4

    con ^*block @r1 M u64 (@r11+0_1) u16 u16 (@r10+3) @r2 @r6 u32 @r8
    @r6 @r5 (^@r9/3) @r8
    jmk <> (^@r7/1) ^@r2 *main M (@r4+1) @r11 M @r7 @r3
    jmp (@r12/1) M @r11 @r1 (@r11+3) u8 ^*block ^<M> (@r8+2)

    jmp u16 @r9 ^@r5

    ldp (^@r9+0_2) ^@r6 @r1 (&&+0_1) u8 ^@r7 @r10
    con M u32
    movk u16 u16 @r8 ^<> ^@r2 @r11 @r4 u32 @r10 u8 ^@r7
    con (@r2+0_2) *main @r10 <M> @r4

    mov M @r8 (@r12/1) @r4
    lsl (@r5/3) @r5 *main @r8 u32 (^u8+3) @r12 @r5 (@r2+0_2) M (u64/0_2)
    lsl @r8 u32 u32 @r1 @r4 (@r4/0_1) @r3 ^M @r2
    xt ^u32 u8 @r12
    lsl ^M &&
    @r5 @r9 *main ^@r8 M <M> u8
    xt @r10 @r8 ^@r9 (@r4+3) <M> <> *main *block M

    @r4 @r3 @r2 (*main/0_1) && (<M>/0_2)
    ldp @r6 @r5 <M> @r1 ^u64 @r7 @r7 ^@r6 <> @r10 ^@r2 ^@r2

    dw @r7 ^u16 u8
    lsl (@r9/2) (@r4/0_1) @r2

    ldp ^@r7 && @r8 ^@r10 u32 M @r7 (<M>+3) (^u64+2)
    push @r10 <> @r5

    mov @r1 ^u16 u64 @r5 @r10
    @r1 ^@r1 (@r9/1) @r3 (@r11/3) <> (M+0_1) (<>/1) @r10 <> @r7 u32
    @r5 @r2 ^u8 @r2 *block @r1 u64 (^u8+0_2) ^@r9 ^@r3
    jmk M @r2 u32 u32 @r3 (*main/0_2) @r9
    ldp @r9 @r8 @r8 (^@r2/0_1) ^@r9 (@r2/1)
    con ^u64 @r11 ^*main u8 @r6 @r2 @r10 (@r4+0_2) @r9 ^*main M u16
    mov ^@r12 @r4

    con @r10 ^*main @r8 ^@r10 @r3 *main @r10 (^@r9/0_2) M ^u8
    mov u16 <> <> u64 u16
    jmp @r7 <M> @r10 (^@r4+3) <>
    @r6 ^u16 @r5 (*block/3) <M>
    @r6 ^@r5 (u64/2) @r9 ^@r10

    lsl (<M>+3) ^*main ^@r12 u16

    @r7 @r8 ^@r12 (^@r7/1) && ^*main @r10

    push @r12 u16 ^@r9
    jmp u64 (^<M>/3) && ^@r2 @r12 @r3 *block (&&/0_1) <M> (@r5+0_1) (@r7/3)

    mov <M> (@r1+1) (@r4/0_1)

    push M u32 ^*main ^@r4 @r10 (^@r3+0_2) (^@r1+3) @r6 u16 @r8
    movk (@r9+1) @r9 @r8 *main @r11 @r7 @r12 @r9 @r5 @r10 @r5 ^@r6
    push @r9 u16 @r8 @r4
    ldp @r8 ^M u32

    cmp ^<M> @r8 u64 (@r5/0_1) ^@r2 u16 u8 u32 u64 @r12 @r9 @r9

    @r2 @r12 @r5 @r7 ^u8 @r4

    @r6 @r12 u16 && M @r8 @r3 @r2 M u8
    jmk ^u16 (^@r2+0_2) @r12 <> M (@r9+2)
    jmp (*block+2) *block @r7 @r12 @r8 @r12 M @r5 <M> u32 (^@r11/3) @r5
    @r7 ^@r3 @r8 (*main+1) ^u64 M @r6 M
    mov (@r8/3) @r6 @r1 @r8 ^@r10 (@r4/1) ^@r5 @r2 u8 <M> *block @r12
    jmk @r4 <M> <> ^@r7 @r6 @r10 (@r1+0_2) ^@r8 && @r2
    lsl ^u64 u16 u32 @r1 @r8 ^@r7 ^@r12 ^&& (@r8+2) (@r11+0_1)

    @r11 ^u8 && ^@r3
    push (@r7+2) ^@r6 @r8

    mov M @r9
    jmk @r5 *block (M/0_1) (@r10+2) @r5 @r5 @r7 <M> @r5 @r10 @r8 *main
    mov u32 @r8

    xt <M> @r2 (^@r7/2) @r9 @r1
    mov u64 ^@r6 @r7

    @r1 M *block u8 u16 u64 @r3 @r4 (@r3/0_2) u16

    @r5 u32 @r6 (M/0_2) (^*block+0_1)
    ldp ^&& ^@r9 M @r6 @r8 *main u32 @r6 u8 @r10
    mov @r6 <M> ^u8 @r6 @r5 @r2
    jmk u8 *main (<M>/3) @r10 ^@r10 ^<M> @r8 u8 *block M

    mov <> <M> (u64+2) (@r7/0_1)
    ldp *block @r11 @r5 @r8 (^@r4+1)
    con @r6 <>
    lsl ^@r6 u16 @r3 (^@r4/1) @r7 @r1 (*block/2)
    push ^@r10 M <M> @r9 @r10
    dw ^@r4 ^@r11 @r2 (@r5/0_1) (@r10/2) @r2 ^@r11 ^*main u64 @r6 @r10 (@r1/1)
    @r2 u64 u16 @r10 @r11 *main @r11 u32 (<M>+0_1) ^<M> @r7
    ldp (<>+1) ^u32 && u64
    xt u32 u32 ^@r12
    con @r7 (^@r10+2) (u32+3) (^@r11+2) (@r3+0_2) @r4 @r12

    movk (@r1/3) @r1 (@r3+2) && ^u8 @r11 @r10
    movk *main u8

    mov @r4 (^<>+2) @r11 ^@r4 @r10 (@r12/0_1) @r9 @r8 M (^M/0_1) @r5
    @r5 @r11 @r1 <M> @r5 @r5 u16
    cmp @r10 (@r2/1) <>

    con @r4 (@r9/0_2) (&&/0_2) <> M @r6

    @r6 @r6 (u16+0_1) @r6 <> u16 @r8 <> <M> @r2

    dw (^@r8/0_2) @r1 ^@r5 (^@r7/3) *block u64 <>
    mov M ^@r2 (@r3+0_1) ^<M> (u16+0_1) @r10 u32 ^u64 @r4 (&&+1)
    jmp (@r7/1) @r12 @r6 @r8 ^@r5
    xt ^@r11 @r11 @r11 &&
    lsl @r11 *main @r5 @r12 &&
    jmp <M> ^*main ^@r6 ^@r6 @r12 @r9
    jmp *block @r2 @r1 *block

    movk @r1 @r11 @r12
    lsl @r8 ^@r2 (@r12+1) ^@r4 (u64+0_2) <M>
    xt ^@r4 (@r12+0_2) u8 (<>+1) u16 *main @r4 ^<> @r5 u64 u8 ^*block

    @r4 @r8 u32 <M> @r3 @r10 *main

    cmp @r8 @r2 (u64+0_1) (@r9/3) u8 *main @r7 (<M>/1) @r1 u64 @r1 @r3
    mov ^@r2 @r12 u64 @r11
    jmp @r6 u8 (u8/0_2) (@r1/2) u8 @r2 @r7 @r7 (^u8+0_2) @r8
    push (&&+0_2) u32
    con @r3 @r8

    dw @r6 ^*block u64 ^@r10 *block *block (^u32+2) ^@r9 && @r12 (<M>/0_2)
    xt @r4 u8 ^u64 @r3 *main && u32 u16 u64 ^@r11 u32 u64

    dw (@r1+2) @r3 @r4 *main @r12 @r5 *main @r1 @r2 <M>

    cmp @r2 u8 @r4 @r4 (M+3) (<M>+0_1) ^<> ^@r11 u16 && M

    @r8 @r9 M @r11 @r9 u16

    movk u8 @r10 @r12 ^@r2 @r6 @r8 @r8 u64 @r8 @r12

    cmp (@r2+0_2) && (^u16/0_1) ^@r8 u64 (@r7+1) ^@r3
    movk @r6 @r8 M @r3 @r5 (^<>/0_1)
    @r7 *block @r12 &&
    dw @r6 u32 <M>
    lsl <> (@r3+2) @r7 ^u16 ^u64 ^u16 (^*main/3) (^@r11+3) u8 u64
    con ^u32 *main M @r10 (^M+2) @r1 @r6 <M> @r10 @r7 ^*block
    jmk @r8 M @r11 @r1 <M>
    push @r12 @r12 <M> @r1 (u64+2) ^@r12 ^@r11

    con u32 @r11 u8

    jmp M @r6

    @r3 @r3 (<M>/0_1) @r11 @r4 ^*block *block @r10 ^@r9 u16 u16
    jmk @r8 @r11 u64
    @r11 @r4 @r7 @r7 @r1

    jmk ^<M> @r5 @r3 ^@r8 (&&+2) ^@r12 ^@r8 @r5 @r6 u32 (^@r3+0_1)
    push ^@r7 u8 ^@r3 (^@r1+2) @r2 (@r12/1) @r3 @r1 u32
    @r7 ^<> (@r1+2) @r9 @r1 (^&&/2) @r9 (<M>/1) @r10 ^@r11

    mov (u16/0_1) @r4 @r2 u64
    @r11 @r5 <>

    @r4 @r8 (M+2) @r4 (^@r12+1) @r7

    con <M> @r1 ^*block *main u64 <> @r1 @r5 @r5 u8
    cmp ^@r12 *block (@r9/3)
    con @r8 u8 ^@r11 @r4 ^@r8 *main

    dw ^*main @r7 @r3 @r10 @r9 u64
    dw @r11 <M> @r9 @r12 @r5
    mov @r4 @r9 @r9 && @r10 @r12

    @r12 (*block+2) u64 ^<>

    movk *main (u32+3)

    jmp ^<> ^*main (@r3/2) <> @r11 u16 @r1 (@r4/2) *block ^u64

    ldp <> (<M>/1) u16 (@r2+1)
    ldp (@r2+1) ^u16 (^@r9/0_1) @r3 @r2 ^*block (@r11/0_1) ^@r11 @r4 M @r4
    mov ^@r8 <M>

    dw ^u8 ^u16 @r11 (@r8/2)

    lsl u64 u64 u64 @r5 ^@r4 <> *block @r7 @r10
    @r8 ^u64 ^u16

    ldp @r5 *main @r10 @r3
    jmk @r4 @r8 &&

    @r12 u64 @r2 ^<> u64 ^@r3 ^u32 ^u8 (u32/3) (u16/0_2) u8 @r1 @r4
    ldp @r10 @r3 *main @r10
    con ^u8 ^@r11 ^@r4 ^@r9
    jmk (@r9+3) u32 && ^@r11 @r10 @r8
    lsl && @r2 @r11 <> ^@r3 ^u64 ^@r2
    cmp @r4 (u16+0_2) @r6 @r3 u64 ^@r1 *block <M> M &&
    jmp ^@r1 @r1 @r5

    @r9 @r9 u32 M *block @r10 @r1

    jmk (@r10/0_2) M (^<>/2) (<>/0_2) @r2 @r3 ^@r8

    dw && ^@r4 && @r7 u8 <> u32 @r2 u64 <M>
    xt ^@r1 *main @r6 @r9 && u32 @r10
    ldp @r7 ^u16 (^*main+2) (@r12+0_1) u8
    mov @r10 u8 ^@r10
    movk *main ^@r4 ^@r5

    mov ^u32 @r9 @r6 ^@r1 @r7 @r11 ^@r1 <> (^@r6+1) u32 @r6
    ldp (*block/3) (@r11/0_1) @r1
    dw (@r11+0_2) @r9
    movk @r5 @r9 @r8 (@r8+1)
    ldp @r2 (@r7/3) ^&& @r8 ^M @r6 @r6
    jmp ^@r11 u32 @r5 @r9
    lsl u8 *block u32 <M>
    jmk *main u64 @r8 @r10 (^@r10/2)
    mov @r8 ^@r6 *block (*main+0_2)
    jmp ^@r2 (@r3+2) @r1 u64 @r1 *main
    cmp @r2 (@r2/0_1) <M> (^@r5+0_2) @r9 ^*block (<M>/2)
    push && *main @r10 @r8 <M> @r12 ^u32
    dw @r4 @r1 ^&&
    @r4 @r4 <> @r11

    jmk @r1 u32 @r3 ^@r10 M @r2 ^M ^u8 @r1

    lsl @r6 (M/2) @r1 @r11
    @r1 ^@r4 ^u8 (u32+3) ^@r9 @r8 *main (@r1/0_1) (@r8+3) <M> ^<M>

    @r7 M @r9 u8 @r9 @r2 u64
    lsl ^*block *main @r2 u32 *main (^@r12+1) @r1 @r3 @r7 @r4 *main @r5
    cmp <M> (u64/3) && @r7 *block (@r12+0_1) @r3 @r12 @r12
    @r4 @r3 @r6 u64 @r9 (u16/0_1) ^@r9 ^<> (@r3/1) @r1 ^*block

    movk u64 && @r2 <> <M> @r6 <> @r4 u32

    @r11 ^@r5 ^<M> @r7 *main && ^*block
    xt (u32/1) ^@r12 M (^*block/0_1) u16 ^u8 @r12
    movk <M> u32 (^@r10+0_1) @r8 @r1 ^@r7 <> *block ^@r12 @r2 ^<M>
    movk <> u8 @r4 @r6

    jmp (u16/1) ^@r7 @r1 (@r4+3) @r12 M ^@r12 u16 @r10 M <> @r5
    dw (*block+1) @r9 @r6 u8 ^@r5 (&&/0_1) @r1 && (@r4/0_1) @r2
    con (*block/1) u64 M ^@r11 @r4 u8 (@r5+2) u32 (@r9+0_1)

    dw ^@r5 <M> && <> <M> u16
    cmp M *main (^@r1+2) @r4 ^u16 (*main/1)
    @r12 && @r7 &&
    movk (@r11/3) ^&& (@r7+0_2) @r12 ^&& (^u64+0_1)

    push (@r3/0_2) @r4 @r12 ^@r6 @r1 (*block/0_2) && @r5 @r9
    movk @r2 && ^M @r11
    dw @r8 *block *block && (@r11+3) @r4 @r9 @r3 @r11 ^@r4 @r3

