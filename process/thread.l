entry: 

    @r2 @r9 u16 u8 <> ^u32 M M @r8 ^@r2 ^@r4 ^@r6 @r4
    @r4 @r3 @r3 ^@r11 ^@r2 u8 (@r3/0_2) (u64+2) @r3 ^<>
    @r11 (u8+0_2) u8 @r3 (u8/3) M u32 @r7 (@r2/1) (u16+1)
    cmp @r3 ^@r3 @r3 @r7 @r1 u8
    dw @r2 u32 ^@r4 @r2 @r4 <> ^@r9
    movk @r10 u32 @r1 @r2 u8
    movk (u16+1) (@r4+0_1) @r9 @r11 *main (@r6/0_1) (u64+0_2) @r9 M ^<M> @r10
    con (*main/0_1) *main ^@r7 @r5 <M> @r3 u64 ^M M @r2 @r6
    dw ^@r1 @r10
    ldp M @r9 (M+2) u16 <> @r8 (@r5+1) M <M> ^<M> @r6
    @r11 @r5 && (M/0_1) @r5 @r11 u32 @r1 ^@r12 @r3
    dw @r11 @r6 @r4 u8 @r6 @r11 (@r7+1) *main ^u8

//    dw u8 ^@r10 M
    @r7 @r5 (M+1) @r8 <> *main 
    ldp @r2 u32 M *main u64 @r6 
    @r1 @r2 @r11

    @r7 u32 (&&/1) ^M @r8 (^&&/2) ^*block ^@r2 @r3 (<>/1) @r5 @r8 &&
    @r1 u16 (@r8/1) M ^@r2 @r3 <> @r5 ^@r1

    push *block <> *block @r9 (@r10/0_1) M u16 u64 @r6 ^@r1
    dw ^M (^@r8+0_2) @r9 *main @r11 ^@r9 @r4 *main ^@r9
    @r2 @r8 ^@r9 *main @r11 u16 <> *block ^@r8
    mov @r1 @r6 (@r2/0_1) @r4

    lsl (*block+2) ^&& (@r1+0_2) u32 @r9 @r11 (u16/0_2) *block ^*block ^u16 (&&+0_1) ^M
    dw *block @r11 <> @r8 ^u8 @r11 @r5 && ^u8 <M>
    movk u16 ^@r2 @r8 (@r1+0_2) @r9 @r9 ^@r10 ^u64 *main @r2 ^@r10 &&

    lsl u16 @r3 ^@r4 @r7 (<M>/3) *main @r11 ^@r4 ^@r11

    dw <M> @r5 u8 u16 ^@r2 @r12 (@r1+0_2) @r10 <M>
    dw u32 <M> u16 && *block ^<> u32
    dw @r7 @r6 @r4 @r11 @r5 @r4 u16
    @r6 (@r3+0_1) <M> @r8
    mov @r3 *main ^@r6 u16 (@r2+1)
    jmk ^u8 ^@r12 u64 @r12 @r11
    movk <> (@r2/0_1) (@r8/1)
    @r8 ^@r1 *main <> @r12 *block u32
    lsl <> @r10 ^<> (@r12/2) @r4 @r12

    @r5 @r1 ^u64
    mov @r5 @r9 ^@r8 @r11 *block (*main+2) @r6 <> (@r1/3) ^M
    lsl (@r10/0_2) <> <> <M> @r5 @r11 ^@r2 ^u32 ^<> (*main+2) ^u8
    xt ^u32 @r8 @r6 ^*block u32 @r11 ^u8
    @r5 (@r6/3) @r2 @r7 (^u64+3) ^u64 <> <M> u64 (@r6/0_1) (^@r8/0_2)

    lsl (<M>+0_2) @r4 *block
    movk (^*main/0_1) @r4 @r9 @r10 (u16/1) u16
    xt (@r1+2) ^@r4 @r1 @r6 u32 u64
    ldp @r4 @r5 @r11 u64 @r5 @r3 M @r12 @r8 &&

    cmp <> <> @r12 (@r1/0_1)
    jmk (@r12/1) (@r7/3)
    @r11 ^u8 @r10 @r11 M @r8 *main @r6
    jmk u8 *main M @r11
    mov ^u32 @r2 u64 (@r6/0_2) <M> ^@r2 (@r6+0_1)
    lsl ^u64 <M> M @r8 *main
    movk @r2 u8
    xt ^@r1 (^@r12/1) (u16/1) ^<> ^@r4 u16 @r11 ^@r2 @r7 @r11

    @r11 <M> @r6 ^<M> @r1
    @r4 ^@r3 @r11 @r11 (@r11/3)

    cmp @r2 ^u8 @r7 u32 @r1 *block u16 u16 (u8+0_2) ^@r3
    mov @r11 u32 @r6 @r6 @r1
    ldp @r6 (@r12+1) <M> u64 (u32+2) ^@r1 @r11 u16 ^u8
    @r8 @r5 (u64/0_2) ^@r12 (@r4+0_1) ^<M> (u16+0_1) ^<> u64 && ^u32
    con @r8 u16 @r1 (*main/1) ^@r3 <M> @r11 *main

    dw @r3 ^u16 *block *main @r9 (^*main/1) u8 @r5 @r10 ^@r5 u8
    lsl @r1 @r10 @r10 @r3 @r9 ^@r11 @r11 ^&& u8

    cmp @r5 u64 @r3 u16 && u64 (@r10+1) ^u32 @r5
    con @r10 (@r6+1) @r10 @r6 @r1 M @r10 @r6 <>
    jmk u16 (M/2) @r8 @r1 @r9 u16 *main ^@r9 @r12 (^@r4+2) <> ^@r2
    push @r8 ^<M> <> ^@r12 ^@r3 && (^u8+0_1) *block u32 *main @r11
    xt @r1 *main @r8 u16
    dw u32 u16 ^@r2 (*main+2) ^@r12 ^@r9 <M> (@r2/0_1) *block
    @r12 @r4 ^@r1 (@r3+3) ^*block <> @r5 ^@r2 @r9 @r5 @r12

    @r12 @r5 @r3 @r5

    ldp <> @r8 ^@r4 *main (@r9+2) (@r11/2)

    xt @r8 u64 @r9 ^u8 @r12 @r1 ^@r12 @r2 @r9 u16 ^&&
    mov u8 ^M M
    @r8 @r12 @r4 (u16+1) @r5 (@r2+3) u8 u32 ^u32 && (@r3+3) u64 *block

    jmk (<M>+1) (@r7/0_2) @r1 @r1 <> *main (^<>/2) *main @r7 @r12
    mov @r9 (u64/0_1)
    con (@r10/3) @r11 ^M @r5

    jmk <M> (^@r3/2) @r10 @r9 @r5 @r2 ^<M>
    @r2 ^@r3 @r8 @r7 <M> ^@r3 ^M *block u32 @r6 @r3 &&

    cmp ^@r10 ^@r1
    jmk @r8 @r6 @r3 ^@r6 @r1 @r4
    mov u32 @r7 @r4 @r5 @r6 @r5 @r6 @r2 u8 (^@r12/1) ^u8
    @r6 @r4 @r10 @r10 <> <> ^@r5 @r7
    mov <> @r6 (u16/3) ^*block
    push <M> @r5 @r2 u8 u64 <M> @r10 ^@r6 (@r6+1) (^@r2/2) ^&& @r12
    @r1 ^@r11 <M> @r4 u16 *block ^@r9 ^*main
    mov @r5 u32 ^<M> M @r1 @r11 u8 *main u8 @r4 (@r3/2) u64
    cmp && ^*main u32 @r6

    @r8 (*main/3) u64 @r7 ^u32 (@r9/3) u8 @r10 @r4 (@r9+3) ^@r3 @r1
    jmp (@r5/0_1) (@r3/0_1) ^@r11 (@r9/3) <M> ^u32 ^@r3 u64 <> @r5
    jmk *main ^*main
    @r12 <> @r9 ^<> @r12 M
    jmk u16 @r1 @r1
    mov *block @r11 @r8 @r10 @r3 @r11

    xt @r4 @r11
    jmk @r1 @r11
    cmp ^@r6 (@r4/3) @r12 <M>

    @r10 <> @r1 @r12 (*main+1) (@r8+3) @r9 ^u64

    xt @r4 (@r9/3)

    lsl (*block+3) @r10 <M>

    xt *block *block

    mov (@r3/1) @r9 u8 u32 && (&&/1)
    dw @r1 @r5
    jmk ^@r6 @r1 @r2

    mov <> @r9 (@r8+2) ^*block
    mov @r5 @r10 u64 (@r4/0_2) (@r2/0_2) @r3 &&

    mov (@r6/0_2) ^u32 @r11 ^<M>
    jmk u64 (^@r5+0_1)
    @r6 M @r6

    @r6 ^<M> @r9 @r7 (u32+1)

    movk @r5 @r11 (M/0_1)

    @r7 u64 ^<M> *block *block

    lsl @r3 @r2
    jmk <> ^u32

    jmk (*block/3) @r10 (^&&+2) u32 ^@r7 @r12 @r3

    ldp @r10 @r10 *block

    con @r12 @r5

    jmk @r12 @r4

    con (@r4/0_2) @r12
    jmp M *main @r1 ^u64 @r2 (<M>/3) M
    @r2 ^@r11 @r1 @r4 @r9 *main u32 @r4
    cmp (<>/3) @r11
    ldp *main (^@r3+0_1) M (^@r11/0_1) @r4 @r11 (@r6/0_2)
    jmp M u32 @r8 @r1 (u16+3) M @r9

    push <M> && u64 <> u16 @r3

    jmk (@r2+2) <M> (<M>+0_2) @r9 <>
    cmp ^*block @r6
    movk *main u32

    @r11 @r11 @r4 (^@r9/0_2) (^@r4/1) @r5 @r2
    dw ^u16 &&

    @r10 u16 @r8 (*main+0_1) @r4 u64 &&

    dw @r1 ^@r6

    mov ^@r10 <M> (@r2/3)

    push (@r7+0_2) @r10 ^*main *main

    @r5 (M+3) u32 <> u8 && ^*block @r12
    movk M @r6
    ldp *block @r4 (@r3/2)

    push @r6 @r10 @r10 ^u16 (<>+0_1) u64

    xt u32 @r11 (<M>+0_2) ^@r8 @r1 @r10
    mov u32 <> @r11 ^*block @r5

    jmp @r2 @r5 @r11 @r8 @r5 ^@r7 *main

    mov ^*main @r10 @r6

    lsl ^@r1 @r11
    @r12 (^<>/2) @r6 @r12 @r9 (^@r6/1) (M+1) @r6

    con (@r2/3) && @r11 u8 @r6
    movk @r7 @r8 M (@r5/1) ^M *block (^@r4+1)
    xt (<M>/0_2) && ^*main @r8 *main M @r1
    mov u32 M @r10 u32
    mov <M> (^@r8+3) @r4 @r10 <>
    @r5 ^@r8 @r9 @r4 @r10

    dw (@r12+0_2) @r9 @r1 @r8 ^@r5 u16 u64

    jmp u8 && && *main

    push (u8/0_2) && @r3 @r12 u32

    @r12 @r2 ^@r3 u16 @r2
    push u16 u8 (@r10+0_2) <M> @r2 @r4
    ldp ^@r10 @r8 <M> *block ^@r11 @r7 <>

    lsl (@r10+0_2) (u16/1) ^u32 @r5 <> *main
    jmk (@r5/0_2) @r4 @r5 ^@r1

    con @r1 @r2 (^@r2/3) @r2

    movk @r1 @r5 <M> (&&/1) u64 <M> ^@r3

    push (@r4+3) ^u32 <> @r4
    jmk ^@r10 ^@r3 u64 @r9 @r2
    con @r11 ^&& @r11 <M> M <> u32

    xt *main @r6 @r8 *main &&
    cmp <M> @r3 @r9

    movk @r2 M

    ldp @r9 @r12 @r7 ^M
    xt && @r4 @r11 @r11 u32 ^@r10
    dw *block (@r7+2) u32 @r1 @r6

    jmk <M> @r3 u8 u32

    @r3 @r7 (@r2/0_2) @r11 ^@r5 && <>

    mov M ^@r6 u16
    jmk @r2 ^@r2 @r12

    @r11 <M> @r4 <M> (^u8+0_1)

    dw (^&&+2) M *block @r5

    con @r7 *main u8 @r8 ^@r4 (@r3+2) *main

    lsl @r4 ^<> @r6 @r1 <M> @r10 (^*main+2)
    ldp u16 ^u32 *main (@r9/2) @r6 <M> @r6
    jmk ^<M> ^M && ^&& ^&& @r6 u16

    con *block @r3 (u64/1) (^*block/2) ^@r10

    con @r10 @r12 u8 ^u32

    push @r9 <> @r8 ^u32 @r10
    con (u8/0_2) u32 @r4

    lsl (<>+0_2) @r10 (u16+0_1) ^@r3 M

    cmp (@r8/2) ^@r10 ^@r7 @r5 @r8 u64

    xt u64 ^@r4 <M>
    @r10 (*block/2) u8 ^&& @r7 @r12 @r4 @r4

    @r1 @r7 @r6 ^@r10
    @r3 ^u64 @r2 ^u64 (*block/3) ^@r5 (^@r7/0_2) @r2

    lsl u16 @r1 (@r1/3) ^&& && *main

    lsl u8 <> <>
    lsl ^u64 (u32/2) *main ^@r5

    con ^*main u8

    cmp @r6 <> u32 ^@r3 M *block
    cmp ^*main ^@r5 (^u16/0_2) (@r7+0_2) @r9

    movk ^@r1 ^@r6 u8 @r5 u16 &&
    dw ^&& @r4 @r3 && (@r11+2)
    jmp (<M>/0_2) (@r4/2) (M+0_2)
    xt *block ^u8 ^*main

    mov ^u64 *main @r12 @r6 &&

    mov @r1 *block

    mov M && u32

    ldp @r5 <> ^u16 (@r6/2)

    mov @r1 @r2 u16
    mov (@r9/0_1) @r12 u32

    movk @r10 @r10 u8

    jmp @r3 *block u32 u32 @r7 (^u64/1)

    mov (u64+1) @r12 @r7 (^*block/0_2) @r3 (@r5+0_2)

    cmp ^@r10 u32

    @r6 @r2 ^@r4 @r8 ^u64 <M> (^@r11/1)

    movk ^*block @r4 u32
    dw @r12 (<>/0_1)

    @r10 *block ^@r7 @r11 <M> (^@r2+2) @r6 @r4
    @r3 @r3 @r3 @r4 u64 (@r1/3) ^@r5 @r2

    dw <> ^<M> @r9 (@r10/0_2) ^u8 ^u64

    lsl u8 @r3 @r2 @r10 ^@r5 && (^u32/0_2)
    push @r8 (u32+1) ^@r5 u32 @r6 (^u16+0_2) (*block/3)

    lsl @r5 u32
    @r7 <M> ^@r10 ^*main @r12

    con @r8 @r1 @r3 M u64 @r8
    ldp u64 ^@r6 *main *block
    lsl ^@r5 (@r4+1) u8 *main ^u8 (@r9/0_1)

    lsl ^<M> @r3

    lsl @r1 @r10 @r12 u16 ^M @r3 &&
    mov u64 ^*main @r4 @r12 ^@r5

    mov (@r11/2) M
    mov @r1 *main @r1 u16 ^u32

    dw @r9 ^@r6 u32 @r11
    ldp @r11 (^@r3/1) @r12 u32 <> (@r3/1) (@r8+0_2)

    con *main u64 u64 (*block/2) ^u8 (^@r7/3)
    push u16 @r4

    ldp ^@r5 @r10 ^@r11 @r5 (u8/1) @r8

    jmp ^@r7 @r11 (^@r9/0_2) <M> @r11

    @r11 && @r11
    jmp @r11 *block (<>/0_1) <M> ^@r2 @r10

    jmk @r1 (u16/2) ^<M> (@r1/2)

    dw @r9 ^u16 (M/2) @r8 *main && (^u16/3)

    jmk <> *block @r3 (M+1) (@r5/1)

    lsl (&&+3) ^@r6

    con u8 u32 && *block ^<>
    @r8 @r11 @r10 ^<>

    xt ^u32 (@r2+0_1) *block u16 <M> (<>/2)

    push u8 ^@r9 (^@r8/0_1) ^@r3 M ^&& <>

    con u64 @r6 (M/1)

    @r9 @r4 (@r6+3)

    movk @r12 ^u32 && u8 (@r5+0_2) u8
    @r11 ^@r5 @r6 ^u16 ^@r4 @r5 @r9

    lsl @r7 && @r3 M @r1 @r10 ^*main

    @r1 *main @r9 ^@r11 <> @r8

    @r2 (^@r9+0_2) u8 && @r6 @r5 (<M>/1) ^@r7
    ldp @r1 (u64/2) (@r8/0_2) @r5 @r3 @r2 @r9

    @r1 (u32/3) @r10 @r3 M ^@r9 u32 ^@r3

    @r2 (@r12/3) @r12 u64 @r2

    dw u32 @r6 *main && <M>

    push u8 && (u64/2) && @r3 (*block/0_1)

    dw (@r12+3) <>

    jmk *block *block @r2 @r6
    push @r10 ^@r4 @r7 u16
    mov ^*block *block @r1 @r12 u8 @r2
    @r4 (@r10/0_1) *main @r9 (@r10+2) @r8 @r5 ^<>

    jmk @r3 u64 (@r1+1) @r3 @r10 (@r10/0_1)

    jmp u8 u32 (@r6/1)
    dw @r4 ^@r6 M
    @r1 @r5 @r6 (*main/2) @r9 (^@r4+1) @r1 <>

    xt *block ^@r8 @r4 M
    lsl @r3 *main (@r11/0_2) ^@r6 ^@r2 M @r4

    @r4 (^u64+3) @r1 u16

    jmk <M> (@r10+0_2) @r11 ^@r12

    @r5 ^@r1 ^@r6 u8 @r12

    @r2 @r9 M ^&& @r9 *main u32
    @r5 (@r12+1) @r12 @r2 ^@r4 M @r1 @r12

    movk @r3 u32 ^@r8 @r10 @r4 *main @r7
    movk @r5 *main (^@r8+3) @r9 ^@r10 u32

    @r7 @r12 (M/1)

    mov *block @r6 ^*main
    con M @r2 <> @r7 @r9 u8 (@r2/0_1)

    con (@r2+0_1) ^*main
    cmp u8 u16 @r5 (@r2/2) u8
    @r7 ^@r4 @r7 ^@r7 (u16+1) ^@r11 u8 <>

    push && @r4 @r8 M
    push ^<> ^u32
    ldp (u64/0_1) *main @r4 (^@r3/3) @r8

    @r8 (@r7/0_1) ^*block @r8 ^<> u16
    xt <M> M @r9 (<>/0_1)

    @r4 @r2 <> <M> @r2

    lsl @r10 @r3 (@r5/2) u16
    push u8 @r10 @r12 ^@r9 (@r12/0_1) u16 ^M
    con *block @r12 @r1 @r7 @r9 u16
    ldp (@r6/0_1) && *main ^@r6 @r1 @r3 u64

    cmp u64 M @r4 u8 M
    dw (@r11/0_1) (^u64/0_1) &&
    cmp *block @r9 ^M
    push (@r10+1) @r2 ^@r11 ^@r10 ^@r11

    @r7 @r2 @r5 u64 @r12 @r3
    mov <M> && @r2 @r12 u64 @r2 @r5
    ldp u32 && @r5 @r3 @r10 @r5
    con @r8 @r8 *block @r10 @r11 <M>

    @r7 @r8 u32 *block M

    jmk @r6 u16 @r2 @r8

    @r2 (u8+0_1) ^@r5 @r1 @r9 @r6 <>
    mov @r3 u64

    dw (@r10+0_1) @r10 (u32+2) ^@r2 (@r2/0_1)

    @r10 u64 u32 M M u16

    con <M> @r7 @r11 (@r4/0_1) (^u32/1) (u32+0_2)

    movk (u16+1) ^@r10

    xt @r2 u32 @r4 @r8 @r11 (<>/3)

    con @r10 @r9 @r9 @r3 u32 u8

    dw u32 ^@r12 @r4 u8

    dw <> ^*block @r7

    @r11 @r5 @r4
    push *block u8 @r3 (@r10+2) @r1 ^@r3 ^@r4

    @r5 u32 @r1 ^@r8 (&&+0_1) M <M> @r10
    @r5 @r11 @r9 M
    @r4 ^@r5 @r12 ^@r5 <> <M> @r11 @r2
    lsl && (^<M>/1) *block ^@r4 <>

    push (^u64+0_2) (^*block+1) *main @r12 @r2 @r11

    @r5 *block @r6 <M> @r3 u64 @r10 ^@r10
    @r3 *main ^<M> @r9
    dw u32 ^<M> (@r9+1)

    dw @r8 u32

    lsl && ^@r2 *block

    lsl @r11 *block @r1 *main @r7 ^*block

    lsl ^@r4 u8 @r4 @r6 (<>+2) @r10
    cmp @r8 ^@r5 @r10 (^u8/2)

    @r8 <M> @r10 @r4

    mov && @r11 (@r4+1)

    mov ^*block @r4 ^@r2 u16 u8

    @r11 @r3 @r11

    mov M u64
    jmp <M> ^u32 (^@r3+0_1)

    con *block @r7 (<M>/3) ^*main u8 @r4 &&

    @r7 <> @r10 ^@r2
    push u16 ^@r6 (@r9+2) u8 @r7 ^@r8 (@r8+2)

    mov @r1 <>
    dw u64 u64 <M> &&
    cmp ^@r7 M *main

    con ^u8 && <M> (@r9/0_2) ^&&
    dw ^u64 @r12

    cmp (@r6/0_2) u16 ^@r6

    xt (@r5/0_2) @r6
    con @r3 @r10 ^@r1
    movk @r7 @r5 ^@r10 (@r4/0_1) (@r2+0_1) (@r8+2) ^u32
    ldp @r5 ^@r7 ^@r9 u32 (u32+3) u64 u32

    @r8 ^@r12 @r12 ^<M> (@r9/0_2) ^@r8
    movk M @r6 u64 ^@r12
    movk ^@r6 @r2 u8 @r5 (^@r3+3)

    @r10 @r2 @r6

    @r3 *block <M> (@r1+3) @r9 @r5 @r12

    ldp (u32/3) (u8+0_2)
    con @r7 @r10 @r4
    jmp u64 M @r8 @r4 @r7 @r3
    cmp (^@r9/0_1) @r7 @r11 u8 M ^u64

    push @r11 M @r12

