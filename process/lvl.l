entry: 
   
    ldp (^@r2/0_2) @r5 <> ^@r6
    dw (<M>/1) ^@r1 (^@r4/0_1)
    lsl (^@r7/2) u8 *main u16 @r8 *block
    push *main (*block/0_1)

    jmk u8 u64 u16 <M>

    dw M ^&& @r5 @r9 @r7 @r6 @r6 <> ^@r1 @r9 (^@r10+2) @r7

    jmk (@r5+0_1) *block (^<>+3) (@r5/0_2)
    ldp u32 (@r4+1) (@r9+3) @r3 @r1

    ldp ^@r11 u8 M @r8 u8 u64 ^u8 ^@r9 u32 u8 <M> @r1
    cmp ^@r4 (@r4/0_2) u16 @r12 *block <M> @r10 @r8 u8 ^&&
    @r3 (^*main+0_1) ^u64 @r4 @r5 ^@r11 (<>/2)
    lsl (&&/3) u16 @r3 @r12 @r8 @r12 u64 (^u64/3) ^@r3 @r10 <>
    jmp (^@r11+2) @r2 @r1 ^*block @r4 @r3 (<>+1)

    @r5 @r8 &&

    jmp ^@r2 @r10 @r4 ^@r6 ^@r9 @r9

    lsl @r12 @r9 ^<> <M> @r11 ^u8 @r3
    cmp (@r3+2) @r11 ^u32 u8
    push @r2 @r3 @r2 @r4 u32 @r4
    push @r2 @r12 @r5 @r11 (@r12+3) *main @r6
    dw ^u16 @r3 ^M (@r4/1) @r11
    @r7 *block u8 @r2 (^@r7+0_1) @r3 *block @r3 *block M

    con @r4 @r4 ^@r1
    jmk (@r9+0_1) @r8 @r5 @r9 @r4
    con u64 ^@r6 u16 && (^@r8/2) ^@r5 @r9
    xt *main <M> ^u8 u8 (@r6+0_2) <>
    @r11 *block @r1 <M> *main
    jmp ^u8 @r9 u16 *main @r8 ^&& ^@r12 @r8 *main @r2 ^@r11
    @r7 ^M ^@r11

    dw @r12 u32 @r3 @r12 (@r12+0_2) @r2
    push ^@r7 u32 (u8/0_2) @r8 @r11 @r3 *main ^@r8 (*main/0_1) @r1 (*main/2)
    dw @r10 *main
    push @r12 @r4 @r12

    mov u64 <M> @r2 @r2 @r5 u16
    @r10 *main @r3 (@r5+1) ^@r1 <> @r1 @r3 

    jmp @r4 *main <> @r9
    @r6 u64 ^@r5 @r11 u32 ^@r8 <M> *block &&
    @r11 ^@r4 (@r9/2) @r1 u16 *block ^*main <> ^@r11
    ldp *block @r6 u8 @r11 <M> ^@r11
    @r8 @r2 u32
    jmp @r9 (*main/0_2) <> *block


    push @r1 ^*block @r12 (<>/0_1) *block ^@r7 @r8 *block @r10 <>
    jmk ^&& u8 @r11 (@r6/0_2) ^u32 (@r6+2)
    con (@r11+3) u16 @r10 @r10 ^@r11 @r11 @r11 @r7 ^@r3 ^@r2

    con (^@r10/2) @r12 @r1 ^u64 (^@r11+3) @r7 @r10 @r10 u64 (@r11/3) u32 *main

    push && u64 <M> @r3 && @r11 @r8 (@r6+0_2) @r8 ^<> u16
    xt *main u64 (*block+0_1) @r1
    @r10 (@r11+3) (u64/3) ^u64 (^@r10/1) <> ^@r6 @r3
    lsl <> @r5 @r4 ^@r11 ^<M> u8 ^@r7 *block @r3 (@r11+1)

    con ^*main @r10 @r2 (<M>+0_2) ^M (<M>/3) @r12
    @r2 *main (@r9+1) @r4 (<>/1) (^@r12+3) <M> @r11 @r11 u16 ^@r5
    push (M/1) u8 *block && @r12 @r2 u8 ^@r2 ^<> @r4 @r12
    ldp ^@r5 @r1 @r8 @r5 @r1 @r11 <M> <M> ^*main M
    movk u64 @r9
    mov u64 @r12 (@r11/2) *block

    lsl u16 @r6 u8 (@r2/0_2) u8 ^u32

    cmp @r3 <M> u8 (@r9/0_2) u8 *block @r11 u8 &&

    lsl @r6 ^@r6 @r7
    jmp u32 && @r3 @r3 ^<> <> @r10 u16 (^@r4+0_2) @r5

    push u64 ^&& u64 @r12
    dw ^@r10 @r2 @r1 (@r1+3) ^@r9

    movk @r12 (^@r2+0_1) *main <>
    @r5 @r5 u16 u16 ^@r9 <M> ^u32 @r2
    @r12 @r5 @r5 @r5 ^*main ^u32 ^@r6
    xt ^u16 @r9 @r9 ^@r7 @r10 <M> ^@r8 @r9 (<M>/1) u64 @r8

    jmp u32 @r10 ^<M>

    xt u64 @r10 (@r7/3) ^u64 @r5 u64 @r6 (@r6+0_1) (^@r8/2)
    @r2 @r8 && (@r2/3) @r7 u8
    lsl *main (*main/0_2) (u8/2)

    @r4 *main (@r1/0_1) @r7 u32 (^@r8+0_1) @r1 (@r7/0_2) ^@r4 <>
    mov (*main+0_2) @r2 @r2 @r1 @r2 @r3 ^*block

    movk @r2 @r11 *block ^u64 (@r9+1)
    lsl (^@r3+2) @r8 (^@r12/2) &&

    ldp (@r2+0_1) @r11 @r4 ^@r3 <M> @r7
    con (@r8/0_2) @r12 u16 *main @r5 ^<M> ^*main (@r6/0_2) ^*block u64 u8
    mov ^u16 ^*main
    push @r2 @r1 u8 ^@r3 @r2 u64 (@r11+2)
    @r2 ^@r7 (*block/0_1) (@r9+3) (<M>/0_1) (u8/0_2) (M+3)

    @r8 @r9 @r12 ^@r6 @r8
    mov @r5 u32 (@r4/2) (@r4/3) M @r9 && (@r11/0_2) @r12 @r8 (@r8+0_1) ^*block
    @r7 ^&& (@r2+0_2) u32 ^@r3 u8 (@r7/1) @r10 @r5 @r11 @r11 @r7
    @r6 @r4 <> ^<M> ^u32 ^@r12 *block u64
    @r1 @r12 <M> ^@r10 u32 @r11 (M/3) @r10 ^u32 u64 ^@r3 u16

    con ^u16 @r7 (^@r7+2) @r5 (<M>/2)
    @r1 <> (u32+2) u32 @r8 @r4 ^u64 @r8
    movk @r2 *main @r1 @r4 @r11 @r3 @r12 (^@r4/0_2) u16 @r7 u8
    dw *block ^@r7 @r11 @r2 ^<> @r9 ^*main @r11 @r12 (@r9+0_1) ^u64

    movk @r2 u64 ^@r4 (M/0_2) (&&/0_2) u64 u64 <> ^M @r2
    cmp (@r9/3) @r5 ^@r2 && @r9 @r5 &&
    @r9 @r7 @r2
    mov M @r3 (M+1)

    ldp (*main/3) ^@r7 (u64/0_2) ^@r1 (@r7/1) (<>+2) @r6 @r1 @r11 @r12 @r2
    cmp ^@r12 ^@r3 (^@r12/0_1) (@r2+2) @r3 u64 M
    dw ^u32 u64 u8 u32 @r3 @r12 @r4 *main M u32 @r1

    @r3 @r8 @r10 (@r9+0_1) (@r1+0_2) @r8
    @r7 ^u16 (u8+0_1)

    movk @r12 && ^*block @r10 u64 @r8 u32 @r5 ^@r1 @r9 u64 &&
    mov u64 @r11 <> @r5 && (u8+3) (u64/3) u8 (@r10/0_2) (*block+0_2)
    movk u32 M u16 u64 @r7 @r9 (^@r12+0_1) M @r7 @r8 <> (@r3/1)

    push ^@r8 u64 *block
    @r2 @r12 (u32+1) ^@r5 u16 u8 @r7 *block *block (*main+0_2) @r5 @r11
    cmp @r12 @r11 ^@r8 ^<M> ^<> @r2 @r9 (u16/3) ^@r12 ^<> *main (@r10+3)
    ldp @r2 @r12 (^u8+0_2) (^u64/0_1) u8 *main @r11 @r4 ^@r7 u16

    @r12 @r8 ^M (^&&/0_2) (M/0_2) @r8
    jmp ^@r3 <> @r3 ^*main @r10
    @r3 u32 @r7
    xt @r7 u32 (@r5+0_1) (<M>/1) @r12 @r12 ^@r10 ^@r10 <> ^u16

    movk @r1 *main

    con <> u64 u8 @r10 u64 u64 (^u16+0_2) @r4 (@r6+2) (@r1/3)

    lsl @r9 u8 @r9 M ^@r11
    movk ^@r2 @r7 (^<>/0_2) @r2 @r7 u32

    jmk @r9 u8 <M> ^@r4
    dw @r6 @r2 (^u8+3) @r4 @r11
    mov @r9 (*block/2) @r4 @r9 ^<M> *main @r7 *block (@r4+3)
    @r3 @r3 @r3 @r11

    @r10 @r6 ^u32 M (^@r6/1)
    dw @r1 @r1 @r11 @r11 ^@r1 (u64+0_2) @r6

    @r2 (^@r4+0_2) @r5
    con @r9 @r1 <M> u16 *block @r2 (@r3/2) @r8 ^<>

    con (<M>/2) (M/0_2)

    @r2 ^<> @r2 u16 ^&& <> @r6 @r6 u64 @r8 ^@r12

    cmp @r8 ^M u64 @r4 @r1 @r2 u8 <> u64 @r11 *main u16
    @r5 (^u16+0_1) @r4 ^u64 @r10 && u8 (<M>/0_2) u32 M ^@r12 u32 @r9

    con @r8 ^@r9 u32 @r9 (@r9+0_2) *block

    jmk u16 ^@r5 *block @r6 ^@r2 @r7 @r2 *block (@r8/1) (^@r10/1) @r4
    con @r2 @r7 @r8 @r4 ^M *main ^*block u8 @r12

    cmp ^@r12 @r9 (@r4/2) @r3 @r9 @r8 <M> (^@r12/3) <M> @r6 @r6
    ldp @r9 (@r4+0_2) @r11 @r6 ^@r12 *block @r10 <M> ^@r7 *block (*main/0_2)
    xt @r1 @r12 @r8 ^M *main @r7 @r3
    @r4 @r2 *main (@r5+3) @r9 @r10 ^@r1 u16 && *block (^@r4/3) ^<>
    mov @r9 *block && M M @r5
    lsl ^@r2 @r3
    jmp u8 *main ^@r4 @r9 <>
    xt *main @r11 (u8+3) (u8+0_1)

    @r7 @r4 u32 ^@r10 ^M u32 <> @r7 @r10 ^M
    jmk *block ^@r9 (<>+1) *block @r10
    jmk @r7 u8 @r9
    jmp ^@r6 u32
    jmp @r7 (<>/2) @r2 @r12 ^*main (@r11/0_2) <>
    movk ^@r12 ^@r5 @r5 (^&&/1) @r4 ^@r9
    @r3 (M+2) @r5 M u8 ^&& <> <M> u32 *block (^@r1+3) @r11

    xt u8 @r11 ^@r6 ^@r9 @r10 @r10 *main <> ^@r3 u16 @r12

    @r11 @r12 ^@r3 ^u64 (@r12/2) @r7 u16

    movk (<>+1) @r6 ^@r4 @r9 <> ^u32 @r5 (^@r3+0_2) *block (&&+3)

    ldp @r4 u32 (@r10/0_1) u8 ^u16 @r11 u8 <> (@r1+3)

    ldp @r7 (@r9+1) (@r1+3) @r12 M (u64/2)
    jmk *main @r7 @r3 ^u8 ^@r8 @r9 ^<M> <M> ^@r12 @r6
    @r5 @r1 (*main+3)
    @r9 <M> (@r8+2) ^*main u32 @r9 <> ^@r4 @r12 @r8 *main

    cmp u32 *block @r5 u16 ^<> ^u64 (u16+1)

    @r6 && @r10 (^@r10/1) *block <> @r12 *main @r7 u64 (*block/0_1) *main
    cmp ^<> (@r8+2) <> (@r2/1) M <> <M> @r12 @r3
    @r12 u32 ^@r3 *block ^@r7 ^u32 <> ^*block ^@r1 @r5 @r5 u8 @r3
    mov (u32/3) @r12 <> @r2 @r3 && (@r4/0_2)

    dw u64 u32 @r4 u16
    cmp <> ^@r6 @r2 && ^u16 &&
    mov <> @r7 @r5 @r11 *block (^@r2+0_1) ^@r6 (u64+2) u8 @r9 @r12
    cmp u16 @r4 (@r4/0_1) @r4 @r10 ^u64 ^*main @r5 <M> u8 u32
    jmk @r10 <M> M ^&& @r4
    lsl (@r1/2) @r11 (@r3+3) (@r6+0_2) u16
    ldp (u16+3) @r11 @r2 (<>/2) <> @r3 ^@r10 @r10 ^@r7 M

    lsl @r1 @r11 ^@r7 && ^*main u16 @r9 @r1 @r4 (@r2+1)

    con (^@r8+3) ^@r6 @r10 @r6 (^@r2/1) ^@r1 ^@r12 (u32/2) (@r6/0_2)

    push ^@r11 @r8 <> u16 @r1 ^<> @r8 M (*block+0_1)
    con && u16
    @r9 u32 ^u16

    jmp @r11 @r10 M u32
    xt (@r1/0_1) u8 M @r3 u32 *block @r9
    ldp ^&& (*block+2) && (^u32+2)
    lsl (u16/0_2) u64 *block (@r9/1) u32 @r11 <M> ^@r4 M *block
    jmp (u64/3) @r2 @r2 u32 ^M <M> (*main+0_1) @r10 (<M>/1) (*main/0_2) && @r9
    push @r3 (^u64+1) <> ^*block

    push ^@r9 @r9 @r7 ^u32 *block && u32 ^@r5 @r7 @r1

    lsl @r3 @r2 ^<>

    jmp ^@r2 u16
    dw ^u32 (@r12+1) u32
    @r8 ^@r4 @r6 *main @r12 && @r9 @r12 @r6 *main @r12
    xt @r10 *main @r9

    cmp @r9 @r10 u32 (@r2+0_1) @r5 ^@r7 M (&&/3) @r5
    @r6 @r11 *block @r7 ^&& @r11
    dw @r6 @r9 (@r1+1) <> ^@r5 @r5 @r1 *block (@r5/1)

    con (@r9+0_2) (@r1+2) (u32+2)
    movk ^@r12 @r4 ^<> (@r8+0_2) @r10 u32 (@r10+2) @r1 @r7 ^<M> (<>/3)
    @r6 <> ^<M> && @r10
    xt ^<M> @r3 @r7 (*block+1) *main &&
    push @r7 @r6 ^@r4
    @r7 ^<> @r9 <> ^<M> (@r3/0_1) M @r2 ^&& ^@r6 @r2 @r2

    jmk @r4 u64 @r11 (<M>+3) @r10 u16
    lsl @r4 @r7 @r2 ^&&
    lsl @r4 ^u8 @r4 (u32/2) ^M <> (*block+0_2)
    @r7 u8 @r5 &&

    dw ^*main @r8
    @r1 u16 (<M>/1) @r8 M (*block/2) <> ^<>
    xt @r7 u16 *main M <>
    push (@r7+0_1) u16 (@r4+1) @r1 (@r12+1)
    mov @r7 u8 <> <M> (M/0_2) ^<> M @r5 <> u16 @r4

    xt @r4 @r8 @r2 @r2 @r2 @r8 u8 @r11 u32 u64 @r10
    push @r10 u8 ^@r12 *block M *main && @r9 @r3 <> @r6

    @r4 <M> ^@r2 @r7 (@r6/3) @r8 (^u64/1)
    jmk u64 <M> ^@r5
    lsl ^u8 u32 u64 @r9 ^@r6 (^@r10/0_1)
    lsl (^&&+3) ^u16 @r6 ^@r6 @r5 @r9 u8 M ^&&

    lsl @r7 @r7 @r4 @r12 @r8 *block @r3 u32 *block <M> ^@r11 @r9
    xt *block (@r1+3) @r3 (^*block+1) @r5 <M> @r8 u16 u8
    xt @r1 @r6 *block u32 *main (u64+2) @r10 <> (@r2+0_2) u32 @r11 u64
    @r12 ^@r5 *block @r7
    @r12 u16 @r8 ^@r4 @r1 ^<M> M @r6

    dw && u16 u64 @r12 u64 u8

    @r4 *main *block ^@r12
    push ^@r10 u16 (^@r1+1) @r3 @r3 ^u16 @r10 <M> @r12 u16 *main @r3

    cmp @r1 (@r6+0_2) ^M (@r7+0_1) (@r2+1)
    dw ^<M> u32 @r6 u64
    lsl @r6 ^@r8 @r8 u16 (@r2+3) (@r1/0_1) ^@r6 @r8 @r2 @r10 @r4

    @r8 @r9 u16 @r10 @r12 ^u64 (@r3+1) @r11

    xt (^@r1/3) (<>+0_2) @r5 ^u32

    ldp @r8 @r1 <> u16

    cmp (^@r2+0_2) @r9 @r11 @r7 @r6 @r2 u32
    lsl (<M>+0_1) u32 (<M>/0_2) @r7 (^<>+0_2) @r8 M @r5 u32
    @r11 *block ^@r11 ^*block @r2 @r5 (<M>+0_1) @r8 @r2 ^M
    con u16 (@r2/0_2) @r3
    @r12 (^u32/0_1) ^u16 @r1 @r2 ^@r8 @r6 ^&&
    dw u32 @r3
    xt @r10 (@r1/0_1) ^*main @r3 u8 u8 (^@r8/2)
    @r1 <> ^@r11 u32 ^@r6 ^&& ^@r1 M @r6 ^@r7 ^u32 *block
    dw ^<M> u8 &&

    cmp u64 u32 && *main @r4
    jmp ^*block <M> <> ^@r5 (@r11/0_1) <> u32 @r11 <M> *block @r2
    push <M> @r2 M

    mov && (u16+0_1) ^@r1 @r12 @r5
    @r2 @r5 (@r5+2) @r3 ^u32 ^u16 @r2 ^u8 u64 @r2 @r1 @r2
    movk u32 (u64+2) ^@r5 @r2 (u8+0_1) && u8
    @r4 @r10 @r9 @r10 @r5 u8 @r11 @r3 @r12 u8 ^@r8 @r1 u16
    con @r8 @r1 ^@r10 (u64+0_1)
    xt @r8 @r11 u64 @r7 ^u16 @r11 *block @r5 ^u8
    @r7 (u16/1) <M> @r5 (@r2+3)

    dw && @r11 *main ^@r12 (u32/0_2) <M> u64 (@r2+0_1) ^@r11 ^@r5 (@r7/0_1)

    mov ^@r11 M @r12 @r8 @r9 @r10 @r11 *block @r8 u16
    mov (u8+1) (^*main/1) && <> ^@r2 @r10 @r10 @r6 ^u16 (@r12/0_1)

    con (^@r4/1) (u16/0_1) @r2 && u8

    xt *block @r12 ^@r2 <> @r3 @r7 <M> ^@r5 M
    jmp && @r11 ^@r5 (@r10+1) @r9 M
    mov @r12 M ^@r9 u8 ^@r10
    jmk @r10 ^@r7 *block ^@r11 @r4 ^<> (*block+3) u32 @r9
    lsl ^*main @r12 @r4 (@r11+0_1)

    xt @r4 (@r8+3) u8
    push ^@r8 <M> (@r11+0_1) ^@r5 (^<M>/0_1) ^u8 ^@r12
    dw (@r8+0_1) <M> @r5 @r10 u32
    cmp ^@r12 (^@r3+0_1) @r6 ^*block u32 @r6 *block ^@r12 ^<M>

    mov @r5 <> @r12 && @r2 && && @r12 u32 ^@r11
    movk @r5 <M> (&&+0_2) @r9 &&
    lsl @r7 @r9 ^@r8 @r8 ^@r4 <M> @r11 *block @r11 @r12 @r7 u32
    push *main @r10 @r8 @r5 ^M *block *main @r6 @r4 *block

    xt @r4 ^*block (@r1+0_1) ^u64 ^u32 @r4 M u16 *block (M+1)
    @r1 ^<M> u8 ^@r4 ^@r12 M
    @r9 @r2 M ^u32 <> u16 (@r1/0_1) @r6 M @r8 @r7 ^@r8
    @r7 *main u8 <M> @r4 u32 @r2 @r10 <M> (^M+3) @r9 @r3

