entry:

    lsl ^@r7 <M> ^@r10 u16 &&
    @r3 u16 @r10 <> @r7 ^@r1 

    con u16 @r1 @r4 @r3
    @r7 ^@r9 <M> @r3 (*main/1)

    lsl @r12 <M> @r6 @r7
    dw <> @r5 @r10 u16
    mov ^@r8 @r8 @r6 @r4 u64 <M> *main @r10 ^@r7 u32 @r12 

    cmp @r10 <M> <M> ^*main @r9 u16 (@r12+3)
    @r9 u32 <> @r10
    
    ldp @r3 @r12 @r8 u32 @r12
    @r4 @r10 *main <M> (@r5/2) u32 @r2 *main @r3 ^@r1
    
    cmp @r6 @r2 @r3
    @r2 *main <M> @r10 @r4 u64 @r1 *block ^@r10 @r9

    ldp ^<> <> @r12
    @r4 @r10 *main <M> u32 @r1

    @r6 u16 <M> ^@r7 *main <M> 
    xt @r5 <> *main @r4 ^@r2 @r3 (u16/2) &&
    mov ^@r1 u16 <M>
    con @r1 @r11 @r10 <> ^@r11 u16 (*block+1) ^@r5 M u32 ^@r8 
    
    @r8 @r6 @r1 *main @r12 ^@r9 @r1
    
    @r10 @r1 <> *main u16 (@r1+0_3)
    xt @r1 @r12 *block u64 M @r10 &&
    @r2 ^@r10 <M> ^@r8 @r1 u32
    lsl ^@r10 @r8 @r1 <> ^*main @r1 &&
    @r7 *main ^@r10 M @r1

    movk @r4 @r10 <M> *main u64 (@r6+0_1) 
    cmp *main <> @r5 u16 @r10 (^*block/1) &&
    @r2 <M> @r10 u64 *block <>
    @r8 @r5 @r10
    dw *main ^@r7 *block <>

    movk u64 @r5

    jmk *main ^@r4 ^@r12 (@r3/3)

    @r12 u8 u64 *main (@r1/2) @r3 
    cmp @r7 *main ^@r5 @r10 <>
    @r8 @r5 ^@r10 (*main/0_2) @r1 <M> &&
    cmp *main u16 @r12 <M> @r1 *block
    ldp u64 (@r10+1) @r4 *main
    @r2 ^u32 @r1 u64 


    ldp @r11 ^@r4 ^@r3

    lsl @r5 ^@r11 u32 @r7 <>
    @r11 ^@r7 (@r3+1) (<M>/2) @r5 u32 &&
    @r4 u64 (<M>/1)
    xt @r4 u16 <> *block @r5 u32 *main (@r2/0_2) @r6 @r4 <M> @r11

    lsl @r11 u16 u64 @r8 ^@r7 @r3 ^@r2
    con ^*block (@r12/2) M ^@r1
    con && ^@r2 M ^@r1 (@r11+3) <M> (@r8/0_1) u64 *main u16

    dw (u32/1) (@r12+3) @r11 u64 ^@r7 &&
    @r6 *block @r4 (^@r4+1) <> ^@r5 (@r8+1) @r10 u16 
    push @r7 (@r2+0_2) u8 (@r10+1) u64 @r11 @r1 *main u64 (@r4/1) @r3 *block <M> @r4

    mov && u16 u8 @r5 u16 (@r12/0_1)
    xt @r12 @r1 <M> ^M (<M>/0_2) u64 ^@r3 @r10 @r7 @r6 (^u64+0_2) @r11
    cmp @r1 ^@r1 @r3 ^*main *block (^&&+2) ^@r2 (*block+3) ^M ^@r6 @r1
    
    con M ^@r5 u32 ^u16 (^@r5/3) *main @r10 @r3 u8 ^<M> @r4
    jmk @r2 ^u64 @r7 *block u32 ^@r9 (^@r2/1) u8 ^@r2 (M+0_1)

    jmp *block ^@r10 @r3 (M/0_1) u16
    ldp @r8 @r7 @r9 u8 ^@r4 ^&& ^@r8 ^*block *block @r9 *main (@r8/1) (u32+1)

    push @r7 u64 <> ^<M> ^@r8 @r4 *main
    @r1 @r12 (@r4/3) (^@r7+2) *block

    jmk ^@r3 *main M u16 ^<M> (@r12+2) ^u64 @r11 u64 @r1 <>
    movk @r2 *block u64 && ^@r1 u64 && @r4 (*main/0_2) ^@r5 *main <M> @r1 (<>/1) @r11

    xt *block ^u16 @r9 @r8 ^u8 @r4 @r5 @r12 *main ^@r8 *block @r11 @r5 <>
    @r4 ^@r5 <M> @r4 @r5 <M> ^@r8 @r2 @r11 *block @r4 
    xt *main M @r1 ^@r4 (@r12+3) <M> ^@r10 @r5 (&&/2) ^@r5

    dw ^@r11 u64 @r10 ^@r1 <> @r5 (<M>+0_2) ^@r10 <> u64 ^@r2 @r9
    push *main (@r12+0_1) <M> ^@r9 ^@r9

    con (^M/2) <M> @r6 *block @r2 u64 @r4 @r11 ^u32 @r12 u8 @r6 ^@r1
    jmk @r6 @r4 <> @r8 ^@r3 (@r11/1) ^@r1

    dw u16 ^*block (^@r6/3) u16 <> ^@r2 @r4 M @r7 u64 ^@r12

    xt @r1 <> *block @r9 @r3 ^@r4 <M> @r9 u64
    ldp @r12 @r9 <M> @r6 (&&/1) <> ^@r11 ^M u8 <M>

    @r1 @r5 ^@r12 && ^@r12 ^@r1 ^<M>
    dw ^@r6 *main ^*block @r5 && @r2 (@r5+0_2)

    con u16 @r6 M
    @r12 *main @r7 *block
    mov @r9 @r5 (^<M>+3) *main (*block+0_2)
    mov <> *block && *main @r7

    jmk u64 ^u16 u8 *block @r10 @r8 @r2

    lsl ^<> u32 @r2 ^@r5 @r5 @r4

    ldp ^@r3 <> M @r7

    xt ^u32 @r11 <> ^@r11 @r11 u32

    lsl @r12 @r7 @r2 ^*main @r2

    xt (^&&+2) @r10 (^@r8+2) @r10
    cmp (M/1) u8

    xt @r1 @r2 (u8+0_1) @r1 @r8
    jmp @r4 u16

    lsl @r6 (@r4+0_1) ^@r10 *block
    xt @r9 ^&& @r9

    @r3 ^@r1 (^&&/0_1) @r1 ^@r5 *main u16 ^@r11

    push @r7 (@r4+3) <> && (@r2+0_1) @r10
    jmp <> @r8 M

    mov u32 *block @r3 ^&& (@r10/2) u16 <M> (@r11+0_1) @r8 <M>

    ldp @r3 (^@r9/2)
    jmp ^@r5 u16 ^u32 u64 (@r3+0_1) ^<M>
    con (^<>+1) ^@r6 u32 u64 @r8 (^@r5/2) <M>

    @r5 @r12 (@r2+1)

    ldp *block @r6 @r9 *main *main @r12

    xt u64 ^<> (u64/2) *main @r11 <M>
    @r8 u16 @r4 ^*block @r5 @r10

    con <> (@r5+0_1) <M>
    @r6 *main <>
    jmk (<M>+2) @r10 @r10
    movk <> u64 u64 *block (u16/0_2) (@r8/0_2) ^@r12

    xt ^u64 @r9

    @r1 @r1 <M> @r9 @r1 ^*main (u16+3) (@r2/2)

    movk @r2 u64 @r6 @r8
    cmp @r12 u16

    cmp u32 @r3 && (@r4+0_2)
    cmp @r4 ^@r2 @r9 (^@r9/0_2)

    @r6 (*main/3) @r1 @r9 ^M @r4



    @r5 @r2 (@r5+2) M @r9 *main @r11
    jmp (@r12/0_2) u8 @r1 @r1

    @r12 (@r3/1) @r7 u64 <> u32 M
    lsl @r2 ^@r1 (@r5+1) u32 *block
    push *main u64

    @r3 @r12 @r9
    lsl @r6 @r2 u32 M @r6 ^u8

    cmp u16 @r7 u64 @r11

    movk @r5 (u16+2) @r11

    push @r1 <> @r12 @r9 u32 u16 @r2
    mov ^@r12 u16 @r9 u16 *main M u64

    jmk (^@r5+1) u32 (@r4+3)
    lsl && <M> (@r10/0_1) (@r3+2) *block

    ldp @r1 @r11 @r6
    lsl <> ^@r12 u32 @r12 u8 @r8
    ldp *block (@r12/0_1) ^@r3 <> @r4 (u8/0_1) (@r12/0_1) @r6 *main && ^@r2

    ldp u16 ^@r7 @r1 u64 *main ^u16 @r1 ^u8 u64 M *block

    mov ^@r7 @r7 u16 @r4 u16
    push ^@r9 @r7 <> @r3
    con @r4 (^*main/2) ^@r10
    mov u16 @r10
    mov @r9 @r6 (@r3/0_1) @r7 @r11 @r5 u64 M (@r3/2) @r6

    cmp @r5 @r8 @r8 ^*main @r1 u32 (M/0_2) @r5 ^@r2
    jmp @r8 <M> @r11
    @r8 @r6 <M> (@r3/3) @r10

    xt @r7 @r11 @r4 (^u32+2) u16 ^u64 *block u64 (^@r8/1)

    push @r2 <> @r3 @r12 ^@r11 ^u32 @r10 (u64+1) M ^@r8 ^@r11
    lsl @r8 u16 @r9 <M> M u64 @r8

    ldp ^@r1 ^*block u16 @r3 <> (@r7+0_2) @r2
    cmp (@r9/0_1) (u8+2) ^<M> @r12 u8
    lsl *block @r9

    dw ^*block @r4 @r9 ^u16 u16 u16

    jmp @r12 u8 ^@r3 @r5
    dw u32 ^u32 u64 (^@r2+1) @r3

    push @r12 (u64+1) @r1 (<M>/0_2) (u8+0_2) @r8 ^@r9 ^@r11 *block <M> ^@r2
    ldp @r3 u8 @r6 && @r1 *main @r7 @r2 (@r5/1) *block

    jmp u32 ^@r9 *block (*block+0_2) @r8 @r3
    jmp && @r5 @r10 ^u16 *block (@r2/1) ^@r12
    jmp <M> (@r8+3) && @r9 u16 ^<M> @r8 u32 @r6 (@r8/3) ^u32

    cmp (@r5+3) @r11 <> ^u64 @r10 @r8 ^@r5 *block (u8/1)

    xt @r2 ^@r7 @r9 <M> @r11 <> u32 <M> (@r5+1) u8 (u8+0_2)
    lsl ^@r9 ^&& @r2 @r3 M

    xt @r4 @r7 @r8 <M> (@r7/2) @r4
    lsl @r12 *block (^@r12/3) *block *block (u64+1) *main (@r12/0_2) u16

    push @r11 @r1 u8 <M> ^u16 @r3 ^&& (@r9+3) @r8 ^*block (^u16/0_1) @r10

    dw ^u32 @r11 @r12
    jmk @r11 (*main+1) @r1 (@r10/2) (^u8/1) ^<M> @r11 @r4 <>
    dw <> @r10 @r6 ^u8 (@r2/2) (<M>/3) @r1 @r10 @r10 <> *main
    push @r9 (u64+1) (^@r5/0_2) @r6
    @r11 u16 @r2 @r9


    ldp u32 ^*main (^@r6+3) @r10
    lsl @r2 @r3
    ldp (@r5/0_1) u32
    ldp @r10 *main *main
    jmp (@r2/0_2) @r9 @r10 ^@r5 ^@r6
    ldp u16 *block *block *block

    jmk (^@r11+1) @r7 ^<M> (^*block/3) *block ^<> && ^u64 (@r6/2) ^@r3
    jmk <M> @r9 @r10 <M> ^@r3 @r7 @r10 @r12 @r10 ^<> @r9
    mov ^<> <M> ^&& (^u32+3) <M> *block ^@r3 <M> u64 u64 ^@r8

    push (@r9+0_1) @r4 (M/0_2) @r3 ^@r12 @r10 @r2 @r8 *block (u8/2) @r2 @r3
    xt u8 (u32+0_2) ^@r10 @r11
    jmp u16 u32 ^M ^u64

    jmp @r6 @r9 u16
    xt @r11 <M>
    jmk @r8 u64 @r1 @r8 ^@r1 ^M (u8+2) (*block/3) && @r3 (*main+0_1)

    xt @r7 ^@r4 @r7 @r12 <M>

    movk @r10 <> @r10 @r4 @r8 @r6
    jmp (M/0_2) && @r10 (M/0_2) *main M @r11 <M> ^@r11 ^&& u64 @r6

    @r3 ^@r1 @r9 u32 ^u8 u16 @r5
    con @r10 ^@r2 u16 @r12 @r3 ^u64
    lsl ^@r4 (@r12/3) ^u64 u32 u32
    con @r2 (<>/2) (@r9/3) @r7 *main ^@r3 @r9 ^@r8 u64 ^u64 @r6 @r3

    lsl <> ^@r12 @r9 @r8 @r3 ^@r9 ^u64 *main @r11 @r1 @r7 (@r7+3)
    mov @r6 *block ^@r9 @r10 ^*block @r6 @r2

    @r9 <> @r11 u32 M @r11 @r8 <M> @r12 (^<M>+2) @r8
    push @r10 ^@r3 (^&&/0_2) <> @r6 *block @r12 @r10 && *block
    ldp <> @r12

    xt @r6 @r3 *block (^u8/2) @r9 u8 ^*block
    @r11 ^&& u64
    @r10 && (*block+1) ^<> M (^@r6/0_2)
    @r2 u32 @r7 @r7 u8




    cmp ^@r4 (@r1+1)
    @r9 @r5 u64 ^@r11 @r8
    ldp @r5 @r12 (@r3/1)
    con u16 u8 @r4 ^@r5 @r12
    @r2 (<M>/0_1) *block (^@r6+1) *block @r1 && <M> M @r6 <> @r12 ^@r11
    xt ^u32 @r1 (@r5/0_2) (^@r5/3) u64 u32

    push @r2 ^<> (@r9/0_2) @r10

    jmp @r6 @r2 @r12
    xt @r8 @r2 @r8 (*block/0_1) u16 u64 *main (u32+1) ^<M> @r8
    @r12 (@r1/3) u16 @r4
    jmk (@r2/3) @r12 @r5 @r11 (@r7/0_2) u16 (@r11/0_1) @r5 && @r7 *main u32
    dw u64 ^@r2 ^@r3 @r4 ^<>
    push @r9 @r10 *block (@r1+0_1) u8 @r11 @r11 @r12 u64 @r12 M @r6
    cmp @r2 u64 @r4 u8 @r7 (u8/1) ^u8 *block u32 (^u32/2) @r7 u16
    mov @r5 ^@r4 @r2 @r2 @r7
    cmp @r3 <M> ^u64 ^@r4 M && ^@r8 ^u8 (u8/0_1)
    con @r6 ^*main u64 u8 *block @r4 (@r6+0_2) && u16

    cmp @r3 <M> @r1 M *block u8 u32 ^<M> (@r8+0_1) (u32/1) <> u64

    movk *main (^u64/0_2)

    dw u16 (@r9+0_1) && ^@r10

//    @r1 @r11 ^*block @r3 <> ^u64 ^@r11 @r7
//    ldp u32 (u16/0_2)
    jmk ^u64 (@r12+0_1) (@r12/3) ^u16 @r3 (@r11/0_1) (@r3+0_1) u8 u32 (@r3+0_1)
    @r11 @r1 ^u32
    lsl @r5 ^@r2 @r3
//    cmp @r7 (@r7+0_1) @r8 (^<M>/0_2) (u16/0_2)
    cmp @r9 *block ^<> ^@r11 <> ^u8 M ^@r1 (^u32/1) && M
    ldp <> @r9 (@r6/0_1) ^@r3 ^@r5 @r5 @r8 @r4 (@r4/0_2)
//    push @r2 (@r6/3) u8 @r7 @r11
//    lsl @r10 <M> @r12 ^*block (u16/0_2) @r7 @r1 @r6 (@r9+0_1)
//    jmk <M> @r9 <M> u8 @r12 (@r2/1)
    dw @r7 (^@r1/0_1) ^*main @r9 u16 ^@r5 ^M M @r9
    lsl u8 @r10 (@r11+0_1) u16 u8 <M> @r5 ^M M
    @r8 <> (*main/0_1) ^@r3 u16 M @r9 *block @r5
    xt @r2 @r6 u32 M @r7 *block @r4 
    ldp @r3 <> u16 *main @r10 ^@r8 
    cmp u16 @r1 u32 <M> @r10 ^@r1 ^@r2 
    jmk @r2 @r6 @r10 *main u32 ^*main (@r4/0_1) @r5 &&
    @r10 @r3 u16 @r9 @r1 u32 *main (*block+1) @r10


    mov @r5 <> @r4 @r5 (u32+0_2) ^@r3 <> ^@r11 <M> @r6
    jmk @r9 ^@r12 (@r6/0_1) (@r4+0_2) && ^@r12
    lsl @r6 (@r7/2) (^@r11+0_2) *main @r12
    jmp (@r10/0_2) <M> (^@r6/2) ^@r4 ^u16
//    jmp @r1 ^@r12
//    @r5 <> @r11 (@r12/0_1) @r9 @r5

    xt (@r11/0_1) (*main+0_2) ^@r4 @r8 ^u16

    cmp @r7 (@r2/0_1) <M> && ^@r8 M (@r6+2) (<>+0_1) ^*main
    con u16 (@r4/0_1) (@r1+0_1)

    push (@r10+2) @r11 @r11
    movk && @r2 @r2 *main

    dw u16 @r8 ^@r3 @r12 ^@r9 @r3 @r7 M @r7 @r11 &&

    dw ^@r4 (*main+3) ^*block @r7 @r2
    ldp u16 <M> *main ^@r3 <M> <> ^@r9

    xt (@r7/2) ^@r2 @r1 @r9 ^&& ^@r6 (^@r4+0_2) u16 ^@r8 @r7 @r9

    @r11 && @r5 (@r11+2) ^&& @r7 @r11 (u16/2) (@r9/3) *block ^&& @r9
    mov (@r1+0_2) @r8 u16 @r11 <M> ^u8 M
    con @r7 u8 @r7 @r4 @r6 @r3

//    lsl ^<M> u16 <M> u16 @r11 (@r8+3) (&&/0_1) @r1 ^@r2 ^@r8
    lsl <M> @r11 (@r8+3) @r1 ^@r8
    @r2 u16 *main @r7 @r7 
    jmp @r11 ^@r2 (@r4/1) @r9 (@r4/0_1) @r9
    @r4 @r8 @r1

//    jmp && @r11 ^@r2 (@r6+0_2) ^@r7 @r5 @r7 @r5 (@r6+2) ^@r9 (@r4/0_1) @r9

//    dw <M> u16 <M> ^*block
    jmp *block u16 <M> &&
    dw *block u16
//    jmp *main u16
    jmp *main
//    lsl ^@r7 ^<> @r8 @r12 u16 (@r8/0_1) @r11 M ^<M> u32 u32 u8
//    xt ^u16 @r3 u32 (u8/3) ^@r6 (@r2+0_1) @r12 ^@r10 <> (*block/3)
    lsl ^@r7 <> @r8 @r12 u16 (@r8/0_1) *main
    @r11 u32 u8 <M> u32 @r3 (u8/3) 
    @r12 u16
    xt *main <> @r8 u32 (^@r12+2) @r10 @r3 ^u16 u8
    @r9 @r8 u32 (^@r12+3) u64 *block

//    dw u64 *main (@r1/0_1) u32 ^u64 *main @r1 u8 @r11 && u64 (@r4+3)


    push ^*block *main @r9 (^@r2+2) @r9 @r11 @r5 M (<M>/0_1) &&    
    xt ^@r9 <>

//    con *block *main ^&& @r9 &&
    con && *main && @r5 *main (^@r7+3) (<>/0_2) (@r1/3) @r2
    dw ^*main u64 @r8 *block @r6 @r8 @r10 <M> (@r9+2) <>
//    push <M> ^u16 u64 M @r1 @r1 ^@r11 ^@r7 @r6 @r8 @r8 *main
//    xt @r1 ^@r4 @r5 u16 u64 @r6 @r7 @r8 @r4 *block @r9
    lsl (@r10/0_1) @r7 M
    jmp @r11 *main (<>/0_2) && @r8 *main ^@r10 u8 @r12 (@r12/0_1) (<M>+1)
    jmp @r5 @r7 (@r5/0_2) @r3 @r8 @r7 @r9
    ldp @r2 (M+1)
    lsl @r12 @r5
    movk @r4 && @r10 <> u16 @r4 ^@r7

    mov @r10 @r5 ^u32 <M>
    jmp ^@r8 @r5
    jmp @r12 @r1 ^@r4 @r4 <M> @r11 u32

    jmk u32 ^@r4

    @r11 @r11 @r9 @r7 (*main/0_2) (*block/2)

    mov @r5 ^@r1 ^@r2 ^@r10 @r8 *block
    jmp ^u8 @r5 (@r1/0_1) *main @r9
    xt ^u32 @r5

    @r8 ^u16 ^@r12 @r9

    ldp M @r1 @r1 (@r5/2) M

    @r3 && @r2

    @r12 ^@r1 <M> ^@r2 *block <M>
    @r4 @r9 u16 M (^M/3)
    push *block <> @r6 u16 ^@r2 *main

    push @r7 @r3 u64 u32 @r4
    @r11 (&&/2) u32 u8 u32 @r2 @r11 *block
    cmp ^@r9 ^@r6
    mov @r9 u16 && <M> u8 @r9 u16
    @r3 ^@r7 @r6

    @r7 @r12 (@r8/3) (u8+3) (@r5+2)
    ldp @r3 @r6 (^M/1) @r11 @r2

    @r8 ^u64 (&&+0_2)
    lsl <M> @r3 @r4 @r11 u32 @r5
    @r8 (@r9/3) <> u64 @r9 @r3 ^@r10

    ldp @r9 @r12 @r2 <>
    movk ^u8 *main ^@r11 ^M
    dw @r4 && *main @r1 (u16+0_2) ^u32 u16

    push ^@r11 && @r4

    dw @r11 *main ^u16 u16 ^@r9

    @r2 (@r4+3) @r12 ^@r10 ^@r4

    @r5 ^@r7 (^@r5/0_2) ^u64 M (^u32+0_1) (@r6+0_1)
    dw u16 @r2 @r2 ^*main ^@r9 @r1 @r11
    cmp u8 (u8+0_1) ^u8 &&

    @r2 @r7 && @r11

    @r6 @r6 @r7 u32
    @r6 u8 @r11 <> @r8 @r7 @r11
    movk @r9 u8 @r11 @r1 && ^@r11

    jmp (^@r9+2) @r10

    @r5 @r11 <M>

    ldp ^@r3 @r2

    jmk *block @r9 @r4

    mov @r1 u64 ^@r10 (@r1+0_2)
    xt ^*block @r3 @r5 ^@r1 ^@r8
    dw u8 u32 u32

    @r5 (^@r1/1) *main
    ldp u32 u8 <> @r3 @r8 *block

    jmk *block *block

    lsl (&&/1) (@r2/0_2) u8 u8 u8
    mov M ^u8 ^@r9 (^u8/0_2) @r7 (@r8/1) @r4

    @r10 u32 u8 @r5 ^*block
    jmp u64 && u16

    dw @r12 <M> ^u16 @r7
    @r1 ^<> u32 @r6 u16 @r2 @r10 ^*main

    dw @r1 u8 ^u8 M <> @r1

    dw ^u8 @r6 ^u64 @r10 M

    @r11 @r8 u32 *main (@r10+1) @r6

    xt <> @r9

    con @r9 @r7 @r7 u32 u32

    lsl @r2 u32 (@r11+3) u16 <>

    @r1 @r12 u32 <> u32 u64 u32 @r1
    jmp @r1 M (@r6+0_1) (@r2+2) ^@r3 @r3 *main
    jmp <M> @r3 ^<> u16 u64

    movk @r7 *block <>

    con @r12 && <> *block (^@r10+0_2) @r10

    @r2 @r3 u64 @r12 @r1 M ^@r12 *block

    jmp @r9 u8 @r1

    dw @r7 ^u64

    lsl @r8 @r1 ^@r3 @r5 (u8/3) @r6
    push <> @r11 @r3 @r6

    movk (u32+0_1) @r3 ^u8 <M> @r12 (@r5/0_2) @r3
    @r2 @r6 @r4 @r11 ^*block u64 <M> @r6

    cmp (@r7+1) ^@r1 (@r11/1) (@r6+0_1) u8 *block (u16/2)

    jmk (@r4+2) M (@r2+3)
    cmp @r6 u64 ^@r2 @r1 @r12 @r4

    cmp u8 ^@r6
    cmp @r8 (^@r5+0_2) <> @r5

    movk u8 (^u8/0_1) ^@r1 @r9

    jmk (^M/3) @r9 ^M @r11 @r3 u32 *main

    cmp ^<> ^@r4 (u8/2)
    jmk (^@r11+1) (u32+3) (@r12+2) u16 M

    @r5 @r1 u16 <>

    push u32 ^@r1 *main ^u64 ^u64

    cmp u64 @r10 @r11
    xt u16 (<>/0_2) *main <>

    @r12 <> u8

    cmp M *main u64 u8 @r1

    dw (@r12/2) @r2 (^@r2/0_2) @r3 *block <M> @r6

    jmp (@r3/2) @r3

    dw @r11 <> <M> ^*block @r8
    ldp && @r3 ^@r3
    movk @r11 u8 @r9 && ^u32 @r12

    ldp @r8 (@r10+0_2) && (@r4+2)
    jmk <> ^@r9 ^@r12 ^M @r10

    lsl (@r6+1) @r1 ^u8 u16 && <> @r7

    ldp u32 (u8+3) (@r6/1) (^@r6/0_2) u64

    @r5 *main ^&& ^@r7 @r6 @r8 @r10
    lsl @r7 @r7

    @r10 (^<M>+1) && @r11

    lsl (^@r12+1) @r6 u64 *main <> (^&&+2)

    dw @r5 @r12 (@r8/2) @r4 (@r6+0_2)

    lsl *main (@r1+3) @r10 u16 u16 @r8
    cmp ^u16 @r4 u16

    dw <M> @r3
    @r6 ^u16 u32 @r6
    mov @r2 @r2 ^<M> ^M

    dw ^<M> ^@r11
    mov <M> u64 @r3 @r12 (^@r7+3)
    jmp u32 @r9

    mov @r12 && @r6

    mov (^*main+0_1) @r5 ^u64 @r3
    jmp @r2 <M>

    cmp (@r1+2) ^@r10 u16 (^u16/1) ^@r8 @r7 @r9

    push @r12 (@r12+3) @r5

    con (@r3+0_1) @r9 (^*main+0_1) M ^@r6 M ^*main
    ldp @r8 @r6
    @r6 *main (u8/1)

    cmp ^@r2 u16 @r10

    con ^@r3 @r1 @r8 @r6

    @r12 (@r10+3) @r11

    cmp ^*block u8 @r9 (^M/3) u8

    dw M @r4

    jmk ^u16 @r9
    mov ^M @r6 *main @r1 *block @r11 @r10

    @r3 ^@r3 @r2 @r12

    @r5 <M> (@r10/0_1) *block ^u16
    xt @r7 @r10 @r8 && @r6 *block

    jmp (@r12+0_2) @r6 *main

    @r12 <> *block @r12 ^u8

    dw @r12 @r11 @r5 u64 @r9 ^@r6

    mov M ^@r4
    lsl @r3 (^M/0_2) <M> @r1 u16

    cmp && @r8 @r10 @r4 @r8 M ^@r5

    dw ^u32 (@r4/0_1) u32 <> u16

    push @r11 @r9

    jmk ^<> @r9

    jmp u16 u16

    @r12 (@r2+1) @r1 <> u16 u32 ^u64
    lsl @r10 @r8 @r8 ^@r2 ^*main @r7 u8

    movk (^@r1+3) @r10 u32 && M @r4 @r3

    jmk @r8 u8

    ldp <M> @r2 @r7 @r9
    @r4 (@r11+2) @r6 ^@r7 @r2 ^u16 <>

    con (@r10+0_1) @r10 @r7 ^u16 (u64+1) @r2

    jmp @r1 @r5 u32 @r8 M u16 *main

    xt @r3 @r9 @r8 (@r6+1) @r3 ^@r8
    jmp @r5 (@r6+0_2) ^*block ^M @r9 @r4
    mov <> M ^@r2 (@r1/0_1)

    movk @r1 @r9 (@r3/0_2) (@r6/0_2) @r8

    xt ^M @r12 u8 @r5 @r10 (u16/2) @r11

    xt <> u8 M (@r4+0_1) @r12 ^@r1

    ldp (<M>+2) @r1 @r2 M

    @r10 @r5 (&&+3) @r9 @r6 (@r11/0_2) <M>

    push @r9 (@r12+0_2) @r8 ^@r2 M ^<>

    @r1 @r7 <> ^@r6
    con @r11 <M> @r6 @r6 @r1
    @r7 ^*main @r8 (@r11/0_2) && @r8 (@r1+3)
    dw ^u16 <M> @r8
    xt @r1 ^@r8 (*block/0_1) *main
    @r12 @r12 *main @r9

    @r4 @r4 <>
    jmk @r11 ^&&
    xt @r6 (@r5+2)

    dw @r5 @r2
    cmp *main @r11 *main @r4 @r2 ^@r1
    con @r3 @r3 (@r9/0_1) (^*block+2) *main
    jmp @r10 @r3 @r2 @r7 @r12 (u16+3)
    cmp (@r11/2) @r6 @r2 && @r9 ^@r8 @r3
    con ^@r2 u32 @r5 @r3 @r1 u32 @r6

    lsl (*main+3) @r1 (@r5+2)
    dw (@r8/3) @r12 *main @r4 u8
    jmp ^@r3 @r5 (@r2/0_1)

    ldp @r9 u8 @r12 ^@r8 u32

    mov @r7 @r11 @r10 *block (@r9+0_1) @r7 ^@r10

    push u64 @r2 u64 ^@r11
    ldp <M> @r6 *block
    dw (u16/0_1) &&

    mov <M> u32 @r4 (@r10+3) @r9 u64 ^u16

    con ^@r4 && @r6 M *main
    jmp @r4 (u16+0_1) (@r11+0_1) @r5 (&&+3) (^@r4/0_1) (@r1/0_1)

    mov ^&& @r7 u16 (<M>/1) u8 M

    @r6 u64 @r10 ^@r2 u8 @r12 @r8

    movk @r3 *block <>

    dw @r3 (@r11+0_1)
    jmp && @r7 ^@r7 (@r7/1) @r2 (@r4/1) ^@r8
    xt (u64+1) @r9 @r8 @r10 @r5 ^@r8
    @r4 ^u32 @r9 ^@r9 @r9 && u32 u16
    ldp (u8+2) @r4 @r7 @r9

    movk ^@r1 ^*block *block *block *main
    @r7 ^*main ^u32
    xt @r11 @r9 ^@r12
    cmp @r11 ^<> (^*block+0_2) @r6

    lsl u8 u64 && (^*main+0_2) @r2 ^@r8
    dw ^@r12 <> @r2 @r6 ^@r11 @r11 (u8/0_1)
    push @r6 @r6
    movk (u16+2) M && ^@r1 @r9 @r11 @r12

    ldp ^u8 && (^<>+2) *main @r11
    con @r8 @r2 && (^&&+3)
    mov @r12 @r8 (@r12+0_1) @r12
    lsl ^@r6 @r3 @r3 u8 @r7 @r5
