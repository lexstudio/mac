entry:
// declaration of boot start
    con ^@r4 (@r12+1) u64 ^<> <> (*block/0_2) (@r10+1) @r6 u64 @r4
    jmk @r11 @r4 (^M+0_1) @r3 (@r8+2) ^@r1 <M> @r8 <> @r6
    xt @r6 *block <M> @r12 *main (u64+3) (@r8+0_2) @r1 ^<M> @r8 (@r7+0_1)

    @r2 @r10 u16 @r2 ^u64 @r6 @r7 ^u32 (M+1) u32 @r4
    push @r11 ^@r4 *main @r1 ^<> @r4 *block && @r6 ^u32
    jmk (^@r10+1) <M> @r5 && @r9 ^&& <> @r9 ^<>
    @r10 ^&& u8 @r4 u32 ^*main (&&/3) @r12 M @r6 ^u8

    xt M ^<M> @r1 <> (&&/2) ^@r3 u8 @r2 @r1 <> u16
    movk @r4 ^u8 @r2 @r2 @r3 @r4 *block *main
    dw (@r7+3) ^u16 @r4 M u16 @r5 u32 @r5
    xt @r12 @r6 @r5 (<>/2) *block ^<> @r1 u16 u32 @r1 u16 ^u8 *main
    dw ^<> @r2 <M> @r9 ^u8 @r12 ^M @r6 ^@r10 @r7 (@r2+2) @r9 u8
    dw @r1 <M>
    mov u64 (@r6/0_1)
    movk @r11 (u8+0_2)
// Memory start and new blocks rules
    jmk <> *block

    @r5 <> @r8 @r6 M ^<M> <>
    dw (^u16+2) (@r11/2)

    jmp M ^@r2 (@r5+3) @r6
    push @r3 @r3 @r7 @r5 @r12 ^u64
    push (u8/3) *block @r5

    mov @r3 @r10 @r11 @r9

    jmk u16 u16 @r7 @r4 @r7 @r9
    jmk @r9 @r8 ^&& (@r6/1) @r6 (@r12/2)
    cmp @r5 ^@r2
    @r12 @r10 *block @r4 && @r10 @r8
    movk <M> @r2 (u32+2) @r5
    jmp u16 @r2 u32
    jmp (^<>/3) ^&& *block ^@r1 @r6 ^*main
    @r9 @r12 ^@r8 @r9 @r2
    mov *main <M> (@r3/3) @r8
// Blocks rules
    @r12 (u64+3) (<M>+1) @r10 (@r12/1) ^@r10 @r8 @r11 *block (@r8/1) ^@r3 @r6 @r8 ^@r11

    cmp @r11 u32 u16 <> @r12 ^*block ^u32 @r6 M @r9 && && u32
    ldp @r10 (u32+0_2) @r5 ^@r3 M @r2 ^u64 (@r11+0_2) @r4 ^&& @r6 (@r10/3)
    @r5 @r1 (@r11+0_1) @r1 @r11 M u64 @r4 @r5 ^@r10 @r2

    @r7 @r1 *block @r12 u64 (^@r4+0_2) @r9 ^@r8 u8

    movk *block @r10 (&&/0_2) (@r10+3) u32 M <M> u16 ^@r12 (@r5/0_2) ^*main @r1
    cmp (&&+0_2) @r3 ^<M> *main (@r7/3) u16 @r7 ^@r10
    ldp @r10 ^*block u64 M @r12 M (<>/3) @r1 (@r11/1) @r8 u32
    push && @r12 @r7 (^@r9/0_2) ^@r2 <M> @r11 ^@r3 (^@r6+0_2)
    lsl @r10 (^@r3+2) u8 *block ^@r2 ^@r1 && @r4 @r3
    mov M @r8 @r6 && *main @r8 ^<> @r11 @r8 @r8
    con @r3 *main @r2 ^<> M @r11 <M> @r8 <M> ^@r11 (@r2/0_2) @r10
    lsl ^@r11 @r10 u16 (u32+3) @r6 (*block/1) @r12 u64 (<>+2) @r1 @r8

    @r3 M ^u8 @r10 M (&&/0_1) *main

    cmp ^<> @r6 u64 @r10 ^&& @r2 @r6 @r5 @r4 ^@r1 (&&+2) ^*main u64

    movk @r3 *block ^@r7 @r7 @r6 *block
    cmp *block ^@r10 @r8 ^<M> @r9 @r11 u32 @r4 u32 ^*block (*block/0_2) ^<M> @r9
    push *block (<M>/0_2) @r1 (@r5/0_1) (@r7+1) *main (^u64/0_2) @r1 ^@r5 @r3

    lsl <M> (^@r1+0_2) u16 ^@r2 M u8 @r6 @r1 (@r6/2) u16 @r9 @r3
    xt @r5 M @r12 <M> @r10 M @r7 ^@r8 <M>
    xt *block @r9 u64 *block ^&& u32
    @r2 u8 ^@r3 (^@r3/0_2) @r10 ^@r5 (@r6/3)
    con (@r7+3) (u64/0_1) *main ^u64 ^&& u16 <M>

    push @r5 ^@r11 (*main/0_2) u16 (@r3/0_2) @r3 u64
    jmp <M> @r11 (^@r9/2) ^<> @r6 ^*block @r6 @r3 @r11 ^@r3
    ldp @r7 (u16/1) ^<M> @r10 (u16+0_1) u64 @r6
    jmp u8 ^@r6 @r3 @r8 ^@r8 <> @r10 (@r8/0_1)

    movk <M> u32 ^u16 u16 @r2 @r12 (@r6+0_1) @r7 &&

// gdt integration 
    mov @r1 ("gtd.l")
    @r7 <> @r11 (<M>+2) u16
    dw (u64/0_2) @r8 M (@r7+0_1) ^@r4 ^@r3 // pointer for the next register
    @r7 @r8 @r8 ^@r5 // main
    push (*main/1) @r9 u8 // group push 

    ldp ^@r2 && @r12 @r4 @r5 *block
    jmp u8 @r11 // r11 register limit u8 
    jmk <M>
    dw ^u8 (@r8/1) <>
    jmp u64 @r8
    jmp (^*main+3) *block <M> @r10 @r6
    jmk (<>/0_1) <> @r9 @r4 @r4 // pointers for registers
    jmp (^M/0_1) <M> u16 *main <> ^u32

    jmp (u64/1) @r6 @r12 <> u16

    dw @r7 @r5
    jmk u64 @r2

    cmp u32 @r8 @r9 @r3 ^u16 // std declaration

    mov (@r1+0_2) @r4 @r2 @r1 @r3 ^@r2
    push @r11 u8 ^@r2 u32 @r12 // no main
    movk u8 @r6 (^@r3/1) (M+1) @r6 @r3

    dw M @r7 ^u16 ^@r6 u32 ^@r11 (u32+0_2
    jmp ^&& @r6 *main u8 ^@r7 <>
    push && u16 (*main/0_3)
    movk ^*main M @r6 // pointing the main




// block rule
    lsl ^@r6 ^@r12
    ldp @r9 (@r7/1) @r10 @r4 u64 (*block/0_2)
    dw (^@r2/1) && (@r7/1)

    jmp ^@r10 
    @r5 <> *block (@r10/u16)
    ldp M @r2 ^@r10
//    movk @r5 ^@r10 @r10
//    @r2 u16 u16

    jmp @r8 <> ^@r9 @r2 (^@r7/1) @r11
    jmp @r4 <M>
    cmp @r8 @r6 @r1 (<M>/0_2)
    jmp u16 @r4 u16 u64 (^@r5+0_1) ^@r10
    lsl M @r7
    cmp (u16+0_1) @r3
    ldp @r5 u8
    movk ^@r6 u16
    @r4 (^@r7/2) @r12
// Text and message print in memory blocks
    jmk <> ^&& u16 @r3
    ldp (@r3+3) @r9 @r1 @r2 u16 @r4
    ldp @r12 ^u8 @r7
    dw @r6 *main @r5
    @r9 *main && (M+1)
    movk @r7 ^@r6 (@r6/0_2) ^@r3 ^@r9 @r7
    dw M *block
    jmp @r2 <M> @r6 ^*main
    mov <M> u16 u16
    jmp @r8 @r2 (M/0_1) *block @r2 (@r3/1)
    @r11 @r7 @r10
    ldp @r3 ^*block
    @r3 @r6 (u64+0_2) *main <M>
    jmk && @r10
    mov (@r3+1) (*main+1) <> @r12

    jmp @r2 ^u64 ^@r1 ^@r12 @r10 u16
    cmp ^@r1 && @r5 (@r12+3)

    jmk @r10 (M/1) && @r1
    mov <M> ^@r6

    lsl <M> @r10 @r2 (@r1/0_1) ^@r11 *main
    @r12 ^u64 @r8 // main register u64 point
    movk u32 u16 && @r8
    push *main <>

    mov ^<M> @r5 <>
    ldp ^M @r10 @r12

    push @r10 @r1

    @r2 ^<> (*main/2) (M+0_1) u32

    dw @r12 <> @r5

    push (u32/2) M u64 ^@r11 (&&/0_1)
    mov @r3 u16
    jmk @r4 ^M *main @r9 u32 @r3
    jmk ^u32 (u8+0_1) u32 (&&/3) @r6
    lsl (<M>+0_2) @r10 u64
    ldp @r3 M u64 *main (*main/3)
    jmp u32 (^@r4+0_1) @r12 *main (M/0_2) u16 (^&&/3)

    mov (@r3+3) <> @r5 @r3 @r6 && (@r9/0_1)

    cmp ^@r12 (@r7/2) *main &&
    mov ^@r8 @r4 (@r1/2) @r5
    xt *block ^*main u32 @r2 @r10 (^@r5/0_2)
    @r10 @r8 ^@r10 u8 ^*main
    ldp @r6 (@r7/0_1)
    @r9 ^@r2 ^@r4
    push u32 @r2 ^@r11 @r3 @r11 @r5 ^&&
    mov u16 u64 @r4 u16 @r11
    cmp ^u32 ^M (u64/0_2) @r8 (@r8/0_1)
    @r3 @r11 *block @r11 u16
    push ^*main u64 @r3 @r12
    lsl u64 (@r2/0_2)
    lsl (@r3/3) @r5 (<M>/1) ^@r9 ^@r2 ^<> u16

    jmp u64 (@r3/0_1)
    cmp u32 *block @r7 (@r9+0_1)

    push @r8 (u32/0_1) ^u64 *block @r11 u8 (^@r10/3)
    movk (u16+3) u16 ^@r5
    con @r3 (^u16/2) &&
    mov @r2 ^*main
    jmp @r9 @r5 @r8 (^@r2/2) @r8 @r1 @r4

    @r10 (@r3/3) ^u64 (^@r5/2) @r7 ^@r12 @r11 @r8
    @r11 @r2 (@r5+0_1) @r5 @r1
    ldp @r6 @r6 @r4 @r2
    dw ^@r3 @r2 @r11 @r10 @r10 @r11 (@r7/2)
    jmp *main @r4 ^*main @r9 @r4

    @r5 ^<M> @r1 u8
    @r4 @r11 @r5 (@r12/1) ^@r4 &&
    dw (@r3/0_1) M @r3 (^@r11+0_2)
    jmk @r11 @r12 @r2 @r6 @r10 @r6
    push @r1 *block
    cmp @r2 @r4 ^@r5 *main ^@r3

    mov ^&& ^@r1 &&

// Cache access route
    mov @r6 @r5 *main *block u16 @r3
    dw @r12 @r1 @r7 @r12 @r7 @r9
    ldp @r11 "chachekernel.l" @r10 <M> @r6 *block
    push u16 @r7 <> @r1 @r7 ^u8

    lsl @r3 u8 @r6 *main u16 u64
    dw (^u64/0_1) ^@r9 u64 @r1
    push @r7 @r7 (M/0_1) @r8
    dw (@r12+2) @r8 M @r5 u16

    mov u8 @r8 @r12
    cmp ^u32 @r10 u64 *main

    lsl ^<> ^@r3 *main @r7 @r7 @r8 @r11
    @r5 *main (@r11+0_1) M @r5 @r7 (@r2/0_2) (*main+1)

    mov M (@r7+3)
    cmp u32 @r5 u8 @r7 ^@r5 @r1

    lsl @r8 @r2
    jmp u16 @r10 && u32 @r11
    @r10 ^<M> @r12 @r1 *main
    @r7 u16 ^@r5 <> @r1

    lsl ^u16 <M>
    dw <> @r8 u32


// Stop and sleep in registers
    @r2 @r11 @r6 @r3 // all registers stop 
    lsl *block @r6 @r10
    @r6 @r5 <M> @r8 (@r8+0_2)
    jmk u64 *block u64 @r4
    movk (<M>/0_2) <M> @r10 u8
    mov u32 (u8+0_2) u8 ^@r2 u8 @r4
    @r2 @r5 @r10

    jmp ^u16 @r11 && ^@r11
    mov u8 ^@r4

    ldp ^@r8 (u32/0_2)
    mov @r9 ^@r6

    ldp ^@r1 *main u64 @r2 *block @r2
    jmk && *main
    cmp @r3 <> (u16/0_1)
    @r7 (@r10/3) u8 @r12
    lsl u16 @r4 M (u64/1)

    @r1 @r10 (u64+1) u16 @r1 (@r10+1)
    jmk M ^@r10 u8 @r6
    mov ^*main *block ^@r4
    lsl (@r4/1) ^u64 @r3 @r4 ^@r9 (@r6+0_1)
    jmk @r3 ^*main (*block/0_2) u16
    dw ^*block (M/2) *main ^@r2 @r1 @r8
    lsl @r9 (*main+2) (<M>/0_1) u8 @r12 *main
    @r2 (@r1+0_2) u64 @r9 u32 @r9 (@r5/0_2) @r10

    jmk ^@r8 (@r12+0_1) ^@r10 @r6 @r7 @r10 &&
    @r4 @r1 @r12 (@r3/1) <> (@r3+2) @r9 ^@r6

    @r3 *main u32 (u8/3)
    push @r7 (@r5/1) ^u8
    jmp @r5 u64 @r1 && (@r8/3) ^u32 @r9
    movk @r6 @r10 *block
    @r2 @r3 @r2 *main (u64+2) @r5 <M> (@r2+3)
    jmk u8 *main *main <M> ^@r12 ^u8
    dw @r8 (@r10/3) @r1

    mov <> u16 @r9 *block @r11 ^@r2
    mov u32 @r12 @r12 M @r7 ^M @r7
    lsl @r6 @r7 <> (^@r8/0_2) @r3
    @r12 @r8 ^@r3 (M/3)
    @r6 <> @r4 (@r2/2) @r11 (@r6/0_2) (^@r2/1)
    ldp u64 (@r11/1)
    mov @r1 ^u16 @r7 <M>
// Driver change and vga hdmi indentification
    cmp ^M u32 @r11 @r1 u32
    cmp u16 @r7 *main (@r2+2) ^u64 @r11 (<M>/2)
    movk @r12 @r9 @r10 ^@r2 @r10
    mov (@r11+3) <M> @r1 @r3 ^<>

    jmk M u8 u8 @r6 ^@r12 (*block+2)

    @r9 ^@r3 (u64/1) @r5 *block
    movk u16 u64 <>
    mov @r5 @r8 @r3 ^<M> @r7
    cmp @r2 (^*block+0_2) ^M
    mov *block <> u32 (<>+0_1)

    jmp @r1 ^@r5 @r1

    cmp M ^@r11 <M>
    jmp @r3 M <>
    jmp @r1 @r11
    mov @r2 @r4 (*main+2) *main u32

    @r2 @r9 (M+2) u8 @r5 @r6 ^@r12
    ldp *main *main *block <M> ^u64 @r5 (u8/3)

    push <M> u64 *block ^@r10 @r10 @r12
    push @r9 M *block @r12 @r8 @r8 (<M>/0_1)

    cmp (^@r11/0_2) (@r2+2) (@r10+2) @r3
    ldp (@r10/1) u8 (@r4/2) u16 (@r2/3)
    push @r10 @r3

    lsl @r8 <> ^@r11 <M> @r7 ^@r1

    mov ^@r11 ^@r12 ^@r10

    cmp M @r12

    mov @r8 u32

    mov <M> *main <> ^u64 @r5 @r4
    cmp (@r5+2) ^*main @r4 <M> @r9
    mov u16 (@r8/0_1) (@r6/0_2)
    lsl @r10 u8 ^M @r6 @r3 @r4 @r12

    cmp @r11 @r10
    ldp ^&& ^@r8 @r4 (@r7/3) u8 @r9 ^@r5

    lsl M u8 u32
    mov ^@r1 ^u16 @r9
    ldp <> u16 ^u32 @r5 @r3 @r5
    @r10 && @r5 <> @r7 @r3 @r12
    @r8 ^u64 ^@r4
    movk ^@r9 (@r5/3) @r5 u16 u64 (^*block+3) @r5
    @r5 u64 u16 u64 @r10
    cmp @r7 <M> u64
    cmp @r12 @r7

    push u16 u64 @r2 (u32/1) @r1
    lsl ^u16 *main <M> @r5
    cmp @r10 u32 @r12 (@r6+0_2) ^@r3 @r5 u64
    mov @r9 (u16/1) <M> @r5
    @r3 *block (@r4+3) *main *block u16 (@r5+2)
    ldp @r6 @r1 ^@r9 ^M (*main/0_1) @r3 @r3
    ldp ^M <> *block @r12
    push @r10 ^&& ^u32 u64
    jmp *block @r12 @r2
    jmk @r10 @r3 @r6 @r8
    jmp ^@r1 (*block/0_2) (@r9+1) @r5 ^@r6
    lsl <> @r2
    jmk @r12 @r10

    movk *block (@r3+2) @r2 ^@r8 <M>
    jmp @r10 @r1 @r11 ^u8 *block
    @r3 @r5 u32 <M> M ^@r8 u16
    @r11 (^@r4/0_2) M u16 ^@r6 ^@r7 u8 ^@r3
    push ^M u16
    push u16 && *main @r3 (@r11+1)
    push @r6 u32 *block @r2 u8 (&&+3)

    mov @r4 (^<M>+2) @r11 @r9
    lsl @r9 <> @r9 (@r3+0_1) // end
// Digital type
    jmp @r2 (@r4/1)
    push @r1 u8 @r10
    jmp (*main+0_1) ^<M> *block @r5
    ldp @r2 ^@r12 @r6 *block (u64/1)
    jmp (<M>+2) @r10 @r3 @r1 u16

    dw u32 @r7 @r4 @r2 @r7 ^@r6 @r6
    jmp @r5 @r2 u32 ^@r6
    jmk *block (@r9/2) (^<M>/1) @r8 u8 (@r12/0_1)
    ldp <M> ^u16
    cmp (u32+0_2) *main @r10 ^@r11 ^@r1

    push @r5 M <> && (@r12+1) *main
    ldp @r2 @r4
    ldp *main *block

    push @r3 (@r2/0_1) @r1
    @r1 u8 M
    @r6 @r9 u16

    @r2 @r1 @r9 && u64 u16 (^@r3/2) u64
    jmp u32 (@r9+3) <>
    lsl && @r1 u8 @r3 u64 u16 <>
    @r6 ^@r7 u32 && @r11
    @r3 @r8 *block *block
    mov M ^@r1 @r9
    movk u64 @r9 ^*block ^u16 M @r8
    cmp ^*block u8 u64 (&&+2) <M>
    movk (@r5+2) <> @r6 M (@r3/3) ^<M>
    ldp (@r1/0_2) u16 ^@r10 M @r6

    jmp ^M ^@r3
    jmk ^@r7 (u64/1) @r12 M && (@r12/0_2)
    push (@r5+1) (u32+1) @r11 (u8+3)
    push u32 @r11 @r2
    movk u16 (u64+2) (^<>+0_1) @r3 && u64 (@r3+3)
    push ^u8 u32 ^u8 && *main (^@r10/0_1)
    @r1 @r4 u8 @r1 @r6 ^@r5 <M> @r6
    @r10 <M> (^*block+0_1) @r4 M u8 u16 <>
    mov u32 @r4 u32
    dw (u8/0_2) @r8 <M> (@r4+3) @r11

    ldp (u8/3) (^M+1) && (^u16/3) u16 <> <M>

    @r1 @r6 @r1 (@r5+0_2)
    @r4 ^u64 @r6 && <M> <M> @r2
    push u8 ^@r8 @r4 @r11 ^@r4 u32 *block
    @r5 @r9 <M> (^@r2+2) @r11 (^@r1+0_2)

    push @r9 @r11 (@r2/0_1)
    jmk @r7 @r11 *block (@r12+1)
    jmk && (&&+1) (u32/0_2)
    @r1 <> ^u16 @r4
    movk (@r11+2) ^*main *main u64 @r6

    jmp @r3 ^u16 @r6 ^*main ^u16 (M/1)

    @r11 @r3 @r10 @r5

    @r11 u32 *block @r4 (u32+0_1) @r2

    ldp ^u16 <> ^@r12 @r1 @r1 u8
    movk (@r1/2) (^@r10/0_1)

    dw ^@r4 @r8

    lsl @r2 (@r8/0_1) @r6 (u64/0_2)
    cmp @r11 @r8
    movk *main @r9
    push @r8 @r1 u32

    ldp @r2 (@r9+0_1) (^@r4+0_2) u8 (*block/3) (u64+3) u16

    jmp && @r7 ^@r7 u8 ^@r4

    @r5 @r5 <> (&&/2) ^@r3 @r2 <>
    jmp u32 u16 @r5 ^<M>
    lsl ^<> @r2 @r1 @r11 @r11
    jmp @r11 (@r9+1)
    @r10 u32 (@r3/3) ^@r5 <>
    @r11 ^@r5 ^*block

    cmp <> (@r1/0_2)
    dw @r12 *main u16 ^@r3
    mov @r3 ^u32 @r12 u32 (^&&+3) *block
    movk @r7 && @r7 *main @r4
    @r7 ^u16 <M> @r4
    mov ^@r12 @r3 @r8 @r8

    @r10 ^@r11 *block @r4 u8 &&
    jmp (<>/2) ^@r4 @r9 <M> @r9 && <>

    lsl (^M/0_1) && @r3 *main (u8+3)
    ldp @r7 @r3
    @r10 @r10 @r6 @r5 u16 @r2 @r7 u8
    movk @r5 @r10 (@r4/0_2) M (^@r1/3) <> M
    mov *block @r6 (^@r2+2)

    mov @r3 M
    @r9 u64 u64 u64 @r3
    push @r6 @r4 ^&&
    @r5 @r9 <M> @r12 @r6 <M> @r12 @r4
    @r5 (u8/2) u32 @r4
    mov (@r6+3) @r11 ^&&
    mov @r1 u64 @r6 u8 u32 (u16/2)
    movk <> @r7 u8 ^M
    jmk @r9 @r8
    @r12 *main ^u32 &&
    mov @r1 <> @r8 <>

    ldp u8 u8 @r11 @r11
    cmp u32 (u16/1) && ^@r1 @r1
    @r10 ^@r7 (M/3) @r6 u64

    mov @r2 @r2 @r7 @r11 @r3 *block (@r3+2)

    ldp ^M ^@r9 u16 (^@r12+0_1) ^@r2 *block
    dw @r6 @r3 (@r11/2) @r2
    push @r2 ^@r5
    ldp @r7 @r11 @r9 @r11
    mov @r12 *main @r7 @r1 M
    cmp @r7 @r5 @r10 ^u16 @r1 ^*main

    jmk ^u64 u32 ^@r2 (^u8+1) @r9 ^<>

    movk @r4 u16 <M> ^@r6 ^@r7 @r4 @r12

    ldp @r3 (*main+0_2) <> @r8 ^@r4
    @r2 (^u64/2) @r5 u32
    @r7 <> @r11 <> @r8 M

    movk ^@r9 && u8 (@r2+3) ^@r5 (@r2/3)
    movk @r1 ^<M> *main u64 u32
    mov *block @r12
    movk ^u16 @r6
    jmp *main @r11 *block ^*block
    mov @r2 @r6 ^u8 <M> @r12 @r2
    push (@r3/0_1) ^@r2 u16
    dw u32 @r2 @r9 ^u64 ^@r10
    @r6 (^u32/0_2) M
    cmp (&&+0_2) @r7
    mov (@r2+3) @r3 *main (@r3+3) *block <M> ^@r9
    mov @r5 (^@r7/2) M u16 ^@r11 @r1
    @r9 *block M (@r3/0_2) <M> *main ^u8

    lsl @r8 @r2
    @r6 <M> @r9 *block @r2 (@r7/0_1) M
    cmp @r10 ^u16 @r7 *main @r12 u32 @r12

    ldp u32 (@r8/2) ^@r1

    lsl ^M @r9
    jmk M *block (M/0_2) *main u64 @r5
    ldp @r10 u16 @r5 @r6 ^@r12 ^@r8
    mov @r1 <M>

    dw @r9 (@r5+0_2) ^@r3 @r7
    @r1 *main ^@r9
    lsl @r1 @r5
    @r5 u16 <> (u64/3)
    movk (&&/0_1) @r4 (u16+3) ^<> (@r11/0_1)
    movk @r2 <> u16 @r7 (@r1+0_1)

    cmp u32 ^@r4 u64

    mov u8 (@r5/0_2)
    mov @r8 M

    lsl (@r7/3) *main @r8 ^&& ^*main
    cmp @r5 @r11 @r2 @r12 @r10 ^@r12 (@r8+0_2)

    ldp u64 u8 @r3 @r11
    push @r9 @r3 u8 u8 (@r2/3) u32
    @r9 (@r3+0_1) @r12 (@r5+0_1)
    @r4 @r9 @r8 @r4 @r2 @r5 @r10 ^@r3

    jmp @r7 *block @r4 u64 ^M @r3 ^@r8
    mov @r2 @r8 @r4 (^M/3)
    push ^@r5 (@r2/0_1) @r6 @r10
    push (<>/0_1) @r1 @r4 @r3 (^@r7+0_1) @r7 u16
    ldp (<M>/3) <> @r11 u16 (^*main+0_2)

    mov (<>+1) ^@r12
    movk && <> (@r6/0_1) @r7 ^<M>

    cmp ^&& @r10
    @r2 *block @r12 ^@r1
    push @r10 @r6 (@r9/1)
    lsl ^@r11 @r11 ^*block M ^&& @r1
    push && u32 @r5 @r12 *block @r11 @r12
    @r11 @r3 @r4 ^@r9 u8 (@r8/0_2)
    movk @r8 u64 ^@r12 <> (@r5/1) *main @r5
    @r2 (u64+1) *block u64 u8 u8 u64 *main
    @r3 @r3 @r7 u32
    @r4 (u16+0_2) @r2 (@r5+3) ^@r9 @r7 (^u8+1)
    push @r10 @r3 (^M/1)
    dw M *main u32 && @r7 @r7 (@r8+3)
    ldp ^M (@r3+2) u32 *block @r5

    jmk <M> ^@r2 u32
    jmp @r2 <> M (*block/1) ^@r2 (@r11+0_1)
    movk @r12 (@r12+2) <> ^@r5 M (*block+0_2)
    push ^@r1 @r12 ^u32
    dw u8 @r7 ^&& @r1 (u8/1) ^<> ^<>

    dw && @r1 @r8 *main

    @r11 @r4 <M> @r8
    jmk u32 @r6 <> (@r3+2) @r4 u32
    @r6 u32 (*block+2) (u64/1) @r3 @r8 @r4 @r10

    push M u64 (@r6/0_2) @r11 ^&& (@r8/3)
    jmp @r9 u8 ^u64

    ldp ^<> <> ^@r4 u32 ^*main
    push (u32+2) u8 @r12
    ldp (@r5/3) @r12 ^@r8 @r4 <M> @r3
    ldp ^u64 *main
    dw *main <> <>
    @r12 @r3 @r2 u32 u32
    @r12 && ^@r9 ^@r11
    ldp @r2 <M> u64
    lsl @r10 ^@r5 @r2
    @r11 u16 @r10
    ldp @r8 @r4 @r2 (<M>+0_1) ^@r5 @r11
    @r8 ^u8 @r8

    jmp @r6 M @r7 && *block
    dw ^@r12 ^&&
    @r8 @r5 && @r3

    @r7 (@r9+1) @r11
    ldp @r3 ^@r8 ^<M> @r12 ^u16 @r1 (*block/3)
    push @r6 @r11 @r3 u16 @r1 (u64+0_1)
    @r1 @r1 (@r3/0_1) @r7 u64 @r7
    jmk (*block/3) && @r9 (@r1/3) *block
    jmp u16 u16
    @r4 @r1 @r2 ^<> <M> u32 *block <>
    @r11 (M+0_1) (u8/3)

    cmp ^@r8 u64 u8 @r2 u16 u64 @r2
    @r5 ^@r12 @r9 @r7 @r4
    push (&&+0_1) &&

    jmk u8 && (<M>/0_1) (*main/3) @r2 *block
    jmp ^<> u64
    @r6 @r2 (u64+3) ^&& @r9 (@r1/2) (^u64+2)
    jmk ^@r12 (M/2) M @r7
    @r3 ^&& ^<> (@r7+0_1) @r10 @r9

    lsl M ^@r12 (@r9/2) (&&+0_1)

    movk @r12 u8 ^@r6 @r10 @r8
    jmk u8 (u8/0_2) u16 <M> ^@r6
    mov <M> <> @r2 @r3

    mov @r7 @r4 @r1 (<>+0_1)

    @r6 @r4 <M> u32 u16
    push ^@r2 ^@r4
    @r1 (u32+0_1) (u16+1) <M> M
    mov M *main ^@r5 <> *main u64
    @r11 @r6 && u8

    jmp <> ^M @r11 @r7 *main <>
    jmk ^u32 @r11 <M>

    @r10 u64 @r9
    cmp (@r6+3) *block *block @r3 u64 (@r6+0_2)
    con (@r5/0_1) M
    jmp @r4 @r9 (@r2+2) (@r10+1) <> ^@r11
    @r4 ^@r2 @r12 @r8 && u32
    @r9 @r1 <M> @r2 @r11 ^u64
    con ^M M (<>+3) *main ^@r6
    cmp @r11 ^*block

    dw @r5 ^<M> ^@r12 @r6 (@r1+3)
    @r2 ^@r6 M M (*main+3) @r1
    lsl @r12 *block
    mov @r5 @r9 u16 u32 *block

    lsl M @r1 (M+0_2) @r7 @r10 (@r5+3)
    @r8 u64 <> <M> @r5
    dw u64 (*block+2) ^@r11 <> u16
    ldp @r6 @r2 ^M *main @r5 @r10

    ldp (@r4+3) (u8+0_2) && ^@r4 (@r7/0_2) &&
    con ^u8 u8 @r10 @r10 (@r1+1) u32 (@r12+1)
    lsl @r12 @r9 *main u64 @r12 ^@r12 @r3

    @r8 (&&+2) @r12 (*block/0_1) ^u16 @r9

    con ^*block @r5 @r8 @r5 @r8
    push ^u16 *block u64 u16
    @r9 (@r3+2) @r11 @r6 (@r11+3) ^@r1 (@r8+1)
    lsl (^*main+0_2) (^u16+2) @r5 ^@r4
    ldp ^@r5 @r3 u32

    @r3 @r6 <> (^@r9/2) (*block+3)

    movk @r10 <> (*main/1) u16 ^@r1
    ldp @r4 @r10 ^@r2 M *main *block u32
    con *main @r3 u16 
    xt @r1 @r10 @r8 @r11 
    push @r4 *main u64 u16 ^@r8


    jmp <> (<M>/3) ^@r12 u32 @r3
    jmp @r11 (&&/1) @r10 ^&&
    dw u64 @r8 M && &&
    xt @r7 @r12 ^u64 ^M ^@r5

    lsl <M> (*block+1)
    lsl M ^M ^@r7 *main @r8 (^u16/1) @r2
    push ^u64 @r6 @r9 @r10 @r9 @r7
    @r2 @r5 ^u64 M @r1 @r9

    con @r1 <> @r6 @r3 @r5 ^@r8
    push <> ^u8 @r2 @r6 (u64/0_1)

    con (@r1/2) u32 ^@r10 @r3 ^u64 u8

    @r1 u8 <M> @r10 (^@r3/1)
    jmk (u16+2) u8
    mov u8 @r5 @r5 @r11 u64 @r9

    lsl u64 @r1 @r6 (^@r8+1) (u16+2) && *block

    @r12 ^@r1 ^*main u32 ^@r2 @r10 ^M *main

    movk @r6 ^u64 (u64/0_1)
    con ^@r4 u8 @r5 u16 @r7 ^@r1 @r3

    jmp u16 u64 @r1 @r10

    jmp <> ^u32 u32 ^@r8 @r5 ^<M>
    jmp <> u8 (*main/1) @r1 @r1 M ^@r9
    movk && u64 @r6 ^@r1

    mov (@r8+0_2) @r5 @r9 ^u32 @r7

    @r4 *block @r3 *block <M> @r8 (@r11+0_1)
    ldp *block @r12 @r2 @r10 @r5

    lsl @r7 (@r5/1) ^u16 (u8+3) (@r7+2) u16 @r2

    dw @r2 u32 @r11 (<M>/1) @r8

    cmp ^&& (^@r3+1)
    @r4 u32 @r11 (@r2+0_2) M
    @r1 @r10 ^*main ^u32 u32 @r2 u8
    push ^M *main @r1 (u8/3)
    jmp ^@r9 M u64 <> (@r4/1) @r5

    push @r9 @r12
    ldp @r1 M @r9 @r8 @r6
    @r3 u16 @r12 @r3 u16
    @r6 M @r12 u32 <M> @r12 <> @r5

    ldp ^@r12 u64
    @r4 ^u32 ^@r3 u64 u16 ^u32 (@r10+3) <>
    @r7 (u16/3) @r7 && u16 (^@r9+1) @r7 @r7
    @r6 @r6 @r11 @r5 (^u64/1)
    jmp <M> u32 u8 @r12 u16 ^<M>
    xt <> @r8 @r9 ^@r7 <> ^@r7 &&
    ldp @r12 ^u64 M
    con @r10 M ^@r11
    @r9 @r12 ^@r4 (u32+0_2) @r2
    jmp (^u64/0_1) @r9 u64 @r2 <> ^@r2
    dw ^@r3 <M> u16 <M> (^@r2/2)
    @r6 <M> (^M/0_1) <> @r11
    @r11 @r2 *block @r7 @r4
    lsl (@r4/0_1) ^@r8 ^&& *block
    jmp ^@r7 u64 <M> (u32+3)

    jmp @r3 @r12 (@r10+0_1) (@r9+3) u8 ^<M>

    @r5 ^@r1 && u8 (^@r12/1)
    ldp ^M @r10 M @r10 ^<> (u16/0_1) @r11
    movk (*block+3) (@r12+3)

    mov *block *block @r2 u8 (@r7+2) @r3 @r8

    jmk (@r4+1) u16 u8
    @r10 @r12 @r6 M

    push ^@r4 ^@r7 M
    mov M (^@r3+3)
    ldp @r4 *block u16 (<M>/0_2)
    dw ^<M> u16 @r8
    @r8 @r7 @r10 ^<M>

    jmp @r12 @r11 @r10 ^u16
    lsl (u8+0_2) (@r9/2) (M+0_1) @r10 @r4
    lsl u16 u8

    con @r4 @r7 M && @r9 @r9
    @r12 @r3 u16 M
    con *main ^@r12 (@r8/2) <M> (@r3+1) @r2

    dw ^<M> ^u16 @r11 ^<> u16
    push @r2 u64 @r12 ^@r6 @r12 @r8 @r3
    jmp @r7 ^<>
    @r4 u64 @r6
    movk ^<M> ^@r5

    lsl (@r7/0_1) ^&&

    ldp @r5 (*block+1) M
    push @r6 (^@r11+0_2) u8 u16 (&&/1)
    @r2 (M+0_2) @r4
    jmk *main *block

    cmp u8 @r9 u16 && @r2 @r6 ^<M>
    cmp @r12 @r8 @r1

    push @r7 (@r8+0_2) @r5

    jmp u32 @r4
    jmk u8 M
    jmp ^@r9 @r1 (@r7/0_2) (u64/3) && (^@r5/3)
    lsl (<M>+0_2) @r1 @r5 u64 @r1

    con @r11 @r4 @r5
    dw @r4 (@r8+3) (u64+1) ^<> (*main/0_1)



    @r7 (^<>/1) (^M/3) @r9
    dw (@r2/0_1) (u32+1) *block (@r4+0_1) @r7
    jmk ^@r12 ^@r2 *block (@r7+0_2) ^u8 @r5 <>

    ldp (u16+1) ^*main u8 (@r5+1) @r4 @r6
    cmp ^<> u64
    con ^@r7 @r4 u32 @r7 u16 <> *block
    jmp <M> (@r7/0_2) u32 (u8/0_1) u16 ^@r2 @r2

    xt u8 ^<>
    movk <> @r10 u8 *block
    dw *block @r9 @r11 <M> <> M

    mov @r2 (u64+3) @r5
    @r12 M u64

    push ^@r6 <> @r11 (@r7/1) @r11 ^u8 (@r9+3)
    movk u16 M (^@r2+0_2)

    lsl (^@r7+0_2) ^<> (@r1/3) u32
    lsl @r12 u32 u64 u16 (@r11+2) M
    mov @r12 (^@r4+0_2) M @r4
    ldp u32 <M> @r10 @r1 @r11

    xt ^u8 (u64+2)
    ldp <> @r9 (u64+0_1) (u16/0_2) @r10

    mov (<M>/2) <M> @r5 (@r3/0_2) *main
    jmp @r12 ^M @r10 *main @r5 u64 &&

    mov M u64 @r11 ^<M> ^u16 (^@r6+1)
    dw u16 ^@r1 ^@r10 (@r1/1) ^@r12 <M> @r2
    cmp ^<> @r9 @r6 @r12 (M+1)
    mov M @r10 (u16+1)
    @r1 @r6 (^M+0_2) (@r12+0_1) @r5 (u16/0_2)
    xt (^M+2) @r2 M @r5 ^@r10

    jmk && @r2 @r9 (@r7/2) (u8+2)
    dw @r6 @r4 (@r9/2) @r12 M

    xt @r3 @r10 (@r10/0_1) @r6 (@r1+1) ^*main
    mov u32 @r9
    jmp (u64/2) @r10 ^@r12 *block u8 u8 *block
    dw @r12 @r2 @r2 (<M>+3) @r4

    push @r11 ^@r11 (@r2+0_1) @r1
    dw ^@r5 ^@r5 (u16+3) ^@r5 *block @r8
    jmk ^u8 @r12 @r1
    @r4 u8 u64 ^@r9 @r3 *block @r8 (*block+3)

    @r6 *block @r5 @r8 u64
    cmp (*block+0_2) ^u16 ^@r12 @r9 @r2
    dw ^u32 M @r11
    movk @r3 @r3 ^@r3
    ldp @r3 ^@r1
    jmk @r3 *block
    @r11 u8 ^@r10
    lsl *block @r2 (@r9/1) u16 @r8
    ldp M (@r8+2) <> u32 *block
    lsl @r9 (^@r3/3)
    ldp M && @r7 @r11 u32 u64 @r1
    dw *main @r2 M @r5 (@r6/0_2)
    mov ^@r3 u16 ^@r7
    dw ^@r4 && u16
    lsl @r8 <> ^@r10 (@r4+2) &&

    mov *main u64 @r3
    jmp @r8 @r5 @r11
    ldp @r5 @r1 @r6 u8 @r7 @r8 @r2

    xt ^@r12 ^@r6

    jmp @r3 u16 @r3
    mov @r1 ^u16

    dw ^@r5 @r10 @r3 ^@r4 ^@r6

    movk @r12 u64 @r9 @r12 M

    @r1 <> <M> ^@r9 (^u8+0_2) (<M>/2) u64
    @r6 && u64 ^@r8 @r12 M

    dw ^u64 @r8 *main @r7 <> @r10 <>

    mov @r1 <> (u16/2) M

    xt (<>/0_2) && (@r3/0_1) @r7 (@r8+0_1)
    cmp (&&+1) && @r8 (@r3+0_1) u64 @r6 ^u32

    push (@r12/1) @r8
    @r9 @r8 (@r4/1)
    dw && u16
    cmp u32 @r3 @r9
    @r2 @r7 @r8 @r12 *main ^u16 @r4 @r12
    dw <> (*main/2) (u32+0_2) @r12 @r7 u16
    ldp @r5 u16 @r12 *block u32 ^@r11
    jmk (u32/3) @r11
    @r6 u16 @r2 @r5 u64 *main ^<M> @r1
    cmp @r4 ^@r9 u8 @r12 ^u32 *block
    jmk *main (@r11+2) @r4 u32 @r2 (@r5+1) ^u64
    @r8 <M> @r11 u64 @r12

    @r5 u8 M ^@r10 ^u64 (@r8/0_1) @r3 @r3
    jmp @r12 <M>

    @r2 @r6 u8 ^u8 @r9 @r6 (^&&/0_2) @r4
    mov <M> u64 (@r3/0_2)
    ldp @r6 (@r11/1)
    movk (@r10+1) u16 ^@r3 <> @r2 ^@r10 ^@r2
    @r3 @r12 @r9 ^@r12 @r3 <M>

    lsl @r11 u32 @r1

    @r2 (@r11/0_2) u32
    con @r4 <M> @r4 ^@r6

    lsl u8 (^u16+0_2) @r2 M u64

    xt ^&& ^u64 (@r3+1) @r11 @r8 ^&& (u8+2)
    cmp u32 u16 (@r12/1) <M>

    push u8 @r8 && u8
    @r7 @r4 @r1 ^@r2
    mov @r2 ^@r6 (@r6/0_2) <>
    lsl u64 *main @r12 u32 @r1
    dw @r1 (@r12+0_2) u64 @r2 *main (u32+0_2)

    @r9 ^@r12 (*block/0_2) &&
    mov ^<> @r11 M ^@r4 && @r6
    cmp <> ^@r6 @r7 u32 @r4 *block <M>
    lsl @r1 u32 (^u32/0_2) u64 <M> <> <M>

    @r11 @r8 @r8 <M> <> @r5 @r7 M

    mov ^u16 (^@r3/0_2) (^@r9/0_2) ^*block @r12 @r11
    push ^@r1 @r10 @r6 (@r3+3) @r6 @r7 @r1
    push @r8 u32 @r9 u16 @r8 u8 *main

    jmp (@r3+1) u8
    lsl @r12 (@r9/3) @r6 @r8 M
    jmp ^*block <> ^@r4

    jmp @r2 (<M>+1) @r7 @r4 u64 @r5 ^*main

    ldp @r12 ^@r4
    @r7 ^*block @r7 ^@r1 ^*block ^u64 @r7
    cmp @r9 @r6 u32 u16 u8 M

    push (*block+0_1) ^@r9 (@r2+1) @r8 ^&& (@r7/1) @r3

    jmp ^*block <>
    cmp <M> *block @r1 (*block+2) ^*block (@r7/0_1)
    push @r3 @r10 @r6 @r10 ^@r1 <M> (*main+2)
    @r6 u8 ^@r6 *main ^@r1 <M>
    cmp @r3 u16
    movk (^*block+3) *block @r7
    push @r4 <M> *main
    lsl @r2 @r9 u8 && <M> ^@r8 @r3
    @r9 @r12 u16 @r12 u8 @r12 u16
    @r8 @r10 (^u16+0_2) (^u16/2)
    ldp @r9 @r9
    push && @r8 ^@r7
    movk @r5 @r4
    @r11 u16 M
    ldp ^@r2 @r12 ^u32 u16
    movk u32 @r4

    dw @r7 <> @r11 <> ^@r8
    cmp @r1 (<M>+3) u8
    dw @r12 *block @r3 (@r9/2)

    cmp u8 @r6 && @r2 @r10
    ldp M @r7 (@r4+2)

    ldp && && ^*main *main
    lsl @r6 (@r7+0_2) ^M ^@r5 (@r9/3)
    dw @r4 @r3 ^<> @r6 ^@r6 (@r7/0_1) @r7
    jmk @r5 (^@r2+0_2) *block @r12
    @r11 @r2 @r2 &&
    movk @r11 @r10 *block (@r4+0_1) u32 u32

    @r6 (@r2/1) <> @r2
    jmp (u64/0_1) ^@r12 @r4 ^<> @r7 @r1 @r10
    movk && *block @r12 ^@r7 ^<> @r3 (@r10+0_2)

    mov @r5 ^@r6 @r10

    cmp ^@r4 @r1 *main u16 (@r2/0_1) u64
    dw (@r6/3) (@r10/1) @r2 @r1 (*main+1) ^u8
    cmp M ^u16
    jmp ^@r2 @r6 u64 @r8
    ldp @r4 M

    dw u8 (@r4+2)
    lsl u8 @r5 (@r12+0_1) ^@r7 @r10 (^@r3/2)
    @r5 (<>+2) M ^@r9 @r2 (^@r12/0_1) @r1
    ldp @r5 @r1
    jmp <M> @r3 <M>
    cmp @r9 ^@r9
    @r6 @r7 (^@r11/3) <> @r10 @r10
    mov @r10 *block @r4 ^&& (@r5/0_1) ^@r9 ^@r12
    @r5 <> <>

    lsl ^@r1 ^@r3 *block (<M>/1) @r7
    push @r8 @r8 @r3 ^u16 ^M @r10

    ldp *main @r12 (u16+3)
    movk @r5 @r2 @r10 ^*main <M> *block *block
    jmk @r4 (@r4+0_1)
    @r6 ^@r5 *block @r6 @r5 @r12 M (u32+2)

    lsl (^@r11/3) u8 ^u16 (<>/0_2) @r3 @r3 @r10

    push ^u8 *block ^@r10 (u32/2)

    jmp @r3 @r1
    ldp ^u32 ^@r4 && (u64+0_2) ^@r2 <>
    @r4 u8 (@r3+3) @r8 @r10
    mov <M> ^@r7 ^@r6 (u16/1) (@r10/0_2)

    mov && *main @r5 (u16/3)
    jmk @r8 && M

    jmp @r8 (@r10+1) u16 @r1
    @r9 @r4 @r12 @r4 u64
    dw @r12 M @r8

    movk ^<M> (<M>+1) (@r8+3) @r7 u32 ^<M>

    cmp ^@r2 (^*main/1) @r4 (M+0_1) @r5 (<>/3) (@r5+0_1)
    push ^u16 (*main+0_2) *main
    @r9 ^@r4 *block u8 @r6 ^@r8
    jmp @r1 *block (u32+2)
    @r7 <> M @r10 @r3 @r12 ^@r12
    @r9 @r6 @r7 @r5 u16 u16

    movk @r3 @r6 (@r3+0_1) ^*main (<>+3) u8

    cmp (u8+0_2) && u8

    mov ^*block u8 &&
    jmk @r1 ^@r1 @r1 @r5
    @r6 && (@r6+1)
    lsl u8 ^@r6 ^u8 u16 (u16/1)
    push @r2 @r12 u8

    ldp ^<M> <M> @r5 (^u16/0_1) (*main+3)

    movk @r8 <M> @r5 ^u16

    jmk (M/0_2) u16 <> ^@r8 (<>+0_2)
    @r7 u64 (^@r10+3) u32 @r9
    jmp (@r1+2) u16 u16 @r5 (@r3/0_1) @r6 @r1
    ldp ^&& @r1
    push @r6 M @r6 (@r6/0_1) @r3
    lsl @r9 ^@r8 ^<> ^@r2 @r3

    cmp @r4 <M>
    con *block ^<> u32
    @r10 @r9 u32 @r1 ^@r9
    mov @r6 ^*main @r10 (u16/0_2)
    ldp && @r8 @r11 @r10 u8 u16 <>

    jmp ^@r2 *main @r7 @r1 @r11 (@r11+2) M
    jmp && @r9 @r12 && @r10 (@r9/0_2)
    push @r2 M M @r3 @r7

    push @r5 @r3 ^u8 @r4 @r4
    @r5 ^@r10 u8
    mov ^@r11 @r10

    push @r10 u16 @r12 ^<> ^@r8
    @r10 @r4 <M> && ^u64 (@r10+0_1) @r12
    dw @r2 ^@r1 M @r2 ^@r7 ^*main @r8
    cmp M u16 u32 @r5 @r4
    jmp u16 *block *main u8

    jmp (@r2/1) && ^@r2 u32 (<M>+1)
    jmp @r8 @r9 <M> @r7
    @r9 @r1 @r4 (u32/3)
    push *main u64 u8 @r4
    jmk *block (@r8/1) ^u16 @r12 u8 *block
    dw ^@r9 *main
    @r5 u64 ^u16 @r2
    mov <> M u16 @r3 ^u8 @r7 @r11
    cmp ^@r10 @r9 @r12 @r9 @r5
    push *block ^u16 ^@r9 @r3 (@r11+0_2) (^&&/2)
    cmp @r5 @r11 && *main
    @r9 (@r9+1) (@r6+1) @r12 && ^u16 &&

    jmp u8 @r5 *main

    ldp *main @r5 @r8 @r8 ^@r12 @r4
    push @r5 ^@r10 ^<M> M @r5 u8
    mov u64 @r10
    ldp u8 u64 @r10 u64 u64
    cmp @r9 @r5 (^M+0_2) ^*block (M+2)
    xt && @r3 @r2 ^@r7 <>
    lsl u16 && M

    xt @r7 @r12 ^@r6 M @r6
    xt ^@r3 ^@r2 @r12 ^@r4 ^M @r12 @r9
    cmp (M/0_1) @r3 @r12 @r8 *main
    xt ^u8 @r2 @r5 @r1
    @r9 @r9 (u64+0_2) M *main @r9 @r5 @r7
    jmk (*block+0_2) u8 @r7 <> @r1 @r1
    @r2 @r12 @r3 ^@r1 @r1 (<M>/0_2)
    xt <M> <M> (^u64/3)

    @r10 (^@r3+1) ^<>
    ldp (@r10/2) ^@r3 u16 ^@r3 @r8 ^<M> @r5
    @r9 *main @r1 &&

    ldp @r6 @r8 u32 ^@r11
    jmp @r6 @r10 @r5 @r1 @r9
    cmp (<>/1) @r5 @r4
    ldp @r9 u32 (^u32/0_1) @r10
    mov ^<M> @r3 ^<M> @r3 @r7 @r8

    jmp @r8 ^@r9 *block (@r8/2) @r12
    movk (@r6/0_1) ^@r12 @r7 u8 ^u8 *main @r3

    cmp && @r5 ^@r12 (@r10/2) @r1 u32 @r5
    mov ^<M> (^*main/0_2)
    mov u32 (<>+1) u16 (M+0_1) u8 u16

    @r3 (^@r12/3) *block u32 @r2
    jmk @r8 (u32+2) @r8 u64 ^@r11
    movk ^@r3 u8 u64 u8 u16
    ldp <M> (^*main+3) @r1 @r8 ^@r8
    cmp @r7 (^@r10+3) ^@r1 ^@r11
    jmk @r5 ^*main @r3 ^@r8 @r4

    jmp M @r10 @r1 ^u32 ^u16
    push @r1 @r2 ^&& @r12 u64 u16

    ldp ^*main *block
    ldp ^@r12 && (^@r8/0_1) @r4
    jmp (@r5/2) @r5
    jmk <M> ^@r6

    movk u16 ^@r5 @r2 @r12 @r6 ^&&
    @r5 (^u32/0_1) u16 u8 @r3 ^@r5 (u32/0_2)

    cmp @r1 u16 @r7

    @r3 (@r8/0_1) @r8 ^@r3 ^u32
    movk M u16 <> *block
    @r7 ^@r6 ^&&
    mov <> @r6
    movk ^u8 @r6 ^@r1 u64

    jmk ^@r11 @r8 @r7

    cmp (*block+0_2) @r7

    jmk @r11 *main @r5 *main (@r6/2)
    ldp @r5 (@r7/0_2) ^@r9
    push @r2 u8 @r10 (^<M>+0_2)

    mov @r4 u32 @r11 @r4 @r12 (*block/0_1) *main

    mov @r9 @r9 <> ^@r2 @r7 @r4
    dw M @r2 ^u8
    push @r2 M
    mov (u32/1) && u16
    cmp u8 (u16/1)

    jmk @r10 u8 @r12
    cmp @r7 u8 @r2 <M> <> u32 <>

    mov M ^@r2 (&&+0_2) @r9 ^*main @r10 @r9
    @r8 @r7 @r10 @r5 (@r2+1) @r6

    @r7 M <> u16

    mov (@r9+2) u16 @r5 ^@r4 @r3 @r10

    @r9 @r11 *block @r1 u64
    push @r12 (^@r8+2) @r6 @r9 @r9 @r9 @r7
    mov @r9 *main <M> @r12 && <M>
    jmk @r12 (@r4/3) (^u32+0_2)
    dw @r3 ^@r5 (@r6/0_1) @r6 @r11
    push @r11 ^@r10 (@r10/0_1) (<>/0_2)
    lsl <> <M>

    jmk u32 ^@r1 ^*block (*block+2) ^M @r12
    mov u64 *main
    mov ^@r12 @r8 @r6 @r3 ^@r8 (*main/3) u64
    @r4 @r12 *block
    dw ^*block @r2 (*block/0_2) ^u16 (@r12+0_2) u64

    movk @r9 @r4 ^u64 *main &&
    @r10 *block ^M (^@r4+0_2)
    jmp (<>+2) @r5 ^u64
    @r9 (@r2/1) u64 @r5 @r6 && <M>

    dw M @r3 @r4 @r11 (^&&/0_1) ^@r9 @r10

    jmp <M> (*main+0_2) @r6 (@r3/1) @r10
    jmk ^@r8 @r8 @r1 @r3 &&
    push (^M+1) && u16 (@r3+2) @r2 ^<M>
    cmp (^u16/0_1) u16 <> <M> @r1

    ldp && ^@r12 ^*main @r4 @r11
    ldp && (@r5/0_1) <>
    jmk (u16/0_2) u16 ^@r6
    push u32 <M> @r7 u32
    mov (@r3+0_1) @r8 ^@r7
    ldp @r6 (^*main/0_2) *main @r10
    movk && @r11 @r4 @r2 *block u32 @r6
    jmp @r10 @r3 ^@r6 && u8
    push *block @r11 @r8 @r9 @r6 @r10 @r5

    dw ^@r3 (&&+1) ^M (*main+3) &&

    ldp ^@r7 @r3 u64 (^&&+0_2) u32 && ^@r3
    movk ^@r6 && M @r11 ^@r7 (&&+3) @r10
    jmk @r3 *main u16 (^M/3) @r6

    @r8 @r4 (^@r1+2) (^@r12+2)
    @r11 @r3 && ^*block @r9 @r4
    mov (@r5/0_2) (<>+2) (*block/3) @r6 (@r5+0_1)
    cmp u8 @r1 u16 @r10 *block ^<M>

    movk @r8 u32 @r11

    jmp @r9 @r10 @r1 *block (@r9/0_2) ^@r11
    movk u16 @r2 ^u32 @r3

    lsl (^@r12/2) (*block+1) *block *main <M> ^@r2
    lsl @r10 ^u8
    lsl @r8 (@r3/2) ^@r6 (^u16/1) (^M+2) @r9
    dw @r7 @r10 @r4 @r2 (@r4+2) @r1
    movk ^@r3 (@r5/3) <M> @r12 (@r11+0_1) ^&& ^M
    movk @r1 (@r7+0_1) @r8 ^@r3 (*block+2)
    dw ^u8 @r2 @r1
    @r8 u64 u32 && ^<> u16
    cmp (@r5+0_1) <>
    movk *block <> @r8
    @r4 @r4 (<>/1) @r11 @r11 ^@r7 ^@r8 ^<M>

    @r2 @r11 @r9 ^&& && (@r9/0_2)

    jmp M (u16/1) (@r8/2) M @r12 ^@r1
    dw u64 @r5 @r9 @r11
    cmp @r2 u16 @r6 (@r8/0_2) @r6 ^@r1
    @r8 (*block+3) (u16/2) <> @r7 &&
    dw @r8 u8 (@r4+2) u16 @r4 ^M ^@r5

    mov @r10 @r4 @r3
    mov @r2 @r3 @r1 (u8/1) <M> u32 @r5
    ldp ^@r10 u16 (^u8/2) u8
    push u8 @r1 @r2 @r10
    jmp @r10 @r3
    dw @r10 *block ^@r7 @r9
    cmp *main ^@r2
    jmp M @r5 (@r12+2) @r11

    dw <M> ^<M>
    jmp @r1 (@r3/1)

    @r4 @r2 (@r3/0_1) (*block+1)

    movk (u64/2) (@r10+1) *main ^@r10 *main && @r12
    movk @r10 @r9
    @r2 @r9 M @r6 u8 @r8
    movk <M> u8
    @r1 ^u64 u64 (@r12+0_2) (^u64+0_1) ^u16 @r9

    cmp @r5 @r11
    jmk ^@r3 ^@r6

    @r9 @r8 ^@r5
    movk M (M/0_2) @r8
    @r5 ^u16 @r3
    @r9 @r4 ^u32 @r5 @r2 @r8 @r12
    jmk (@r10+0_1) @r12
    jmp @r12 M @r7 *block (&&/0_1) @r6 @r10

    lsl @r3 @r5 @r12
    jmk @r3 && (@r2+2) @r5 *main
    @r6 @r10 @r5 @r7 @r12 @r12 ^u64 ^u16
    jmk @r2 @r1 <M> @r6 u16 (@r9+0_2)
    jmk u16 *main @r6 @r3 *main @r3 u64

    dw @r6 ^*block

    lsl *main ^@r2
    @r7 (^@r11+2) @r1 (@r9+3) @r10 <> @r2 u64
    @r4 ^@r9 ^@r7 @r12

    @r11 ^u64 @r7 ^@r10 ^<> (@r12+1) ^u16
    ldp M u8 @r8 u64 (@r11+0_1) @r9
    ldp @r7 u64 (^<M>+1) @r9

    movk M @r10 && @r3 ^@r4
    cmp u8 @r3
    @r10 u32 u16 M u64 @r6

    @r3 (<M>+2) && *block @r1 ^<M> u8 @r10

    @r12 ^<> M

    movk @r4 @r7 @r5 <M> @r2 @r4 (@r8+1)
    movk u8 @r11 u32 ^*main
    jmk @r1 (^@r10/0_2) @r5 @r1
    dw <M> @r7 ^@r8 @r3
    jmp (u8+0_2) u32 @r4 (*main+1) (@r12/2) ^u64 @r9

    @r3 @r12 @r10 ^@r5 u8
    lsl @r5 @r8 @r10 @r11

    mov <> <M> @r4 (*main/0_2) ^@r5
    cmp @r1 u32 @r5 @r2 u32 @r5 ^@r8
    jmp ^u8 ^&&
    ldp ^@r2 ^@r10 (^@r5+0_2) (^u64+0_1) @r10 M @r11
    jmp u64 u32 &&
    dw @r1 u16 M u16 @r4
    @r11 @r3 @r9 @r4 u64 @r2 <M>

    jmp *main <M> @r2 && (@r2/2) *main
    jmk @r2 @r7 u32

    @r7 @r6 *main (*block/0_1) (@r5/0_2)
    jmk (@r5/1) @r12 ^M (@r4/2) @r5 u16

    ldp ^<> ^@r10

    movk ^@r6 <M> <M> ^@r3 @r6 (^<>/3) @r12
    mov @r2 u32 *main
    jmk @r7 @r8
    ldp *main u64 @r1 <> @r7 @r7

    movk @r9 @r4 u8 @r4 ^@r10

    movk <M> @r8 (u16/1) (*block+0_2) (u64/0_2) u32

    jmp @r12 @r6
    mov *block @r5
    jmp M ^<> <> @r5 (@r4/1) (^@r3+2)
    mov @r10 @r10 @r10 (&&+3)
    mov u16 @r6
    @r7 ^@r11 u16 ^@r1 *main (u64+0_2) ^u16
    push ^u32 u64 u16 (<>+0_2) ^@r1 M

    @r12 *main @r1 @r2 (@r11/0_1)

    jmp (^u32/0_1) ^@r3
    lsl @r2 ^@r3 ^u64 @r6 ^<> (@r10+3)
    ldp @r10 @r1 ^u64 *block M <M>

    movk ^@r1 ^<M> @r9 @r2 ^u64 &&
    jmk u32 <> ^@r8
    movk ^@r4 && @r9 ^*main
    push u64 (@r10+0_2) ^@r11 @r11 (@r12+0_2) u16 @r1
    ldp M ^@r9

    movk <> @r9 u8
    @r8 @r8 u16 *block <> M @r2
    movk M @r7 (*block+1)
    mov u32 (@r6/3) <M> @r7 u32 @r7 ^@r10

    dw @r4 u8 @r12 *main @r6 @r4
    dw u32 *block @r2 ^@r11

    ldp && u64
    ldp *main (@r2/2) @r12 @r12 @r12 && @r4

    movk @r6 (^u32/2) @r9 @r4 @r9 @r5
    cmp @r5 @r5 ^u32 M M *main
    mov u64 (@r8/2) @r10
    dw (*main+1) @r10
    push u8 @r10 ^@r8 @r8

    dw @r6 *main @r8 @r5 u32

    dw ^@r9 @r1
    jmk @r8 @r8 @r6 M @r9 (*block+2)

    cmp @r3 u16 @r10 @r11 u8 (@r4/0_2) *main
    push @r4 (@r7/0_1) @r4

    push (@r8+1) u16 u8 @r9 @r2 (u32+3)

    mov ^@r1 u64 u16 u64 @r10 ^@r10
    movk ^@r7 @r4

    movk (&&/3) *main ^@r7 ^@r2 @r12 *block
    jmp u64 (&&+2)

    cmp @r3 <> ^*main (@r9/0_1) @r3

    dw @r9 @r11 @r11 *block ^@r4
    mov (@r5+0_1) ^@r1
    @r11 @r1 @r9 (&&/1) @r3 (@r11+3)
    jmk @r7 ^u16 <M> u8 @r6 (@r5+1) @r12
    dw (@r12+0_1) u32 ^@r12 @r12 u32

    jmp ^@r4 @r7 @r8 ^@r10
    push u16 @r1 M @r11
    push u32 <> (@r12/3) @r1 ^<>
    @r2 ^u16 u8
    mov u16 @r7 (*block+0_1) (u8+2) @r8
    movk (^@r1/3) ^@r5 M ^@r6 @r10 <>
    jmp @r12 ^&& @r4 @r5
    @r9 <> *block (@r5/0_1)

    @r7 (@r4/0_2) @r1 @r5
    ldp @r7 ^<M> ^@r5 u64 ^u16
    ldp M <M> @r6 u32 (@r12+1) ^@r5
    cmp *main (^@r9+0_1) <> @r7 @r5
    ldp ^@r10 u16 ^@r3
    @r5 ^@r12 @r3 (@r8/3)
    movk @r10 @r6 (@r2+1) <M> *main @r5

    ldp @r12 (@r9/3) u16 u64 u16 @r9 *block
    jmk (@r1/2) u8 @r12 @r2 u64
    lsl @r5 ^@r12 @r6 @r2
    @r4 @r12 (@r4/0_1) ^@r11

    jmp <M> (@r3+1) @r11 u16 u16
    dw @r9 *main (*main+0_1)
    movk @r12 u32 ^M @r5 u64 (<>/2) (@r3+3)
    push (@r3/0_2) M ^@r9 u8 *block
    @r8 @r5 @r9 @r6 @r1 <M> @r10 ^u8
    cmp *main *main
    cmp ^@r9 u64
    @r7 (u32+1) ^<> (@r5/0_2) ^<M> @r11 u64 ^@r7

    jmp u16 @r5 @r5 @r11 && (@r7+2) u16

    @r12 (u32+3) u64 @r9 (@r8/0_1)
    ldp ^<> ^u32
    jmp (M/0_1) @r4 M u8 (^<M>+3) ^@r11
    mov (u64/2) (^u32+0_2) @r1 u16 @r5 M
    jmp @r3 *block u16 @r8
    cmp @r11 @r3

    mov (M+0_2) (@r1/0_2) @r6 *block @r11 (^@r6/2) *block
    movk @r7 @r1 ^@r5 @r7 ^@r9

    movk @r3 ^@r5 @r4 @r10 u8 (M/3) @r4
    dw ^@r10 @r3

    dw ^@r10 (@r5/0_2) @r10 M u16 (@r4/0_1)
    dw u64 (^@r11/0_2) (^@r6+1) @r10 u8 @r6
    @r4 @r1 (@r3+2) u16 @r6 u8 (<M>+2)

    @r4 @r3 ^@r6 @r2 @r3 ^@r5 &&
    lsl ^@r9 M u64 @r9 *main <>
    ldp u8 @r9 u32 u64 ^@r10
    @r1 u64 @r7 ^@r11
    mov @r2 (^@r8+2)

    cmp @r6 @r8 @r4 ^@r5 (*main+2) @r4

    jmp @r7 @r11
    dw u32 (^@r9+0_1) @r8 ^@r3 @r12 ^@r10 @r9
    jmp ^@r8 u32 @r10

    movk (u16/2) <M> @r12 (@r9/0_2)
    jmp ^*block ^<> u32 (u64/0_2)
    push (^@r11/2) (^@r2+0_1) @r9 (@r2/3) u16 @r3 @r12
    ldp <M> <M>
    dw @r8 ^M @r5 <M> @r3 @r11

    push u64 <M> @r1
    cmp @r2 @r7
    @r12 && @r12 M @r11 <M> *block @r4
    movk @r11 (@r2+2)
    dw *block @r5 u32
    movk (@r10+3) && @r3 u8 @r4
    jmk (@r7/2) *main @r10 u64 u32 ^@r8 @r4
    cmp u16 @r4 u16

    jmp u32 ^*main (@r4+1) @r2
    lsl *main ^*main M (@r5/0_2) (@r5/0_1) *block
    jmp <M> @r9 && ^@r7 *block @r2 @r9
    @r10 @r2 @r5
    movk @r11 @r10
    @r10 u16 @r1
    mov (@r2+3) @r10 (@r2+0_2) (@r3+3)
    movk u8 @r6 *block
    push @r5 (<>/3)
    lsl ^u16 <> (*block/0_1) ^@r7
    ldp (u64/3) @r2 (@r11/1)

    mov @r9 (^@r8+0_2) (^@r3/2) @r9 <M>

    @r1 *block u64 ^u8 @r6 (^u64+0_1) (@r4/1)
    movk ^<M> @r9 (@r8+0_1)

    ldp ^@r2 <> @r9 u8
    cmp @r2 @r7 && <M> ^&& @r12
    mov (@r1+2) ^M
    lsl @r9 *block ^*block @r7 @r1 M ^@r1
    movk (*main/0_2) @r10 u64 (@r10+2) @r12 *block (^&&+2)
    dw @r10 ^M @r3
    @r2 u64 (@r12+2) @r7 @r1 (@r7+2)
    @r5 *block @r3 ^M
    ldp @r12 && @r4 @r9

    mov M ^@r11 (<M>+0_2) u64 (@r6+1) @r7
    movk @r4 ^@r2
    @r6 @r12 @r7

    cmp @r2 @r11 u64 @r4 *main

    @r4 ^@r3 @r9 ^u16 @r8 @r7
    jmk @r8 @r12
    lsl M ^@r1 ^@r7 (@r5/1) && <> @r1
    movk ^@r2 (u64/0_1) *block (@r12/0_1) (<>+0_1)
    movk ^*block @r6 *main ^u16 @r6 (^@r3/0_1)

    @r1 *main (u64/1) <> @r4 
    mov @r10 *block ^@r1 u16 @r3 ^*main (@r5)

    jmk @r11 u64 (@r5+0_2)
    ldp @r1 (u32+0_1) @r6 M ^<M> *block
    movk ^@r7 M u32 *main (<>+1) @r4 *block
    cmp @r2 @r9 @r11 (<>+2) (u64+3) ^u16 ^@r10
    con ^@r6 <M> (u64+0_1) @r5 *block @r11 (^<>+0_2)

    lsl (@r9/1) M @r12 (^@r4+0_2) ^@r8 (@r8/3) ^*main

    ldp ^@r2 @r12 ^<> u32
    jmp <M> u16

    xt @r2 ^*main @r12 ^@r12 u32

    jmk ^*main (@r12/2) @r6
    lsl ^@r3 u64 (u16+3) @r9 ^@r9 *main

    con @r1 @r12 *block @r6
    @r7 ^@r3 @r1 @r1
    jmk @r3 u32 ^*block @r8 M @r2 ^@r1
    xt <> *block u16
    dw @r9 *main u32 @r8 @r11 u64 @r8

    mov (@r5/2) @r12 @r3 @r10
    @r9 @r12 (u32/0_2) ^@r3
    xt ^u32 (^@r8/1) *block (^*main/3) (u32+3) @r1 M
    ldp @r3 @r1 ^@r6 (^&&/3) @r8 ^@r2 M
    mov *block ^@r7 u16 *main *main
    con @r2 @r12 ^&& @r11
    dw *block @r6 (@r6+0_1) ^@r6

    ldp @r6 @r12 @r3 ^M u32 ^@r7
    dw u64 @r12 <> @r12 ^@r3 (@r11/1) @r12
    mov (@r6+3) *block
    push @r3 ^@r8 u8 (^@r1+2) @r3 (@r2/3) (^@r1/2)
    xt u64 ^@r12 @r6 ^@r7

    ldp ^@r3 ^u8 ^u16 @r5 @r1 u16
    @r9 u32 (*block+3) *block *main @r8

    con *main @r4 (@r3/2) (@r7+3)
    con @r4 @r2 (u16/0_1) @r10 @r9 @r6

    xt @r10 ^@r9
    mov ^M (^u32/0_1) (@r8/0_1) u8
    cmp @r4 <M> (u32+0_1) u8 u16 (^<M>/2)
    lsl @r12 @r11 @r5 *main
    movk u16 u32 (^&&+0_1) @r4 ^@r10 ^@r2
    dw ^*main @r5

    dw *main @r11 M
    xt @r7 (@r5/3) (&&/1) @r10 u32 ^@r9
    jmp u64 @r4 u8 @r9 <> ^@r9
    con @r8 @r8 M *main @r5

    @r3 @r5 u64 M
    dw u32 @r2 u32 @r10 @r9 ^@r10 M
    push M *block ^M u8 u32 (@r11+0_2)

    @r4 <M> *main ^*main ^*block @r2

    push @r3 (@r2+1) @r6 u16 @r9 (<>+0_2)
    ldp u32 <M> @r1
    jmk ^*main *block u8 (u64/1) (^u8/1) (@r1/0_1) @r6
    @r2 ^@r7 M (@r10/0_1) (^u8+3) ^u32 *block
    con *block @r7 ^@r2 @r11
    @r4 *block && ^@r9 <M> u64
    push @r10 <M>
    con u16 *main
    dw @r12 ^@r4 u32 <> (^*main+3)
    dw @r5 @r9 (*main+3) @r5
    xt @r5 @r12

    @r1 @r7 @r9
    @r2 u32 @r2 ^@r7 ^@r12 @r10

    mov (@r5+0_1) M @r6 @r8 ^<M> @r3
    movk @r7 *block ^*block u32 ^@r7

    xt u8 ^@r8 @r3
    jmk ^u64 (^*main/1) @r2 (u16+0_1) @r5

    con @r4 @r11 @r9 M
    xt @r7 u8 (@r7/3) ^*block ^@r2
    movk ^u16 u16

    @r12 u16 ^<M> (^*block/3) @r5 @r3 @r10
    cmp u32 u8 ^@r5 @r3 ^@r12 ^@r1

    dw @r5 u32 @r2 @r2

    @r7 (<>+0_2) @r7 (*block+2) (u64/3) @r4 (M+2)

    cmp ^u16 ^u64 (@r8/1)
    mov @r10 && u64 M u8
    dw ^@r11 (^<>/0_1)
    @r2 (u8/0_1) @r8 ^u8 ^u16

    xt <> (@r7+0_1) M

    movk @r3 ^@r6 @r1 &&
    lsl && @r4 (u32+0_2) @r3 ^@r5
    dw (@r6/2) @r6 <M> @r10
    @r1 @r3 *block M u8
    jmk @r12 @r5
    jmp && <M> (^@r8+0_2) u64
    xt @r3 ^@r6 ^<M>
    mov <M> ^<M>
    cmp ^u64 (*block/0_1)
    movk (&&/1) @r5 @r3 (^@r12+0_1)
    @r2 @r6 (@r12/1)
    jmk @r8 && (*block+1) @r7
    push @r9 M
    xt @r2 u32 @r9 <M> @r9 (@r7/1)
    xt @r8 @r9
    dw (u32+2) @r5 @r9 @r1 (^@r11+0_2) @r7
    @r6 @r8 *main (@r9/1) <M>
    ldp (@r5/1) && u64 (@r7+3) @r3

    xt ^&& @r2 (u16+0_1) ^@r6

    xt ^@r9 *main
    mov (@r2+0_2) @r3 (@r5/0_2)
    @r8 @r5 ^@r9 (^u32+2) (<>+0_1) ^@r12 @r11
    @r8 <> ^@r2 (u16/2)
    movk && @r9 && @r4 u32

    ldp *main ^&&

    mov @r3 @r5 ^@r5

    lsl (@r10+1) u8 (@r8+0_2) (^@r9/3) u8 ^@r1
    xt @r9 @r12 (*main/0_2) ^@r3 <>

    movk @r11 <M> @r2 M
    @r5 u16 @r8 u8 @r6 @r2
    cmp @r5 @r2 ^u64 @r2

    ldp @r5 ^@r4 @r2 *block @r3 @r6
    @r12 ^@r7 ^@r1 <M> @r7 (*main/0_1) && ^@r8

    @r4 @r1 @r3 M (@r9+2)
    @r2 @r4 @r9
    push @r7 ^@r5 ^@r11 @r2 ^@r1 *main
    ldp u16 &&

    xt @r3 <M> M

    ldp ^@r12 @r11 @r11 *main ^<>
    jmk u8 u16 ^*block @r5 @r8 @r5
    cmp ^<M> @r4 ^@r1 @r5 ^@r8 (u32+1) @r5
    ldp (^@r7/3) ^@r4 @r7 u16 (u32/2) <>

    mov ^@r7 @r5 u32 @r4
    push ^<M> u64 (*block+1) u16 ^*main u64

    mov @r6 *main u16 (^@r10/2) (^@r5+2) u8 @r5

    jmp @r8 ^M u8
    ldp <> ^<> (@r10/3)

    jmp u32 (^u64/0_2) @r10 && @r7 && @r6
    xt ^@r10 @r2 (^*main/0_2) (^@r12/1) ^u16 u8
    jmk @r4 (@r2/3) @r1 @r4

    ldp @r4 (*block+0_2) @r2
    cmp @r2 ^@r4 @r10 u8 ^u64 @r8 (@r6+0_1)
    xt (&&/2) @r8 *main @r7 (@r10/2) @r8 ^@r8
    @r1 @r4 @r12 *main
    mov ^&& @r1 ^<M>
    cmp @r5 *block @r6 *block && @r3 u32
    jmp (@r8/2) u64 ^<> @r4 *main @r12
    @r4 @r7 <M> (^@r9+0_2) (@r9+0_2) <>

    @r2 @r9 (u16+0_1) ^u8 @r6 @r6 @r4 @r1
    con (^@r1+0_1) (u16/2) ^u32 ^@r6

    @r10 @r8 @r11 u16 @r2
    jmk ^*main &&
    jmk @r6 *main @r8
    @r4 @r3 u32 @r6 *block <> *main @r6
    @r10 @r1 *main <> @r12 u64 @r3
    lsl @r5 <> @r9 u64 @r1 @r4
    con <> <M>
    ldp (&&+0_1) @r2 @r8 ^u8

    cmp ^u32 @r12

    cmp *block @r12 <>
    xt u64 u16 @r8 (*main+0_2) @r3 M M

    lsl (@r2+3) *block ^@r5 (@r4/0_1) u64 @r3
    cmp @r9 u8 (@r5+3) @r6 @r7 @r6

    @r4 @r3 <>

    jmk *main (@r7/3)
    con @r3 @r1
    jmk @r7 @r1 *block u8

    @r7 && ^@r5 ^<> *main u8
    dw @r10 @r6 @r12
    lsl u16 && ^@r2
    @r8 *main @r2 @r12 M <M> @r7

    mov *block u64 @r6 @r12 @r5 @r5 u32
    movk @r8 ^@r7 u8
    dw <> @r8 @r2 ^<M> @r8 @r4 (u8/0_2)
    jmk u32 @r1 @r12 @r7

    ldp ^u8 @r3 <> u32 @r5
    jmp M @r3 M u16 @r1
    con u8 ^*main ^u64 @r10 @r7 && @r4
    dw (@r12+0_2) u8 @r10 @r11 u8 ^u64 &&

    con @r11 @r6 (^@r7/2) (u16+0_2)
    push M @r6
    jmp @r10 @r2 (u16+1) ^*main *block @r4 ^@r4
    jmk ^@r11 (@r1/3) @r12 (@r12/2) *main @r8

    cmp ^@r10 @r1 @r8 @r8 @r3 *main *block
    jmk u8 <>

    @r12 @r5 <>

    @r7 (^u16/3) *main @r11
    ldp @r8 (@r2/0_2) @r6 ^M @r9
    movk @r4 ^@r8 *main
    mov @r5 ^@r2 @r5 *main
    lsl ^u32 @r10 @r3 ^u8 u64
    con ^@r11 (^u8/3) M (@r7+3) <M>

    cmp (@r9/0_2) @r4 @r6 @r1 ^M
    movk @r7 @r10 u16 ^@r4 u64 @r10
    @r3 ^@r4 M @r8 u64 @r1 @r10
    dw <M> @r9 @r6
    cmp @r1 *main

    push *main @r9 @r4 M
    lsl (^@r7+0_1) @r9 @r9 @r9
    @r8 (@r3/0_1) <> @r12 u8 u8 ^@r12

    movk && && ^@r2 ^@r3 @r12 *block
    con ^*main (M/1) (*block+0_1) ^*main ^@r3 @r1 (@r2/1)
    jmk (@r6/0_2) ^<M> @r7 <> (@r9+0_1) @r11

    xt <M> ^@r11
    jmk @r1 ^u8 @r1 @r2
    @r7 (@r2/0_2) u64 *main M *main ^u32
    jmk u32 ^*main @r7
    jmk @r8 @r12 ^@r3 (@r12/1) @r12

    cmp @r11 @r5 @r8 <> ^&& u32

    mov @r11 *block

    dw @r6 ^u16 ^@r9 @r11 M
    @r6 M ^@r4 (@r5/2) @r8 (*main/0_1)

    con (^@r2/1) ^@r7 u32 @r4 @r5 ^*main @r3
    ldp u16 @r8 <M> @r4 @r4

    mov ^u16 *main ^u32 (u32+2) u8 @r7 @r5
    jmk u8 u32 (@r1+1) ^*main @r7 ^@r3 @r6

    mov (&&/3) @r4 @r2 <> ^<M>
    con ^@r11 @r7 (@r3+3) @r11 @r2 @r9
    jmk @r10 @r11 @r9 ^u16 @r2 (^@r10+2)
    @r7 @r1 @r12 @r4 @r3
    push (^&&/3) ^@r10 @r5

    @r4 M ^u16 (@r5/1) (^*main+2) (^<M>+3)
    movk @r3 @r5 ^@r9 @r4 ^@r8 ^@r3
    lsl @r5 *main @r3 u16 @r11
    mov @r1 u64
    con @r8 @r11 u8 u64 && (u8+2)
    movk (@r3+2) <>

    jmp ^u8 && <> M @r9

    con @r9 <M>
    jmk ^@r6 ^u32 @r9 (*main+0_2) (@r7+0_2)
    movk @r2 @r4 (@r9/0_1) M <M>

    @r5 ^u16 @r10 @r11
    mov ^<M> (@r6/0_1) @r9 ^M ^@r4 @r6

    xt u16 @r5 && @r2 u16 @r3
    @r12 ^@r10 (^@r7/3) (u64/0_2) @r5 u64 ^u8 @r5
    xt @r7 *main <> M (@r2/0_1)

    xt @r10 ^&& && @r5 @r4
    movk M u32 @r2 ^M @r4

    ldp <> &&
    dw @r5 u32 u64 @r10 M *block @r3

    movk @r11 u16 ^@r4 u32

    jmk @r1 (u16/0_1)
    movk && ^@r1 @r8 <> *main
    @r11 u8 ^*main @r4

    ldp <> <M> u32 @r3 (@r8+3) @r5 (@r12/0_2)
    push ^@r12 ^<M> ^@r8 ^@r8

    lsl *main @r2 @r10
    jmk && @r7 u64 @r1 @r2
    mov @r12 <M> @r4 u32 @r1 @r4 u32

    @r7 *block @r9 @r1 @r5 (@r12+3) @r8 u8

    xt <M> (@r7/0_2) u64 u16 @r5 @r4 @r1

    jmk ^@r4 @r7 @r4 u64

    jmp *block @r3 @r11 M
    xt @r1 M (&&/1) @r8 @r11 @r6 (@r9/0_1)

    ldp @r8 u32 ^@r2 *block u8 (@r4+0_2) (u16/1)

    @r4 ^u64 @r3 @r7
    cmp @r7 M ^@r1 ^<M> @r7 @r11 <M>

    movk @r3 u8 @r12 && ^u32
    jmk @r10 @r9 (u16/3) (@r5/0_2) u64 @r8
    ldp *block (*main/2) @r2 @r1 @r8
    jmp @r1 @r8 @r1 @r7 ^u64 u8
    jmk (<>/0_2) u32 @r4

    ldp u16 *main ^@r10 *block && @r7 @r10
    jmk u32 @r5 (M+3) @r8 @r8 @r2 @r3

    push (^@r10+0_2) u64 u64
    ldp @r3 ^@r11 @r2 @r3 @r5
    ldp (<M>/2) @r5 @r9 @r2

    @r6 @r7 && *main M (u64+0_2)
    @r11 @r9 u32 (@r6+1) <> u16 @r4 ^u32

    push @r12 <M> u32 (^@r9+2) ^<> @r3 (M/2)
    mov @r10 @r7 (@r7/2) @r5 u64 @r9 (*main+3)

    ldp ^<> @r1 @r11 @r4 (@r3+2) @r10 M
    @r8 @r11 u64 M @r12
    xt @r6 @r1 ^@r4
    con @r9 @r10 ^@r2 *block
    cmp (@r7/1) &&
    con (*block+2) @r10 u64
    mov ^u16 (*main+2) @r4
    @r12 ^@r10 <> u8 u64

    push ^<> @r4
    dw ^@r3 (^@r2/2)
    jmk u8 (@r11+2) ^@r3 *main
    jmp u16 @r2 @r6 @r1 ^@r8
    con @r7 (@r1/3) (@r1+0_2) ^@r2 @r2 @r5 ^*block

    @r4 ^@r11 (^@r5+3) (@r2/0_2) ^<M> (@r5/2) (M+1) @r5

    jmk @r4 @r8 ^u8 (@r12+1) ^@r9

    dw @r3 <> *block ^@r6
    movk ^@r8 @r10
    cmp (M/2) @r8 u8 && (^@r12+1)
    cmp <> @r11
    @r4 (u32+3) (@r7+1) (^@r10/0_1)

    mov *main @r5
    ldp (*main/2) (M/2) @r6 u64 @r8 @r8 (@r8/3)
    @r4 <M> ^@r10 (<>+1) (@r4/0_1) @r2
    push (@r1/3) (u16+2) *block && ^&& (&&+0_1) u32
    xt u8 u16 @r2 (M+0_1)
    mov @r4 ^<> ^M @r1 u32 ^@r10
    push @r12 @r1 <>

    jmp *block u8 @r3 ^@r7 @r11 ^&& (@r1/0_1)

    cmp <M> @r8

    dw ^@r10 <M> ^u64 @r5 @r8 @r8 @r4
    @r8 (^@r5/3) @r1 <M> (u16/1) @r4
    jmk @r5 @r8 ^u8 @r1
    cmp @r12 @r7 ^@r12 (@r4+3) u32 ^@r8
    mov (^*main+1) ^@r6 @r3
    movk @r3 @r6
    mov (@r8+2) @r8 *main

    jmp M *main u8 @r5 ^u32 ^@r7 @r2

    movk (^@r4+3) @r2 @r6 @r3
    @r5 (^*block+0_1) *block (@r11/3) @r3 <M> @r7 @r7

    xt @r5 @r2 ^@r12 u32

    movk @r4 @r4 *main M
    ldp (<>+2) u16 <> @r8 @r2
    con ^@r8 @r5 @r3 *main &&
    push @r4 @r5 u64 ^@r5
    ldp @r3 @r5 @r7 ^u64 <M> @r12

    movk @r5 && @r1
    ldp @r7 (@r3+2) <M> *main @r9

    push @r7 (@r10+3) u64 *main @r7 ^@r2
    jmk (&&+2) (*block/0_1) u8
    cmp u8 ^@r12 @r8 u32 <M> (@r8/2)
    jmk <> @r11
    @r1 (u64+3) @r5 @r11 <> *block @r3
    ldp @r3 (u8+2)
    dw u16 ^@r7 @r11 u8
    jmk ^@r5 @r4 (u32+0_2) @r9 @r5 *block

    ldp @r8 @r12 @r6 @r9
    xt *main @r11 @r2 @r11

    jmk && ^@r1 u8 ^@r3 &&

    @r9 ^u32 u16 @r10 ^u8 @r4 <> <>
    cmp <> ^u16 @r6 <> M @r11

    mov (u64+1) @r11
    jmp @r6 @r11 &&

    lsl @r6 u8 @r1 <M> (u16+1) u32

    mov ^@r1 <>

    cmp *main (^@r12/3) ^u32 @r6 (@r8+2) @r9
    ldp *main ^@r6 u32 @r7 @r7 @r1
    lsl @r2 u8 (&&/0_1) u16 ^@r8 @r5
    cmp ^@r2 *block u32 <M>
    @r8 @r9 @r7 *block (&&+3) ^@r1 @r7
    push (M/3) @r2 (@r3+1)
    @r4 @r5 @r10 @r11 @r2 <M> &&

    @r10 @r11 u8 @r9 ^@r3 (^@r5/2)

    xt @r7 @r9 @r8 u32

    mov @r3 @r4
    cmp u32 @r5 ^u8 ^*main (^@r4+1)
    dw @r9 u64
    lsl @r3 ^@r9 <M> u32
    mov @r11 @r4 M
    lsl @r6 ^@r11 @r2 @r5 u16 M

    mov (*main/0_1) M *block @r10
    @r5 ^@r10 @r1 (@r4+1) @r6 u8 (^@r11/0_2) u8

    @r10 u32 *main

    ldp <> @r5 (*main/3) ^<M> ^*block u64
    jmk ^*block <M> @r10 @r7 u8 M

    ldp ^@r3 *block u16 @r9
    @r10 *block u16 ^@r5 ^@r7 @r11 @r11
    jmk && (<>/3) @r4 u16 (@r3/3)
    @r1 (&&+0_1) (^&&+2) <> @r2 @r3

    cmp @r11 u16 @r10

    @r8 ^@r10 ^@r10 u8 (u16/1)
    lsl (&&/2) @r4 @r8 *block @r11 (@r9+3)

    movk @r7 ^u32 u64

    @r8 @r6 <M> @r1 (<M>/2) u16
    jmk <> (@r11+3) (u16+2) ^@r5
    cmp @r8 u8 M

    @r5 *main *main (u32/3)
    @r10 u64 @r3 u32 @r8 u16 *block
    jmp ^@r11 u16 @r5 (u8/3) @r4 <> <M>
    @r2 @r5 @r10 u8 @r2 ^@r2 <> u32
    ldp (@r6/0_2) (u64+0_2) @r6 u8
    @r6 <> ^u8 <M> (@r7+0_1) (@r4/1) <> (@r3/0_2)

    @r7 @r10 @r12 && @r9 u8

    @r6 ^@r8 M <> @r9 @r12 ^&&
    @r9 (*block/1) u64 u16 (^@r10/2)

    jmk ^@r8 <> @r1 ^u32 u64 @r3 ^u8
    con u32 ^@r4 (M+0_2) @r10 @r1 u8 (@r8+0_2)
    ldp ^@r11 ^@r4
    dw ^M @r8 <> (M+0_2) u32 (^u16/0_1)
    dw @r2 u32 (@r11/0_2) u16 u16 <M> u16
    movk u8 (^@r12/2) (@r10+0_1) ^*block
    movk *main ^u64 ^&& u32 u8
    lsl M @r9 u32 u16
    mov M (@r10/3) u16 @r6 @r12 *block
    ldp ^@r5 && @r9 M @r12 u16
    ldp M @r11 @r4
    xt @r4 @r12 @r6 (@r6+0_1)
    dw M u32 ^u32
    cmp (@r12/1) u8 ^@r3 <M> ^u16 ^u32 *block
    ldp (@r2/1) @r1 *main (^@r12+1) (@r1+1) *main M
    dw @r1 *main @r5 @r1 @r6 (@r4+0_1)
    lsl (@r2/1) @r5 ^*main u16 ^@r6 @r12

    movk ^@r9 (u8/3) *block <> u8 ^@r11 @r1

    lsl (@r5+3) u16 (^<M>/0_2)
    ldp (@r4+0_1) && *block @r8 @r12 @r12
    dw @r3 u16

    mov @r8 u16 <> (*main/1) @r12
    jmk *main @r1
    @r1 u64 *main @r10 <M> *block @r5 @r4 @8
    ldp @r1 @r8 *main
    cmp @r8 @r10 <> @r1 *block u16
    @r8 *block @r10 @r5 @r6 u16 (*block+0_1) 
    xt @r10 @r8 <M> @r1 (*main/1) *block
    xt @r1 @r3 *main 
    con u16 *block @r1 @r4 (@r10/1) &&
    ^@r1

    ldp *main @r3 (^@r8/1) @r10 *block
    @r3 *block (^@r1/2)
    


    jmk *main ^@r6
    jmp @r7 M @r9
    @r7 <M> ^@r10 <M> ^*block @r7
    con <> (u32/1) M (@r11+2)

    cmp (u16+2) M (@r1+0_2) @r12 <> u16

    movk <> M ^*block @r2 (u64/0_1)

    xt *main (@r7/0_1) (^&&+0_2) @r1
    jmk *main @r6 @r6 *main (^@r12/3) @r12 ^u64

    @r1 @r4 @r6 ^<M>
    dw ^<> && u8 (u32+0_1)
    xt <M> @r2
    @r5 @r1 *main (M+3) @r9 @r10 u64 *block

    lsl ^&& (@r7/3)
    lsl (u16+3) u32 @r3 @r9 @r7 ^&&
    xt (*main+0_1) (u64+0_1)
    @r12 @r12 @r1 *main u16
    jmk (<>+1) @r3
    ldp (u8/0_2) ^@r11 (^@r6+2) (*block+0_1) u8 M @r5
    ldp ^@r5 ^u32
    xt @r6 @r1 @r12 @r2 u32
    mov (&&+1) ^&& u8 @r1 @r4 @r9
    jmk M @r10 u64 @r1 @r2 (^u64+0_2)

    mov @r9 *main (^*block+1) *block && @r7
    @r11 M ^<> @r3 <M> @r5 @r1
    dw u8 @r5
    @r7 @r12 @r1 u8 @r11 u8 @r3 ^M
    jmp <M> && @r5 @r4 ^M @r9 <M>
    jmk u64 @r8 (@r9+1) ^*main M ^u32 @r6

    mov ^*main u16 ^u32
    @r3 ^u32 u8 ^u32 ^@r6 @r11

    cmp @r10 u64

    jmk u32 ^*main (^@r4+1) u16 (@r7/0_2)
    mov u32 *block
    @r9 <> u32 u32 (@r11/0_1) *block

    push (^@r10/1) @r10 u64 (@r5+2) ^@r2
    push *main ^<M> (@r3+2) @r7
    xt u8 (u32/2) @r11 @r6 @r10 (@r4+1) (^@r2/3)
    push *main (@r10+0_1) @r2 *block (@r9/0_1) (@r3+3) @r8
    lsl (^M+0_1) M
    con @r5 ^u8 ^u64 @r6 @r7 <M>

    @r2 ^*main @r9 @r9 (*main+0_1) @r7 ^@r3 M

    @r6 u64 @r1 <>
    push @r4 ^@r1 @r9 @r10

    jmp @r1 <> (u32+0_2) @r5 (u32+3)

    lsl (@r8+2) (*main+0_1) @r5 && <> @r7 @r3

    lsl && u8
    push @r4 u8 @r3
    xt (@r9+0_1) @r1
    xt @r2 @r7 (@r9+1) ^<> @r10
    push u16 @r8 @r10 @r2 ^@r7
    cmp u64 (^@r11+0_2) u64 @r6 ^@r5
    lsl @r12 u32 @r5 @r6
    xt (^@r10+2) (^@r5+1) @r2 (@r12+3) ^u64 @r6
    jmp u64 @r11
    lsl u64 ^*block u16 u32 @r10 *block
    con && (<M>/3) (@r1+3) <>
    push <> @r8
    ldp @r5 u8 ^@r4 u8 (u64+0_2)

    @r2 <M> ^<M> u32 (@r1/0_1) (@r9+0_1) u32
    @r7 @r12 && *block @r8
    mov ^*block @r3 @r12 ^u16 u32
    @r3 && u32
    jmp u16 (&&+1) M
    @r5 <> @r1

    ldp u16 ^u16 @r7 u64 @r12 *block @r9
    jmk && ^@r6 *main ^<M>
    @r11 M @r10 @r6 @r9

    @r9 ^u64 @r6 (@r2/1) u64

    ldp *block *block ^@r6

    jmp (@r5+3) @r2 u32
    dw u64 @r11 ^*block (<>/2) @r8 @r9 (@r4/1)
    push *block ^@r3
    mov *main @r7 @r10 <> @r12 && @r12
    ldp <> @r12 @r1 @r8 *main @r7
    movk ^u16 && @r8 u32 *block @r3 u64

    cmp (^u32/3) *main @r11
    cmp ^<> @r5 u16 u64
    jmp u64 @r1 @r4 (*block/1) (@r3+1) u8 (^@r11/2)

    @r7 @r9 *block && u32
    @r11 (^u32+1) @r6 @r2

    @r11 @r10 ^@r5 *block
    movk u64 @r11 *main ^u64
    push (@r6+2) (@r8+2) @r10

    mov @r8 @r6 u32 (@r8/0_1) (@r10/0_2) u8
    ldp @r8 @r10 @r9 @r8

    xt u8 @r10
    jmk (@r10/1) @r7 ^@r10 (@r12+3) @r9 ^&& ^<>
    lsl @r6 @r9 @r5
    movk (*block+0_1) *block *block M

    @r10 ^@r12 ^@r12

    ldp (@r9+1) @r5 (@r3/0_1) @r6 @r4

    @r11 *main @r2 @r5 @r11 ^@r12 (*block+0_1)
    xt ^@r11 (u8/1) u64
    ldp @r2 ^<> ^u8 @r6 &&
    @r11 *block ^M ^@r3 M (@r3/2) u32 *main
    @r2 ^<> @r4 @r10 u16
    ldp @r1 @r5
    cmp @r1 @r11 ^*block @r4 @r6 *block
    jmk u64 @r7 u16 @r6 <M> (@r7/3) @r6
    jmp <> ^<M> <> (@r1+0_2) ^u8 <>
    lsl @r8 u32 <M> u8

    @r9 (u16+2) ^@r9 @r3 @r10

    xt M ^@r2 u32 @r11

    @r2 @r9 @r7 @r10 ^M
    xt ^u32 ^@r9 <> u32 u32

    jmp ^u8 <> @r2 @r1 ^<M>
    mov ^u64 u32 (@r6/0_1) @r8 (@r10+2)
    @r11 @r6 u16 (*main/0_2) @r5 @r6 (@r1/0_1)
    push *block (@r1/1)
    @r9 ^@r4 ^*block @r1

    mov && <M>

    dw ^@r8 ^@r10 @r6 (@r11/2)
    lsl @r2 @r8 *main ^u8 ^u64 @r4
    xt @r3 ^@r3 ^u8 (<>+2) @r6 @r5 u64

    cmp @r8 @r3 && @r8 <>
    jmp *main @r7
    ldp @r12 (@r5/3) @r3 ^@r5 ^@r10
    movk ^<> @r12 *block
    jmk @r8 u64 @r4 @r5 @r1 @r11 @r12
    push (@r7/3) ^u64 u32
    cmp @r9 ^*main @r5
    ldp (@r6+3) ^@r2 M
    @r4 u32 @r7 u32 M u8

    movk @r1 @r3 @r7 @r11
    dw @r8 @r1 @r5 u8 ^u64
    @r10 @r3 M u32 ^*main *main @r2 u16
    jmp <M> @r12 (<>+0_2) (@r11+0_2) (u16+1) @r6 ^u8
    @r5 (&&/1) @r6 @r7 (&&+1) u64 ^<M> @r2
    ldp <M> (u16+1) @r1 *main @r1
    movk u16 ^@r3 ^@r9 @r3 u64
    @r4 u16 <M> ^@r2 @r2
    jmk ^u8 @r8 <M> @r6 (@r3+1)

    @r9 ^@r3 (@r4/1) @r4 ^@r6 @r11 (<>/2) @r10
    mov (u32+2) <M> ^@r3 @r7 (@r7/0_1) u64
    dw @r11 u64 (&&/2) @r7
    push u16 ^@r8 @r2

    jmk <> M && *main @r3
    movk @r2 && u32 @r8 @r6 @r3
    cmp && (&&+3) *main (M/2)

    ldp M @r11 M @r10 (&&/3)
    dw *main <M>

    @r4 (^@r8/1) ^@r10
    ldp @r5 @r4 M ^@r5 @r9 (^@r7+2)

    cmp @r4 @r1 (M/0_2) @r8
    cmp M ^&& ^@r7 (u32/3) u8 @r7

    @r3 (^u8+0_1) @r7 <M> ^@r6

    mov *main u64 u16 (*block+0_1)
    @r9 (&&+0_2) ^u8 u16 @r4 <M>
    cmp @r1 <> (@r11/0_2)

    @r6 *main u32 u16 @r11 *block ^@r8
    lsl u8 @r1 @r7 (@r11/0_2) ^*block
    dw <M> (u32/0_1) (@r9/0_2) u8
    @r3 u32 @r11
    jmk @r12 *main

    ldp @r3 u32 M u8 *block @r4
    @r11 (^*main/0_2) @r2 (@r2+1) @r1 (u32+1)
    @r8 u8 @r3
    @r8 @r1 ^@r8 (@r10/3) *block

    jmp M @r7 M @r10 *main @r1
    movk @r4 u16 u64 (<M>/2)
    con u32 @r6 (@r12/0_1) ^@r8 @r6 M @r8

    @r5 M && @r8 *block (<M>/0_1) (^<>+1) &&
    cmp @r1 ^@r10 ^@r11
    mov @r10 @r11 <M>
    @r12 @r4 ^u32 (^@r9/1) ^@r3
    con @r2 ^<M> u16 @r3 <> @r4 (^<>+3)

    @r8 @r1 u16 @r11 (&&/0_1)

    movk @r10 @r10

    @r1 ^<M> @r10 ^u64 (@r12/2) ^@r10 @r10 u64
    lsl @r1 *block
    xt @r10 @r12 @r7 (^@r2+3)
    ldp ^@r5 @r12
    jmp @r1 u32 ^@r5 @r9 <M> (<M>+0_2) @r4
    xt ^@r9 (@r7+3) M @r12
    movk u64 && @r10 ^u16 u32 ^@r11

    @r2 ^M ^@r10 @r5

    cmp (^*block/3) @r12 u16
    push @r8 ^@r3
    ldp ^@r3 @r6 @r12 (u32/0_1) (@r8/0_2) @r11 u64 @r8 @r7
    mov u16 u32 *block (@r8+3) (u8/3) @r3 ^u16 (^@r1+0_2) u8 u32 *main
    mov (^@r6+2) @r5
    jmp @r8 u64 ^@r3
    jmp *block @r12 ^&& u32 (@r8/2) M (M+2) (@r7/0_2) ^@r8 ^@r3 @r1 ^@r1

    push @r4 @r6

    ldp @r9 (@r5/2) <M> @r10

    cmp && ^@r5 ^u32 *main (@r10+1) M M u32 @r8 ^@r7 u16
    jmk @r9 @r8
    cmp u32 ^@r6 (@r11+0_1) u32 (@r11/1) @r7 M (^*block+0_1) (@r3/2) u8

    lsl *block u32 ^*block (<>+0_2) @r6 (*main+0_2) ^u64 u16 @r2 u16 && ^*main
    cmp u32 @r4 @r7 (@r1/0_2) ^@r1 && @r6
    con @r6 *block <M>
    movk @r5 @r10 ^@r4 ^@r8 @r2 <> @r6 @r10 @r1

    lsl *block ^<>
    mov @r1 u64 @r10 (u64/1) ^u32 (M+0_1) (u16/0_1) @r11 @r5 @r12 @r10 (@r12+1)
    push && ^@r11 *block *main @r10

    push @r1 *main

    con ^<> <> u8 @r12 @r9
    lsl (^u16+1) ^@r11 u64 (@r12/3) @r12 (@r6/3) @r10 @r3 ^u32 @r11 ^@r7 @r8
    @r10 u32 (^u16+1) @r2 *block ^&& <M> M @r6 @r2 ^&& (^@r2+2) ^@r2

    dw @r12 u64 @r9 ^@r8 ^*block @r4 @r9 @r2 (<>/2) @r2 @r2
    con @r2 @r2 ^@r11 ^@r12 *main *block
    push u16 @r12 ^@r11 @r8

    jmp @r5 (u32/0_1) *block u32 *block @r10 ^@r3 <> *block
    dw *block *main (<M>+0_2)

    dw @r6 @r7 @r4 @r7 <M> ^@r2 (@r3+0_2) ^u64 M ^u64
    @r10 @r2 @r5 @r6

    @r2 *block @r12 ^@r2 @r8 (@r5+1) (M+0_2)
    @r11 (@r12/2) u32

    @r4 <M> @r9 @r12 ^@r12 @r10 ^@r12 u16 ^@r12 @r8
    jmp u32 <> @r3
    con *main @r10 @r10 u8 @r9
    movk u16 *main @r3 <> <M> ^@r10 @r12

    ldp && @r1
    mov @r4 @r9 M u32 u64
    jmk u16 @r6 *block ^M u64 ^u64
    jmp ^@r8 @r7 @r10 (@r10/3) && @r10 @r10 (@r7/0_1) @r4 @r5 && @r9
    con @r12 @r5 ^<> @r3
    @r5 M *main @r5 @r6 *block (@r5+1)
    @r9 @r2 @r2 (@r8/0_2)

    xt @r9 (^*main/1) && @r2
    movk @r3 (@r1+1) @r9 u8 <M> @r1 @r6 @r11 u32 ^@r5

    movk @r11 u16 <M> *main u8 (u32+3) (^&&+1) ^@r12 *block @r3 ^@r2

    @r11 && @r4 *block ^@r7 (u32/0_1)

    lsl (u8/2) @r10 @r10 (M+2) ^u16 u32 @r8 *block @r10 *main M @r3
    jmk ^@r5 @r5 @r11

    push @r9 @r11 ^u64 ^@r1 @r7
    xt ^&& @r5 u32 ^@r8 u8 *main *block
    jmk u16 @r1 ^@r11 (@r10+1)

    lsl @r3 (<>+3) @r4 ^u32 u16 (M+0_2) @r6
    cmp @r12 u8 (@r2/3)

    jmp ^@r9 @r12 ^<M> ^u32 *main
    ldp @r5 u8 ^M @r2
    @r10 && @r7 (@r11+1) u8 *block @r1
    @r12 u16 <> @r12 u8 @r3 ^@r10 u16 <> u8 @r6 u8
    push @r12 @r8 ^@r6 (^@r5+3) (<>+0_2) ^@r11 u32 @r2 @r2 <M> @r9 @r10
    cmp u8 && (M+0_2) <> &&
    cmp && *main (M/0_1) <M> @r7 @r9 <M> @r3 ^u8 <> (@r5+2) (@r10/2)
    xt @r5 @r3 ^@r6 u8 ^@r4 u32 ^@r8 (*block+0_1) ^@r1 M @r7
    xt @r2 *block
    movk @r4 (u64/0_1)
    lsl u32 (@r5/2) <> ^u32 @r4 *main (^<M>+2) *main *main ^u32 @r8
    mov (^@r7+1) ^@r5 *block (@r8/0_1) *block (@r10/0_1) @r1 @r2 u16 @r3
    jmk @r2 @r8 u64 (@r6+3) ^@r10 @r7 @r10
    movk ^@r7 @r2 @r10 @r7 @r3 (@r6/1) *block *main ^<>
    xt *block @r8 M (@r11/2) ^u64 @r10
    @r1 u32 <> <M> u16 (@r8/0_1) ^u64 *main @r1 (u32+1) @r12 ^@r11 ^@r11

    dw @r9 @r4 (@r4/1) @r7 (*main/1) @r11 u16 (*block/0_1) ^@r11 (@r2+0_1) (u16+2) (^@r5/1)
    jmk (@r8+2) @r10 @r5 (@r5/1) @r9 @r10
    ldp <> *main
    @r2 u32 @r12 ^<> u8 @r1 ^<M> <M> <M> @r3 ^@r12 @r2

    @r11 ^u8 @r4 M (u32+2) (^<M>+1) (<M>+0_1) u64
    movk @r1 @r1 (*main/0_2) <> @r11 *main
    @r12 @r12 @r12
    @r12 <> <M> <> @r11 @r8 @r7 u8
    dw ^@r3 @r3 *block ^@r4 u8 @r7 ^@r10
    xt @r8 <M>
    @r12 @r12 u16 *main *block u8 u64
    push (@r5+1) <M> ^M *block

    con (@r3+3) @r2 @r12 @r5 <M>
    dw @r12 <> (@r11/0_2) *main u8
    xt @r5 u16
    dw (@r8+1) (@r12+1) ^u64 @r5 (^u32/3) @r9
    push *block @r4 u16
    con ^u32 M *block @r11 @r2 (@r5/0_2) u32

    @r4 (^*block+3) @r12 (@r2/1) ^@r10 (@r10/2) @r12 @r9
    cmp (^@r7+3) ^@r10
    jmk (@r11/0_1) u32
    mov @r3 (@r6/0_1) (u8/0_1) u64 @r8 @r6 @r3
    movk @r8 ^u64 ^&& <>

    @r8 <> ^@r9 (M+2) *main (@r10+0_1) @r6 u16
    xt @r3 *main @r10

    ldp u32 ^*block <M> @r1

    cmp @r8 @r10 u64 @r10 u16 @r5 M
    xt (@r2+1) @r11
    con *block @r5 @r5 (^M/2) @r3 u32 M
    @r2 ^@r6 u8 u32 @r12 u32 @r5

    ldp @r2 &&
    @r10 ^@r2 @r2 ^u8 <> *block <>
    dw @r12 (u16/1) ^u64 (@r9/0_1) @r11
    mov (u8/0_1) @r12 (@r11+0_2) ^u64 (@r7+2)
    con @r1 ^@r9 @r11 && @r3
    movk ^@r8 @r6 @r5
    cmp (@r9+2) u32 @r6 @r6
    ldp ^@r3 <>
    movk *block @r7 @r4 @r7 ^*main @r7

    mov @r5 u16 ^@r4 u64 @r8 (*block+1) @r12
    @r5 (@r1+2) @r8 @r3 (&&/0_2)

    dw ^*block @r3 u32 ^@r3 ^&& @r11

    push ^@r11 (*block/0_2) @r10 *main

    ldp ^u8 *main <> @r8
    jmp @r11 u64 ^@r12
    @r4 @r10 M (u32/2) ^@r9 ^<> ^@r6 ^M
    @r2 (^@r8/2) @r1 *block @r8
    dw *block && <M> @r12 @r4 @r5
    @r6 @r7 *block (u32+0_1) ^M
    dw (<>/2) @r12 ^u64 @r4 ^@r5 ^M
    @r12 ^@r5 @r12 (@r2/2)
    mov @r7 <M> u8 ^@r4 @r10

    ldp (@r1/0_1) @r7

    con @r8 u16 (&&+0_2) @r11 @r5
    xt @r4 ^@r1 ^<>
    mov <> @r12 @r6
    movk @r9 <M>

    @r9 @r7 u8 @r3 u64 <M> <> <M>

    dw @r9 ^@r7

    @r6 @r7 @r9 @r8 ^@r4 *main
    cmp u32 @r6 @r9 u8 ^@r1 *block @r4
    dw @r1 ^<M> @r10 (M/0_2)

    push ^@r4 ^@r8
    lsl @r2 <M> <M> M @r11
    push @r4 @r9 @r1
    @r7 (@r1/1) @r10 (^*main+3) ^@r8 u16 u64 u32

    @r3 *main *block (^u64/2) u64 M ^*main
    xt @r1 (M+1) (@r2/0_2)
    movk ^*block ^@r3 <> u8 M @r1 ^@r5
    @r3 @r7 u16 @r1 (@r1/0_1) ^*main @r9 ^u64

    xt <M> (@r6+2) *main
    cmp ^@r4 @r6 *main @r4 *block (u32/0_1)
    movk @r7 @r6 @r7
    jmp @r2 @r3 @r12 *block
    @r2 @r2 u8 @r10
    con @r9 ^u16 @r4 @r5 @r8 <M>
    mov @r2 *main u16 ^@r7 (M+3)

    lsl M ^<M> @r7 @r10
    ldp (@r10+3) @r3 @r5 (@r8/0_1) ^*block <>
    jmk @r9 @r6 (^<>+0_1) <M> && u32
    push u32 (^<M>/2)
    jmp @r1 (@r5/1) *block (@r5+3)
    @r11 @r6 @r1

    dw && *block @r11 M @r10 (<M>/0_2) @r9

    push M @r8 @r2 (^u8+1) ^*main
    dw @r6 @r8
    @r11 ^&& ^@r4 *block @r11 ^@r5 ^*main
