entry:
    mov ^M @r10 @r2 @r6 @r3

    movk *main && @r9 @r1 
    cmp @r12 u16 <M> @r2 *main && @r1 *main 
    ldp ^@r3 *main @r1 <> *block u64
    lpd @r1 *main 
    push ^@r3 *main (@r4/1) *block u32 &&
    @r4 @r1 (*main+3) u16
    con @r4 @r1
 
    xt @r8 @r1 <M> ^@r8 (@r1/2) @r3 u64
    @r1 @r7
    @r10 ^*main <M> ^*block @r1 u64


    ldp *block @r10 ^u8 (@r11+1) ^@r12 @r7

//    jmk @r7 (*block/1) u64 @r11 @r2 @r9 (*block+2)
    jmp @r4 (@r12/1) u32 @r11 @r3
    jmk @r7 (*block+1) u64 @r2 @r9
   
    ldp @r8 @r4 @r1 u64

    dw @r3 (<M>/0_2)

    cmp <M> (u64+2) ^@r10 @r10
    lsl (@r12+1) @r7 @r2 (@r9/2) (@r1/1)

    jmp u32 @r8 && (@r2/0_2) u8 M u16
    mov @r6 (*main/3) @r2 u32 ^@r12
    
//    mov @r2 ^@r11 u32 *block ^u32 u64
    movk (@r6/3) @r6 u64 u8
    
    jmk (<>+0_1) *block (@r7+0_2) u64 ^*main @r11 @r7


