declarative(0xff000000):
    mov @r1 @r2 @r3 @r4 @r5 @r6 @r7 @r8 @r9 @r10 @r11 @r12
    @r1 <M> @r1
    @r2 <M> @r2
    @r3 <M> @r3
    @r4 <M> @r4
    @r5 <M> @r5
    @r6 <M> @r6 
    @r7 <M> @r7 
    @r8 <M> @r8
    @r9 <M> @r9
    @r10 <M> @r10
    @r11 <M> @r11
    @r12 <M> @r12

    mov @r1 @r2 @r3 @r4 @r5 @r6 @r7 @r8 @r9 @r10 @r11 @r12 <M> *main
    mov u64 *main
    @r1 @r2 @r3 @r4 @r5 @r6 @r7 @r8 @r9 @r10 @r11 @r12 (u64/3) 
    mov u8 u16 u32 u64 *main

    mov ^@r1 *main <M> u32
    mov @r3 u32 ^*main *block u64
    @r4 @r7 (@r3+3) u32
    mov @r3 @r4 *main
    @r1 u32 *main
    @r1 u64
    push @r1 u64
    @r1 *block (@r1/2)
    @r3 <M> @r1 *main (@r4+1) 
    mov *main @r1 u64 (^*block/0_1)

    push *main <M> @r2
    push *main u32



