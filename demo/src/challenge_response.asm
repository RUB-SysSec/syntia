push	0x36458
jmp	0x9317d
push	-0x7fefa61f
call	0x7a058
pushfq	
jmp	0x68e29
push	rsi
not	esi
mov	esi, 0x14105944
push	rcx
movsx	esi, cx
push	rbp
xchg	bp, bp
push	rdi
push	rbx
mov	edi, edx
movzx	bx, al
push	rax
cwde	
push	rdx
mov	eax, 0xffc20000
jmp	0x67b0e
push	rax
dec	bp
mov	esi, dword ptr [rsp + 0x28]
jmp	0x685c1
rol	esi, 2
rol	di, 0x31
not	esi
shr	bx, cl
shl	bl, 0x7c
neg	esi
rol	bx, -0x6e
xadd	bh, bl
lea	esi, [rsi + rax]
mov	ebp, esp
mov	di, bx
xor	bx, sp
add	eax, esp
lea	esp, [rsp - 0xc0]
mov	ebx, esi
stc	
xor	eax, 0x74853751
sar	eax, cl
mov	eax, 0xffc20000
sbb	edi, ebx
mov	edi, eax
sub	ebx, eax
stc	
movzx	edi, bx
lea	edi, [rip + 0x68607]
btr	ax, dx
sub	esi, 4
rcr	eax, cl
shld	ax, bp, -0x65
shl	ax, cl
mov	eax, dword ptr [rsi]
xor	eax, ebx
stc	
cmp	edi, ebx
add	eax, 0x3e547e5
rol	eax, 2
jmp	0x6f1cf
jmp	0x44009
not	eax
cmp	ax, di
xor	ebx, eax
jmp	0x94c58
add	edi, eax
jmp	0x491e3
push	rdi
ret	
sub	esi, 1
sal	al, 0x40
movzx	eax, byte ptr [rsi]
btr	ecx, 0x52
adc	cl, ah
xor	al, bl
movzx	cx, bh
dec	cl
mov	cl, cl
dec	al
bts	cx, sp
rol	al, 1
shld	ecx, edx, 0x45
movsx	ecx, bp
or	ecx, 0x547071b6
add	al, 0xf8
mov	cl, bl
inc	cl
not	al
setg	cl
inc	al
neg	al
bsr	ecx, esi
mov	cx, 0x56a3
xor	bl, al
mov	ch, 0xcd
mov	ecx, dword ptr [rbp]
cmc	
add	ebp, 4
jmp	0x54e5e
mov	dword ptr [rsp + rax], ecx
cbw	
test	si, dx
sub	esi, 4
not	ah
mov	eax, dword ptr [rsi]
cmp	ecx, esi
test	al, ch
test	di, 0x4d1f
xor	eax, ebx
cmp	bh, ch
add	eax, 0x3e547e5
jmp	0xaa381
rol	eax, 2
jmp	0x4fd66
cmp	dh, 0x67
not	eax
xor	ebx, eax
cmc	
add	edi, eax
jmp	0x9dcd5
push	rdi
ret	
lea	esi, [rsi - 1]
movzx	eax, byte ptr [rsi]
xor	al, bl
xchg	ch, cl
movsx	ecx, dx
dec	al
movsx	cx, bh
bt	ecx, eax
rol	al, 1
and	cx, 0x2087
add	al, 0xf8
not	al
inc	al
cmp	dh, 0x57
adc	cx, di
neg	al
shr	cx, -0x73
movsx	cx, dh
xor	bl, al
shl	ch, cl
mov	ecx, dword ptr [rbp]
test	ch, dh
lea	ebp, [rbp + 4]
cmc	
mov	dword ptr [rsp + rax], ecx
add	ax, di
lea	esi, [rsi - 4]
cmovge	ax, si
mov	eax, dword ptr [rsi]
cmc	
xor	eax, ebx
add	eax, 0x3e547e5
stc	
clc	
rol	eax, 2
test	ah, 0xdb
not	eax
test	dx, bx
jmp	0x550cb
xor	ebx, eax
add	edi, eax
jmp	0x63f03
push	rdi
ret	
sub	esi, 1
movzx	eax, byte ptr [rsi]
bts	ecx, edi
bswap	cx
xor	al, bl
movzx	cx, al
xchg	ecx, ecx
jmp	0x61cf6
dec	al
stc	
rol	al, 1
sal	ecx, 0x45
shl	ecx, cl
add	al, 0xf8
inc	ch
cmovno	ecx, edi
not	al
dec	cx
setp	cl
mov	ecx, 0x28f22e1a
inc	al
bsr	cx, di
cmovs	ecx, eax
neg	al
neg	cl
xor	bl, al
bsf	ecx, esp
shl	ecx, -0x41
mov	ecx, dword ptr [rbp]
add	ebp, 4
test	dx, cx
mov	dword ptr [rsp + rax], ecx
lea	esi, [rsi - 4]
mov	eax, dword ptr [rsi]
xor	eax, ebx
add	eax, 0x3e547e5
jmp	0xa2d0d
rol	eax, 2
jmp	0x3e219
clc	
not	eax
xor	ebx, eax
test	esp, 0x39ba2a16
jmp	0x8e4a0
add	edi, eax
jmp	rdi
lea	esi, [rsi - 1]
shld	cx, cx, -4
movzx	eax, byte ptr [rsi]
not	ecx
test	bh, 0x46
rcl	cx, cl
xor	al, bl
movzx	cx, bl
jmp	0x7a599
dec	al
movsx	ecx, cx
btc	cx, di
rcr	ecx, cl
rol	al, 1
cmova	cx, si
shl	cx, cl
add	al, 0xf8
not	al
mov	ecx, esp
inc	al
neg	al
xor	bl, al
mov	cl, 0x48
mov	ecx, dword ptr [rbp]
test	ecx, edi
stc	
lea	ebp, [rbp + 4]
test	bx, bx
stc	
mov	dword ptr [rsp + rax], ecx
shld	eax, ecx, 0x27
lea	esi, [rsi - 4]
mov	eax, dword ptr [rsi]
xor	eax, ebx
clc	
test	cl, 0xbf
add	eax, 0x3e547e5
rol	eax, 2
jmp	0x8dea5
not	eax
cmp	sp, di
stc	
xor	ebx, eax
test	bp, cx
add	edi, eax
jmp	0x623c0
jmp	rdi
sub	esi, 1
bt	ecx, -0xb
rcr	cx, 0x5d
neg	ah
movzx	eax, byte ptr [rsi]
xor	cx, bp
shl	ecx, 0x28
bts	cx, si
xor	al, bl
dec	al
rcr	ch, cl
btc	ecx, -0x6e
rol	al, 1
add	al, 0xf8
not	al
inc	al
neg	al
xor	bl, al
btr	ecx, -0x3e
bts	cx, cx
mov	ecx, dword ptr [rbp]
cmp	si, di
add	ebp, 4
test	ah, 0
jmp	0x755b9
mov	dword ptr [rsp + rax], ecx
lea	esi, [rsi - 4]
xadd	al, ah
ror	eax, cl
mov	eax, dword ptr [rsi]
cmp	ah, 0x8c
xor	eax, ebx
add	eax, 0x3e547e5
cmc	
stc	
clc	
rol	eax, 2
jmp	0x4e658
test	sp, sp
not	eax
test	edx, esi
xor	ebx, eax
clc	
add	edi, eax
jmp	0x678c4
push	rdi
ret	
lea	esi, [rsi - 1]
movzx	eax, byte ptr [rsi]
movzx	ecx, di
bts	cx, dx
xor	al, bl
jmp	0x4105f
dec	al
rol	al, 1
add	al, 0xf8
not	al
mov	cx, di
movzx	ecx, di
inc	al
bts	ecx, esp
sar	ch, 0x32
neg	al
xor	bl, al
bt	ecx, 4
add	cx, bx
sar	cx, -0x29
mov	ecx, dword ptr [rbp]
test	di, 0x3785
cmp	cx, si
clc	
lea	ebp, [rbp + 4]
mov	dword ptr [rsp + rax], ecx
rcr	eax, 0x26
neg	ax
or	ax, di
lea	esi, [rsi - 4]
inc	ax
bt	eax, 0x55
mov	eax, dword ptr [rsi]
xor	eax, ebx
jmp	0x7f150
add	eax, 0x3e547e5
rol	eax, 2
jmp	0x3c28b
cmp	cl, 0x17
not	eax
clc	
cmc	
xor	ebx, eax
jmp	0x61b05
add	edi, eax
jmp	0x47706
push	rdi
ret	
lea	esi, [rsi - 1]
movzx	eax, byte ptr [rsi]
setp	ch
test	ecx, 0x2e005fa2
xor	al, bl
movzx	ecx, cx
movsx	cx, al
setg	ch
dec	al
ror	ecx, cl
jmp	0xa8048
rol	al, 1
shr	ch, 0x34
clc	
add	al, 0xf8
jmp	0x67358
not	al
movsx	ecx, cx
inc	al
cmc	
add	ecx, esi
neg	al
add	cx, 0x25d2
xor	bl, al
dec	cl
mov	ecx, dword ptr [rbp]
lea	ebp, [rbp + 4]
test	dx, 0x3ba7
stc	
mov	dword ptr [rsp + rax], ecx
sub	esi, 4
mov	al, 0xde
lahf	
or	eax, ecx
mov	eax, dword ptr [rsi]
clc	
xor	eax, ebx
jmp	0x4b787
add	eax, 0x3e547e5
cmc	
clc	
jmp	0x9ea1d
rol	eax, 2
jmp	0x736c0
cmp	esi, esp
not	eax
xor	ebx, eax
cmc	
add	edi, eax
jmp	0xa7641
jmp	rdi
lea	esi, [rsi - 1]
bsf	ax, di
movzx	eax, byte ptr [rsi]
sar	ecx, -0x41
cmp	dx, si
xor	al, bl
inc	ch
movsx	cx, bh
dec	cl
dec	al
bt	cx, -0x1b
rol	al, 1
mov	ch, 0x5d
shr	cl, 0x72
add	al, 0xf8
not	al
inc	al
bswap	ecx
bsf	cx, dx
shl	cl, 0x13
neg	al
bt	ecx, -0x2b
inc	cl
xor	bl, al
btr	cx, bx
xadd	ch, cl
or	ecx, 0x7c14df2
mov	ecx, dword ptr [rbp]
add	ebp, 4
jmp	0x96e40
mov	dword ptr [rsp + rax], ecx
cmp	edi, 0x5ca51d5a
movzx	ax, ch
cwde	
sub	esi, 4
sar	al, 0x80
rol	al, cl
mov	eax, dword ptr [rsi]
xor	eax, ebx
add	eax, 0x3e547e5
jmp	0xa9172
rol	eax, 2
jmp	0x3b4c4
cmp	sp, 0x3cfd
cmc	
clc	
not	eax
xor	ebx, eax
jmp	0x9f58f
add	edi, eax
jmp	0xa6869
jmp	rdi
lea	esi, [rsi - 1]
movzx	eax, byte ptr [rsi]
xor	al, bl
dec	al
btc	cx, 0x71
mov	ecx, 0xbc40900
rol	cl, cl
rol	al, 1
rol	cl, 0xe0
shl	ch, cl
or	cx, bx
add	al, 0xf8
setge	cl
not	al
inc	al
shrd	ecx, esp, -0x33
bts	ecx, ebx
neg	al
mov	ecx, eax
xor	bl, al
sub	ecx, 0x55c3508e
mov	ecx, dword ptr [rbp]
lea	ebp, [rbp + 4]
mov	dword ptr [rsp + rax], ecx
sub	esi, 4
or	ax, 0x7369
mov	eax, dword ptr [rsi]
xor	eax, ebx
cmp	bx, si
jmp	0xb1409
add	eax, 0x3e547e5
rol	eax, 2
jmp	0xad314
cmc	
test	ebp, edx
not	eax
xor	ebx, eax
cmp	ax, 0x2f35
clc	
test	ebx, 0xc212d65
add	edi, eax
push	rdi
ret	
lea	esi, [rsi - 1]
cmc	
movzx	eax, byte ptr [rsi]
xor	al, bl
mov	cx, bx
cmovbe	ecx, ecx
dec	al
btr	ecx, -0x55
rol	al, 1
test	esi, 0x794e557b
add	al, 0xf8
seta	ch
not	cx
dec	cx
not	al
inc	al
btc	cx, -0x64
mov	ch, 0x6a
neg	al
xor	bl, al
adc	ecx, esi
and	cl, 0x21
mov	ecx, dword ptr [rbp]
clc	
test	edi, 0xcd47357
test	esp, edx
add	ebp, 4
jmp	0x3f335
mov	dword ptr [rsp + rax], ecx
btc	ax, -0x70
sub	esi, 4
or	eax, edi
mov	eax, dword ptr [rsi]
cmp	ebp, edx
stc	
xor	eax, ebx
clc	
add	eax, 0x3e547e5
clc	
rol	eax, 2
jmp	0xa2a29
not	eax
xor	ebx, eax
jmp	0x95817
add	edi, eax
jmp	0x40c1b
push	rdi
ret	
sub	esi, 1
clc	
cmovbe	ax, ax
movzx	eax, byte ptr [rsi]
setge	ch
xor	ecx, esi
bsr	cx, cx
xor	al, bl
movzx	cx, ch
setg	cl
mov	ch, 0xc7
dec	al
bswap	cx
rol	al, 1
add	al, 0xf8
movsx	cx, dh
movzx	ecx, sp
cmove	ecx, ebp
not	al
inc	al
test	cx, bp
ror	ecx, 0x5a
neg	al
bt	ecx, esp
rol	ch, cl
xor	bl, al
xchg	cl, ch
cmc	
add	ch, 0xe0
mov	ecx, dword ptr [rbp]
jmp	0x8ca92
lea	ebp, [rbp + 4]
mov	dword ptr [rsp + rax], ecx
and	ax, 0x597c
rcl	ax, cl
sub	esi, 4
bswap	eax
sbb	ah, 0x78
clc	
mov	eax, dword ptr [rsi]
cmc	
cmp	ebp, 0x1d3f1813
xor	eax, ebx
add	eax, 0x3e547e5
rol	eax, 2
not	eax
test	dl, 0x78
test	esp, esi
stc	
xor	ebx, eax
cmp	bl, ah
add	edi, eax
push	rdi
ret	
mov	eax, ebp
sub	ebp, 4
cmp	esp, 0x50b0b5a
mov	dword ptr [rbp], eax
ror	eax, cl
shr	al, 0x69
adc	ah, 2
lea	esi, [rsi - 4]
cmp	ebp, eax
rol	eax, 3
mov	eax, dword ptr [rsi]
cmp	bp, cx
cmp	edi, 0x62cb66c9
xor	eax, ebx
add	eax, 0x3e547e5
stc	
rol	eax, 2
clc	
not	eax
cmc	
xor	ebx, eax
jmp	0x4a78e
add	edi, eax
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
sub	esi, 4
btr	ax, -0x65
bswap	eax
mov	eax, dword ptr [rsi]
cmc	
xor	eax, ebx
bswap	eax
jmp	0x7e624
xor	eax, 0x4cf3616f
jmp	0x53f5f
jmp	0x77d0d
rol	eax, 3
bswap	eax
jmp	0x8abc8
xor	ebx, eax
lea	ebp, [rbp - 4]
mov	dword ptr [rbp], eax
cmp	ebx, 0x57c4294a
mov	ax, 0x6055
xor	ax, 0x5661
lea	esi, [rsi - 4]
stc	
mov	eax, dword ptr [rsi]
stc	
cmc	
xor	eax, ebx
cmp	ecx, ebx
add	eax, 0x3e547e5
rol	eax, 2
jmp	0x9c852
jmp	0xa8278
not	eax
cmp	dl, 0x93
xor	ebx, eax
clc	
add	edi, eax
jmp	0x5f97a
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
mov	eax, dword ptr [rbp]
bsr	ecx, esp
mov	ecx, dword ptr [rbp + 4]
add	eax, ecx
jmp	0x8ceb3
mov	dword ptr [rbp + 4], eax
sete	ah
pushfq	
pop	qword ptr [rbp]
bt	eax, 0x60
test	si, ax
sal	ax, -0x6f
lea	esi, [rsi - 4]
shrd	eax, ebp, 0x52
sbb	ax, sp
mov	eax, dword ptr [rsi]
cmp	esp, 0x64862b1a
xor	eax, ebx
add	eax, 0x3e547e5
clc	
stc	
rol	eax, 2
jmp	0x99b32
cmp	di, 0x6e9
clc	
not	eax
cmc	
jmp	0x60eac
xor	ebx, eax
clc	
add	edi, eax
jmp	0x413ab
jmp	rdi
sub	esi, 1
sal	al, 0x40
movzx	eax, byte ptr [rsi]
btr	ecx, 0x52
adc	cl, ah
xor	al, bl
movzx	cx, bh
dec	cl
mov	cl, cl
dec	al
bts	cx, sp
rol	al, 1
shld	ecx, edx, 0x45
movsx	ecx, bp
or	ecx, 0x547071b6
add	al, 0xf8
mov	cl, bl
inc	cl
not	al
setg	cl
inc	al
neg	al
bsr	ecx, esi
mov	cx, 0x56a3
xor	bl, al
mov	ch, 0xcd
mov	ecx, dword ptr [rbp]
cmc	
add	ebp, 4
jmp	0x54e5e
mov	dword ptr [rsp + rax], ecx
cbw	
test	si, dx
sub	esi, 4
not	ah
mov	eax, dword ptr [rsi]
cmp	ecx, esi
test	al, ch
test	di, 0x4d1f
xor	eax, ebx
cmp	bh, ch
add	eax, 0x3e547e5
jmp	0xaa381
rol	eax, 2
jmp	0x4fd66
cmp	dh, 0x67
not	eax
xor	ebx, eax
cmc	
add	edi, eax
jmp	0x9dcd5
push	rdi
ret	
mov	ebp, dword ptr [rbp]
sbb	ax, si
lea	esi, [rsi - 4]
shr	ax, cl
sbb	al, 0xf9
mov	al, bl
mov	eax, dword ptr [rsi]
xor	eax, ebx
test	esp, 0x321567c8
cmc	
add	eax, 0x3e547e5
cmc	
rol	eax, 2
jmp	0x9e1e0
not	eax
stc	
xor	ebx, eax
cmp	ch, 0xd6
add	edi, eax
jmp	0x9868c
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
lea	esi, [rsi - 1]
movzx	eax, byte ptr [rsi]
cmc	
xor	al, bl
jmp	0x74c6b
dec	al
rol	al, 1
test	ax, 0x6aa6
add	al, 0xf8
not	al
jmp	0x79a22
inc	al
neg	al
xor	bl, al
test	ebp, esi
stc	
mov	eax, dword ptr [rsp + rax]
cmp	di, 0x2e28
cmp	esp, edx
lea	ebp, [rbp - 4]
jmp	0xa688d
mov	dword ptr [rbp], eax
lea	esi, [rsi - 4]
btc	eax, 0x48
bts	eax, ebx
mov	eax, dword ptr [rsi]
cmc	
xor	eax, ebx
jmp	0x3f8c2
add	eax, 0x3e547e5
stc	
cmc	
rol	eax, 2
jmp	0x75881
jmp	0x69462
not	eax
xor	ebx, eax
clc	
stc	
add	edi, eax
jmp	0x83058
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
sub	esi, 1
movzx	eax, byte ptr [rsi]
xor	al, bl
jmp	0x6dcbd
dec	al
stc	
cmc	
rol	al, 1
jmp	0x628c1
add	al, 0xf8
jmp	0x9cddb
not	al
jmp	0x5730e
inc	al
neg	al
test	bh, 0x5d
cmc	
clc	
xor	bl, al
stc	
cmp	ebx, edx
mov	eax, dword ptr [rsp + rax]
sub	ebp, 4
stc	
mov	dword ptr [rbp], eax
shr	ah, 9
not	eax
neg	ax
sub	esi, 4
bts	ax, sp
mov	eax, dword ptr [rsi]
cmp	si, si
xor	eax, ebx
add	eax, 0x3e547e5
clc	
stc	
rol	eax, 2
jmp	0xb3e55
clc	
not	eax
xor	ebx, eax
clc	
add	edi, eax
jmp	0xa399e
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
mov	eax, dword ptr [rbp]
sar	ch, 0x49
mov	ecx, dword ptr [rbp + 4]
add	eax, ecx
mov	dword ptr [rbp + 4], eax
movzx	eax, cx
jmp	0x6eba8
pushfq	
rol	ah, 0x4e
shr	ah, cl
pop	qword ptr [rbp]
sar	ax, cl
sub	esi, 4
cwde	
mov	eax, dword ptr [rsi]
cmp	esp, 0x4809359a
cmc	
clc	
xor	eax, ebx
stc	
test	esi, ebp
add	eax, 0x3e547e5
jmp	0xb1462
rol	eax, 2
jmp	0x58860
stc	
not	eax
cmp	esi, eax
test	ebx, edx
xor	ebx, eax
add	edi, eax
jmp	0xa0325
jmp	rdi
lea	esi, [rsi - 1]
movzx	eax, byte ptr [rsi]
xor	al, bl
xchg	ch, cl
movsx	ecx, dx
dec	al
movsx	cx, bh
bt	ecx, eax
rol	al, 1
and	cx, 0x2087
add	al, 0xf8
not	al
inc	al
cmp	dh, 0x57
adc	cx, di
neg	al
shr	cx, -0x73
movsx	cx, dh
xor	bl, al
shl	ch, cl
mov	ecx, dword ptr [rbp]
test	ch, dh
lea	ebp, [rbp + 4]
cmc	
mov	dword ptr [rsp + rax], ecx
add	ax, di
lea	esi, [rsi - 4]
cmovge	ax, si
mov	eax, dword ptr [rsi]
cmc	
xor	eax, ebx
add	eax, 0x3e547e5
stc	
clc	
rol	eax, 2
test	ah, 0xdb
not	eax
test	dx, bx
jmp	0x550cb
xor	ebx, eax
add	edi, eax
jmp	0x63f03
push	rdi
ret	
sub	esi, 1
movzx	eax, byte ptr [rsi]
bts	ecx, edi
bswap	cx
xor	al, bl
movzx	cx, al
xchg	ecx, ecx
jmp	0x61cf6
dec	al
stc	
rol	al, 1
sal	ecx, 0x45
shl	ecx, cl
add	al, 0xf8
inc	ch
cmovno	ecx, edi
not	al
dec	cx
setp	cl
mov	ecx, 0x28f22e1a
inc	al
bsr	cx, di
cmovs	ecx, eax
neg	al
neg	cl
xor	bl, al
bsf	ecx, esp
shl	ecx, -0x41
mov	ecx, dword ptr [rbp]
add	ebp, 4
test	dx, cx
mov	dword ptr [rsp + rax], ecx
lea	esi, [rsi - 4]
mov	eax, dword ptr [rsi]
xor	eax, ebx
add	eax, 0x3e547e5
jmp	0xa2d0d
rol	eax, 2
jmp	0x3e219
clc	
not	eax
xor	ebx, eax
test	esp, 0x39ba2a16
jmp	0x8e4a0
add	edi, eax
jmp	rdi
lea	esi, [rsi - 1]
movzx	eax, byte ptr [rsi]
xor	al, bl
dec	al
stc	
cmc	
rol	al, 1
cmc	
add	al, 0xf8
jmp	0x41623
not	al
jmp	0x5974d
inc	al
neg	al
xor	bl, al
test	bp, 0x50aa
mov	eax, dword ptr [rsp + rax]
lea	ebp, [rbp - 4]
cmc	
mov	dword ptr [rbp], eax
test	ch, 0x5a
movsx	ax, al
adc	al, 0x50
lea	esi, [rsi - 4]
sar	eax, cl
cmc	
mov	eax, dword ptr [rsi]
jmp	0x49d32
xor	eax, ebx
test	dl, 0xb2
cmp	di, 0x75c1
cmp	al, bh
add	eax, 0x3e547e5
rol	eax, 2
jmp	0x8b14b
cmc	
clc	
not	eax
test	di, ax
stc	
xor	ebx, eax
clc	
jmp	0x92270
add	edi, eax
jmp	0x9eb50
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
sub	esi, 1
or	ah, al
ror	eax, cl
movzx	eax, byte ptr [rsi]
cmp	si, 0x7327
test	cx, sp
xor	al, bl
jmp	0x6f86c
dec	al
rol	al, 1
jmp	0x9645d
add	al, 0xf8
not	al
jmp	0xae444
inc	al
test	di, bp
neg	al
xor	bl, al
test	edx, esi
test	ah, 0xf2
cmp	bp, 0x263
mov	eax, dword ptr [rsp + rax]
test	di, bp
test	sp, 0x66f3
lea	ebp, [rbp - 4]
mov	dword ptr [rbp], eax
lea	esi, [rsi - 4]
mov	eax, dword ptr [rsi]
xor	eax, ebx
cmc	
test	si, dx
add	eax, 0x3e547e5
cmc	
jmp	0x55e12
rol	eax, 2
cmp	ebp, 0x45490fc6
not	eax
stc	
cmc	
xor	ebx, eax
add	edi, eax
jmp	0x90bbc
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
mov	eax, dword ptr [rbp]
shr	cx, 0x60
bswap	cx
shr	cx, cl
mov	ecx, dword ptr [rbp + 4]
cmp	si, sp
not	eax
jmp	0x97a6e
not	ecx
and	eax, ecx
jmp	0x4bed0
mov	dword ptr [rbp + 4], eax
pushfq	
cbw	
ror	ax, cl
pop	qword ptr [rbp]
lahf	
sal	ax, -0x67
sub	esi, 4
add	eax, 0x158b5f86
or	ax, 0x13e8
mov	eax, dword ptr [rsi]
xor	eax, ebx
add	eax, 0x3e547e5
rol	eax, 2
jmp	0x642e0
not	eax
clc	
xor	ebx, eax
add	edi, eax
jmp	0x9952f
push	rdi
ret	
lea	esi, [rsi - 1]
shld	cx, cx, -4
movzx	eax, byte ptr [rsi]
not	ecx
test	bh, 0x46
rcl	cx, cl
xor	al, bl
movzx	cx, bl
jmp	0x7a599
dec	al
movsx	ecx, cx
btc	cx, di
rcr	ecx, cl
rol	al, 1
cmova	cx, si
shl	cx, cl
add	al, 0xf8
not	al
mov	ecx, esp
inc	al
neg	al
xor	bl, al
mov	cl, 0x48
mov	ecx, dword ptr [rbp]
test	ecx, edi
stc	
lea	ebp, [rbp + 4]
test	bx, bx
stc	
mov	dword ptr [rsp + rax], ecx
shld	eax, ecx, 0x27
lea	esi, [rsi - 4]
mov	eax, dword ptr [rsi]
xor	eax, ebx
clc	
test	cl, 0xbf
add	eax, 0x3e547e5
rol	eax, 2
jmp	0x8dea5
not	eax
cmp	sp, di
stc	
xor	ebx, eax
test	bp, cx
add	edi, eax
jmp	0x623c0
jmp	rdi
sub	esi, 1
bt	ecx, -0xb
rcr	cx, 0x5d
neg	ah
movzx	eax, byte ptr [rsi]
xor	cx, bp
shl	ecx, 0x28
bts	cx, si
xor	al, bl
dec	al
rcr	ch, cl
btc	ecx, -0x6e
rol	al, 1
add	al, 0xf8
not	al
inc	al
neg	al
xor	bl, al
btr	ecx, -0x3e
bts	cx, cx
mov	ecx, dword ptr [rbp]
cmp	si, di
add	ebp, 4
test	ah, 0
jmp	0x755b9
mov	dword ptr [rsp + rax], ecx
lea	esi, [rsi - 4]
xadd	al, ah
ror	eax, cl
mov	eax, dword ptr [rsi]
cmp	ah, 0x8c
xor	eax, ebx
add	eax, 0x3e547e5
cmc	
stc	
clc	
rol	eax, 2
jmp	0x4e658
test	sp, sp
not	eax
test	edx, esi
xor	ebx, eax
clc	
add	edi, eax
jmp	0x678c4
push	rdi
ret	
sub	esi, 1
btr	ax, -0x52
movzx	eax, byte ptr [rsi]
test	ax, 0x3d8a
test	ebx, edi
jmp	0x93b85
xor	al, bl
dec	al
clc	
rol	al, 1
cmp	si, bp
add	al, 0xf8
jmp	0xa8565
not	al
jmp	0x826a0
inc	al
test	esp, edx
neg	al
xor	bl, al
test	esp, esi
test	al, 0x58
mov	eax, dword ptr [rsp + rax]
test	bx, sp
clc	
lea	ebp, [rbp - 4]
mov	dword ptr [rbp], eax
bt	eax, edx
rcr	eax, cl
sbb	al, 0x53
lea	esi, [rsi - 4]
sbb	ax, bx
ror	ax, cl
mov	eax, dword ptr [rsi]
test	bh, 0x3a
xor	eax, ebx
add	eax, 0x3e547e5
clc	
rol	eax, 2
jmp	0x7bee2
not	eax
cmp	sp, bp
xor	ebx, eax
add	edi, eax
jmp	0x3c41c
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
sub	esi, 1
movzx	eax, byte ptr [rsi]
cmc	
clc	
xor	al, bl
dec	al
clc	
jmp	0x4e343
rol	al, 1
test	esp, 0x32734b47
cmp	dx, sp
add	al, 0xf8
jmp	0x5d5e3
not	al
inc	al
cmp	ebx, edi
test	si, 0x380a
test	bp, cx
neg	al
stc	
clc	
xor	bl, al
mov	eax, dword ptr [rsp + rax]
test	esp, 0x42f953bf
lea	ebp, [rbp - 4]
mov	dword ptr [rbp], eax
lea	esi, [rsi - 4]
sub	eax, 0x183274f4
mov	eax, dword ptr [rsi]
xor	eax, ebx
add	eax, 0x3e547e5
stc	
clc	
jmp	0x680be
rol	eax, 2
cmc	
cmp	esp, ebp
not	eax
test	bx, si
cmp	dh, 0x20
xor	ebx, eax
test	ah, 0x74
add	edi, eax
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
lea	esi, [rsi - 1]
adc	eax, 0x707185
cmp	al, cl
movzx	eax, byte ptr [rsi]
cmc	
cmp	eax, esp
xor	al, bl
jmp	0x90e53
dec	al
rol	al, 1
add	al, 0xf8
jmp	0x8249b
not	al
jmp	0xa44ad
inc	al
stc	
neg	al
cmp	sp, sp
xor	bl, al
mov	eax, dword ptr [rsp + rax]
sub	ebp, 4
test	cx, 0x4e28
mov	dword ptr [rbp], eax
bts	eax, ebp
sub	esi, 4
btc	eax, edi
bsf	eax, edi
cwde	
mov	eax, dword ptr [rsi]
stc	
cmp	eax, eax
xor	eax, ebx
add	eax, 0x3e547e5
cmc	
stc	
clc	
rol	eax, 2
jmp	0x54cf5
not	eax
xor	ebx, eax
cmc	
stc	
add	edi, eax
jmp	0x49acd
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
mov	eax, dword ptr [rbp]
sub	cl, dh
and	cl, dh
mov	cx, di
mov	ecx, dword ptr [rbp + 4]
stc	
cmp	edx, ebp
not	eax
not	ecx
and	eax, ecx
jmp	0x6ef81
mov	dword ptr [rbp + 4], eax
movzx	ax, dl
pushfq	
bt	ax, bx
bsf	ax, bx
sar	ax, -0x60
pop	qword ptr [rbp]
mov	eax, 0x67513498
sar	ah, 0xe
rcl	ah, 0x86
lea	esi, [rsi - 4]
neg	al
bsr	eax, esp
mov	eax, dword ptr [rsi]
jmp	0x5b519
xor	eax, ebx
add	eax, 0x3e547e5
stc	
rol	eax, 2
not	eax
cmc	
jmp	0x4a7a3
xor	ebx, eax
add	edi, eax
jmp	rdi
lea	esi, [rsi - 1]
movzx	eax, byte ptr [rsi]
movzx	ecx, di
bts	cx, dx
xor	al, bl
jmp	0x4105f
dec	al
rol	al, 1
add	al, 0xf8
not	al
mov	cx, di
movzx	ecx, di
inc	al
bts	ecx, esp
sar	ch, 0x32
neg	al
xor	bl, al
bt	ecx, 4
add	cx, bx
sar	cx, -0x29
mov	ecx, dword ptr [rbp]
test	di, 0x3785
cmp	cx, si
clc	
lea	ebp, [rbp + 4]
mov	dword ptr [rsp + rax], ecx
rcr	eax, 0x26
neg	ax
or	ax, di
lea	esi, [rsi - 4]
inc	ax
bt	eax, 0x55
mov	eax, dword ptr [rsi]
xor	eax, ebx
jmp	0x7f150
add	eax, 0x3e547e5
rol	eax, 2
jmp	0x3c28b
cmp	cl, 0x17
not	eax
clc	
cmc	
xor	ebx, eax
jmp	0x61b05
add	edi, eax
jmp	0x47706
push	rdi
ret	
sub	esi, 1
movzx	eax, byte ptr [rsi]
xor	al, bl
jmp	0x7b131
dec	al
rol	al, 1
add	al, 0xf8
jmp	0xad8b7
not	al
jmp	0xa7643
inc	al
stc	
jmp	0xb04a8
neg	al
cmc	
test	cx, cx
xor	bl, al
test	ebp, 0xd37746b
mov	eax, dword ptr [rsp + rax]
sub	ebp, 4
jmp	0xa5109
mov	dword ptr [rbp], eax
sar	ax, -9
sub	esi, 4
sar	ah, cl
bswap	ax
mov	eax, dword ptr [rsi]
test	ah, 0xa7
xor	eax, ebx
cmp	sp, cx
add	eax, 0x3e547e5
stc	
rol	eax, 2
not	eax
cmp	si, sp
cmp	dh, 0xab
xor	ebx, eax
add	edi, eax
jmp	0xa72c0
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
lea	esi, [rsi - 1]
movzx	eax, byte ptr [rsi]
test	dl, 0xb1
xor	al, bl
jmp	0x45b58
dec	al
jmp	0x42b21
rol	al, 1
stc	
test	eax, 0x19e921c7
cmp	esi, 0x36672612
add	al, 0xf8
not	al
jmp	0x62a67
inc	al
jmp	0x3c20d
neg	al
stc	
test	si, 0x18b3
cmp	dl, dl
xor	bl, al
jmp	0x87322
mov	eax, dword ptr [rsp + rax]
cmp	sp, bx
cmp	bx, 0x2a9b
sub	ebp, 4
mov	dword ptr [rbp], eax
btr	eax, 0x59
lea	esi, [rsi - 4]
rcl	al, cl
and	ax, 0x7495
clc	
mov	eax, dword ptr [rsi]
cmp	sp, 0x668b
stc	
xor	eax, ebx
jmp	0x8db59
add	eax, 0x3e547e5
jmp	0x8b0cb
rol	eax, 2
jmp	0x89d8a
cmp	di, ax
cmc	
not	eax
stc	
cmp	ch, 0xb9
xor	ebx, eax
clc	
add	edi, eax
jmp	0x5542b
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
mov	eax, dword ptr [rbp]
ror	cl, 0x32
bts	ecx, edi
bsf	ecx, eax
mov	ecx, dword ptr [rbp + 4]
cmp	edx, edi
not	eax
not	ecx
test	edi, edx
and	eax, ecx
jmp	0x5a9b7
mov	dword ptr [rbp + 4], eax
movzx	eax, ax
pushfq	
nop	
pop	qword ptr [rbp]
clc	
lea	esi, [rsi - 4]
mov	eax, dword ptr [rsi]
test	cx, 0x1b19
xor	eax, ebx
cmp	dh, 0x10
cmp	bp, ax
add	eax, 0x3e547e5
stc	
jmp	0xaecf4
rol	eax, 2
jmp	0x570c5
test	dl, 0x75
cmp	al, 0x97
cmp	edx, edx
not	eax
xor	ebx, eax
clc	
cmp	sp, di
stc	
add	edi, eax
jmp	0x8c0f0
jmp	rdi
lea	esi, [rsi - 1]
movzx	eax, byte ptr [rsi]
setp	ch
test	ecx, 0x2e005fa2
xor	al, bl
movzx	ecx, cx
movsx	cx, al
setg	ch
dec	al
ror	ecx, cl
jmp	0xa8048
rol	al, 1
shr	ch, 0x34
clc	
add	al, 0xf8
jmp	0x67358
not	al
movsx	ecx, cx
inc	al
cmc	
add	ecx, esi
neg	al
add	cx, 0x25d2
xor	bl, al
dec	cl
mov	ecx, dword ptr [rbp]
lea	ebp, [rbp + 4]
test	dx, 0x3ba7
stc	
mov	dword ptr [rsp + rax], ecx
sub	esi, 4
mov	al, 0xde
lahf	
or	eax, ecx
mov	eax, dword ptr [rsi]
clc	
xor	eax, ebx
jmp	0x4b787
add	eax, 0x3e547e5
cmc	
clc	
jmp	0x9ea1d
rol	eax, 2
jmp	0x736c0
cmp	esi, esp
not	eax
xor	ebx, eax
cmc	
add	edi, eax
jmp	0xa7641
jmp	rdi
mov	eax, dword ptr [rbp]
bts	ecx, esp
dec	ch
mov	ecx, dword ptr [rbp + 4]
not	eax
test	bh, 0x36
not	ecx
and	eax, ecx
mov	dword ptr [rbp + 4], eax
movzx	ax, bl
cbw	
pushfq	
bsf	eax, esi
add	ah, 0xbd
pop	qword ptr [rbp]
rcl	ah, 8
cmp	si, 0x20d2
add	al, dl
lea	esi, [rsi - 4]
mov	eax, dword ptr [rsi]
xor	eax, ebx
cmp	sp, di
add	eax, 0x3e547e5
rol	eax, 2
jmp	0xa359e
jmp	0x7b5c4
not	eax
stc	
xor	ebx, eax
cmp	ebx, esi
test	ebp, ebx
cmp	esp, 0xf3d3372
add	edi, eax
jmp	rdi
lea	esi, [rsi - 1]
bsf	ax, di
movzx	eax, byte ptr [rsi]
sar	ecx, -0x41
cmp	dx, si
xor	al, bl
inc	ch
movsx	cx, bh
dec	cl
dec	al
bt	cx, -0x1b
rol	al, 1
mov	ch, 0x5d
shr	cl, 0x72
add	al, 0xf8
not	al
inc	al
bswap	ecx
bsf	cx, dx
shl	cl, 0x13
neg	al
bt	ecx, -0x2b
inc	cl
xor	bl, al
btr	cx, bx
xadd	ch, cl
or	ecx, 0x7c14df2
mov	ecx, dword ptr [rbp]
add	ebp, 4
jmp	0x96e40
mov	dword ptr [rsp + rax], ecx
cmp	edi, 0x5ca51d5a
movzx	ax, ch
cwde	
sub	esi, 4
sar	al, 0x80
rol	al, cl
mov	eax, dword ptr [rsi]
xor	eax, ebx
add	eax, 0x3e547e5
jmp	0xa9172
rol	eax, 2
jmp	0x3b4c4
cmp	sp, 0x3cfd
cmc	
clc	
not	eax
xor	ebx, eax
jmp	0x9f58f
add	edi, eax
jmp	0xa6869
jmp	rdi
lea	esi, [rsi - 1]
movzx	eax, byte ptr [rsi]
xor	al, bl
dec	al
btc	cx, 0x71
mov	ecx, 0xbc40900
rol	cl, cl
rol	al, 1
rol	cl, 0xe0
shl	ch, cl
or	cx, bx
add	al, 0xf8
setge	cl
not	al
inc	al
shrd	ecx, esp, -0x33
bts	ecx, ebx
neg	al
mov	ecx, eax
xor	bl, al
sub	ecx, 0x55c3508e
mov	ecx, dword ptr [rbp]
lea	ebp, [rbp + 4]
mov	dword ptr [rsp + rax], ecx
sub	esi, 4
or	ax, 0x7369
mov	eax, dword ptr [rsi]
xor	eax, ebx
cmp	bx, si
jmp	0xb1409
add	eax, 0x3e547e5
rol	eax, 2
jmp	0xad314
cmc	
test	ebp, edx
not	eax
xor	ebx, eax
cmp	ax, 0x2f35
clc	
test	ebx, 0xc212d65
add	edi, eax
push	rdi
ret	
lea	esi, [rsi - 1]
cmc	
movzx	eax, byte ptr [rsi]
xor	al, bl
mov	cx, bx
cmovbe	ecx, ecx
dec	al
btr	ecx, -0x55
rol	al, 1
test	esi, 0x794e557b
add	al, 0xf8
seta	ch
not	cx
dec	cx
not	al
inc	al
btc	cx, -0x64
mov	ch, 0x6a
neg	al
xor	bl, al
adc	ecx, esi
and	cl, 0x21
mov	ecx, dword ptr [rbp]
clc	
test	edi, 0xcd47357
test	esp, edx
add	ebp, 4
jmp	0x3f335
mov	dword ptr [rsp + rax], ecx
btc	ax, -0x70
sub	esi, 4
or	eax, edi
mov	eax, dword ptr [rsi]
cmp	ebp, edx
stc	
xor	eax, ebx
clc	
add	eax, 0x3e547e5
clc	
rol	eax, 2
jmp	0xa2a29
not	eax
xor	ebx, eax
jmp	0x95817
add	edi, eax
jmp	0x40c1b
push	rdi
ret	
lea	esi, [rsi - 1]
bsf	eax, esi
movzx	eax, byte ptr [rsi]
xor	al, bl
dec	al
rol	al, 1
cmc	
cmp	di, 0x38c2
add	al, 0xf8
jmp	0xa5356
not	al
inc	al
jmp	0x626d9
neg	al
xor	bl, al
mov	eax, dword ptr [rsp + rax]
stc	
lea	ebp, [rbp - 4]
test	ebx, 0x5643396
test	bp, cx
mov	dword ptr [rbp], eax
ror	ah, 0xfc
xor	eax, ebp
sub	esi, 4
jmp	0x74cca
mov	eax, dword ptr [rsi]
xor	eax, ebx
cmc	
add	eax, 0x3e547e5
rol	eax, 2
jmp	0x685bb
jmp	0x47727
not	eax
xor	ebx, eax
add	edi, eax
jmp	0xb457f
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
lea	esi, [rsi - 1]
movzx	eax, byte ptr [rsi]
xor	al, bl
jmp	0x9f808
dec	al
rol	al, 1
test	bp, bp
add	al, 0xf8
jmp	0x77715
not	al
jmp	0x8ce52
inc	al
test	ecx, 0xa4f692e
clc	
neg	al
xor	bl, al
mov	eax, dword ptr [rsp + rax]
sub	ebp, 4
mov	dword ptr [rbp], eax
rcl	al, cl
cmovl	ax, ax
rcr	al, 0x46
lea	esi, [rsi - 4]
movsx	eax, di
adc	al, bl
mov	eax, dword ptr [rsi]
test	ebp, 0x1df6730c
test	bp, di
xor	eax, ebx
add	eax, 0x3e547e5
stc	
clc	
rol	eax, 2
clc	
not	eax
xor	ebx, eax
add	edi, eax
jmp	0x65f0d
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
mov	eax, dword ptr [rbp]
setge	cl
mov	ecx, dword ptr [rbp + 4]
test	ebp, edx
cmp	esp, edx
not	eax
cmp	sp, 0x5fe8
cmp	esp, ebx
not	ecx
stc	
cmc	
and	eax, ecx
mov	dword ptr [rbp + 4], eax
cbw	
movsx	eax, cx
pushfq	
sal	ax, 0x29
sub	ah, dh
or	eax, ebp
pop	qword ptr [rbp]
sub	ax, bp
movzx	ax, dl
ror	al, 0x8b
sub	esi, 4
xor	ah, 0x78
mov	eax, dword ptr [rsi]
cmp	bx, sp
cmc	
test	sp, 0x3fd4
xor	eax, ebx
jmp	0x7d85f
add	eax, 0x3e547e5
rol	eax, 2
jmp	0x4a1a9
cmp	bl, 0x79
test	edi, ebx
clc	
not	eax
clc	
cmp	bx, 0x1f4d
xor	ebx, eax
cmp	si, si
add	edi, eax
jmp	0x97647
jmp	rdi
sub	esi, 1
clc	
cmovbe	ax, ax
movzx	eax, byte ptr [rsi]
setge	ch
xor	ecx, esi
bsr	cx, cx
xor	al, bl
movzx	cx, ch
setg	cl
mov	ch, 0xc7
dec	al
bswap	cx
rol	al, 1
add	al, 0xf8
movsx	cx, dh
movzx	ecx, sp
cmove	ecx, ebp
not	al
inc	al
test	cx, bp
ror	ecx, 0x5a
neg	al
bt	ecx, esp
rol	ch, cl
xor	bl, al
xchg	cl, ch
cmc	
add	ch, 0xe0
mov	ecx, dword ptr [rbp]
jmp	0x8ca92
lea	ebp, [rbp + 4]
mov	dword ptr [rsp + rax], ecx
and	ax, 0x597c
rcl	ax, cl
sub	esi, 4
bswap	eax
sbb	ah, 0x78
clc	
mov	eax, dword ptr [rsi]
cmc	
cmp	ebp, 0x1d3f1813
xor	eax, ebx
add	eax, 0x3e547e5
rol	eax, 2
not	eax
test	dl, 0x78
test	esp, esi
stc	
xor	ebx, eax
cmp	bl, ah
add	edi, eax
push	rdi
ret	
mov	eax, ebp
cmc	
lea	ebp, [rbp - 4]
clc	
mov	dword ptr [rbp], eax
sub	eax, 0x4ea693d
lea	esi, [rsi - 4]
mov	eax, dword ptr [rsi]
xor	eax, ebx
jmp	0x3d877
add	eax, 0x3e547e5
clc	
rol	eax, 2
jmp	0x44cba
not	eax
cmc	
stc	
jmp	0x9ef8a
xor	ebx, eax
clc	
test	bp, 0x12bd
cmc	
add	edi, eax
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
mov	ecx, dword ptr [rbp]
bt	ax, dx
[rcx]
cmc	
mov	dword ptr [rbp], eax
and	al, 0x2f
sub	esi, 4
sal	eax, cl
adc	ax, 0x5584
cbw	
mov	eax, dword ptr [rsi]
stc	
cmp	esp, 0x4d2f76ef
xor	eax, ebx
add	eax, 0x3e547e5
stc	
cmc	
rol	eax, 2
jmp	0x540f5
test	ebp, edi
stc	
not	eax
xor	ebx, eax
cmc	
add	edi, eax
push	rdi
ret	
mov	eax, dword ptr [rbp]
shr	ch, cl
mov	ecx, dword ptr [rbp + 4]
not	eax
not	ecx
and	eax, ecx
mov	dword ptr [rbp + 4], eax
pushfq	
pop	qword ptr [rbp]
test	ax, cx
lea	esi, [rsi - 4]
neg	eax
mov	eax, dword ptr [rsi]
stc	
cmp	edi, ecx
cmp	bp, 0x47d
xor	eax, ebx
add	eax, 0x3e547e5
jmp	0x7d6c8
rol	eax, 2
jmp	0x56ec3
not	eax
cmp	cl, 0x5f
xor	ebx, eax
add	edi, eax
jmp	0xa77f5
jmp	rdi
sub	esi, 1
sal	al, 0x40
movzx	eax, byte ptr [rsi]
btr	ecx, 0x52
adc	cl, ah
xor	al, bl
movzx	cx, bh
dec	cl
mov	cl, cl
dec	al
bts	cx, sp
rol	al, 1
shld	ecx, edx, 0x45
movsx	ecx, bp
or	ecx, 0x547071b6
add	al, 0xf8
mov	cl, bl
inc	cl
not	al
setg	cl
inc	al
neg	al
bsr	ecx, esi
mov	cx, 0x56a3
xor	bl, al
mov	ch, 0xcd
mov	ecx, dword ptr [rbp]
cmc	
add	ebp, 4
jmp	0x54e5e
mov	dword ptr [rsp + rax], ecx
cbw	
test	si, dx
sub	esi, 4
not	ah
mov	eax, dword ptr [rsi]
cmp	ecx, esi
test	al, ch
test	di, 0x4d1f
xor	eax, ebx
cmp	bh, ch
add	eax, 0x3e547e5
jmp	0xaa381
rol	eax, 2
jmp	0x4fd66
cmp	dh, 0x67
not	eax
xor	ebx, eax
cmc	
add	edi, eax
jmp	0x9dcd5
push	rdi
ret	
lea	esi, [rsi - 1]
movzx	eax, byte ptr [rsi]
xor	al, bl
xchg	ch, cl
movsx	ecx, dx
dec	al
movsx	cx, bh
bt	ecx, eax
rol	al, 1
and	cx, 0x2087
add	al, 0xf8
not	al
inc	al
cmp	dh, 0x57
adc	cx, di
neg	al
shr	cx, -0x73
movsx	cx, dh
xor	bl, al
shl	ch, cl
mov	ecx, dword ptr [rbp]
test	ch, dh
lea	ebp, [rbp + 4]
cmc	
mov	dword ptr [rsp + rax], ecx
add	ax, di
lea	esi, [rsi - 4]
cmovge	ax, si
mov	eax, dword ptr [rsi]
cmc	
xor	eax, ebx
add	eax, 0x3e547e5
stc	
clc	
rol	eax, 2
test	ah, 0xdb
not	eax
test	dx, bx
jmp	0x550cb
xor	ebx, eax
add	edi, eax
jmp	0x63f03
push	rdi
ret	
lea	esi, [rsi - 1]
movzx	eax, byte ptr [rsi]
cmc	
xor	al, bl
jmp	0x74c6b
dec	al
rol	al, 1
test	ax, 0x6aa6
add	al, 0xf8
not	al
jmp	0x79a22
inc	al
neg	al
xor	bl, al
test	ebp, esi
stc	
mov	eax, dword ptr [rsp + rax]
cmp	di, 0x2e28
cmp	esp, edx
lea	ebp, [rbp - 4]
jmp	0xa688d
mov	dword ptr [rbp], eax
lea	esi, [rsi - 4]
btc	eax, 0x48
bts	eax, ebx
mov	eax, dword ptr [rsi]
cmc	
xor	eax, ebx
jmp	0x3f8c2
add	eax, 0x3e547e5
stc	
cmc	
rol	eax, 2
jmp	0x75881
jmp	0x69462
not	eax
xor	ebx, eax
clc	
stc	
add	edi, eax
jmp	0x83058
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
sub	esi, 1
movzx	eax, byte ptr [rsi]
xor	al, bl
jmp	0x6dcbd
dec	al
stc	
cmc	
rol	al, 1
jmp	0x628c1
add	al, 0xf8
jmp	0x9cddb
not	al
jmp	0x5730e
inc	al
neg	al
test	bh, 0x5d
cmc	
clc	
xor	bl, al
stc	
cmp	ebx, edx
mov	eax, dword ptr [rsp + rax]
sub	ebp, 4
stc	
mov	dword ptr [rbp], eax
shr	ah, 9
not	eax
neg	ax
sub	esi, 4
bts	ax, sp
mov	eax, dword ptr [rsi]
cmp	si, si
xor	eax, ebx
add	eax, 0x3e547e5
clc	
stc	
rol	eax, 2
jmp	0xb3e55
clc	
not	eax
xor	ebx, eax
clc	
add	edi, eax
jmp	0xa399e
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
lea	esi, [rsi - 1]
movzx	eax, byte ptr [rsi]
xor	al, bl
dec	al
stc	
cmc	
rol	al, 1
cmc	
add	al, 0xf8
jmp	0x41623
not	al
jmp	0x5974d
inc	al
neg	al
xor	bl, al
test	bp, 0x50aa
mov	eax, dword ptr [rsp + rax]
lea	ebp, [rbp - 4]
cmc	
mov	dword ptr [rbp], eax
test	ch, 0x5a
movsx	ax, al
adc	al, 0x50
lea	esi, [rsi - 4]
sar	eax, cl
cmc	
mov	eax, dword ptr [rsi]
jmp	0x49d32
xor	eax, ebx
test	dl, 0xb2
cmp	di, 0x75c1
cmp	al, bh
add	eax, 0x3e547e5
rol	eax, 2
jmp	0x8b14b
cmc	
clc	
not	eax
test	di, ax
stc	
xor	ebx, eax
clc	
jmp	0x92270
add	edi, eax
jmp	0x9eb50
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
mov	eax, dword ptr [rbp]
not	ecx
mov	ecx, dword ptr [rbp + 4]
not	eax
not	ecx
and	eax, ecx
jmp	0x78d74
mov	dword ptr [rbp + 4], eax
pushfq	
mov	eax, edx
cbw	
or	ah, dh
pop	qword ptr [rbp]
cmc	
lea	esi, [rsi - 4]
mov	eax, dword ptr [rsi]
cmc	
xor	eax, ebx
test	esp, 0x179d1530
cmp	ax, sp
stc	
add	eax, 0x3e547e5
rol	eax, 2
jmp	0x8cf97
cmp	ebx, esp
not	eax
clc	
cmp	di, 0x5ae6
xor	ebx, eax
test	bx, di
add	edi, eax
jmp	0x75766
push	rdi
ret	
sub	esi, 1
movzx	eax, byte ptr [rsi]
bts	ecx, edi
bswap	cx
xor	al, bl
movzx	cx, al
xchg	ecx, ecx
jmp	0x61cf6
dec	al
stc	
rol	al, 1
sal	ecx, 0x45
shl	ecx, cl
add	al, 0xf8
inc	ch
cmovno	ecx, edi
not	al
dec	cx
setp	cl
mov	ecx, 0x28f22e1a
inc	al
bsr	cx, di
cmovs	ecx, eax
neg	al
neg	cl
xor	bl, al
bsf	ecx, esp
shl	ecx, -0x41
mov	ecx, dword ptr [rbp]
add	ebp, 4
test	dx, cx
mov	dword ptr [rsp + rax], ecx
lea	esi, [rsi - 4]
mov	eax, dword ptr [rsi]
xor	eax, ebx
add	eax, 0x3e547e5
jmp	0xa2d0d
rol	eax, 2
jmp	0x3e219
clc	
not	eax
xor	ebx, eax
test	esp, 0x39ba2a16
jmp	0x8e4a0
add	edi, eax
jmp	rdi
mov	eax, dword ptr [rbp]
stc	
sar	ch, cl
bts	ecx, esi
mov	ecx, dword ptr [rbp + 4]
stc	
clc	
add	eax, ecx
jmp	0x8a229
mov	dword ptr [rbp + 4], eax
mov	ax, 0x7b6b
pushfq	
sar	al, 5
rcr	al, 0xb8
pop	qword ptr [rbp]
and	eax, 0x8e30318
bt	eax, edx
sbb	ax, 0x1192
sub	esi, 4
sal	ax, -0x3a
or	ax, 0x38f7
shr	ah, 0x31
mov	eax, dword ptr [rsi]
cmp	si, cx
cmp	sp, 0x5829
xor	eax, ebx
stc	
cmp	esp, edx
add	eax, 0x3e547e5
stc	
clc	
rol	eax, 2
jmp	0x7eecf
not	eax
cmp	edx, 0x48ef5574
jmp	0x7a68c
xor	ebx, eax
test	esp, esp
cmc	
add	edi, eax
jmp	0x5f55d
push	rdi
ret	
lea	esi, [rsi - 1]
shld	cx, cx, -4
movzx	eax, byte ptr [rsi]
not	ecx
test	bh, 0x46
rcl	cx, cl
xor	al, bl
movzx	cx, bl
jmp	0x7a599
dec	al
movsx	ecx, cx
btc	cx, di
rcr	ecx, cl
rol	al, 1
cmova	cx, si
shl	cx, cl
add	al, 0xf8
not	al
mov	ecx, esp
inc	al
neg	al
xor	bl, al
mov	cl, 0x48
mov	ecx, dword ptr [rbp]
test	ecx, edi
stc	
lea	ebp, [rbp + 4]
test	bx, bx
stc	
mov	dword ptr [rsp + rax], ecx
shld	eax, ecx, 0x27
lea	esi, [rsi - 4]
mov	eax, dword ptr [rsi]
xor	eax, ebx
clc	
test	cl, 0xbf
add	eax, 0x3e547e5
rol	eax, 2
jmp	0x8dea5
not	eax
cmp	sp, di
stc	
xor	ebx, eax
test	bp, cx
add	edi, eax
jmp	0x623c0
jmp	rdi
mov	eax, ebp
sub	ebp, 4
clc	
mov	dword ptr [rbp], eax
bt	eax, ebx
shrd	eax, ebx, -0x48
sub	esi, 4
bsr	ax, si
mov	eax, dword ptr [rsi]
xor	eax, ebx
cmp	edx, ebp
test	ecx, 0x1eba4291
add	eax, 0x3e547e5
jmp	0x6ed6a
rol	eax, 2
jmp	0xb3811
test	edi, esp
not	eax
cmc	
xor	ebx, eax
test	ecx, 0x63dd54c7
cmc	
add	edi, eax
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
mov	ecx, dword ptr [rbp]
[rcx]
cmp	eax, ebp
mov	dword ptr [rbp], eax
xadd	eax, eax
test	dl, ch
lea	esi, [rsi - 4]
mov	eax, dword ptr [rsi]
clc	
test	di, 0x2ad7
cmp	edi, 0x36c92209
xor	eax, ebx
cmp	di, 0x70aa
add	eax, 0x3e547e5
jmp	0xb22cf
rol	eax, 2
jmp	0x91739
jmp	0x71057
not	eax
xor	ebx, eax
add	edi, eax
jmp	0x83a9d
push	rdi
ret	
mov	eax, dword ptr [rbp]
xchg	cx, cx
setl	ch
shr	ch, 0xe3
mov	ecx, dword ptr [rbp + 4]
not	eax
stc	
cmp	esp, edi
not	ecx
and	eax, ecx
jmp	0xaf504
mov	dword ptr [rbp + 4], eax
pushfq	
pop	qword ptr [rbp]
movzx	ax, bh
shrd	eax, esi, -0x41
lea	esi, [rsi - 4]
movzx	ax, cl
mov	eax, dword ptr [rsi]
xor	eax, ebx
test	edx, edx
cmp	si, 0x3b1f
add	eax, 0x3e547e5
rol	eax, 2
jmp	0x8ac83
cmp	ebp, 0x3a8207c1
jmp	0x8106b
not	eax
jmp	0x94b22
xor	ebx, eax
cmc	
cmp	al, ch
add	edi, eax
jmp	0x6447d
jmp	rdi
sub	esi, 1
bt	ecx, -0xb
rcr	cx, 0x5d
neg	ah
movzx	eax, byte ptr [rsi]
xor	cx, bp
shl	ecx, 0x28
bts	cx, si
xor	al, bl
dec	al
rcr	ch, cl
btc	ecx, -0x6e
rol	al, 1
add	al, 0xf8
not	al
inc	al
neg	al
xor	bl, al
btr	ecx, -0x3e
bts	cx, cx
mov	ecx, dword ptr [rbp]
cmp	si, di
add	ebp, 4
test	ah, 0
jmp	0x755b9
mov	dword ptr [rsp + rax], ecx
lea	esi, [rsi - 4]
xadd	al, ah
ror	eax, cl
mov	eax, dword ptr [rsi]
cmp	ah, 0x8c
xor	eax, ebx
add	eax, 0x3e547e5
cmc	
stc	
clc	
rol	eax, 2
jmp	0x4e658
test	sp, sp
not	eax
test	edx, esi
xor	ebx, eax
clc	
add	edi, eax
jmp	0x678c4
push	rdi
ret	
lea	esi, [rsi - 1]
movzx	eax, byte ptr [rsi]
movzx	ecx, di
bts	cx, dx
xor	al, bl
jmp	0x4105f
dec	al
rol	al, 1
add	al, 0xf8
not	al
mov	cx, di
movzx	ecx, di
inc	al
bts	ecx, esp
sar	ch, 0x32
neg	al
xor	bl, al
bt	ecx, 4
add	cx, bx
sar	cx, -0x29
mov	ecx, dword ptr [rbp]
test	di, 0x3785
cmp	cx, si
clc	
lea	ebp, [rbp + 4]
mov	dword ptr [rsp + rax], ecx
rcr	eax, 0x26
neg	ax
or	ax, di
lea	esi, [rsi - 4]
inc	ax
bt	eax, 0x55
mov	eax, dword ptr [rsi]
xor	eax, ebx
jmp	0x7f150
add	eax, 0x3e547e5
rol	eax, 2
jmp	0x3c28b
cmp	cl, 0x17
not	eax
clc	
cmc	
xor	ebx, eax
jmp	0x61b05
add	edi, eax
jmp	0x47706
push	rdi
ret	
sub	esi, 1
or	ah, al
ror	eax, cl
movzx	eax, byte ptr [rsi]
cmp	si, 0x7327
test	cx, sp
xor	al, bl
jmp	0x6f86c
dec	al
rol	al, 1
jmp	0x9645d
add	al, 0xf8
not	al
jmp	0xae444
inc	al
test	di, bp
neg	al
xor	bl, al
test	edx, esi
test	ah, 0xf2
cmp	bp, 0x263
mov	eax, dword ptr [rsp + rax]
test	di, bp
test	sp, 0x66f3
lea	ebp, [rbp - 4]
mov	dword ptr [rbp], eax
lea	esi, [rsi - 4]
mov	eax, dword ptr [rsi]
xor	eax, ebx
cmc	
test	si, dx
add	eax, 0x3e547e5
cmc	
jmp	0x55e12
rol	eax, 2
cmp	ebp, 0x45490fc6
not	eax
stc	
cmc	
xor	ebx, eax
add	edi, eax
jmp	0x90bbc
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
sub	esi, 1
btr	ax, -0x52
movzx	eax, byte ptr [rsi]
test	ax, 0x3d8a
test	ebx, edi
jmp	0x93b85
xor	al, bl
dec	al
clc	
rol	al, 1
cmp	si, bp
add	al, 0xf8
jmp	0xa8565
not	al
jmp	0x826a0
inc	al
test	esp, edx
neg	al
xor	bl, al
test	esp, esi
test	al, 0x58
mov	eax, dword ptr [rsp + rax]
test	bx, sp
clc	
lea	ebp, [rbp - 4]
mov	dword ptr [rbp], eax
bt	eax, edx
rcr	eax, cl
sbb	al, 0x53
lea	esi, [rsi - 4]
sbb	ax, bx
ror	ax, cl
mov	eax, dword ptr [rsi]
test	bh, 0x3a
xor	eax, ebx
add	eax, 0x3e547e5
clc	
rol	eax, 2
jmp	0x7bee2
not	eax
cmp	sp, bp
xor	ebx, eax
add	edi, eax
jmp	0x3c41c
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
mov	eax, dword ptr [rbp]
mov	ecx, dword ptr [rbp + 4]
test	bh, 0x4e
not	eax
not	ecx
and	eax, ecx
jmp	0x54c54
mov	dword ptr [rbp + 4], eax
pushfq	
pop	qword ptr [rbp]
cwde	
rcr	ah, cl
sub	esi, 4
btr	ax, cx
mov	eax, dword ptr [rsi]
jmp	0x45dbb
xor	eax, ebx
add	eax, 0x3e547e5
rol	eax, 2
jmp	0x42a35
not	eax
cmp	sp, bx
xor	ebx, eax
jmp	0x9e35a
add	edi, eax
jmp	0x79a1b
jmp	rdi
lea	esi, [rsi - 1]
movzx	eax, byte ptr [rsi]
setp	ch
test	ecx, 0x2e005fa2
xor	al, bl
movzx	ecx, cx
movsx	cx, al
setg	ch
dec	al
ror	ecx, cl
jmp	0xa8048
rol	al, 1
shr	ch, 0x34
clc	
add	al, 0xf8
jmp	0x67358
not	al
movsx	ecx, cx
inc	al
cmc	
add	ecx, esi
neg	al
add	cx, 0x25d2
xor	bl, al
dec	cl
mov	ecx, dword ptr [rbp]
lea	ebp, [rbp + 4]
test	dx, 0x3ba7
stc	
mov	dword ptr [rsp + rax], ecx
sub	esi, 4
mov	al, 0xde
lahf	
or	eax, ecx
mov	eax, dword ptr [rsi]
clc	
xor	eax, ebx
jmp	0x4b787
add	eax, 0x3e547e5
cmc	
clc	
jmp	0x9ea1d
rol	eax, 2
jmp	0x736c0
cmp	esi, esp
not	eax
xor	ebx, eax
cmc	
add	edi, eax
jmp	0xa7641
jmp	rdi
sub	esi, 4
or	eax, 0x31c3674d
lahf	
add	eax, esp
mov	eax, dword ptr [rsi]
cmp	ah, 0xa6
xor	eax, ebx
bswap	eax
cmc	
test	sp, 0x5118
xor	eax, 0x4cf3616f
jmp	0x93d0b
jmp	0xae1d8
rol	eax, 3
bswap	eax
xor	ebx, eax
stc	
test	esi, 0x64432dc4
cmc	
lea	ebp, [rbp - 4]
jmp	0x70b6f
mov	dword ptr [rbp], eax
sar	al, 0x8a
sub	esi, 4
mov	eax, dword ptr [rsi]
cmp	cl, 0x8c
jmp	0x87e31
xor	eax, ebx
clc	
add	eax, 0x3e547e5
stc	
rol	eax, 2
jmp	0x5112c
test	ah, 0x89
not	eax
cmp	bh, bh
stc	
xor	ebx, eax
add	edi, eax
jmp	0xadb0b
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
mov	eax, dword ptr [rbp]
sub	cx, bp
btr	ecx, edx
neg	ecx
mov	ecx, dword ptr [rbp + 4]
jmp	0xaaa0a
not	eax
test	si, 0x7856
not	ecx
and	eax, ecx
jmp	0x97b39
mov	dword ptr [rbp + 4], eax
jmp	0x85a13
pushfq	
shr	al, cl
pop	qword ptr [rbp]
sub	esi, 4
bts	ax, si
mov	eax, dword ptr [rsi]
cmp	edi, 0x2ce46e46
cmp	esi, edi
stc	
xor	eax, ebx
clc	
stc	
jmp	0xad890
add	eax, 0x3e547e5
clc	
cmc	
rol	eax, 2
jmp	0xb17fb
jmp	0xa05a6
not	eax
test	ax, 0x754
cmc	
jmp	0x86a2c
xor	ebx, eax
stc	
add	edi, eax
push	rdi
ret	
lea	esi, [rsi - 1]
bsf	ax, di
movzx	eax, byte ptr [rsi]
sar	ecx, -0x41
cmp	dx, si
xor	al, bl
inc	ch
movsx	cx, bh
dec	cl
dec	al
bt	cx, -0x1b
rol	al, 1
mov	ch, 0x5d
shr	cl, 0x72
add	al, 0xf8
not	al
inc	al
bswap	ecx
bsf	cx, dx
shl	cl, 0x13
neg	al
bt	ecx, -0x2b
inc	cl
xor	bl, al
btr	cx, bx
xadd	ch, cl
or	ecx, 0x7c14df2
mov	ecx, dword ptr [rbp]
add	ebp, 4
jmp	0x96e40
mov	dword ptr [rsp + rax], ecx
cmp	edi, 0x5ca51d5a
movzx	ax, ch
cwde	
sub	esi, 4
sar	al, 0x80
rol	al, cl
mov	eax, dword ptr [rsi]
xor	eax, ebx
add	eax, 0x3e547e5
jmp	0xa9172
rol	eax, 2
jmp	0x3b4c4
cmp	sp, 0x3cfd
cmc	
clc	
not	eax
xor	ebx, eax
jmp	0x9f58f
add	edi, eax
jmp	0xa6869
jmp	rdi
sub	esi, 1
movzx	eax, byte ptr [rsi]
cmc	
clc	
xor	al, bl
dec	al
clc	
jmp	0x4e343
rol	al, 1
test	esp, 0x32734b47
cmp	dx, sp
add	al, 0xf8
jmp	0x5d5e3
not	al
inc	al
cmp	ebx, edi
test	si, 0x380a
test	bp, cx
neg	al
stc	
clc	
xor	bl, al
mov	eax, dword ptr [rsp + rax]
test	esp, 0x42f953bf
lea	ebp, [rbp - 4]
mov	dword ptr [rbp], eax
lea	esi, [rsi - 4]
sub	eax, 0x183274f4
mov	eax, dword ptr [rsi]
xor	eax, ebx
add	eax, 0x3e547e5
stc	
clc	
jmp	0x680be
rol	eax, 2
cmc	
cmp	esp, ebp
not	eax
test	bx, si
cmp	dh, 0x20
xor	ebx, eax
test	ah, 0x74
add	edi, eax
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
lea	esi, [rsi - 1]
adc	eax, 0x707185
cmp	al, cl
movzx	eax, byte ptr [rsi]
cmc	
cmp	eax, esp
xor	al, bl
jmp	0x90e53
dec	al
rol	al, 1
add	al, 0xf8
jmp	0x8249b
not	al
jmp	0xa44ad
inc	al
stc	
neg	al
cmp	sp, sp
xor	bl, al
mov	eax, dword ptr [rsp + rax]
sub	ebp, 4
test	cx, 0x4e28
mov	dword ptr [rbp], eax
bts	eax, ebp
sub	esi, 4
btc	eax, edi
bsf	eax, edi
cwde	
mov	eax, dword ptr [rsi]
stc	
cmp	eax, eax
xor	eax, ebx
add	eax, 0x3e547e5
cmc	
stc	
clc	
rol	eax, 2
jmp	0x54cf5
not	eax
xor	ebx, eax
cmc	
stc	
add	edi, eax
jmp	0x49acd
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
sub	esi, 4
mov	eax, dword ptr [rsi]
xor	eax, ebx
cmp	si, ax
jmp	0x87b0b
bswap	eax
cmp	sp, 0x6e63
test	bp, bp
xor	eax, 0x4cf3616f
jmp	0x8bdff
rol	eax, 3
stc	
jmp	0x62251
bswap	eax
test	bp, 0x5b30
cmp	di, 0x32e7
xor	ebx, eax
cmc	
sub	ebp, 4
mov	dword ptr [rbp], eax
sets	ah
ror	al, cl
lea	esi, [rsi - 4]
cmc	
adc	al, bh
mov	eax, dword ptr [rsi]
xor	eax, ebx
cmp	cx, sp
add	eax, 0x3e547e5
stc	
cmc	
clc	
rol	eax, 2
test	bp, 0x79cc
not	eax
cmc	
clc	
jmp	0x4c0fb
xor	ebx, eax
add	edi, eax
jmp	0x9d4bd
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
mov	eax, dword ptr [rbp]
mov	ecx, dword ptr [rbp + 4]
cmp	bp, 0x7d97
add	eax, ecx
jmp	0x68df0
mov	dword ptr [rbp + 4], eax
not	al
pushfq	
shl	eax, cl
pop	qword ptr [rbp]
shr	al, cl
lea	esi, [rsi - 4]
mov	eax, dword ptr [rsi]
cmp	ecx, 0x63812940
clc	
cmc	
xor	eax, ebx
cmp	sp, si
cmp	esp, 0x1d73556e
add	eax, 0x3e547e5
cmc	
stc	
rol	eax, 2
jmp	0xa7af6
cmc	
not	eax
cmc	
test	dx, di
xor	ebx, eax
add	edi, eax
jmp	0x4a82e
push	rdi
ret	
lea	esi, [rsi - 1]
movzx	eax, byte ptr [rsi]
xor	al, bl
dec	al
btc	cx, 0x71
mov	ecx, 0xbc40900
rol	cl, cl
rol	al, 1
rol	cl, 0xe0
shl	ch, cl
or	cx, bx
add	al, 0xf8
setge	cl
not	al
inc	al
shrd	ecx, esp, -0x33
bts	ecx, ebx
neg	al
mov	ecx, eax
xor	bl, al
sub	ecx, 0x55c3508e
mov	ecx, dword ptr [rbp]
lea	ebp, [rbp + 4]
mov	dword ptr [rsp + rax], ecx
sub	esi, 4
or	ax, 0x7369
mov	eax, dword ptr [rsi]
xor	eax, ebx
cmp	bx, si
jmp	0xb1409
add	eax, 0x3e547e5
rol	eax, 2
jmp	0xad314
cmc	
test	ebp, edx
not	eax
xor	ebx, eax
cmp	ax, 0x2f35
clc	
test	ebx, 0xc212d65
add	edi, eax
push	rdi
ret	
mov	ecx, dword ptr [rbp]
sal	ah, 0x2d
mov	eax, dword ptr [rbp + 4]
add	ebp, 8
cmc	
[rcx], eax
rcl	ah, 9
shrd	eax, eax, 0x6c
bsf	eax, edi
lea	esi, [rsi - 4]
mov	eax, dword ptr [rsi]
cmp	dx, 0x7995
xor	eax, ebx
clc	
add	eax, 0x3e547e5
rol	eax, 2
jmp	0x73c77
clc	
not	eax
test	ebx, 0x21ec3827
cmc	
xor	ebx, eax
cmp	ecx, 0x468269fc
add	edi, eax
jmp	0x876cd
jmp	rdi
sub	esi, 1
movzx	eax, byte ptr [rsi]
xor	al, bl
jmp	0x7b131
dec	al
rol	al, 1
add	al, 0xf8
jmp	0xad8b7
not	al
jmp	0xa7643
inc	al
stc	
jmp	0xb04a8
neg	al
cmc	
test	cx, cx
xor	bl, al
test	ebp, 0xd37746b
mov	eax, dword ptr [rsp + rax]
sub	ebp, 4
jmp	0xa5109
mov	dword ptr [rbp], eax
sar	ax, -9
sub	esi, 4
sar	ah, cl
bswap	ax
mov	eax, dword ptr [rsi]
test	ah, 0xa7
xor	eax, ebx
cmp	sp, cx
add	eax, 0x3e547e5
stc	
rol	eax, 2
not	eax
cmp	si, sp
cmp	dh, 0xab
xor	ebx, eax
add	edi, eax
jmp	0xa72c0
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
lea	esi, [rsi - 1]
movzx	eax, byte ptr [rsi]
test	dl, 0xb1
xor	al, bl
jmp	0x45b58
dec	al
jmp	0x42b21
rol	al, 1
stc	
test	eax, 0x19e921c7
cmp	esi, 0x36672612
add	al, 0xf8
not	al
jmp	0x62a67
inc	al
jmp	0x3c20d
neg	al
stc	
test	si, 0x18b3
cmp	dl, dl
xor	bl, al
jmp	0x87322
mov	eax, dword ptr [rsp + rax]
cmp	sp, bx
cmp	bx, 0x2a9b
sub	ebp, 4
mov	dword ptr [rbp], eax
btr	eax, 0x59
lea	esi, [rsi - 4]
rcl	al, cl
and	ax, 0x7495
clc	
mov	eax, dword ptr [rsi]
cmp	sp, 0x668b
stc	
xor	eax, ebx
jmp	0x8db59
add	eax, 0x3e547e5
jmp	0x8b0cb
rol	eax, 2
jmp	0x89d8a
cmp	di, ax
cmc	
not	eax
stc	
cmp	ch, 0xb9
xor	ebx, eax
clc	
add	edi, eax
jmp	0x5542b
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
mov	eax, dword ptr [rbp]
mov	ecx, dword ptr [rbp + 4]
test	esi, esi
stc	
not	eax
jmp	0x9176c
not	ecx
test	al, 0x37
stc	
and	eax, ecx
jmp	0xb3113
mov	dword ptr [rbp + 4], eax
pushfq	
dec	al
btr	ax, 0x3b
pop	qword ptr [rbp]
lahf	
not	eax
xadd	al, al
sub	esi, 4
mov	al, 0x17
ror	ah, 0xa9
xor	eax, 0x5847597c
mov	eax, dword ptr [rsi]
xor	eax, ebx
add	eax, 0x3e547e5
rol	eax, 2
jmp	0x4ed35
test	ch, ah
cmp	ah, 0xe6
not	eax
cmp	di, 0x5cea
cmc	
xor	ebx, eax
add	edi, eax
jmp	0x46140
push	rdi
ret	
lea	esi, [rsi - 1]
cmc	
movzx	eax, byte ptr [rsi]
xor	al, bl
mov	cx, bx
cmovbe	ecx, ecx
dec	al
btr	ecx, -0x55
rol	al, 1
test	esi, 0x794e557b
add	al, 0xf8
seta	ch
not	cx
dec	cx
not	al
inc	al
btc	cx, -0x64
mov	ch, 0x6a
neg	al
xor	bl, al
adc	ecx, esi
and	cl, 0x21
mov	ecx, dword ptr [rbp]
clc	
test	edi, 0xcd47357
test	esp, edx
add	ebp, 4
jmp	0x3f335
mov	dword ptr [rsp + rax], ecx
btc	ax, -0x70
sub	esi, 4
or	eax, edi
mov	eax, dword ptr [rsi]
cmp	ebp, edx
stc	
xor	eax, ebx
clc	
add	eax, 0x3e547e5
clc	
rol	eax, 2
jmp	0xa2a29
not	eax
xor	ebx, eax
jmp	0x95817
add	edi, eax
jmp	0x40c1b
push	rdi
ret	
sub	esi, 4
and	ax, dx
shl	ax, cl
sub	eax, esi
mov	eax, dword ptr [rsi]
xor	eax, ebx
test	bp, ax
cmp	esp, esi
bswap	eax
clc	
xor	eax, 0x4cf3616f
jmp	0x97d59
stc	
rol	eax, 3
bswap	eax
cmp	di, ax
test	cx, bx
stc	
xor	ebx, eax
cmp	ebx, ecx
cmp	ebp, 0x2bd067e8
lea	ebp, [rbp - 4]
mov	dword ptr [rbp], eax
sub	esi, 4
rcl	ax, 0x2f
mov	ah, bl
mov	eax, dword ptr [rsi]
jmp	0x764f0
xor	eax, ebx
stc	
test	ebp, 0x6be05d1f
add	eax, 0x3e547e5
cmc	
stc	
rol	eax, 2
jmp	0xab579
cmp	eax, esi
jmp	0x4671b
not	eax
test	bx, 0x543c
cmp	ax, bp
xor	ebx, eax
stc	
add	edi, eax
jmp	0x92d99
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
lea	esi, [rsi - 1]
bsf	eax, esi
movzx	eax, byte ptr [rsi]
xor	al, bl
dec	al
rol	al, 1
cmc	
cmp	di, 0x38c2
add	al, 0xf8
jmp	0xa5356
not	al
inc	al
jmp	0x626d9
neg	al
xor	bl, al
mov	eax, dword ptr [rsp + rax]
stc	
lea	ebp, [rbp - 4]
test	ebx, 0x5643396
test	bp, cx
mov	dword ptr [rbp], eax
ror	ah, 0xfc
xor	eax, ebp
sub	esi, 4
jmp	0x74cca
mov	eax, dword ptr [rsi]
xor	eax, ebx
cmc	
add	eax, 0x3e547e5
rol	eax, 2
jmp	0x685bb
jmp	0x47727
not	eax
xor	ebx, eax
add	edi, eax
jmp	0xb457f
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
lea	esi, [rsi - 4]
sal	ax, 0x5a
rcr	al, 0x5e
shr	ax, -0xc
mov	eax, dword ptr [rsi]
cmp	cl, 0x88
xor	eax, ebx
bswap	eax
jmp	0x59a23
xor	eax, 0x4cf3616f
jmp	0xaba14
jmp	0x6e5f9
rol	eax, 3
cmp	cl, al
bswap	eax
test	eax, esp
xor	ebx, eax
cmc	
test	eax, 0x14393535
cmp	ecx, esp
lea	ebp, [rbp - 4]
cmp	cx, cx
mov	dword ptr [rbp], eax
sub	esi, 4
btc	eax, eax
add	al, 0xe5
mov	eax, dword ptr [rsi]
cmc	
jmp	0x56e17
xor	eax, ebx
cmp	ax, di
add	eax, 0x3e547e5
rol	eax, 2
jmp	0x4992b
not	eax
xor	ebx, eax
clc	
stc	
add	edi, eax
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
mov	eax, dword ptr [rbp]
btc	ecx, ecx
btr	cx, 0x49
jmp	0x8dc60
mov	ecx, dword ptr [rbp + 4]
add	eax, ecx
jmp	0x8a4fa
mov	dword ptr [rbp + 4], eax
setae	al
pushfq	
sbb	al, 0x1f
movzx	eax, dx
test	bp, si
pop	qword ptr [rbp]
adc	eax, esi
mov	ax, si
dec	ax
lea	esi, [rsi - 4]
mov	eax, dword ptr [rsi]
cmp	ax, sp
clc	
xor	eax, ebx
jmp	0x7cb7b
add	eax, 0x3e547e5
rol	eax, 2
stc	
not	eax
test	sp, bx
test	ah, 0xe7
xor	ebx, eax
cmp	ax, sp
jmp	0x4ef76
add	edi, eax
jmp	0x7f414
push	rdi
ret	
sub	esi, 1
clc	
cmovbe	ax, ax
movzx	eax, byte ptr [rsi]
setge	ch
xor	ecx, esi
bsr	cx, cx
xor	al, bl
movzx	cx, ch
setg	cl
mov	ch, 0xc7
dec	al
bswap	cx
rol	al, 1
add	al, 0xf8
movsx	cx, dh
movzx	ecx, sp
cmove	ecx, ebp
not	al
inc	al
test	cx, bp
ror	ecx, 0x5a
neg	al
bt	ecx, esp
rol	ch, cl
xor	bl, al
xchg	cl, ch
cmc	
add	ch, 0xe0
mov	ecx, dword ptr [rbp]
jmp	0x8ca92
lea	ebp, [rbp + 4]
mov	dword ptr [rsp + rax], ecx
and	ax, 0x597c
rcl	ax, cl
sub	esi, 4
bswap	eax
sbb	ah, 0x78
clc	
mov	eax, dword ptr [rsi]
cmc	
cmp	ebp, 0x1d3f1813
xor	eax, ebx
add	eax, 0x3e547e5
rol	eax, 2
not	eax
test	dl, 0x78
test	esp, esi
stc	
xor	ebx, eax
cmp	bl, ah
add	edi, eax
push	rdi
ret	
mov	ecx, dword ptr [rbp]
[rcx]
test	bp, 0x60cc
test	bx, di
mov	dword ptr [rbp], eax
cmc	
shr	ah, 0xe3
bts	eax, ecx
sub	esi, 4
and	eax, 0x2418119d
sal	eax, -0x70
mov	eax, dword ptr [rsi]
cmp	ax, cx
stc	
xor	eax, ebx
cmp	ebx, esi
clc	
cmp	edi, 0x72a27241
add	eax, 0x3e547e5
stc	
rol	eax, 2
clc	
not	eax
clc	
xor	ebx, eax
clc	
cmp	esp, edi
add	edi, eax
jmp	0x84208
jmp	rdi
sub	esi, 1
sal	al, 0x40
movzx	eax, byte ptr [rsi]
btr	ecx, 0x52
adc	cl, ah
xor	al, bl
movzx	cx, bh
dec	cl
mov	cl, cl
dec	al
bts	cx, sp
rol	al, 1
shld	ecx, edx, 0x45
movsx	ecx, bp
or	ecx, 0x547071b6
add	al, 0xf8
mov	cl, bl
inc	cl
not	al
setg	cl
inc	al
neg	al
bsr	ecx, esi
mov	cx, 0x56a3
xor	bl, al
mov	ch, 0xcd
mov	ecx, dword ptr [rbp]
cmc	
add	ebp, 4
jmp	0x54e5e
mov	dword ptr [rsp + rax], ecx
cbw	
test	si, dx
sub	esi, 4
not	ah
mov	eax, dword ptr [rsi]
cmp	ecx, esi
test	al, ch
test	di, 0x4d1f
xor	eax, ebx
cmp	bh, ch
add	eax, 0x3e547e5
jmp	0xaa381
rol	eax, 2
jmp	0x4fd66
cmp	dh, 0x67
not	eax
xor	ebx, eax
cmc	
add	edi, eax
jmp	0x9dcd5
push	rdi
ret	
mov	eax, dword ptr [rbp]
shr	cx, 0x60
bswap	cx
shr	cx, cl
mov	ecx, dword ptr [rbp + 4]
cmp	si, sp
not	eax
jmp	0x97a6e
not	ecx
and	eax, ecx
jmp	0x4bed0
mov	dword ptr [rbp + 4], eax
pushfq	
cbw	
ror	ax, cl
pop	qword ptr [rbp]
lahf	
sal	ax, -0x67
sub	esi, 4
add	eax, 0x158b5f86
or	ax, 0x13e8
mov	eax, dword ptr [rsi]
xor	eax, ebx
add	eax, 0x3e547e5
rol	eax, 2
jmp	0x642e0
not	eax
clc	
xor	ebx, eax
add	edi, eax
jmp	0x9952f
push	rdi
ret	
lea	esi, [rsi - 1]
movzx	eax, byte ptr [rsi]
xor	al, bl
xchg	ch, cl
movsx	ecx, dx
dec	al
movsx	cx, bh
bt	ecx, eax
rol	al, 1
and	cx, 0x2087
add	al, 0xf8
not	al
inc	al
cmp	dh, 0x57
adc	cx, di
neg	al
shr	cx, -0x73
movsx	cx, dh
xor	bl, al
shl	ch, cl
mov	ecx, dword ptr [rbp]
test	ch, dh
lea	ebp, [rbp + 4]
cmc	
mov	dword ptr [rsp + rax], ecx
add	ax, di
lea	esi, [rsi - 4]
cmovge	ax, si
mov	eax, dword ptr [rsi]
cmc	
xor	eax, ebx
add	eax, 0x3e547e5
stc	
clc	
rol	eax, 2
test	ah, 0xdb
not	eax
test	dx, bx
jmp	0x550cb
xor	ebx, eax
add	edi, eax
jmp	0x63f03
push	rdi
ret	
mov	eax, dword ptr [rbp]
test	dx, dx
sal	ch, 0xde
mov	ecx, dword ptr [rbp + 4]
jmp	0x45f22
add	eax, ecx
jmp	0xa16c4
mov	dword ptr [rbp + 4], eax
cbw	
xchg	al, ah
bswap	eax
pushfq	
movsx	eax, dx
shrd	ax, ax, 0x46
pop	qword ptr [rbp]
bt	ax, -0x3d
sar	eax, cl
lea	esi, [rsi - 4]
xadd	eax, eax
sal	ax, cl
xchg	al, ah
mov	eax, dword ptr [rsi]
xor	eax, ebx
add	eax, 0x3e547e5
jmp	0x88ef6
rol	eax, 2
jmp	0x9b1a1
stc	
not	eax
xor	ebx, eax
test	ecx, ebp
test	bp, 0xebf
add	edi, eax
jmp	rdi
sub	esi, 1
movzx	eax, byte ptr [rsi]
bts	ecx, edi
bswap	cx
xor	al, bl
movzx	cx, al
xchg	ecx, ecx
jmp	0x61cf6
dec	al
stc	
rol	al, 1
sal	ecx, 0x45
shl	ecx, cl
add	al, 0xf8
inc	ch
cmovno	ecx, edi
not	al
dec	cx
setp	cl
mov	ecx, 0x28f22e1a
inc	al
bsr	cx, di
cmovs	ecx, eax
neg	al
neg	cl
xor	bl, al
bsf	ecx, esp
shl	ecx, -0x41
mov	ecx, dword ptr [rbp]
add	ebp, 4
test	dx, cx
mov	dword ptr [rsp + rax], ecx
lea	esi, [rsi - 4]
mov	eax, dword ptr [rsi]
xor	eax, ebx
add	eax, 0x3e547e5
jmp	0xa2d0d
rol	eax, 2
jmp	0x3e219
clc	
not	eax
xor	ebx, eax
test	esp, 0x39ba2a16
jmp	0x8e4a0
add	edi, eax
jmp	rdi
lea	esi, [rsi - 1]
shld	cx, cx, -4
movzx	eax, byte ptr [rsi]
not	ecx
test	bh, 0x46
rcl	cx, cl
xor	al, bl
movzx	cx, bl
jmp	0x7a599
dec	al
movsx	ecx, cx
btc	cx, di
rcr	ecx, cl
rol	al, 1
cmova	cx, si
shl	cx, cl
add	al, 0xf8
not	al
mov	ecx, esp
inc	al
neg	al
xor	bl, al
mov	cl, 0x48
mov	ecx, dword ptr [rbp]
test	ecx, edi
stc	
lea	ebp, [rbp + 4]
test	bx, bx
stc	
mov	dword ptr [rsp + rax], ecx
shld	eax, ecx, 0x27
lea	esi, [rsi - 4]
mov	eax, dword ptr [rsi]
xor	eax, ebx
clc	
test	cl, 0xbf
add	eax, 0x3e547e5
rol	eax, 2
jmp	0x8dea5
not	eax
cmp	sp, di
stc	
xor	ebx, eax
test	bp, cx
add	edi, eax
jmp	0x623c0
jmp	rdi
lea	esi, [rsi - 4]
bsf	eax, edx
btr	eax, esp
bt	eax, -0x6f
mov	eax, dword ptr [rsi]
jmp	0x849c7
xor	eax, ebx
bswap	eax
cmp	edi, edx
cmp	bl, 0x8f
test	cx, sp
xor	eax, 0x4cf3616f
rol	eax, 3
cmp	bl, 0x46
cmp	edi, esp
test	di, bp
bswap	eax
xor	ebx, eax
lea	ebp, [rbp - 4]
cmp	si, 0x75
mov	dword ptr [rbp], eax
lea	esi, [rsi - 4]
mov	eax, dword ptr [rsi]
cmp	ah, 0xda
clc	
xor	eax, ebx
jmp	0xaa476
add	eax, 0x3e547e5
stc	
rol	eax, 2
jmp	0xac5e1
cmp	bl, al
not	eax
xor	ebx, eax
clc	
add	edi, eax
jmp	0x3c42b
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
lea	esi, [rsi - 1]
movzx	eax, byte ptr [rsi]
xor	al, bl
jmp	0x9f808
dec	al
rol	al, 1
test	bp, bp
add	al, 0xf8
jmp	0x77715
not	al
jmp	0x8ce52
inc	al
test	ecx, 0xa4f692e
clc	
neg	al
xor	bl, al
mov	eax, dword ptr [rsp + rax]
sub	ebp, 4
mov	dword ptr [rbp], eax
rcl	al, cl
cmovl	ax, ax
rcr	al, 0x46
lea	esi, [rsi - 4]
movsx	eax, di
adc	al, bl
mov	eax, dword ptr [rsi]
test	ebp, 0x1df6730c
test	bp, di
xor	eax, ebx
add	eax, 0x3e547e5
stc	
clc	
rol	eax, 2
clc	
not	eax
xor	ebx, eax
add	edi, eax
jmp	0x65f0d
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
mov	eax, dword ptr [rbp]
mov	ecx, dword ptr [rbp + 4]
cmp	al, 0x3b
cmc	
test	di, 0x2827
add	eax, ecx
jmp	0x74698
mov	dword ptr [rbp + 4], eax
pushfq	
btr	eax, -0x68
pop	qword ptr [rbp]
sbb	eax, ebp
mov	al, 0xf2
lea	esi, [rsi - 4]
jmp	0x8ebd7
mov	eax, dword ptr [rsi]
cmp	edi, 0x2f041218
xor	eax, ebx
add	eax, 0x3e547e5
cmc	
clc	
rol	eax, 2
jmp	0x7a409
clc	
stc	
not	eax
test	sp, 0x35d4
cmc	
xor	ebx, eax
cmc	
stc	
add	edi, eax
jmp	0x45978
jmp	rdi
sub	esi, 1
bt	ecx, -0xb
rcr	cx, 0x5d
neg	ah
movzx	eax, byte ptr [rsi]
xor	cx, bp
shl	ecx, 0x28
bts	cx, si
xor	al, bl
dec	al
rcr	ch, cl
btc	ecx, -0x6e
rol	al, 1
add	al, 0xf8
not	al
inc	al
neg	al
xor	bl, al
btr	ecx, -0x3e
bts	cx, cx
mov	ecx, dword ptr [rbp]
cmp	si, di
add	ebp, 4
test	ah, 0
jmp	0x755b9
mov	dword ptr [rsp + rax], ecx
lea	esi, [rsi - 4]
xadd	al, ah
ror	eax, cl
mov	eax, dword ptr [rsi]
cmp	ah, 0x8c
xor	eax, ebx
add	eax, 0x3e547e5
cmc	
stc	
clc	
rol	eax, 2
jmp	0x4e658
test	sp, sp
not	eax
test	edx, esi
xor	ebx, eax
clc	
add	edi, eax
jmp	0x678c4
push	rdi
ret	
lea	esi, [rsi - 1]
movzx	eax, byte ptr [rsi]
cmc	
xor	al, bl
jmp	0x74c6b
dec	al
rol	al, 1
test	ax, 0x6aa6
add	al, 0xf8
not	al
jmp	0x79a22
inc	al
neg	al
xor	bl, al
test	ebp, esi
stc	
mov	eax, dword ptr [rsp + rax]
cmp	di, 0x2e28
cmp	esp, edx
lea	ebp, [rbp - 4]
jmp	0xa688d
mov	dword ptr [rbp], eax
lea	esi, [rsi - 4]
btc	eax, 0x48
bts	eax, ebx
mov	eax, dword ptr [rsi]
cmc	
xor	eax, ebx
jmp	0x3f8c2
add	eax, 0x3e547e5
stc	
cmc	
rol	eax, 2
jmp	0x75881
jmp	0x69462
not	eax
xor	ebx, eax
clc	
stc	
add	edi, eax
jmp	0x83058
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
sub	esi, 1
movzx	eax, byte ptr [rsi]
xor	al, bl
jmp	0x6dcbd
dec	al
stc	
cmc	
rol	al, 1
jmp	0x628c1
add	al, 0xf8
jmp	0x9cddb
not	al
jmp	0x5730e
inc	al
neg	al
test	bh, 0x5d
cmc	
clc	
xor	bl, al
stc	
cmp	ebx, edx
mov	eax, dword ptr [rsp + rax]
sub	ebp, 4
stc	
mov	dword ptr [rbp], eax
shr	ah, 9
not	eax
neg	ax
sub	esi, 4
bts	ax, sp
mov	eax, dword ptr [rsi]
cmp	si, si
xor	eax, ebx
add	eax, 0x3e547e5
clc	
stc	
rol	eax, 2
jmp	0xb3e55
clc	
not	eax
xor	ebx, eax
clc	
add	edi, eax
jmp	0xa399e
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
lea	esi, [rsi - 1]
movzx	eax, byte ptr [rsi]
xor	al, bl
dec	al
stc	
cmc	
rol	al, 1
cmc	
add	al, 0xf8
jmp	0x41623
not	al
jmp	0x5974d
inc	al
neg	al
xor	bl, al
test	bp, 0x50aa
mov	eax, dword ptr [rsp + rax]
lea	ebp, [rbp - 4]
cmc	
mov	dword ptr [rbp], eax
test	ch, 0x5a
movsx	ax, al
adc	al, 0x50
lea	esi, [rsi - 4]
sar	eax, cl
cmc	
mov	eax, dword ptr [rsi]
jmp	0x49d32
xor	eax, ebx
test	dl, 0xb2
cmp	di, 0x75c1
cmp	al, bh
add	eax, 0x3e547e5
rol	eax, 2
jmp	0x8b14b
cmc	
clc	
not	eax
test	di, ax
stc	
xor	ebx, eax
clc	
jmp	0x92270
add	edi, eax
jmp	0x9eb50
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
sub	esi, 1
or	ah, al
ror	eax, cl
movzx	eax, byte ptr [rsi]
cmp	si, 0x7327
test	cx, sp
xor	al, bl
jmp	0x6f86c
dec	al
rol	al, 1
jmp	0x9645d
add	al, 0xf8
not	al
jmp	0xae444
inc	al
test	di, bp
neg	al
xor	bl, al
test	edx, esi
test	ah, 0xf2
cmp	bp, 0x263
mov	eax, dword ptr [rsp + rax]
test	di, bp
test	sp, 0x66f3
lea	ebp, [rbp - 4]
mov	dword ptr [rbp], eax
lea	esi, [rsi - 4]
mov	eax, dword ptr [rsi]
xor	eax, ebx
cmc	
test	si, dx
add	eax, 0x3e547e5
cmc	
jmp	0x55e12
rol	eax, 2
cmp	ebp, 0x45490fc6
not	eax
stc	
cmc	
xor	ebx, eax
add	edi, eax
jmp	0x90bbc
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
sub	esi, 1
btr	ax, -0x52
movzx	eax, byte ptr [rsi]
test	ax, 0x3d8a
test	ebx, edi
jmp	0x93b85
xor	al, bl
dec	al
clc	
rol	al, 1
cmp	si, bp
add	al, 0xf8
jmp	0xa8565
not	al
jmp	0x826a0
inc	al
test	esp, edx
neg	al
xor	bl, al
test	esp, esi
test	al, 0x58
mov	eax, dword ptr [rsp + rax]
test	bx, sp
clc	
lea	ebp, [rbp - 4]
mov	dword ptr [rbp], eax
bt	eax, edx
rcr	eax, cl
sbb	al, 0x53
lea	esi, [rsi - 4]
sbb	ax, bx
ror	ax, cl
mov	eax, dword ptr [rsi]
test	bh, 0x3a
xor	eax, ebx
add	eax, 0x3e547e5
clc	
rol	eax, 2
jmp	0x7bee2
not	eax
cmp	sp, bp
xor	ebx, eax
add	edi, eax
jmp	0x3c41c
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
sub	esi, 1
movzx	eax, byte ptr [rsi]
cmc	
clc	
xor	al, bl
dec	al
clc	
jmp	0x4e343
rol	al, 1
test	esp, 0x32734b47
cmp	dx, sp
add	al, 0xf8
jmp	0x5d5e3
not	al
inc	al
cmp	ebx, edi
test	si, 0x380a
test	bp, cx
neg	al
stc	
clc	
xor	bl, al
mov	eax, dword ptr [rsp + rax]
test	esp, 0x42f953bf
lea	ebp, [rbp - 4]
mov	dword ptr [rbp], eax
lea	esi, [rsi - 4]
sub	eax, 0x183274f4
mov	eax, dword ptr [rsi]
xor	eax, ebx
add	eax, 0x3e547e5
stc	
clc	
jmp	0x680be
rol	eax, 2
cmc	
cmp	esp, ebp
not	eax
test	bx, si
cmp	dh, 0x20
xor	ebx, eax
test	ah, 0x74
add	edi, eax
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
lea	esi, [rsi - 1]
adc	eax, 0x707185
cmp	al, cl
movzx	eax, byte ptr [rsi]
cmc	
cmp	eax, esp
xor	al, bl
jmp	0x90e53
dec	al
rol	al, 1
add	al, 0xf8
jmp	0x8249b
not	al
jmp	0xa44ad
inc	al
stc	
neg	al
cmp	sp, sp
xor	bl, al
mov	eax, dword ptr [rsp + rax]
sub	ebp, 4
test	cx, 0x4e28
mov	dword ptr [rbp], eax
bts	eax, ebp
sub	esi, 4
btc	eax, edi
bsf	eax, edi
cwde	
mov	eax, dword ptr [rsi]
stc	
cmp	eax, eax
xor	eax, ebx
add	eax, 0x3e547e5
cmc	
stc	
clc	
rol	eax, 2
jmp	0x54cf5
not	eax
xor	ebx, eax
cmc	
stc	
add	edi, eax
jmp	0x49acd
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
sub	esi, 1
movzx	eax, byte ptr [rsi]
xor	al, bl
jmp	0x7b131
dec	al
rol	al, 1
add	al, 0xf8
jmp	0xad8b7
not	al
jmp	0xa7643
inc	al
stc	
jmp	0xb04a8
neg	al
cmc	
test	cx, cx
xor	bl, al
test	ebp, 0xd37746b
mov	eax, dword ptr [rsp + rax]
sub	ebp, 4
jmp	0xa5109
mov	dword ptr [rbp], eax
sar	ax, -9
sub	esi, 4
sar	ah, cl
bswap	ax
mov	eax, dword ptr [rsi]
test	ah, 0xa7
xor	eax, ebx
cmp	sp, cx
add	eax, 0x3e547e5
stc	
rol	eax, 2
not	eax
cmp	si, sp
cmp	dh, 0xab
xor	ebx, eax
add	edi, eax
jmp	0xa72c0
jmp	0x52dc7
lea	eax, [rsp + 0x60]
test	dx, 0x28db
cmp	ebp, eax
jmp	0x6b429
ja	0x3b9e9
jmp	rdi
mov	esp, ebp
btr	si, 0x12
movzx	ecx, bp
rcl	si, 0x18
pop	rdx
sub	di, dx
btc	ax, 0x34
pop	rax
or	di, 0x7ae3
btr	edi, 0x79
pop	rbx
cmp	edi, 0x5e0b7af5
rcl	cx, -0x79
sar	ch, cl
pop	rdi
sub	ch, 0xd6
add	esi, 0x680d2d61
pop	rbp
pop	rcx
btr	si, bp
pop	rsi
popfq	
ret	
mov	eax, dword ptr [rbp + 8]
cmp	esi, eax
