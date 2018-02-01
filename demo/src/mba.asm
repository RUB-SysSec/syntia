mov	eax, dword ptr [rbp - 0x14]
imul	eax, eax, 0x55be239b
add	eax, 0x5c99a1a9
mov	edi, eax
mov	eax, dword ptr [rbp - 0x10]
imul	eax, eax, 0x55be239b
add	eax, 0x5c99a1a9
mov	ecx, eax
mov	eax, dword ptr [rbp - 0xc]
imul	eax, eax, 0x55be239b
add	eax, 0x5c99a1a9
mov	edx, eax
mov	eax, dword ptr [rbp - 8]
imul	eax, eax, 0x55be239b
add	eax, 0x5c99a1a9
mov	esi, eax
mov	eax, dword ptr [rbp - 4]
imul	eax, eax, 0x55be239b
add	eax, 0x5c99a1a9
mov	r8d, edi
mov	edi, eax
call	0xffffffffffffddce
push	rbp
mov	rbp, rsp
mov	dword ptr [rbp - 0x14], edi
mov	dword ptr [rbp - 0x18], esi
mov	dword ptr [rbp - 0x1c], edx
mov	dword ptr [rbp - 0x20], ecx
mov	dword ptr [rbp - 0x24], r8d
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0xa7e08a93
mov	edx, 0xb03cee0a
sub	edx, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0xa7e08a93
add	eax, 0x4fc311f5
or	eax, edx
imul	edx, eax, 0x55be239b
mov	eax, dword ptr [rbp - 0x24]
add	eax, edx
imul	eax, eax, 0xa7e08a93
lea	ecx, [rax + 1]
mov	edx, dword ptr [rbp - 0x1c]
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0xa7e08a93
mov	esi, 0xb03cee0a
sub	esi, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0xa7e08a93
add	eax, 0x4fc311f5
or	eax, esi
imul	eax, eax, 0x55be239b
sub	edx, eax
mov	eax, edx
sub	eax, 0x55be239b
imul	ecx, eax
mov	edx, ecx
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0xa7e08a93
mov	ecx, 0xb03cee0a
sub	ecx, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0xa7e08a93
add	eax, 0x4fc311f5
or	eax, ecx
imul	ecx, eax, 0x55be239b
mov	eax, dword ptr [rbp - 0x24]
add	eax, ecx
imul	eax, eax, 0xb03cee0b
mov	ecx, edx
sub	ecx, eax
mov	edx, dword ptr [rbp - 0x1c]
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0xa7e08a93
mov	esi, 0xb03cee0a
sub	esi, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0xa7e08a93
add	eax, 0x4fc311f5
or	eax, esi
imul	eax, eax, 0x55be239b
sub	edx, eax
mov	eax, edx
imul	eax, eax, 0xb03cee0b
mov	esi, ecx
sub	esi, eax
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0xa7e08a93
mov	edx, 0xb03cee0a
sub	edx, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0x581f756d
sub	eax, 0x4fc311f6
or	eax, edx
imul	edx, eax, 0x55be239b
mov	eax, dword ptr [rbp - 0x24]
add	eax, edx
imul	eax, eax, 0xa7e08a93
lea	ecx, [rax + 1]
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0x581f756d
mov	edx, 0x4fc311f5
sub	edx, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0xa7e08a93
add	eax, 0x4fc311f5
or	eax, edx
imul	edx, eax, 0x55be239b
mov	eax, dword ptr [rbp - 0x24]
sub	edx, eax
mov	eax, edx
sub	eax, 0x46ccbcae
imul	ecx, eax
mov	edx, ecx
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0xa7e08a93
mov	ecx, 0xb03cee0a
sub	ecx, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0x581f756d
sub	eax, 0x4fc311f6
or	eax, ecx
imul	ecx, eax, 0x55be239b
mov	eax, dword ptr [rbp - 0x24]
add	eax, ecx
imul	eax, eax, 0xb03cee0b
mov	ecx, edx
sub	ecx, eax
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0x581f756d
mov	edx, 0x4fc311f5
sub	edx, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0xa7e08a93
add	eax, 0x4fc311f5
or	eax, edx
imul	edx, eax, 0x55be239b
mov	eax, dword ptr [rbp - 0x24]
sub	edx, eax
mov	eax, edx
imul	eax, eax, 0xb03cee0b
sub	ecx, eax
mov	eax, ecx
add	esi, eax
mov	eax, dword ptr [rbp - 0x14]
imul	eax, eax, 0xa7e08a93
mov	edx, 0xb03cee0a
mov	edi, edx
sub	edi, eax
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0xa7e08a93
mov	edx, 0xb03cee0a
sub	edx, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0xa7e08a93
add	eax, 0x4fc311f5
or	eax, edx
imul	edx, eax, 0x55be239b
mov	eax, dword ptr [rbp - 0x24]
add	eax, edx
imul	eax, eax, 0xa7e08a93
lea	ecx, [rax + 1]
mov	edx, dword ptr [rbp - 0x1c]
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0xa7e08a93
mov	r8d, 0xb03cee0a
sub	r8d, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0xa7e08a93
add	eax, 0x4fc311f5
or	eax, r8d
imul	eax, eax, 0x55be239b
sub	edx, eax
mov	eax, edx
sub	eax, 0x55be239b
imul	ecx, eax
mov	edx, ecx
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0xa7e08a93
mov	ecx, 0xb03cee0a
sub	ecx, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0xa7e08a93
add	eax, 0x4fc311f5
or	eax, ecx
imul	ecx, eax, 0x55be239b
mov	eax, dword ptr [rbp - 0x24]
add	eax, ecx
imul	eax, eax, 0xb03cee0b
mov	ecx, edx
sub	ecx, eax
mov	edx, dword ptr [rbp - 0x1c]
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0xa7e08a93
mov	r8d, 0xb03cee0a
sub	r8d, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0xa7e08a93
add	eax, 0x4fc311f5
or	eax, r8d
imul	eax, eax, 0x55be239b
sub	edx, eax
mov	eax, edx
imul	eax, eax, 0xb03cee0b
sub	ecx, eax
mov	r8d, ecx
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0xa7e08a93
mov	edx, 0xb03cee0a
sub	edx, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0x581f756d
sub	eax, 0x4fc311f6
or	eax, edx
imul	edx, eax, 0x55be239b
mov	eax, dword ptr [rbp - 0x24]
add	eax, edx
imul	eax, eax, 0xa7e08a93
lea	ecx, [rax + 1]
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0x581f756d
mov	edx, 0x4fc311f5
sub	edx, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0xa7e08a93
add	eax, 0x4fc311f5
or	eax, edx
imul	edx, eax, 0x55be239b
mov	eax, dword ptr [rbp - 0x24]
sub	edx, eax
mov	eax, edx
sub	eax, 0x46ccbcae
imul	ecx, eax
mov	edx, ecx
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0xa7e08a93
mov	ecx, 0xb03cee0a
sub	ecx, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0x581f756d
sub	eax, 0x4fc311f6
or	eax, ecx
imul	ecx, eax, 0x55be239b
mov	eax, dword ptr [rbp - 0x24]
add	eax, ecx
imul	eax, eax, 0xb03cee0b
mov	ecx, edx
sub	ecx, eax
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0x581f756d
mov	edx, 0x4fc311f5
sub	edx, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0xa7e08a93
add	eax, 0x4fc311f5
or	eax, edx
imul	edx, eax, 0x55be239b
mov	eax, dword ptr [rbp - 0x24]
sub	edx, eax
mov	eax, edx
imul	eax, eax, 0xb03cee0b
sub	ecx, eax
mov	eax, ecx
add	eax, r8d
imul	eax, eax, 0xa7e08a93
add	eax, 0x4fc311f5
or	eax, edi
imul	eax, eax, 0x55be239b
sub	esi, eax
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0xa7e08a93
mov	edx, 0xb03cee0a
sub	edx, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0xa7e08a93
add	eax, 0x4fc311f5
or	eax, edx
imul	edx, eax, 0x55be239b
mov	eax, dword ptr [rbp - 0x24]
add	eax, edx
imul	eax, eax, 0xa7e08a93
lea	ecx, [rax + 1]
mov	edx, dword ptr [rbp - 0x1c]
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0xa7e08a93
mov	edi, 0xb03cee0a
sub	edi, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0xa7e08a93
add	eax, 0x4fc311f5
or	eax, edi
imul	eax, eax, 0x55be239b
sub	edx, eax
mov	eax, edx
sub	eax, 0x55be239b
imul	ecx, eax
mov	edx, ecx
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0xa7e08a93
mov	ecx, 0xb03cee0a
sub	ecx, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0xa7e08a93
add	eax, 0x4fc311f5
or	eax, ecx
imul	ecx, eax, 0x55be239b
mov	eax, dword ptr [rbp - 0x24]
add	eax, ecx
imul	eax, eax, 0xb03cee0b
mov	ecx, edx
sub	ecx, eax
mov	edx, dword ptr [rbp - 0x1c]
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0xa7e08a93
mov	edi, 0xb03cee0a
sub	edi, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0xa7e08a93
add	eax, 0x4fc311f5
or	eax, edi
imul	eax, eax, 0x55be239b
sub	edx, eax
mov	eax, edx
imul	eax, eax, 0xb03cee0b
mov	edi, ecx
sub	edi, eax
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0xa7e08a93
mov	edx, 0xb03cee0a
sub	edx, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0x581f756d
sub	eax, 0x4fc311f6
or	eax, edx
imul	edx, eax, 0x55be239b
mov	eax, dword ptr [rbp - 0x24]
add	eax, edx
imul	eax, eax, 0xa7e08a93
lea	ecx, [rax + 1]
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0x581f756d
mov	edx, 0x4fc311f5
sub	edx, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0xa7e08a93
add	eax, 0x4fc311f5
or	eax, edx
imul	edx, eax, 0x55be239b
mov	eax, dword ptr [rbp - 0x24]
sub	edx, eax
mov	eax, edx
sub	eax, 0x46ccbcae
imul	ecx, eax
mov	edx, ecx
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0xa7e08a93
mov	ecx, 0xb03cee0a
sub	ecx, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0x581f756d
sub	eax, 0x4fc311f6
or	eax, ecx
imul	ecx, eax, 0x55be239b
mov	eax, dword ptr [rbp - 0x24]
add	eax, ecx
imul	eax, eax, 0xb03cee0b
mov	ecx, edx
sub	ecx, eax
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0x581f756d
mov	edx, 0x4fc311f5
sub	edx, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0xa7e08a93
add	eax, 0x4fc311f5
or	eax, edx
imul	edx, eax, 0x55be239b
mov	eax, dword ptr [rbp - 0x24]
sub	edx, eax
mov	eax, edx
imul	eax, eax, 0xb03cee0b
sub	ecx, eax
mov	eax, ecx
add	edi, eax
mov	eax, dword ptr [rbp - 0x14]
imul	eax, eax, 0xa7e08a93
mov	edx, 0xb03cee0a
sub	edx, eax
mov	r8d, edx
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0xa7e08a93
mov	edx, 0xb03cee0a
sub	edx, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0xa7e08a93
add	eax, 0x4fc311f5
or	eax, edx
imul	edx, eax, 0x55be239b
mov	eax, dword ptr [rbp - 0x24]
add	eax, edx
imul	eax, eax, 0xa7e08a93
lea	ecx, [rax + 1]
mov	edx, dword ptr [rbp - 0x1c]
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0xa7e08a93
mov	r9d, 0xb03cee0a
sub	r9d, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0xa7e08a93
add	eax, 0x4fc311f5
or	eax, r9d
imul	eax, eax, 0x55be239b
sub	edx, eax
mov	eax, edx
sub	eax, 0x55be239b
imul	ecx, eax
mov	edx, ecx
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0xa7e08a93
mov	ecx, 0xb03cee0a
sub	ecx, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0xa7e08a93
add	eax, 0x4fc311f5
or	eax, ecx
imul	ecx, eax, 0x55be239b
mov	eax, dword ptr [rbp - 0x24]
add	eax, ecx
imul	eax, eax, 0xb03cee0b
mov	ecx, edx
sub	ecx, eax
mov	edx, dword ptr [rbp - 0x1c]
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0xa7e08a93
mov	r9d, 0xb03cee0a
sub	r9d, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0xa7e08a93
add	eax, 0x4fc311f5
or	eax, r9d
imul	eax, eax, 0x55be239b
sub	edx, eax
mov	eax, edx
imul	eax, eax, 0xb03cee0b
sub	ecx, eax
mov	r9d, ecx
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0xa7e08a93
mov	edx, 0xb03cee0a
sub	edx, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0x581f756d
sub	eax, 0x4fc311f6
or	eax, edx
imul	edx, eax, 0x55be239b
mov	eax, dword ptr [rbp - 0x24]
add	eax, edx
imul	eax, eax, 0xa7e08a93
lea	ecx, [rax + 1]
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0x581f756d
mov	edx, 0x4fc311f5
sub	edx, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0xa7e08a93
add	eax, 0x4fc311f5
or	eax, edx
imul	edx, eax, 0x55be239b
mov	eax, dword ptr [rbp - 0x24]
sub	edx, eax
mov	eax, edx
sub	eax, 0x46ccbcae
imul	ecx, eax
mov	edx, ecx
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0xa7e08a93
mov	ecx, 0xb03cee0a
sub	ecx, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0x581f756d
sub	eax, 0x4fc311f6
or	eax, ecx
imul	ecx, eax, 0x55be239b
mov	eax, dword ptr [rbp - 0x24]
add	eax, ecx
imul	eax, eax, 0xb03cee0b
mov	ecx, edx
sub	ecx, eax
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0x581f756d
mov	edx, 0x4fc311f5
sub	edx, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0xa7e08a93
add	eax, 0x4fc311f5
or	eax, edx
imul	edx, eax, 0x55be239b
mov	eax, dword ptr [rbp - 0x24]
sub	edx, eax
mov	eax, edx
imul	eax, eax, 0xb03cee0b
sub	ecx, eax
mov	eax, ecx
add	eax, r9d
imul	eax, eax, 0xa7e08a93
add	eax, 0x4fc311f5
or	eax, r8d
imul	eax, eax, 0x55be239b
sub	edi, eax
mov	eax, edi
lea	edi, [rsi + rax]
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0x581f756d
mov	edx, 0x4fc311f5
sub	edx, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0xa7e08a93
add	eax, 0x4fc311f5
or	eax, edx
imul	edx, eax, 0x55be239b
mov	eax, dword ptr [rbp - 0x24]
sub	edx, eax
mov	eax, edx
imul	eax, eax, 0xb03cee0b
mov	edx, dword ptr [rbp - 0x24]
imul	edx, edx, 0xa7e08a93
mov	ecx, 0xb03cee0a
sub	ecx, edx
mov	edx, dword ptr [rbp - 0x1c]
imul	edx, edx, 0x581f756d
sub	edx, 0x4fc311f6
or	edx, ecx
imul	ecx, edx, 0x55be239b
mov	edx, dword ptr [rbp - 0x24]
add	edx, ecx
imul	ecx, edx, 0xb03cee0b
mov	edx, dword ptr [rbp - 0x24]
imul	edx, edx, 0xa7e08a93
mov	esi, 0xb03cee0a
sub	esi, edx
mov	edx, dword ptr [rbp - 0x1c]
imul	edx, edx, 0x581f756d
sub	edx, 0x4fc311f6
or	edx, esi
imul	esi, edx, 0x55be239b
mov	edx, dword ptr [rbp - 0x24]
add	edx, esi
imul	edx, edx, 0xa7e08a93
lea	r8d, [rdx + 1]
mov	edx, dword ptr [rbp - 0x24]
imul	edx, edx, 0x581f756d
mov	esi, 0x4fc311f5
sub	esi, edx
mov	edx, dword ptr [rbp - 0x1c]
imul	edx, edx, 0xa7e08a93
add	edx, 0x4fc311f5
or	edx, esi
imul	esi, edx, 0x55be239b
mov	edx, dword ptr [rbp - 0x24]
sub	esi, edx
mov	edx, esi
sub	edx, 0x46ccbcae
imul	edx, r8d
sub	ecx, edx
mov	edx, ecx
lea	r8d, [rax + rdx]
mov	edx, dword ptr [rbp - 0x1c]
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0xa7e08a93
mov	ecx, 0xb03cee0a
sub	ecx, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0xa7e08a93
add	eax, 0x4fc311f5
or	eax, ecx
imul	eax, eax, 0x55be239b
sub	edx, eax
mov	eax, edx
imul	eax, eax, 0xb03cee0b
mov	edx, dword ptr [rbp - 0x24]
imul	edx, edx, 0xa7e08a93
mov	ecx, 0xb03cee0a
sub	ecx, edx
mov	edx, dword ptr [rbp - 0x1c]
imul	edx, edx, 0xa7e08a93
add	edx, 0x4fc311f5
or	edx, ecx
imul	ecx, edx, 0x55be239b
mov	edx, dword ptr [rbp - 0x24]
add	edx, ecx
imul	ecx, edx, 0xb03cee0b
mov	edx, dword ptr [rbp - 0x24]
imul	edx, edx, 0xa7e08a93
mov	esi, 0xb03cee0a
sub	esi, edx
mov	edx, dword ptr [rbp - 0x1c]
imul	edx, edx, 0xa7e08a93
add	edx, 0x4fc311f5
or	edx, esi
imul	esi, edx, 0x55be239b
mov	edx, dword ptr [rbp - 0x24]
add	edx, esi
imul	edx, edx, 0xa7e08a93
lea	r9d, [rdx + 1]
mov	esi, dword ptr [rbp - 0x1c]
mov	edx, dword ptr [rbp - 0x24]
imul	edx, edx, 0xa7e08a93
mov	r10d, 0xb03cee0a
sub	r10d, edx
mov	edx, dword ptr [rbp - 0x1c]
imul	edx, edx, 0xa7e08a93
add	edx, 0x4fc311f5
or	edx, r10d
imul	edx, edx, 0x55be239b
sub	esi, edx
mov	edx, esi
sub	edx, 0x55be239b
imul	edx, r9d
sub	ecx, edx
mov	edx, ecx
add	eax, edx
lea	edx, [r8 + rax]
mov	eax, dword ptr [rbp - 0x14]
mov	esi, edx
sub	esi, eax
mov	eax, dword ptr [rbp - 0x14]
imul	eax, eax, 0xb03eeada
lea	r8d, [rax + 0x6079dc15]
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0xa7e08a93
mov	edx, 0xb03cee0a
sub	edx, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0xa7e08a93
add	eax, 0x4fc311f5
or	eax, edx
imul	edx, eax, 0x55be239b
mov	eax, dword ptr [rbp - 0x24]
add	eax, edx
imul	eax, eax, 0xa7e08a93
lea	ecx, [rax + 1]
mov	edx, dword ptr [rbp - 0x1c]
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0xa7e08a93
mov	r9d, 0xb03cee0a
sub	r9d, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0xa7e08a93
add	eax, 0x4fc311f5
or	eax, r9d
imul	eax, eax, 0x55be239b
sub	edx, eax
mov	eax, edx
sub	eax, 0x55be239b
imul	ecx, eax
mov	edx, ecx
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0xa7e08a93
mov	ecx, 0xb03cee0a
sub	ecx, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0xa7e08a93
add	eax, 0x4fc311f5
or	eax, ecx
imul	ecx, eax, 0x55be239b
mov	eax, dword ptr [rbp - 0x24]
add	eax, ecx
imul	eax, eax, 0xb03cee0b
mov	ecx, edx
sub	ecx, eax
mov	edx, dword ptr [rbp - 0x1c]
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0xa7e08a93
mov	r9d, 0xb03cee0a
sub	r9d, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0xa7e08a93
add	eax, 0x4fc311f5
or	eax, r9d
imul	eax, eax, 0x55be239b
sub	edx, eax
mov	eax, edx
imul	eax, eax, 0xb03cee0b
sub	ecx, eax
mov	r9d, ecx
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0xa7e08a93
mov	edx, 0xb03cee0a
sub	edx, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0x581f756d
sub	eax, 0x4fc311f6
or	eax, edx
imul	edx, eax, 0x55be239b
mov	eax, dword ptr [rbp - 0x24]
add	eax, edx
imul	eax, eax, 0xa7e08a93
lea	ecx, [rax + 1]
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0x581f756d
mov	edx, 0x4fc311f5
sub	edx, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0xa7e08a93
add	eax, 0x4fc311f5
or	eax, edx
imul	edx, eax, 0x55be239b
mov	eax, dword ptr [rbp - 0x24]
sub	edx, eax
mov	eax, edx
sub	eax, 0x46ccbcae
imul	ecx, eax
mov	edx, ecx
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0xa7e08a93
mov	ecx, 0xb03cee0a
sub	ecx, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0x581f756d
sub	eax, 0x4fc311f6
or	eax, ecx
imul	ecx, eax, 0x55be239b
mov	eax, dword ptr [rbp - 0x24]
add	eax, ecx
imul	eax, eax, 0xb03cee0b
mov	ecx, edx
sub	ecx, eax
mov	eax, dword ptr [rbp - 0x24]
imul	eax, eax, 0x581f756d
mov	edx, 0x4fc311f5
sub	edx, eax
mov	eax, dword ptr [rbp - 0x1c]
imul	eax, eax, 0xa7e08a93
add	eax, 0x4fc311f5
or	eax, edx
imul	edx, eax, 0x55be239b
mov	eax, dword ptr [rbp - 0x24]
sub	edx, eax
mov	eax, edx
imul	eax, eax, 0xb03cee0b
sub	ecx, eax
mov	eax, ecx
add	eax, r9d
imul	eax, eax, 0xb03eeada
add	eax, 0x6079dc15
or	eax, r8d
imul	eax, eax, 0x55be239b
sub	esi, eax
mov	eax, esi
add	eax, edi
add	eax, 0x5b5f36d8
mov	dword ptr [rbp - 4], eax
mov	eax, dword ptr [rbp - 4]
imul	eax, eax, 0xa7e08a93
add	eax, 0x4fc311f5
pop	rbp
ret	
