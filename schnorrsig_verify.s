	.globl	secp256k1_schnorrsig_verify
	.type	secp256k1_schnorrsig_verify, @function
secp256k1_schnorrsig_verify:
.LFB340:
	.cfi_startproc
	endbr64
	pushq	%r15
	.cfi_def_cfa_offset 16
	.cfi_offset 15, -16
	pushq	%r14
	.cfi_def_cfa_offset 24
	.cfi_offset 14, -24
	movq	%rdi, %r14
	pushq	%r13
	.cfi_def_cfa_offset 32
	.cfi_offset 13, -32
	pushq	%r12
	.cfi_def_cfa_offset 40
	.cfi_offset 12, -40
	pushq	%rbp
	.cfi_def_cfa_offset 48
	.cfi_offset 6, -48
	pushq	%rbx
	.cfi_def_cfa_offset 56
	.cfi_offset 3, -56
	subq	$2696, %rsp
	.cfi_def_cfa_offset 2752
	movq	%fs:40, %rax
	movq	%rax, 2680(%rsp)
	xorl	%eax, %eax
	testq	%rsi, %rsi
	je	.L1384
	movq	%rsi, %rbp
	movq	%rdx, %r12
	movq	%rcx, %r15
	movq	%r8, %r13
	testq	%rdx, %rdx
	jne	.L1362
	testq	%rcx, %rcx
	jne	.L1385
.L1362:
	testq	%r13, %r13
	je	.L1386
	leaq	176(%rsp), %rdi
	movq	%rbp, %rsi
	call	secp256k1_fe_impl_set_b32_mod
	movq	200(%rsp), %r9
	movq	192(%rsp), %r10
	movabsq	$4503599627370495, %rdx
	movq	184(%rsp), %r11
	movq	208(%rsp), %rbx
	movq	%r9, %rax
	movq	176(%rsp), %rcx
	andq	%r10, %rax
	movq	%rbx, 8(%rsp)
	andq	%r11, %rax
	movq	%rcx, 16(%rsp)
	cmpq	%rdx, %rax
	jne	.L1364
	movabsq	$281474976710655, %rax
	cmpq	%rax, %rbx
	movabsq	$4503595332402222, %rax
	sete	%dl
	cmpq	%rax, %rcx
	seta	%al
	testb	%al, %dl
	je	.L1364
.L1365:
	xorl	%ebx, %ebx
.L1359:
	movq	2680(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L1387
	addq	$2696, %rsp
	.cfi_remember_state
	.cfi_def_cfa_offset 56
	movl	%ebx, %eax
	popq	%rbx
	.cfi_def_cfa_offset 48
	popq	%rbp
	.cfi_def_cfa_offset 40
	popq	%r12
	.cfi_def_cfa_offset 32
	popq	%r13
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	ret
	.p2align 4,,10
	.p2align 3
.L1364:
	.cfi_restore_state
	leaq	112(%rsp), %rax
	leaq	76(%rsp), %rdx
	movq	%r11, 48(%rsp)
	leaq	32(%rbp), %rsi
	movq	%rax, %rdi
	movq	%r10, 40(%rsp)
	movq	%r9, 32(%rsp)
	movq	%rax, 24(%rsp)
	call	secp256k1_scalar_set_b32
	movl	76(%rsp), %ebx
	testl	%ebx, %ebx
	jne	.L1365
	leaq	224(%rsp), %rsi
	movq	%r13, %rdx
	movq	%r14, %rdi
	movq	%rsi, 56(%rsp)
	call	secp256k1_pubkey_load
	testl	%eax, %eax
	je	.L1365
	leaq	2640(%rsp), %r8
	movq	56(%rsp), %rsi
	movq	%r12, %rdx
	leaq	144(%rsp), %r14
	movq	%r8, %rdi
	leaq	576(%rsp), %r13
	leaq	1600(%rsp), %r12
	call	secp256k1_fe_impl_get_b32
	movq	%r15, %rcx
	movq	%rbp, %rsi
	movq	%r14, %rdi
	call	secp256k1_schnorrsig_challenge
	movq	%r14, %rsi
	movq	%r14, %rdi
	leaq	896(%rsp), %rbp
	call	secp256k1_scalar_negate
	movl	304(%rsp), %edx
	movq	24(%rsp), %r8
	movq	%r14, %rcx
	movdqa	224(%rsp), %xmm0
	leaq	80(%rsp), %rdi
	movdqa	240(%rsp), %xmm1
	leaq	320(%rsp), %rsi
	movl	%edx, 568(%rsp)
	movq	%rsi, %r14
	movq	256(%rsp), %rdx
	movdqu	264(%rsp), %xmm2
	movdqu	280(%rsp), %xmm3
	movq	$1, 528(%rsp)
	movq	%rdx, 480(%rsp)
	movq	296(%rsp), %rdx
	movq	$0, 560(%rsp)
	movq	%rdx, 520(%rsp)
	leaq	448(%rsp), %rdx
	movq	$0, 552(%rsp)
	movq	$0, 544(%rsp)
	movq	$0, 536(%rsp)
	movq	%r13, 80(%rsp)
	movq	%rbp, 88(%rsp)
	movq	%r12, 96(%rsp)
	movaps	%xmm0, 448(%rsp)
	movaps	%xmm1, 464(%rsp)
	movups	%xmm2, 488(%rsp)
	movups	%xmm3, 504(%rsp)
	call	secp256k1_ecmult_strauss_wnaf.constprop.0
	movl	440(%rsp), %eax
	testl	%eax, %eax
	jne	.L1359
	movq	432(%rsp), %rax
	movq	%rbp, %rdi
	leaq	400(%rsp), %r15
	movdqa	400(%rsp), %xmm4
	movdqa	416(%rsp), %xmm5
	movq	%rax, 928(%rsp)
	movaps	%xmm4, 896(%rsp)
	movaps	%xmm5, 912(%rsp)
	call	secp256k1_fe_impl_normalize_var
	movq	%r12, %rdi
	movq	%rbp, %rsi
	call	secp256k1_fe_to_signed62
	leaq	secp256k1_const_modinfo_fe(%rip), %rsi
	call	secp256k1_modinv64_var
	movq	%r12, %rsi
	movq	%r15, %rdi
	call	secp256k1_fe_from_signed62
	movq	%r15, %rsi
	movq	%r13, %rdi
	call	secp256k1_fe_sqr_inner
	movq	%r13, %rdx
	movq	%r15, %rsi
	movq	%rbp, %rdi
	call	secp256k1_fe_mul_inner
	movq	%r13, %rdx
	movq	%r14, %rsi
	movq	%r14, %rdi
	call	secp256k1_fe_mul_inner
	leaq	360(%rsp), %rdi
	movq	%rbp, %rdx
	movq	%rdi, %rsi
	call	secp256k1_fe_mul_inner
	movq	352(%rsp), %rax
	movdqa	320(%rsp), %xmm6
	leaq	1640(%rsp), %rdi
	movdqa	336(%rsp), %xmm7
	movdqu	360(%rsp), %xmm4
	movq	$1, 400(%rsp)
	movq	%rax, 1632(%rsp)
	movdqu	376(%rsp), %xmm5
	movq	392(%rsp), %rax
	movq	$0, 432(%rsp)
	movq	$0, 424(%rsp)
	movq	$0, 416(%rsp)
	movq	$0, 408(%rsp)
	movl	$0, 1680(%rsp)
	movq	%rax, 1672(%rsp)
	movaps	%xmm6, 1600(%rsp)
	movaps	%xmm7, 1616(%rsp)
	movups	%xmm4, 1640(%rsp)
	movups	%xmm5, 1656(%rsp)
	call	secp256k1_fe_impl_normalize_var
	movq	32(%rsp), %r9
	movq	40(%rsp), %r10
	testb	$1, 1640(%rsp)
	movq	48(%rsp), %r11
	jne	.L1365
	movq	1608(%rsp), %rdx
	movq	%rbp, %rdi
	xorl	%ebx, %ebx
	movabsq	$18014381329608892, %rax
	addq	1600(%rsp), %rax
	subq	16(%rsp), %rax
	movq	%rax, 896(%rsp)
	movabsq	$18014398509481980, %rax
	addq	%rax, %rdx
	subq	%r11, %rdx
	movq	%rdx, 904(%rsp)
	movq	1616(%rsp), %rdx
	addq	%rax, %rdx
	addq	1624(%rsp), %rax
	subq	%r9, %rax
	subq	%r10, %rdx
	movq	%rax, 920(%rsp)
	movabsq	$1125899906842620, %rax
	addq	1632(%rsp), %rax
	subq	8(%rsp), %rax
	movq	%rdx, 912(%rsp)
	movq	%rax, 928(%rsp)
	call	secp256k1_fe_impl_normalizes_to_zero
	testl	%eax, %eax
	setne	%bl
	jmp	.L1359
	.p2align 4,,10
	.p2align 3
.L1385:
	movq	176(%rdi), %rsi
	xorl	%ebx, %ebx
	leaq	.LC7(%rip), %rdi
	call	*168(%r14)
	jmp	.L1359
	.p2align 4,,10
	.p2align 3
.L1384:
	movq	176(%rdi), %rsi
	xorl	%ebx, %ebx
	leaq	.LC6(%rip), %rdi
	call	*168(%r14)
	jmp	.L1359
	.p2align 4,,10
	.p2align 3
.L1386:
	movq	176(%r14), %rsi
	leaq	.LC18(%rip), %rdi
	xorl	%ebx, %ebx
	call	*168(%r14)
	jmp	.L1359
.L1387:
	call	__stack_chk_fail@PLT
	.cfi_endproc
.LFE340:
	.size	secp256k1_schnorrsig_verify, .-secp256k1_schnorrsig_verify
