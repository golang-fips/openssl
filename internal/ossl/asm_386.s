// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !cgo

#include "go_asm.h"
#include "textflag.h"

TEXT ·syscallNSystemStack_trampoline(SB),NOSPLIT,$16-0
	MOVL	20(SP), AX	// libcArgs from C caller (frame_size + ret_addr = 16 + 4)
	MOVL	AX, 0(SP)	// pass to Go function
	CALL	·syscallNSystemStack(SB)
	RET

TEXT ·syscallNAsm(SB),NOSPLIT,$16-4
	// Frame layout: 16 bytes local storage
	// 0(SP) - saved BP (original SP)
	// 4(SP) - saved libcArgs pointer
	// 8(SP) - saved fn pointer
	// 12(SP) - scratch

	// Load args pointer FIRST before any stack modifications
	MOVL	libcArgs+0(FP), SI

	// Save original SP and libcArgs in local frame
	MOVL	SP, BP
	ADDL	$16, BP			// BP = original SP (before frame allocation)
	MOVL	BP, 0(SP)		// save original SP
	MOVL	SI, 4(SP)		// save libcArgs pointer

	// Load struct fields
	MOVL	libcCallInfo_fn(SI), AX
	MOVL	AX, 8(SP)		// save fn pointer
	MOVL	libcCallInfo_n(SI), CX
	MOVL	libcCallInfo_args(SI), BX

	// Allocate 16 bytes for fast path (0-3 args)
	MOVL	SP, BP
	SUBL	$16, SP

	// Fast path for 0-3 args, otherwise fall through to manyargs
	CMPL	CX, $0;	JE	_0args
	CMPL	CX, $1;	JE	_1args
	CMPL	CX, $2;	JE	_2args
	CMPL	CX, $3;	JE	_3args

	// manyargs: 4+ args, restore SP and reallocate
	MOVL	BP, SP

	// Calculate stack space needed: n*4 bytes, aligned to 16
	MOVL	CX, AX
	SHLL	$2, AX			// AX = n * 4
	ADDL	$15, AX
	ANDL	$~15, AX		// 16-byte align
	SUBL	AX, SP

	// Copy all args to stack
	// BX = args pointer, CX = count, DI = dest
	MOVL	SP, DI
copy_loop:
	DECL	CX
	MOVL	(BX)(CX*4), AX
	MOVL	AX, (DI)(CX*4)
	CMPL	CX, $0
	JNE	copy_loop
	JMP	_0args

	// Fast path: fall through to copy args
_3args:
	MOVL	8(BX), AX
	MOVL	AX, 8(SP)
_2args:
	MOVL	4(BX), AX
	MOVL	AX, 4(SP)
_1args:
	MOVL	0(BX), AX
	MOVL	AX, 0(SP)
_0args:
	MOVL	8(BP), DX		// fn pointer from saved location
	CALL	DX
	MOVL	BP, SP

ret:
	// Reload libcArgs pointer from saved location
	MOVL	4(SP), SI

	// Save return values (AX already has r1, need to save DX before it's clobbered)
	MOVL	DX, 12(SP)		// temporarily save r2
	MOVL	AX, libcCallInfo_r1(SI)
	MOVL	12(SP), AX
	MOVL	AX, libcCallInfo_r2(SI)

	RET
