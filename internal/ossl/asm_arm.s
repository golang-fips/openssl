// Copyright 2026 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !cgo

#include "go_asm.h"
#include "textflag.h"

TEXT ·syscallNSystemStack_trampoline(SB),NOSPLIT,$8
	MOVW	R0, 4(R13)
	CALL	·syscallNSystemStack(SB)
	RET

TEXT ·syscallNAsm(SB),NOSPLIT,$0-4
	// Load args pointer first, before modifying SP
	MOVW	libcArgs+0(FP), R0
	
	// Save callee-saved registers R4-R8 and LR.
	// We use R4 for libcArgs pointer.
	// We use R5 for args pointer.
	// We use R6 for n.
	// We use R7 for scratch.
	// We use R8 for saving SP.
	MOVM.DB.W [R4-R8, R14], (R13)

	MOVW	R0, R4 // Move libcArgs to R4

	MOVW	libcCallInfo_n(R4), R6
	MOVW	libcCallInfo_args(R4), R5
	MOVW	libcCallInfo_fn(R4), R12

	CMP	$4, R6
	BGT	args_stack

	CMP	$0, R6
	BEQ	call
	CMP	$1, R6
	BEQ	args_1
	CMP	$2, R6
	BEQ	args_2
	CMP	$3, R6
	BEQ	args_3
	
args_4:	
	MOVM.IA	(R5), [R0, R1, R2, R3]
	B	call

args_3:
	MOVM.IA	(R5), [R0, R1, R2]
	B	call

args_2:
	MOVM.IA	(R5), [R0, R1]
	B	call

args_1:
	MOVW	(R5), R0
	B	call

args_stack:
	// Calculate stack space needed: (n-4)*4
	SUB	$4, R6, R7
	MOVW	R7, R2
	SLL	$2, R2 // bytes
	
	// Save SP
	MOVW	R13, R8
	
	// Allocate stack
	SUB	R2, R13
	BIC	$7, R13 // Align to 8 bytes
	
	// Copy args
	ADD	$16, R5, R14 // Src = args + 16
	MOVW	R13, R3      // Dst = SP
	
copy_loop:
	MOVW.P	4(R14), R1 // read
	MOVW.P	R1, 4(R3)  // write
	SUB	$1, R7
	CMP	$0, R7
	BNE	copy_loop
	
	// Load first 4 args
	MOVM.IA	(R5), [R0, R1, R2, R3]
	
	// Reload fn
	MOVW	libcCallInfo_fn(R4), R12
	
	BL	(R12)
	
	// Restore SP
	MOVW	R8, R13
	B	ret

call:
	BL	(R12)

ret:
	MOVW	R0, libcCallInfo_r1(R4)
	MOVW	R1, libcCallInfo_r2(R4)
	
	MOVM.IA.W (R13), [R4-R8, R14]
	RET
