// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !cgo

#include "go_asm.h"
#include "textflag.h"

TEXT ·syscallNSystemStack_trampoline(SB),NOSPLIT,$16
	MOVD	R0, 8(RSP)
	CALL	·syscallNSystemStack(SB)
	RET

TEXT ·syscallNAsm(SB),NOSPLIT,$0-16
	// Save original stack pointer
	MOVD	RSP, R20

	// Load pointer from stack (ABI0 calling convention)
	MOVD	libcArgs+0(FP), R3

	MOVD	libcCallInfo_args(R3), R12
	MOVD	libcCallInfo_fn(R3), R13
	// Do we have more than 8 arguments?
	MOVD	libcCallInfo_n(R3), R0
	CMP	$0,	R0; BEQ	_0args
	CMP	$1,	R0; BEQ	_1args
	CMP	$2,	R0; BEQ	_2args
	CMP	$3,	R0; BEQ	_3args
	CMP	$4,	R0; BEQ	_4args
	CMP	$5,	R0; BEQ	_5args
	CMP	$6,	R0; BEQ	_6args
	CMP	$7,	R0; BEQ	_7args
	CMP	$8,	R0; BEQ	_8args

	// Reserve stack space for remaining args
	SUB	$8, R0, R2
	ADD	$1, R2, R3 // make even number of words for stack alignment
	AND	$~1, R3
	LSL	$3, R3
	SUB	R3, RSP

	// R4: size of stack arguments (n-8)*8
	// R5: &args[8]
	// R6: loop counter, from 0 to (n-8)*8
	// R7: scratch
	// R8: copy of RSP - (R2)(RSP) assembles as (R2)(ZR)
	SUB	$8, R0, R4
	LSL	$3, R4
	ADD	$(8*8), R12, R5
	MOVD	$0, R6
	MOVD	RSP, R8
stackargs:
	MOVD	(R6)(R5), R7
	MOVD	R7, (R6)(R8)
	ADD	$8, R6
	CMP	R6, R4
	BNE	stackargs

_8args:
	MOVD	(7*8)(R12), R7
_7args:
	MOVD	(6*8)(R12), R6
_6args:
	MOVD	(5*8)(R12), R5
_5args:
	MOVD	(4*8)(R12), R4
_4args:
	MOVD	(3*8)(R12), R3
_3args:
	MOVD	(2*8)(R12), R2
_2args:
	MOVD	(1*8)(R12), R1
_1args:
	MOVD	(0*8)(R12), R0
_0args:

	BL	(R13)

	// Restore original stack pointer
	MOVD	R20, RSP

	MOVD	libcArgs+0(FP), R3
	MOVD	R0, libcCallInfo_r1(R3)	// save r1
	MOVD	R1, libcCallInfo_r2(R3)	// save r2

    RET
