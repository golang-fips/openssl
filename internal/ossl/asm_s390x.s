// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.27 && !cgo

#include "go_asm.h"
#include "textflag.h"

// S390X ELF ABI:
// - Args in R2-R6, float args in F0, F2, F4, F6
// - Return values in R2, R3 (and F0 for floats)
// - Callee-saved: R6-R13, R15, F8-F15
// - R14 is link register (return address)
// - R15 is stack pointer
// - Standard frame: 160 bytes minimum with register save area at 48(R15)

TEXT ·syscallNSystemStack_trampoline(SB), NOSPLIT|NOFRAME, $0-0
	// R2 already contains the libcArgs pointer from cgocall
	// Save callee-saved registers to caller's save area
	STMG R6, R15, 48(R15)
	MOVD R15, R1
	SUB  $32, R15
	MOVD R1, 0(R15)
	MOVD R2, 8(R15)
	BL   ·syscallNSystemStack(SB)
	ADD  $32, R15
	LMG  48(R15), R6, R15
	RET

TEXT ·syscallNAsm(SB), NOSPLIT, $64-8
	// Save callee-saved registers we'll use (R6-R11)
	STMG R6, R11, 8(R15)

	// Load libcArgs pointer from stack (ABI0 calling convention)
	MOVD libcArgs+0(FP), R11

	// Store values we need across the C call in callee-saved registers
	MOVD R15, R7                    // R7 = original SP
	MOVD R11, R8                    // R8 = libcArgs
	MOVD libcCallInfo_args(R11), R9 // R9 = args
	MOVD libcCallInfo_fn(R11), R10  // R10 = fn
	MOVD libcCallInfo_n(R11), R6    // R6 = n

	// Do we have more than 5 arguments?
	CMPBLE R6, $5, _allocsmall

	// >5 args: allocate frame for stack args ((n-5+1) & ~1) * 8 + 160
	MOVD R6, R1
	SUB  $5, R1
	ADD  $1, R1
	MOVD $~1, R0
	AND  R0, R1
	SLD  $3, R1
	ADD  $160, R1
	SUB  R1, R7, R15
	MOVD $~15, R0
	AND  R0, R15     // 16-byte align
	MOVD R7, 0(R15)  // back chain

	// Copy args[5..n-1] to stack at offset 160
	MOVD $5, R1

_stackargs:
	SLD  $3, R1, R3
	MOVD (R9)(R3*1), R0
	SUB  $5, R1, R4
	SLD  $3, R4
	ADD  $160, R4
	MOVD R0, (R15)(R4*1)
	ADD  $1, R1
	CMP  R1, R6
	BLT  _stackargs
	BR   _5args

_allocsmall:
	// <=5 args: allocate minimum 160-byte C frame
	SUB  $160, R7, R15
	MOVD $~15, R0
	AND  R0, R15
	MOVD R7, 0(R15)    // back chain

	// Branch to appropriate label based on arg count
	CMPBEQ R6, $0, _0args
	CMPBEQ R6, $1, _1args
	CMPBEQ R6, $2, _2args
	CMPBEQ R6, $3, _3args
	CMPBEQ R6, $4, _4args

_5args:
	MOVD (4*8)(R9), R6

_4args:
	MOVD (3*8)(R9), R5

_3args:
	MOVD (2*8)(R9), R4

_2args:
	MOVD (1*8)(R9), R3

_1args:
	MOVD (0*8)(R9), R2

_0args:
	BL R10

	// Restore stack pointer
	MOVD R7, R15

	// Save return values
	MOVD R2, libcCallInfo_r1(R8)
	MOVD R3, libcCallInfo_r2(R8)

	// Restore callee-saved registers (R6-R11)
	LMG 8(R15), R6, R11
	RET
