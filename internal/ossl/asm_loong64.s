// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !cgo

#include "go_asm.h"
#include "textflag.h"

TEXT ·syscallNSystemStack_trampoline(SB), NOSPLIT, $16
	MOVV R4, 8(R3)
	CALL ·syscallNSystemStack(SB)
	RET

TEXT ·syscallNAsm(SB), NOSPLIT, $0-8
	// Load pointer from stack (ABI0 calling convention)
	MOVV libcArgs+0(FP), R12

	// Save original stack pointer
	MOVV R3, R23

	// Align stack to 16 bytes for C calling convention
	MOVV $-16, R15
	AND  R15, R3

	MOVV libcCallInfo_args(R12), R13
	MOVV libcCallInfo_fn(R12), R14

	// Do we have more than 8 arguments?
	MOVV libcCallInfo_n(R12), R4
	BEQ  R4, R0, _0args
	MOVV $1, R15
	BEQ  R4, R15, _1args
	MOVV $2, R15
	BEQ  R4, R15, _2args
	MOVV $3, R15
	BEQ  R4, R15, _3args
	MOVV $4, R15
	BEQ  R4, R15, _4args
	MOVV $5, R15
	BEQ  R4, R15, _5args
	MOVV $6, R15
	BEQ  R4, R15, _6args
	MOVV $7, R15
	BEQ  R4, R15, _7args
	MOVV $8, R15
	BEQ  R4, R15, _8args

	// Reserve stack space for remaining args
	MOVV R4, R16
	ADDV $-8, R16 // R16 = n-8
	MOVV R16, R12 // R12 = n-8 (reuse R12, no longer need libcArgs)
	ADDV $1, R12  // R12 = (n-8)+1
	MOVV $-2, R15
	AND  R15, R12 // make even number of words for stack alignment
	SLLV $3, R12  // R12 = bytes to reserve
	SUBV R12, R3  // SP -= bytes

	// R16: size of stack arguments (n-8)*8
	// R15: &args[8]
	// R17: loop counter, from 0 to (n-8)*8
	// R18: scratch
	// R19: copy of R3 (SP)
	// R20: scratch
	SLLV $3, R16     // R16 = (n-8)*8
	MOVV R13, R15
	ADDV $(8*8), R15 // R15 = args + 64 = &args[8]
	MOVV R0, R17     // R17 = 0 (loop counter)
	MOVV R3, R19     // R19 = SP copy

stackargs:
	MOVV R15, R18
	ADDV R17, R18            // R18 = &args[8] + counter
	MOVV (R18), R18          // R18 = args[8 + counter/8]
	MOVV R19, R20
	ADDV R17, R20            // R20 = SP_copy + counter
	MOVV R18, (R20)          // stack[counter/8] = R18
	ADDV $8, R17             // counter += 8
	BNE  R17, R16, stackargs // while counter != (n-8)*8

_8args:
	MOVV (7*8)(R13), R11

_7args:
	MOVV (6*8)(R13), R10

_6args:
	MOVV (5*8)(R13), R9

_5args:
	MOVV (4*8)(R13), R8

_4args:
	MOVV (3*8)(R13), R7

_3args:
	MOVV (2*8)(R13), R6

_2args:
	MOVV (1*8)(R13), R5

_1args:
	MOVV (0*8)(R13), R4

_0args:

	CALL (R14)

	// Restore original stack pointer
	MOVV R23, R3

	MOVV libcArgs+0(FP), R12
	MOVV R4, libcCallInfo_r1(R12) // save r1
	MOVV R5, libcCallInfo_r2(R12) // save r2

	RET
