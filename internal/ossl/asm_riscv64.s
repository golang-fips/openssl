// Copyright 2015 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !cgo

#include "go_asm.h"
#include "textflag.h"

TEXT ·syscallNSystemStack_trampoline(SB), NOSPLIT, $16
	MOV  A0, 8(X2)
	CALL ·syscallNSystemStack(SB)
	RET

TEXT ·syscallNAsm(SB), NOSPLIT, $0-8
	// Load pointer from stack (ABI0 calling convention)
	MOV libcArgs+0(FP), X5

	// Save original stack pointer
	MOV X2, X20

	// Align stack to 16 bytes for C calling convention
	ANDI $-16, X2, X2

	MOV libcCallInfo_args(X5), X30
	MOV libcCallInfo_fn(X5), X29

	// Do we have more than 8 arguments?
	MOV libcCallInfo_n(X5), X10
	BEQ X10, ZERO, _0args
	MOV $1, X6
	BEQ X10, X6, _1args
	MOV $2, X6
	BEQ X10, X6, _2args
	MOV $3, X6
	BEQ X10, X6, _3args
	MOV $4, X6
	BEQ X10, X6, _4args
	MOV $5, X6
	BEQ X10, X6, _5args
	MOV $6, X6
	BEQ X10, X6, _6args
	MOV $7, X6
	BEQ X10, X6, _7args
	MOV $8, X6
	BEQ X10, X6, _8args

	// Reserve stack space for remaining args
	ADDI $-8, X10, X7
	ADDI $1, X7, X5   // make even number of words for stack alignment
	ANDI $-2, X5, X5
	SLLI $3, X5, X5
	SUB  X5, X2, X2

	// X6: size of stack arguments (n-8)*8
	// X7: &args[8]
	// X8: loop counter, from 0 to (n-8)*8
	// X9: scratch
	// X28: copy of X2 (SP)
	ADDI $-8, X10, X6
	SLLI $3, X6, X6
	ADDI $(8*8), X7, X7
	MOV  ZERO, X8
	MOV  X2, X28

stackargs:
	ADD  X8, X7, X9
	MOV  (X9), X9
	ADD  X8, X28, X31
	MOV  X9, (X31)
	ADDI $8, X8, X8
	BNE  X8, X6, stackargs

_8args:
	MOV (7*8)(X30), X17

_7args:
	MOV (6*8)(X30), X16

_6args:
	MOV (5*8)(X30), X15

_5args:
	MOV (4*8)(X30), X14

_4args:
	MOV (3*8)(X30), X13

_3args:
	MOV (2*8)(X30), X12

_2args:
	MOV (1*8)(X30), X11

_1args:
	MOV (0*8)(X30), X10

_0args:

	CALL X29

	// Restore original stack pointer
	MOV X20, X2

	MOV libcArgs+0(FP), X5
	MOV X10, libcCallInfo_r1(X5) // save r1
	MOV X11, libcCallInfo_r2(X5) // save r2

	RET
