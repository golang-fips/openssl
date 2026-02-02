// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !cgo

#include "go_asm.h"
#include "textflag.h"

TEXT ·syscallNSystemStack_trampoline(SB), NOSPLIT|NOFRAME, $0-0
	// R3 already contains the libcArgs pointer from cgocall
	MOVD  LR, R0
	MOVD  R0, 16(R1)
	MOVDU R1, -32(R1)
	MOVD  R3, 32(R1)
	CALL  ·syscallNSystemStack(SB)
	ADD   $32, R1
	MOVD  16(R1), R0
	MOVD  R0, LR
	RET

// PPC64LE ELFv2 ABI: R3-R10 args, R3-R4 return, R14-R31 callee-saved
// Go ABI: R3-R10, R14-R17 args, R20-R21 scratch, R30=g, R31=scratch
// We use R24-R28 which are callee-saved in both ABIs.
// Go frame: 48 locals + 32 linkage = 80 bytes. Locals start at 32(R1).

TEXT ·syscallNAsm(SB), NOSPLIT, $48-8
	// Save callee-saved registers we'll use
	MOVD R24, 32(R1)
	MOVD R25, 40(R1)
	MOVD R26, 48(R1)
	MOVD R27, 56(R1)
	MOVD R28, 64(R1)

	// Load libcArgs pointer from stack (ABI0 calling convention)
	MOVD libcArgs+0(FP), R11

	// Store values we need across the C call in callee-saved registers
	MOVD R1, R24                     // R24 = original SP
	MOVD R11, R25                    // R25 = libcArgs
	MOVD libcCallInfo_args(R11), R26 // R26 = args
	MOVD libcCallInfo_fn(R11), R27   // R27 = fn
	MOVD libcCallInfo_n(R11), R28    // R28 = n

	// Do we have more than 8 arguments?
	CMP R28, $8
	BLE _allocsmall

	// >8 args: allocate large frame ((n-8+1) & ~1) * 8 + 96
	SUB  $8, R28, R3
	ADD  $1, R3
	MOVD $~1, R4
	AND  R4, R3
	SLD  $3, R3
	ADD  $96, R3
	NEG  R3, R4
	ADD  R4, R24, R1
	MOVD $~15, R3
	AND  R3, R1      // 16-byte align
	MOVD R24, 0(R1)  // back chain
	MOVD R2, 24(R1)  // save TOC

	// Copy args[8..n-1] to stack at offset 96
	MOVD $8, R3

_stackargs:
	SLD  $3, R3, R5
	MOVD (R26)(R5), R6
	SUB  $8, R3, R7
	SLD  $3, R7
	ADD  $96, R7
	MOVD R6, (R1)(R7)
	ADD  $1, R3
	CMP  R3, R28
	BLT  _stackargs
	BR   _8args

_allocsmall:
	// <=8 args: allocate minimum 96-byte C frame
	ADD  $-96, R24, R1
	MOVD $~15, R3
	AND  R3, R1
	MOVD R24, 0(R1)    // back chain
	MOVD R2, 24(R1)    // save TOC

	// Branch to appropriate label based on arg count
	CMP R28, $0; BEQ _0args
	CMP R28, $1; BEQ _1args
	CMP R28, $2; BEQ _2args
	CMP R28, $3; BEQ _3args
	CMP R28, $4; BEQ _4args
	CMP R28, $5; BEQ _5args
	CMP R28, $6; BEQ _6args
	CMP R28, $7; BEQ _7args

_8args:
	MOVD (7*8)(R26), R10

_7args:
	MOVD (6*8)(R26), R9

_6args:
	MOVD (5*8)(R26), R8

_5args:
	MOVD (4*8)(R26), R7

_4args:
	MOVD (3*8)(R26), R6

_3args:
	MOVD (2*8)(R26), R5

_2args:
	MOVD (1*8)(R26), R4

_1args:
	MOVD (0*8)(R26), R3

_0args:
	// ELFv2: function address in R12 and CTR
	MOVD R27, R12
	MOVD R12, CTR
	BL   (CTR)

	// Restore TOC and stack pointer
	MOVD 24(R1), R2
	MOVD R24, R1

	// Save return values
	MOVD R3, libcCallInfo_r1(R25)
	MOVD R4, libcCallInfo_r2(R25)

	// Restore callee-saved registers
	MOVD 32(R1), R24
	MOVD 40(R1), R25
	MOVD 48(R1), R26
	MOVD 56(R1), R27
	MOVD 64(R1), R28

	RET
