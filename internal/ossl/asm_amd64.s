// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !cgo

#include "go_asm.h"
#include "textflag.h"

TEXT ·syscallNSystemStack_trampoline(SB),NOSPLIT,$16
#ifdef GOOS_windows
	MOVQ	CX, 0(SP)
#else
	MOVQ	DI, 0(SP)
#endif
	CALL	·syscallNSystemStack(SB)
	RET

#ifdef GOOS_windows
#define RegArgsN 4
#else
#define RegArgsN 6
#endif

TEXT ·syscallNAsm(SB),NOSPLIT,$16-8
	// Load pointer from stack (ABI0 calling convention)
	// Store argument and original SP in a callee-saved register
	MOVQ	libcArgs+0(FP), R13
	MOVQ	SP, R14
	
	// Align stack to 16 bytes
	ANDQ	$~15, SP

	MOVQ	libcCallInfo_fn(R13), R11
	MOVQ	libcCallInfo_n(R13), CX
	MOVQ	libcCallInfo_args(R13), R10

	// Fast version, do not store args on the stack.
	CMPL	CX, $0;	JE	_0args
	CMPL	CX, $1;	JE	_1args
	CMPL	CX, $2;	JE	_2args
	CMPL	CX, $3;	JE	_3args
	CMPL	CX, $4;	JE	_4args
#ifndef GOOS_windows // Windows does not pass more than 4 args in registers
	CMPL	CX, $5;	JE	_5args
	CMPL	CX, $6;	JE	_6args
#endif

	// Reserve stack space for remaining args
	MOVQ	CX, R12
	SUBQ	$RegArgsN, R12
	ADDQ	$1, R12 // make even number of words for stack alignment
	ANDQ	$~1, R12
	SHLQ	$3, R12
	SUBQ	R12, SP

	// Copy args to the stack.
	// CX: count of stack arguments (n-RegArgsN)
	// SI: &args[RegArgsN]
	// DI: copy of RSP
	SUBQ	$RegArgsN, CX
	MOVQ	R10, SI
	ADDQ	$(8*RegArgsN), SI
	MOVQ	SP, DI
	CLD
	REP; MOVSQ

#ifndef GOOS_windows
_6args:
	MOVQ	(5*8)(R10), R9
_5args:
	MOVQ	(4*8)(R10), R8
#endif
_4args:
	MOVQ	(3*8)(R10), CX
_3args:
	MOVQ	(2*8)(R10), DX
_2args:
	MOVQ	(1*8)(R10), SI
_1args:
	MOVQ	(0*8)(R10), DI
_0args:

	XORL	AX, AX	    // vararg: say "no float args"

#ifdef GOOS_windows
	// Windows x64 syscall ABI: first four integer args in CX, DX, R8, R9
	// and 32 bytes of shadow space on the stack.
	ADJSP	$32
	MOVQ	CX, R9
	MOVQ	DX, R8
	MOVQ	SI, DX
	MOVQ	DI, CX
#endif

	CALL	R11

#ifdef GOOS_windows
	ADJSP	$-32
#endif

	MOVQ	R14, SP		// free stack space

	// Return result.
	MOVQ	AX, libcCallInfo_r1(R13)
	MOVQ	DX, libcCallInfo_r2(R13)

	RET
