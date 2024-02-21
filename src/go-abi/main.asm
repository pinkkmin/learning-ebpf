main.main STEXT size=238 args=0x0 locals=0xc0 funcid=0x0 align=0x0
	0x0000 00000 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:3)	TEXT	main.main(SB), ABIInternal, $192-0
	0x0000 00000 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:3)	LEAQ	-64(SP), R12
	0x0005 00005 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:3)	CMPQ	R12, 16(R14)
	0x0009 00009 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:3)	PCDATA	$0, $-2
	0x0009 00009 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:3)	JLS	228
	0x000f 00015 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:3)	PCDATA	$0, $-1
	0x000f 00015 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:3)	SUBQ	$192, SP
	0x0016 00022 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:3)	MOVQ	BP, 184(SP)
	0x001e 00030 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:3)	LEAQ	184(SP), BP
	0x0026 00038 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:3)	FUNCDATA	$0, gclocals·g2BeySu+wFnoycgXfElmcg==(SB)
	0x0026 00038 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:3)	FUNCDATA	$1, gclocals·o6Zg9+zmRBFm//1GHy3gfQ==(SB)
	0x0026 00038 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:4)	MOVQ	$2, main.v1+104(SP)
	0x002f 00047 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:4)	MOVQ	$3, main.v2+96(SP)
	0x0038 00056 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:4)	MOVQ	$4, main.v3+88(SP)
	0x0041 00065 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:4)	MOVQ	$5, main.v4+80(SP)
	0x004a 00074 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:5)	LEAQ	go:string."cccccc"(SB), BX
	0x0051 00081 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:5)	MOVQ	BX, main.str+144(SP)
	0x0059 00089 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:5)	MOVQ	$6, main.str+152(SP)
	0x0065 00101 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:6)	LEAQ	main..autotmp_6+112(SP), AX
	0x006a 00106 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:6)	MOVL	$6, CX
	0x006f 00111 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:6)	PCDATA	$1, $0
	0x006f 00111 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:6)	CALL	runtime.stringtoslicebyte(SB)
	0x0074 00116 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:6)	MOVQ	AX, main.b+160(SP)
	0x007c 00124 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:6)	MOVQ	BX, main.b+168(SP)
	0x0084 00132 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:6)	MOVQ	CX, main.b+176(SP)
	0x008c 00140 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:8)	MOVQ	main.v2+96(SP), DX
	0x0091 00145 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:8)	MOVQ	main.v3+88(SP), SI
	0x0096 00150 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:8)	MOVQ	main.v4+80(SP), DI
	0x009b 00155 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:8)	MOVQ	main.v1+104(SP), R8
	0x00a0 00160 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:8)	MOVQ	main.v2+96(SP), R9
	0x00a5 00165 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:8)	MOVQ	main.v3+88(SP), R10
	0x00aa 00170 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:8)	MOVQ	main.v1+104(SP), R11
	0x00af 00175 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:6)	MOVQ	AX, (SP)
	0x00b3 00179 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:6)	MOVQ	BX, 8(SP)
	0x00b8 00184 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:6)	MOVQ	CX, 16(SP)
	0x00bd 00189 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:8)	MOVQ	R11, AX
	0x00c0 00192 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:8)	MOVQ	DX, BX
	0x00c3 00195 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:8)	MOVQ	SI, CX
	0x00c6 00198 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:8)	MOVQ	R8, SI
	0x00c9 00201 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:8)	MOVQ	R9, R8
	0x00cc 00204 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:8)	MOVQ	R10, R9
	0x00cf 00207 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:8)	CALL	main.foo(SB)
	0x00d4 00212 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:9)	MOVQ	184(SP), BP
	0x00dc 00220 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:9)	ADDQ	$192, SP
	0x00e3 00227 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:9)	RET
	0x00e4 00228 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:9)	NOP
	0x00e4 00228 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:3)	PCDATA	$1, $-1
	0x00e4 00228 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:3)	PCDATA	$0, $-2
	0x00e4 00228 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:3)	CALL	runtime.morestack_noctxt(SB)
	0x00e9 00233 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:3)	PCDATA	$0, $-1
	0x00e9 00233 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:3)	JMP	0
	0x0000 4c 8d 64 24 c0 4d 3b 66 10 0f 86 d5 00 00 00 48  L.d$.M;f.......H
	0x0010 81 ec c0 00 00 00 48 89 ac 24 b8 00 00 00 48 8d  ......H..$....H.
	0x0020 ac 24 b8 00 00 00 48 c7 44 24 68 02 00 00 00 48  .$....H.D$h....H
	0x0030 c7 44 24 60 03 00 00 00 48 c7 44 24 58 04 00 00  .D$`....H.D$X...
	0x0040 00 48 c7 44 24 50 05 00 00 00 48 8d 1d 00 00 00  .H.D$P....H.....
	0x0050 00 48 89 9c 24 90 00 00 00 48 c7 84 24 98 00 00  .H..$....H..$...
	0x0060 00 06 00 00 00 48 8d 44 24 70 b9 06 00 00 00 e8  .....H.D$p......
	0x0070 00 00 00 00 48 89 84 24 a0 00 00 00 48 89 9c 24  ....H..$....H..$
	0x0080 a8 00 00 00 48 89 8c 24 b0 00 00 00 48 8b 54 24  ....H..$....H.T$
	0x0090 60 48 8b 74 24 58 48 8b 7c 24 50 4c 8b 44 24 68  `H.t$XH.|$PL.D$h
	0x00a0 4c 8b 4c 24 60 4c 8b 54 24 58 4c 8b 5c 24 68 48  L.L$`L.T$XL.\$hH
	0x00b0 89 04 24 48 89 5c 24 08 48 89 4c 24 10 4c 89 d8  ..$H.\$.H.L$.L..
	0x00c0 48 89 d3 48 89 f1 4c 89 c6 4d 89 c8 4d 89 d1 e8  H..H..L..M..M...
	0x00d0 00 00 00 00 48 8b ac 24 b8 00 00 00 48 81 c4 c0  ....H..$....H...
	0x00e0 00 00 00 c3 e8 00 00 00 00 e9 12 ff ff ff        ..............
	rel 77+4 t=14 go:string."cccccc"+0
	rel 112+4 t=7 runtime.stringtoslicebyte+0
	rel 208+4 t=7 main.foo+0
	rel 229+4 t=7 runtime.morestack_noctxt+0
main.foo STEXT nosplit size=254 args=0x50 locals=0x50 funcid=0x0 align=0x0
	0x0000 00000 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:11)	TEXT	main.foo(SB), NOSPLIT|ABIInternal, $80-80
	0x0000 00000 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:11)	SUBQ	$80, SP
	0x0004 00004 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:11)	MOVQ	BP, 72(SP)
	0x0009 00009 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:11)	LEAQ	72(SP), BP
	0x000e 00014 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:11)	FUNCDATA	$0, gclocals·wgcWObbY2HYnK2SU/U22lA==(SB)
	0x000e 00014 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:11)	FUNCDATA	$1, gclocals·cRnfy3ll8DXPG7zGjyjjXw==(SB)
	0x000e 00014 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:11)	FUNCDATA	$5, main.foo.arginfo1(SB)
	0x000e 00014 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:11)	MOVQ	AX, main.a1+112(SP)
	0x0013 00019 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:11)	MOVQ	BX, main.a2+120(SP)
	0x0018 00024 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:11)	MOVQ	CX, main.a3+128(SP)
	0x0020 00032 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:11)	MOVQ	DI, main.a4+136(SP)
	0x0028 00040 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:11)	MOVQ	SI, main.a5+144(SP)
	0x0030 00048 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:11)	MOVQ	R8, main.a6+152(SP)
	0x0038 00056 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:11)	MOVQ	R9, main.a7+160(SP)
	0x0040 00064 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:11)	MOVQ	$0, main.~r0(SP)
	0x0048 00072 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:11)	MOVQ	$0, main.~r1+24(SP)
	0x0051 00081 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:11)	MOVUPS	X15, main.~r1+32(SP)
	0x0057 00087 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:12)	MOVQ	$10, main.b1+16(SP)
	0x0060 00096 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:12)	MOVQ	$20, main.b2+8(SP)
	0x0069 00105 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:13)	MOVQ	main.bbbb+88(SP), BX
	0x006e 00110 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:13)	MOVQ	main.bbbb+96(SP), CX
	0x0073 00115 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:13)	MOVQ	main.bbbb+104(SP), DI
	0x0078 00120 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:13)	MOVQ	BX, main.c+48(SP)
	0x007d 00125 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:13)	MOVQ	CX, main.c+56(SP)
	0x0082 00130 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:13)	MOVQ	DI, main.c+64(SP)
	0x0087 00135 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:14)	MOVQ	main.a3+128(SP), DX
	0x008f 00143 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:14)	MOVQ	main.a1+112(SP), SI
	0x0094 00148 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:14)	IMULQ	DX, SI
	0x0098 00152 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:14)	MOVQ	main.a2+120(SP), DX
	0x009d 00157 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:14)	MOVQ	main.a4+136(SP), R8
	0x00a5 00165 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:14)	IMULQ	R8, DX
	0x00a9 00169 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:14)	ADDQ	SI, DX
	0x00ac 00172 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:14)	MOVQ	main.b1+16(SP), SI
	0x00b1 00177 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:14)	MOVQ	main.b2+8(SP), R8
	0x00b6 00182 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:14)	IMULQ	R8, SI
	0x00ba 00186 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:14)	ADDQ	SI, DX
	0x00bd 00189 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:14)	ADDQ	main.a4+136(SP), DX
	0x00c5 00197 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:14)	ADDQ	main.a5+144(SP), DX
	0x00cd 00205 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:14)	ADDQ	main.a6+152(SP), DX
	0x00d5 00213 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:14)	ADDQ	main.a7+160(SP), DX
	0x00dd 00221 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:14)	MOVQ	DX, main.~r0(SP)
	0x00e1 00225 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:14)	MOVQ	BX, main.~r1+24(SP)
	0x00e6 00230 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:14)	MOVQ	CX, main.~r1+32(SP)
	0x00eb 00235 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:14)	MOVQ	DI, main.~r1+40(SP)
	0x00f0 00240 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:14)	MOVQ	main.~r0(SP), AX
	0x00f4 00244 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:14)	MOVQ	72(SP), BP
	0x00f9 00249 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:14)	ADDQ	$80, SP
	0x00fd 00253 (/home/ohh/dev/learning-ebpf/src/go-abi/main.go:14)	RET
	0x0000 48 83 ec 50 48 89 6c 24 48 48 8d 6c 24 48 48 89  H..PH.l$HH.l$HH.
	0x0010 44 24 70 48 89 5c 24 78 48 89 8c 24 80 00 00 00  D$pH.\$xH..$....
	0x0020 48 89 bc 24 88 00 00 00 48 89 b4 24 90 00 00 00  H..$....H..$....
	0x0030 4c 89 84 24 98 00 00 00 4c 89 8c 24 a0 00 00 00  L..$....L..$....
	0x0040 48 c7 04 24 00 00 00 00 48 c7 44 24 18 00 00 00  H..$....H.D$....
	0x0050 00 44 0f 11 7c 24 20 48 c7 44 24 10 0a 00 00 00  .D..|$ H.D$.....
	0x0060 48 c7 44 24 08 14 00 00 00 48 8b 5c 24 58 48 8b  H.D$.....H.\$XH.
	0x0070 4c 24 60 48 8b 7c 24 68 48 89 5c 24 30 48 89 4c  L$`H.|$hH.\$0H.L
	0x0080 24 38 48 89 7c 24 40 48 8b 94 24 80 00 00 00 48  $8H.|$@H..$....H
	0x0090 8b 74 24 70 48 0f af f2 48 8b 54 24 78 4c 8b 84  .t$pH...H.T$xL..
	0x00a0 24 88 00 00 00 49 0f af d0 48 01 f2 48 8b 74 24  $....I...H..H.t$
	0x00b0 10 4c 8b 44 24 08 49 0f af f0 48 01 f2 48 03 94  .L.D$.I...H..H..
	0x00c0 24 88 00 00 00 48 03 94 24 90 00 00 00 48 03 94  $....H..$....H..
	0x00d0 24 98 00 00 00 48 03 94 24 a0 00 00 00 48 89 14  $....H..$....H..
	0x00e0 24 48 89 5c 24 18 48 89 4c 24 20 48 89 7c 24 28  $H.\$.H.L$ H.|$(
	0x00f0 48 8b 04 24 48 8b 6c 24 48 48 83 c4 50 c3        H..$H.l$HH..P.
go:cuinfo.producer.<unlinkable> SDWARFCUINFO dupok size=0
	0x0000 2d 4e 20 2d 6c 20 72 65 67 61 62 69              -N -l regabi
go:cuinfo.packagename.main SDWARFCUINFO dupok size=0
	0x0000 6d 61 69 6e                                      main
main..inittask SNOPTRDATA size=24
	0x0000 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	0x0010 00 00 00 00 00 00 00 00                          ........
go:string."cccccc" SRODATA dupok size=6
	0x0000 63 63 63 63 63 63                                cccccc
type:.eqfunc32 SRODATA dupok size=16
	0x0000 00 00 00 00 00 00 00 00 20 00 00 00 00 00 00 00  ........ .......
	rel 0+8 t=1 runtime.memequal_varlen+0
runtime.memequal64·f SRODATA dupok size=8
	0x0000 00 00 00 00 00 00 00 00                          ........
	rel 0+8 t=1 runtime.memequal64+0
runtime.gcbits.0100000000000000 SRODATA dupok size=8
	0x0000 01 00 00 00 00 00 00 00                          ........
type:.namedata.*[32]uint8- SRODATA dupok size=12
	0x0000 00 0a 2a 5b 33 32 5d 75 69 6e 74 38              ..*[32]uint8
type:*[32]uint8 SRODATA dupok size=56
	0x0000 08 00 00 00 00 00 00 00 08 00 00 00 00 00 00 00  ................
	0x0010 26 0d b3 9e 08 08 08 36 00 00 00 00 00 00 00 00  &......6........
	0x0020 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	0x0030 00 00 00 00 00 00 00 00                          ........
	rel 24+8 t=1 runtime.memequal64·f+0
	rel 32+8 t=1 runtime.gcbits.0100000000000000+0
	rel 40+4 t=5 type:.namedata.*[32]uint8-+0
	rel 48+8 t=1 type:[32]uint8+0
runtime.gcbits. SRODATA dupok size=0
type:[32]uint8 SRODATA dupok size=72
	0x0000 20 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ...............
	0x0010 aa ab 93 92 0a 01 01 11 00 00 00 00 00 00 00 00  ................
	0x0020 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	0x0030 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
	0x0040 20 00 00 00 00 00 00 00                           .......
	rel 24+8 t=1 type:.eqfunc32+0
	rel 32+8 t=1 runtime.gcbits.+0
	rel 40+4 t=5 type:.namedata.*[32]uint8-+0
	rel 44+4 t=-32763 type:*[32]uint8+0
	rel 48+8 t=1 type:uint8+0
	rel 56+8 t=1 type:[]uint8+0
gclocals·g2BeySu+wFnoycgXfElmcg== SRODATA dupok size=8
	0x0000 01 00 00 00 00 00 00 00                          ........
gclocals·o6Zg9+zmRBFm//1GHy3gfQ== SRODATA dupok size=9
	0x0000 01 00 00 00 05 00 00 00 00                       .........
gclocals·wgcWObbY2HYnK2SU/U22lA== SRODATA dupok size=10
	0x0000 02 00 00 00 01 00 00 00 01 00                    ..........
gclocals·cRnfy3ll8DXPG7zGjyjjXw== SRODATA dupok size=10
	0x0000 02 00 00 00 06 00 00 00 00 00                    ..........
main.foo.arginfo1 SRODATA static dupok size=23
	0x0000 18 08 20 08 28 08 30 08 38 08 40 08 48 08 fe 00  .. .(.0.8.@.H...
	0x0010 08 08 08 10 08 fd ff                             .......
