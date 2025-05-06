# Makefile Win x64 MSVC + NASM
PY      := python
ASM     := nasm
CXX     := cl
CXXFLAGS:= /nologo /EHsc /std:c++17 /Iinclude
ASMFLAGS:= -f win64
OUT     := injector.exe

TEMPLATE:= Shellcode.h.template
HDR     := include/PEB.h include/Callbacks.h Shellcode.h
SRCS    := main.cpp
ASMS    := Callbacks.asm

all: $(OUT)

Shellcode.h: $(TEMPLATE) generate_shellcode_header.py
	@echo "[*] Shellcode.h"
	$(PY) generate_shellcode_header.py $(TEMPLATE) $@

Callbacks.obj: $(ASMS)
	@echo "[*] Callbacks.asm"
	$(ASM) $(ASMFLAGS) $< -o $@

main.obj: main.cpp include/PEB.h include/Callbacks.h Shellcode.h
	@echo "[*] main.cpp"
	$(CXX) $(CXXFLAGS) /c main.cpp /Fo$@

$(OUT): Shellcode.h Callbacks.obj main.obj
	@echo "[*] $(OUT)"
	$(CXX) $(CXXFLAGS) Callbacks.obj main.obj /link /OUT:$(OUT)

clean:
	del /Q *.obj $(OUT) Shellcode.h 2>nul

.PHONY: all clean
