import sys, re
from keystone import Ks, KS_ARCH_X86, KS_MODE_64

def assemble_lines(lines):
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    encoding, count = ks.asm('\n'.join(lines))
    return encoding

def main():
    if len(sys.argv) != 3:
        print("Usage: python generate_shellcode_header.py <in.template> <out.h>")
        sys.exit(1)

    tpl_path, out_path = sys.argv[1], sys.argv[2]
    with open(tpl_path, 'r') as f:
        tpl = f.read().splitlines()

    dsl = []
    in_dsl = False
    for line in tpl:
        if 'SHELLCODE_START' in line:
            in_dsl = True
            continue
        if 'SHELLCODE_END' in line:
            in_dsl = False
            break
        if in_dsl:
            code_line = re.sub(r'^\s*(//|;)\s*', '', line)
            if code_line.strip():
                dsl.append(code_line)

    if not dsl:
        print("Error: no DSL instructions found between SHELLCODE_START/END")
        sys.exit(1)

    encoding = assemble_lines(dsl)

    byte_lines = []
    for i in range(0, len(encoding), 16):
        chunk = encoding[i:i+16]
        byte_lines.append('    ' + ', '.join(f'0x{b:02X}' for b in chunk) + ',')

    out = []
    in_bytes = False
    for line in tpl:
        if 'BYTES_BEGIN' in line:
            out.append(line)
            out.extend(byte_lines)
            in_bytes = True
            continue
        if 'BYTES_END' in line:
            in_bytes = False
        if in_bytes:
            continue
        out.append(line)

    with open(out_path, 'w') as f:
        f.write('\n'.join(out))

    print(f"Generated {out_path}: {len(encoding)} bytes of shellcode")

if __name__ == '__main__':
    main()
