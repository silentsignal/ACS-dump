import sys

plain="userb1".encode("utf-16le")
part0=[0x28, 0x41, 0x85, 0x67]
part1=[0xc9, 0x50, 0x7b, 0x00]

t0=part0+part1
t1=part1+part0

def print_hex(input):
    for i in input:
        sys.stdout.write("%02X " % (i))
    print()

def obfuscate_1470(t0, t1, plain):
    ret = []
    for i, p in enumerate(plain):
        val0 = (p + (t1[i % 8])) % 256
        val1 = (val0 ^ t0[i % 7]) % 256
        #sys.stdout.write("%02X " % (val1))
        ret.append(val1)
    return ret

def obfuscate(t0, t1, host1473, val1472, plain):
    round0 = obfuscate_1470(t0, t1, plain)
    input1 = t0.copy()
    input1.extend(round0)
    round1 = obfuscate_1470(val1472, host1473, input1)
    print_hex(round1)

obfuscate(t0, t1, "WIN-N6MF".encode("ascii"), [0x63, 0x45, 0, 0, 0, 0, 0x45, 0x63], plain)


