import sys

plain = "userb1".encode("utf-16le")
part0 = [0x28, 0x41, 0x85, 0x67]
part1 = [0xC9, 0x50, 0x7B, 0x00]

t0 = part0 + part1
t1 = part1 + part0


def print_hex(input):
    for i in input:
        sys.stdout.write("%02X " % (i))
    print()


def obfuscate_1470(t0, t1, plain):
    ret = []
    for i, p in enumerate(plain):
        val0 = (p + (t1[i % 8])) % 256
        val1 = (val0 ^ t0[i % 7]) % 256
        # sys.stdout.write("%02X " % (val1))
        ret.append(val1)
    return ret


def deobfuscate_1471(t0, t1, cipher):
    ret = []
    for i, p in enumerate(cipher):
        val1 = (p ^ t0[i % 7]) % 256
        val0 = (val1 - (t1[i % 8])) % 256
        # sys.stdout.write("%02X " % (val1))
        ret.append(val0)
    return ret


def obfuscate(t0, t1, host1473, val1472, plain):
    round0 = obfuscate_1470(t0, t1, plain)
    input1 = t0.copy()
    input1.extend(round0)
    round1 = obfuscate_1470(val1472, host1473, input1)
    return round1


def deobfuscate(host1473, val1472, cipher):
    round1 = deobfuscate_1471(val1472, host1473, cipher)
    print_hex(round1)
    part0 = round1[0:4]
    part1 = round1[4:8]
    cipher1 = round1[8:]
    t0 = part0 + part1
    t1 = part1 + part0

    return deobfuscate_1471(t0, t1, cipher1)


ob = obfuscate(
    t0, t1, "WIN-N6MF".encode("ascii"), [0x63, 0x45, 0, 0, 0, 0, 0x45, 0x63], plain
)

deob = deobfuscate("WIN-N6MF".encode("ascii"), [0x63, 0x45, 0, 0, 0, 0, 0x45, 0x63], ob)

print(bytes(deob).decode("utf-16le"))
