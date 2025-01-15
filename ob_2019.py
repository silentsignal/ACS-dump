import sys
import re


def print_hex(input):
    for i in input:
        sys.stdout.write("%02X " % (i))
    print()


def obfuscate_1470(t0, t1, plain):
    ret = []
    for i, p in enumerate(plain):
        val0 = (p + (t1[i % 7])) % 256
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
    # print_hex(round1)
    part0 = round1[0:4]
    part1 = round1[4:8]
    cipher1 = round1[8:]
    t0 = part0 + part1
    t1 = part1 + part0

    return deobfuscate_1471(t0, t1, cipher1)

def gen_obfuscator_key(build_guid, product_id):
    ret=[0,0,0,0,0,0,0,0]
    machine_id=list(build_guid.encode('utf-16le'))
    machine_id.extend(list(product_id.encode('utf-16le')))
    print("Machine ID [%d]:" % (len(machine_id)))
    print_hex(machine_id)
    idx=0
    for i in range(0, len(machine_id), 2):
        print(bytes(machine_id[i:]).decode("utf-16le"), i, hex(machine_id[i]))
        print_hex(ret)
        ret[idx] = ret[idx] ^ machine_id[i]
        idx = (idx + 1) & 7
    return ret

def test():
    plain = "TrustNo1".encode("utf-16le")
    part0 = [0x27, 0x9f, 0x87, 0x67]
    part1 = [0x75, 0x7c, 0x5d, 0x08]

    t0 = part0 + part1
    t1 = part1 + part0
    
    round0 = obfuscate_1470(t0, t1, plain)
    print_hex(round0)
    
    obkey=gen_obfuscator_key("ffffffff-ffff-ffff-ffff-ffffffffffff", "00431-10000-00000-AA321")
    print_hex(obkey)
    """
    ob = obfuscate(
        t0, t1, "WIN-N6MF".encode("ascii"), [0x63, 0x45, 0, 0, 0, 0, 0x45, 0x63], plain
    )

    deob = deobfuscate(
        "WIN-N6MF".encode("ascii"), [0x63, 0x45, 0, 0, 0, 0, 0x45, 0x63], ob
    )

    print(bytes(deob).decode("utf-16le"))
    """

def main():
    # Dumb parsing of Registry export
    fat_re = re.compile('"Function Admin Timestamp"=hex:[0-9a-f,\\\\ \n]*', re.DOTALL)
    hostname = sys.argv[1]
    reg_data = open(sys.argv[2], "r", encoding="utf-16le").read()
    fat_line = fat_re.search(reg_data)
    fat_hex = (
        fat_line.group(0)
        .split(":")[1]
        .replace("\n", "")
        .replace("\\", "")
        .replace(" ", "")
    )
    fat_bytes = [int(b, 16) for b in fat_hex.split(",")]
    # print_hex(fat_bytes)

    # Brute-Force val1472
    for b0 in range(0, 256):
        for b1 in range(0, 256):
            deob = deobfuscate(
                hostname.encode("ascii"), [b0, b1, 0, 0, 0, 0, b1, b0], fat_bytes
            )

            # Heuristic: we look for typeable UTF-16LE
            found = True
            for i in range(1, 17, 2):
                if deob[i] != 0:
                    found = False
                    break
            if not found:
                continue
            for i in range(0, 16, 2):
                if deob[i] < 0x1F or deob[i] > 0x7E:
                    found = False
                    break
            if found:
                print(
                    "[+] Found candidate with key (%02X, %02X): %s"
                    % (b0, b1, bytes(deob[0:16]).decode("utf-16le"))
                )


#main()
test()
