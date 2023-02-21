#! /usr/bin/python3

import argparse
import sys
import struct

RC = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008
]

r = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14]
]


def rotate_left(x, n):
    return (x << n) % (1 << 64) | (x >> (64 - n))


def keccak_permutations(lanes, rc):
    # tetha step
    c = [lanes[x][0] ^ lanes[x][1] ^ lanes[x][2] ^ lanes[x][3] ^ lanes[x][4] for x in range(5)]
    d = [c[x - 1] ^ rotate_left(c[(x + 1) % 5], 1) for x in range(5)]
    lanes = [[lanes[x][y] ^ d[x] for y in range(5)] for x in range(5)]

    # rho & pi steps
    b = [[0 for _ in range(5)] for _ in range(5)]
    for x in range(5):
        for y in range(5):
            b[y][(2 * x + 3 * y) % 5] = rotate_left(lanes[x][y], r[x][y])

    # chi step
    lanes = [[b[x][y] ^ ((~b[(x + 1) % 5][y]) & b[(x + 2) % 5][y]) for y in range(5)] for x in range(5)]

    # iota step
    lanes[0][0] ^= rc
    return lanes


def state2lanes(state):
    lanes = [[0 for _ in range(5)] for _ in range(5)]
    for y in range(5):
        for x in range(5):
            lanes[x][y] = struct.unpack("<Q", state[x * 8 + y * 40:x * 8 + y * 40 + 8])[0]
    return lanes


def lanes2state(lanes):
    state = bytearray(200)
    for y in range(5):
        for x in range(5):
            state[x * 8 + y * 40:x * 8 + y * 40 + 8] = struct.pack("<Q", lanes[x][y])
    return state


def keccak_f(state):
    lanes = state2lanes(state)
    for i in range(24):
        lanes = keccak_permutations(lanes, RC[i])
    state = lanes2state(lanes)
    return state


def padding(block, block_size, d):
    block.append(d)
    while len(block) < block_size:
        block.append(0x00)
    block[-1] ^= 0x80
    return block


def keccak(data, bitrate, delimited_suffix, out_len):
    block_size = bitrate // 8

    # Initialisation
    state = bytearray(200)

    # Phase d'absorption
    block = bytearray(data.read(block_size))
    while len(block) == block_size:
        for i in range(block_size):
            state[i] ^= block[i]
        state = keccak_f(state)
        block = bytearray(data.read(block_size))
    block = padding(block, block_size, delimited_suffix)
    for i in range(block_size):
        state[i] ^= block[i]
    state = keccak_f(state)

    # Phase de pressage
    z = bytearray()
    out_len_byte = out_len // 8
    while out_len_byte > 0:
        block_size = min(block_size, out_len_byte)
        z += state[:block_size]
        out_len_byte -= block_size
        if out_len > 0:
            state = keccak_f(state)
    return z


def sha3_224(data):
    return keccak(data, 1152, 0x06, 224).hex()


def sha3_256(data):
    return keccak(data, 1088, 0x06, 256).hex()


def sha3_384(data):
    return keccak(data, 832, 0x06, 384).hex()


def sha3_512(data):
    return keccak(data, 576, 0x06, 512).hex()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog='python sha3.py',
                                     description='Print SHA-3 checksums'
                                     )
    parser.add_argument("file", type=argparse.FileType("rb"), nargs="?", help="Input file")
    parser.add_argument("-a", "--algorithm", type=int, default=256, help="224, 256 (default), 384, 512")
    args = parser.parse_args()
    if args.file:
        data_bytes = args.file
    elif not sys.stdin.isatty():
        data_bytes = sys.stdin.buffer
    else:
        sys.exit("You didn't provide input")

    if args.algorithm == 224:
        print(sha3_224(data_bytes))
    elif args.algorithm == 256:
        print(sha3_256(data_bytes))
    elif args.algorithm == 384:
        print(sha3_384(data_bytes))
    elif args.algorithm == 512:
        print(sha3_512(data_bytes))
    else:
        sys.exit("Wrong algorithm")
