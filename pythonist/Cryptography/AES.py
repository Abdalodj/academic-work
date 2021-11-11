SBOX = [
    ["63", "7c", "77", "7b", "f2", "6b", "6f", "c5", "30", "01", "67", "2b", "fe", "d7", "ab", "76"],
    ["ca", "82", "c9", "7d", "fa", "59", "47", "f0", "ad", "d4", "a2", "af", "9c", "a4", "72", "c0"],
    ["b7", "fd", "93", "26", "36", "3f", "f7", "cc", "34", "a5", "e5", "f1", "71", "d8", "31", "15"],
    ["04", "c7", "23", "c3", "18", "96", "05", "9a", "07", "12", "80", "e2", "eb", "27", "b2", "75"],
    ["09", "83", "2c", "1a", "1b", "6e", "5a", "a0", "52", "3b", "d6", "b3", "29", "e3", "2f", "84"],
    ["53", "d1", "00", "ed", "20", "fc", "b1", "5b", "6a", "cb", "be", "39", "4a", "4c", "58", "cf"],
    ["d0", "ef", "aa", "fb", "43", "4d", "33", "85", "45", "f9", "02", "7f", "50", "3c", "9f", "a8"],
    ["51", "a3", "40", "8f", "92", "9d", "38", "f5", "bc", "b6", "da", "21", "10", "ff", "f3", "d2"],
    ["cd", "0c", "13", "ec", "5f", "97", "44", "17", "c4", "a7", "7e", "3d", "64", "5d", "19", "73"],
    ["60", "81", "4f", "dc", "22", "2a", "90", "88", "46", "ee", "b8", "14", "de", "5e", "0b", "db"],
    ["e0", "32", "3a", "0a", "49", "06", "24", "5c", "c2", "d3", "ac", "62", "91", "95", "e4", "79"],
    ["e7", "c8", "37", "6d", "8d", "d5", "4e", "a9", "6c", "56", "f4", "ea", "65", "7a", "ae", "08"],
    ["ba", "78", "25", "2e", "1c", "a6", "b4", "c6", "e8", "dd", "74", "1f", "4b", "bd", "8b", "8a"],
    ["70", "3e", "b5", "66", "48", "03", "f6", "0e", "61", "35", "57", "b9", "86", "c1", "1d", "9e"],
    ["e1", "f8", "98", "11", "69", "d9", "8e", "94", "9b", "1e", "87", "e9", "ce", "55", "28", "df"],
    ["8c", "a1", "89", "0d", "bf", "e6", "42", "68", "41", "99", "2d", "0f", "b0", "54", "bb", "16"]
]

RCON1 = [
    ["01", "02", "04", "08", "10", "20", "40", "80", "1b", "36"],
    ["00", "00", "00", "00", "00", "00", "00", "00", "00", "00"],
    ["00", "00", "00", "00", "00", "00", "00", "00", "00", "00"],
    ["00", "00", "00", "00", "00", "00", "00", "00", "00", "00"]
]

RCON2 = [
    ["01", "00", "00", "00"],
    ["02", "00", "00", "00"],
    ["04", "00", "00", "00"],
    ["08", "00", "00", "00"],
    ["10", "00", "00", "00"],
    ["20", "00", "00", "00"],
    ["40", "00", "00", "00"],
    ["80", "00", "00", "00"],
    ["1b", "00", "00", "00"],
    ["36", "00", "00", "00"]
]


def rotWord(word):
    return [word[1], word[2], word[3], word[0]]


def keySubBytes(mat):
    matsub = []
    for j in mat:
        x = j[:1]
        y = j[1:]
        matsub.append(SBOX[int(x, 16)][int(y, 16)])
    return matsub


def appendColumn(mat, col_mat):
    col_mat[0].append(mat[0])
    col_mat[1].append(mat[1])
    col_mat[2].append(mat[2])
    col_mat[3].append(mat[3])
    return col_mat


def appendMat(mat, col_mat):
    for i in range(len(mat[0])):
        col_mat[0].append(mat[0][i])
        col_mat[1].append(mat[1][i])
        col_mat[2].append(mat[2][i])
        col_mat[3].append(mat[3][i])
    return col_mat


def hex_bin(string):
    return " ".join(
        reversed([i + j for i, j in zip(*[["{0:04b}".format(int(c, 16)) for c in reversed("0" + string)][n::2] for n
                                          in [1, 0]])]))


def bin_hex(string):
    return hex(int(string, 2))


def xor(a, b, c, d):
    e = hex(int(a, 16) ^ int(b, 16) ^ (int(c, 16) if c != "" else 0) ^ (int(d, 16) if d != "" else 0))
    return "0" + e[2:] if len(e[2:]) == 1 else e[2:]


def multi_xor(col1, col2, col3):
    new_col = []
    if isinstance(col3, list):
        for x, y, z in zip(col1, col2, col3):
            new_col.append(xor(x, y, z, ""))
        return new_col
    else:
        for x, y in zip(col1, col2):
            new_col.append(xor(x, y, "", ""))
        return new_col


def subdivide(matrix):
    dico = {}
    id_k = 0
    n_key = [[], [], [], []]
    counter = 0
    for i in range(len(matrix[0])):
        counter += 1
        n_key[0].append(matrix[0][i])
        n_key[1].append(matrix[1][i])
        n_key[2].append(matrix[2][i])
        n_key[3].append(matrix[3][i])
        if counter == 4:
            dico["k" + str(id_k)] = n_key
            id_k += 1
            n_key = [[], [], [], []]
            counter = 0
    return dico


def galois_multiplication(a, b):
    """Galois multiplication of 8 bit characters a and b."""
    a = int(a, 16)
    b = int(b, 16)
    p = 0
    for counter in range(8):
        if b & 1: p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        # keep a 8 bit
        a &= 0xFF
        if hi_bit_set:
            a ^= 0x1b
        b >>= 1
    return str(hex(p))[2:]


def subBytes(mat):
    matsub = [[], [], [], []]
    for i in range(len(mat)):
        line = mat[i]
        for j in line:
            x = j[:1]
            y = j[1:]
            matsub[i].append(SBOX[int(x, 16)][int(y, 16)])
    return matsub


def shiftRows(mat):
    shift = [1, 2, 3]
    for i in shift:
        for j in range(i):
            elt = mat[i].pop(0)
            mat[i].append(elt)
    return mat


def mixColumn(mat):
    mixed = [[], [], [], []]
    mix = [
        ["02", "03", "01", "01"],
        ["01", "02", "03", "01"],
        ["01", "01", "02", "03"],
        ["03", "01", "01", "02"]
    ]
    for i in range(4):
        xora = []
        for j in range(4):
            m1 = galois_multiplication(mat[0][i], mix[j][0])
            m2 = galois_multiplication(mat[1][i], mix[j][1])
            m3 = galois_multiplication(mat[2][i], mix[j][2])
            m4 = galois_multiplication(mat[3][i], mix[j][3])
            a = xor(m1, m2, m3, m4)
            xora.append(a)
        mixed = appendColumn(xora, mixed)
    return mixed


def addRoundKey(mat, key):
    roundmat = [[], [], [], []]
    for i in range(4):
        m1 = xor(mat[0][i], key[0][i], "", "")
        m2 = xor(mat[1][i], key[1][i], "", "")
        m3 = xor(mat[2][i], key[2][i], "", "")
        m4 = xor(mat[3][i], key[3][i], "", "")
        roundmat = appendColumn([m1, m2, m3, m4], roundmat)
    return roundmat


def keyExpansion(key):
    if len(key[0]) == 8:
        okay = [[], [], [], []]
        okay = appendMat(key, okay)
        for i in range(7):
            n_key = [[], [], [], []]
            l1_line = [key[1][7], key[2][7], key[3][7], key[0][7]]
            l1_prime = keySubBytes(l1_line)
            rcon = RCON2[i]
            first_line = [key[0][0], key[1][0], key[2][0], key[3][0]]
            first_next_line = multi_xor(first_line, rcon, l1_prime)
            n_key = appendColumn(first_next_line, n_key)
            for j in range(1, 8):
                prev_k = [n_key[0][j - 1], n_key[1][j - 1], n_key[2][j - 1], n_key[3][j - 1]]
                key_i = [key[0][j], key[1][j], key[2][j], key[3][j]]
                n_key = appendColumn(multi_xor(key_i, prev_k, ""), n_key)
            key = n_key
            okay = appendMat(n_key, okay)
        return subdivide(okay)
    elif len(key[0]) == 6:
        okay = [[], [], [], []]
        okay = appendMat(key, okay)
        for i in range(8):
            n_key = [[], [], [], []]
            l1_line = [key[1][5], key[2][5], key[3][5], key[0][5]]
            l1_prime = keySubBytes(l1_line)
            rcon = RCON2[i]
            first_line = [key[0][0], key[1][0], key[2][0], key[3][0]]
            first_next_line = multi_xor(first_line, rcon, l1_prime)
            n_key = appendColumn(first_next_line, n_key)
            for j in range(1, 6):
                prev_k = [n_key[0][j - 1], n_key[1][j - 1], n_key[2][j - 1], n_key[3][j - 1]]
                key_i = [key[0][j], key[1][j], key[2][j], key[3][j]]
                n_key = appendColumn(multi_xor(key_i, prev_k, ""), n_key)
            key = n_key
            okay = appendMat(n_key, okay)
        return subdivide(okay)
    elif len(key[0]) == 4:
        dicokey = {"k0": key}
        for i in range(10):
            n_key = [[], [], [], []]
            l1_line = [key[1][3], key[2][3], key[3][3], key[0][3]]
            l1_prime = keySubBytes(l1_line)
            rcon = RCON2[i]
            first_line = [key[0][0], key[1][0], key[2][0], key[3][0]]
            first_next_line = multi_xor(first_line, rcon, l1_prime)
            n_key = appendColumn(first_next_line, n_key)
            for j in range(1, 4):
                prev_k = [n_key[0][j - 1], n_key[1][j - 1], n_key[2][j - 1], n_key[3][j - 1]]
                key_i = [key[0][j], key[1][j], key[2][j], key[3][j]]
                n_key = appendColumn(multi_xor(key_i, prev_k, ""), n_key)
            key = n_key
            dicokey["k" + str(i + 1)] = n_key
        return dicokey
    else:
        return "Clé de chiffrement/déchiffrement non reconnue!!!"


block = [
    ['04', 'e0', '48', '28'],
    ['66', 'cb', 'f8', '06'],
    ['81', '19', 'd3', '26'],
    ['e5', '9a', '7a', '4c']
]

key1 = [
    ["a0", "88", "23", "2a"],
    ["fa", "54", "a3", "6c"],
    ["fe", "2c", "39", "76"],
    ["17", "b1", "39", "05"]
]

key = [
    ["8e", "da", "c8", "80", "62", "52"],
    ["73", "0e", "10", "90", "f8", "2c"],
    ["b0", "64", "f3", "79", "ea", "6b"],
    ["f7", "52", "2b", "e5", "d2", "7b"]
]

main = [
    ["60", "15", "2b", "85", "1f", "3b", "2d", "09"],
    ["3d", "ca", "73", "7d", "35", "61", "98", "14"],
    ["eb", "71", "ae", "77", "2c", "08", "10", "df"],
    ["10", "be", "f0", "81", "07", "d7", "a3", "f4"]
]

#l_line = [main[1][7], main[2][7], main[3][7], main[0][7]]
#print(l_line, '\n\n')
print(keyExpansion(main))
