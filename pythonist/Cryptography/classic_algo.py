from copy import deepcopy
import random


"""Usefull Fonctions"""

#Convertit une chaine en majuscules non accentuées
def to_upper(ch):

    alpha1 = u"aàÀâÂäÄåÅbcçÇdeéÉèÈêÊëËfghiîÎïÏjklmnoôÔöÖpqrstuùÙûÛüÜvwxyÿŸz"
    alpha2 = u"AAAAAAAAABCCCDEEEEEEEEEFGHIIIIIJKLMNOOOOOPQRSTUUUUUUUVWXYYYZ"
    let = ""
    for c in ch:
        k = alpha1.find(c)  # k = indice de "c" dans alpha1
        if k >= 0:
            # "c" est dans alpha1: on remplace par le car. correspondant de alpha2
            let += alpha2[k]
        else:
            # "c" n'est pas dans alpha1: on le laisse passer
            let += c
    return let

#Calculate the Determinant of a matrix
def det_matrix_2(matrix):
    return (matrix[0][0] * matrix[1][1]) - (matrix[1][0] * matrix[0][1])


def det_matrix_n(matrix):
    det = 0
    if len(matrix) == 2:
        det = det_matrix_2(matrix)
        return det
    else:
        det_list = []
        list_coefficient = matrix[0]
        for x in range(len(matrix)):
            mat = deepcopy(matrix)
            del mat[0]
            j = len(mat)
            for y in range(j):
                del mat[y][x]
            det_list.append(det_matrix_n(mat))
        for z in range(len(det_list)):
            if (z % 2) == 0:
                det += list_coefficient[z] * det_list[z]
            else:
                det += (-list_coefficient[z]) * det_list[z]
        return det

#Calculates the Comatrix of a matrix
def co_matrix_2(matrix):
    return [[matrix[1][1], (-(matrix[1][0]))], [(-(matrix[0][1])), matrix[0][0]]]


def co_matrix(matrix):
    com = []
    for w in range(len(matrix)):
        mat_list = []
        com_2 = []
        for x in range(len(matrix)):
            mat = deepcopy(matrix)
            del mat[w]
            j = len(mat)
            for y in range(j):
                del mat[y][x]
            mat_list.append(det_matrix_n(mat))
        com.append([mat_list[i] if ((w + i) % 2) == 0 else (-(mat_list[i])) for i in range(len(mat_list))])
    return com

#Calculate the transpose of a matrix
def trans_matrix(matrix):
    return [[matrix[y][x] for y in range(len(matrix))] for x in range(len(matrix))]

#Calculate the inverse of the determinant modulo 26
def reverse_det(det):
    i = 1
    det_inv = 0
    while i <= 25:
        if (i * det) % 26 == 1:
            det_inv = i
            break
        i += 1
    return det_inv

#Compute the inverse of the matrix
def inv_matrix(com_matrix, inv_det):
    trans_co_mat = trans_matrix(com_matrix)
    return [[(inv_det * trans_co_mat[x][y]) % 26 for y in range(len(trans_co_mat))] for x in range(len(trans_co_mat))]


"""ENCRYPTION KEY GENERATION FUNCTION"""

#Shift encryption key
def gen_key_shift():
    return random.randint(1, 25)

#Affine encryption key
def gen_key_affine():
    while True:
        key_list = [random.randint(1, 25), random.randint(1, 25)]
        if (key_list[0] % 2) == 1:
            break
    i = 1
    while i <= 25:
        inv_k = i
        if ((inv_k * key_list[0]) % 26) == 1:
            key_list.append(inv_k)
            break
        i += 1
    return key_list


#Substitution Encryption Key
def gen_key_subs():
    subs_alpha = []
    while True:
        str_alpha = "".join(subs_alpha)
        alpha = chr(random.randint(65, 90))
        if str_alpha.find(alpha) == -1:
            subs_alpha.append(alpha)
            if len(subs_alpha) == 26:
                break
    return subs_alpha

#Permutation encryption key
def gen_key_perm(height):
    key_height = random.randint(2, height)
    key = [i for i in range(0, key_height)]
    random.shuffle(key)
    return key

#Vigenere encryption key
def gen_key_vigenere(height):
    key_height = (random.randint(2, height) if height <= 4 else random.randint(2, int(height / 2)))
    key = [random.randint(0, 25) for i in range(0, key_height)]
    random.shuffle(key)
    return key

#Hill's encryption key
def gen_key_hill(height):
    if height > 4:
        tail = random.randint(2, 4)
    else:
        tail = random.randint(2, height)
    inv_det = 0
    while True:
        matrix = [[random.randint(1, 10) for y in range(tail)] for x in range(tail)]
        inv_det = reverse_det(det_matrix_n(matrix))
        if inv_det != 0:
            break
        else:
            pass
    rev_key_mat = inv_matrix(co_matrix(matrix), inv_det) if tail != 2 else inv_matrix(co_matrix_2(matrix), inv_det)
    return matrix, rev_key_mat

#Vernam's encryption key
def gen_key_vernam(height):
    key = [random.randint(0, 25) for i in range(0, height)]
    random.shuffle(key)
    return key


"""ENCRYPTION FUNCTIONS"""

#Shift cypher algorithms
def cypher_shift(key, text):
    cypher_letter = []
    upper_text = to_upper(text)
    upper_text = upper_text.replace(" ", "")
    alphabet = [chr(j) for j in range(65, 91)]
    for i in range(len(upper_text)):
        letter = upper_text[i]
        if letter in alphabet:
            pos = alphabet.index(letter)
            cyp_let = (pos + key) % 25
            cypher_letter.append(alphabet[cyp_let])
        else:
            cypher_letter.append(letter)
    return "".join(cypher_letter), [i for i in range(0, len(text)) if text[i] == " "]

#Affine cypher algorithms
def cypher_affine(key, text):
    cypher_letter = []
    upper_text = to_upper(text)
    alphabet = [chr(j) for j in range(65, 91)]
    for i in range(len(text)):
        letter = upper_text[i]
        if letter in alphabet:
            pos = alphabet.index(letter)
            cyp_let = ((key[0] * pos) + key[1]) % 26
            cypher_letter.append(alphabet[cyp_let])
        else:
            cypher_letter.append(letter)
    return "".join(cypher_letter)

#Substitution cypher algorithms
def cypher_subs(key, text):
    cypher_letter = []
    upper_text = to_upper(text)
    alphabet = [chr(j) for j in range(65, 91)]
    for x in range(len(text)):
        letter = upper_text[x]
        if letter in alphabet:
            pos = alphabet.index(letter)
            cyp_let = key[pos]
            cypher_letter.append(cyp_let)
        else:
            cypher_letter.append(letter)
    return "".join(cypher_letter)

#Permutation cypher algorithms
def cypher_perm(key, text):
    cypher_letter = []
    upper_text = to_upper(text)
    if len(text) % len(key) == 0:
        for x in range(0, len(text), len(key)):
            bloc = upper_text[x:(len(key) + x)]
            cypher_letter += [bloc[key[i]] for i in range(len(key))]
    else:
        upper_text += "X" * (len(key) - (len(text) % len(key)))
        for x in range(0, (len(text) + 1), len(key)):
            bloc = upper_text[x:(len(key) + x)]
            cypher_letter += [bloc[key[i]] for i in range(len(key))]
    return "".join(cypher_letter)

#Vigenere cypher algorithms
def cypher_vigenere(key, text):
    cypher_letter = []
    upper_text = to_upper(text)
    space = [i for i in range(0, len(text)) if upper_text[i] == " "]
    upper_text = upper_text.replace(" ", "")
    alphabet = [chr(j) for j in range(65, 91)]
    if len(upper_text) % len(key) == 0:
        for x in range(0, len(upper_text), len(key)):
            bloc = upper_text[x:(len(key) + x)]
            cypher_letter += [alphabet[((alphabet.index(bloc[i]) + key[i]) % 26)] if bloc[i] in alphabet else bloc[i]
                              for i in range(len(key))]
    else:
        upper_text += "X" * (len(key) - (len(upper_text) % len(key)))
        for x in range(0, (len(upper_text)), len(key)):
            bloc = upper_text[x:(len(key) + x)]
            cypher_letter += [alphabet[((alphabet.index(bloc[i]) + key[i]) % 26)] if bloc[i] in alphabet else bloc[i]
                              for i in range(len(key))]
    return "".join(cypher_letter), space

#Hill's cypher algorithms
def cypher_hill(text, key):
    cypher_letter = []
    upper_text = to_upper(text)
    alphabet = [chr(j) for j in range(65, 91)]
    upper_text = [upper_text[i] if upper_text[i] in alphabet else (" " if upper_text[i] == " " else "") for i in
                  range(len(upper_text))]
    upper_text = "".join(upper_text)
    space = [i for i in range(0, len(upper_text)) if upper_text[i] == " "]
    upper_text = upper_text.replace(" ", "")
    tail = len(upper_text)
    if len(upper_text) % len(key) == 0:
        for x in range(0, len(upper_text), len(key)):
            bloc = upper_text[x:(len(key) + x)]
            for y in range(len(key)):
                ciphered = 0
                char = ""
                for z in range(len(key)):
                    if bloc[z] in alphabet:
                        ciphered += key[y][z] * alphabet.index(bloc[z])
                cypher_letter.append(char if char != "" else alphabet[(ciphered % 26)])
    else:
        upper_text += "X" * (len(key) - (len(upper_text) % len(key)))
        for x in range(0, (len(upper_text)), len(key)):
            bloc = upper_text[x:(len(key) + x)]
            for y in range(len(key)):
                ciphered = 0
                char = ""
                for z in range(len(key)):
                    if bloc[z] in alphabet:
                        ciphered += key[y][z] * alphabet.index(bloc[z])
                cypher_letter.append(char if char != "" else alphabet[(ciphered % 26)])
    return "".join(cypher_letter), space, tail

#Vernam's cypher algorithms
def cypher_vernam(key, text):
    cypher_letter = []
    upper_text = to_upper(text)
    space = [i for i in range(0, len(text)) if upper_text[i] == " "]
    upper_text = upper_text.replace(" ", "")
    alphabet = [chr(j) for j in range(65, 91)]
    for x in range(0, len(upper_text), len(key)):
        bloc = upper_text[x:(len(key) + x)]
        cypher_letter += [alphabet[((alphabet.index(bloc[i]) + key[i]) % 25)] if bloc[i] in alphabet else bloc[i] for i
                          in range(len(key))]
    return "".join(cypher_letter), space



"""DECIPHERING FUNCTIONS"""

#Shift deciphering algorithms
def decipher_shift(key, text, space):
    decipher_letter = []
    upper_text = to_upper(text)
    alphabet = [chr(j) for j in range(65, 91)]
    for i in range(len(text)):
        letter = upper_text[i]
        if letter in alphabet:
            pos = alphabet.index(letter)
            cyp_let = (pos - key) % 25
            decipher_letter.append(alphabet[cyp_let])
        else:
            decipher_letter.append(letter)
    for i in range(len(space)):
        decipher_letter.insert(space[i], " ")
    return "".join(decipher_letter)

#Affine deciphering algorithms
def decipher_affine(key, text):
    cypher_letter = []
    upper_text = to_upper(text)
    alphabet = [chr(j) for j in range(65, 91)]
    for i in range(len(text)):
        letter = upper_text[i]
        if letter in alphabet:
            pos = alphabet.index(letter)
            cyp_let = (key[2] * (pos - key[1])) % 26
            cypher_letter.append(alphabet[cyp_let])
        else:
            cypher_letter.append(letter)
    return "".join(cypher_letter)

#Substitution deciphering algorithms
def decipher_subs(key, text):
    cypher_letter = []
    upper_text = to_upper(text)
    alphabet = [chr(j) for j in range(65, 91)]
    for x in range(len(text)):
        letter = upper_text[x]
        if letter in alphabet:
            pos = key.index(letter)
            cyp_let = alphabet[pos]
            cypher_letter.append(cyp_let)
        else:
            cypher_letter.append(letter)
    return "".join(cypher_letter)

#Permutation deciphering algorithms
def decipher_perm(key, text, or_height):
    decipher_letter = []
    upper_text = text
    if len(text) == or_height:
        for x in range(0, len(text), len(key)):
            bloc = upper_text[x:(len(key) + x)]
            decipher_letter += [bloc[key.index(i)] for i in range(len(key))]
    else:
        for x in range(0, (len(text) - 1), len(key)):
            bloc = upper_text[x:(len(key) + x)]
            decipher_letter += [bloc[key.index(i)] for i in range(len(key))]
        decipher_letter = decipher_letter[: or_height]
    return "".join(decipher_letter)

#Vigenere deciphering algorithms
def decipher_vigenere(key, text, or_height, space):
    decipher_letter = []
    upper_text = text.replace(" ", "")
    alphabet = [chr(j) for j in range(65, 91)]
    if len(upper_text) == or_height:
        for x in range(0, len(upper_text), len(key)):
            bloc = upper_text[x:(len(key) + x)]
            decipher_letter += [alphabet[((alphabet.index(bloc[i]) - key[i]) % 26)] if bloc[i] in alphabet else bloc[i]
                                for i in range(len(key))]
    else:
        for x in range(0, (len(upper_text) - 1), len(key)):
            bloc = upper_text[x:(len(key) + x)]
            decipher_letter += [alphabet[((alphabet.index(bloc[i]) - key[i]) % 26)] if bloc[i] in alphabet else bloc[i]
                                for i in range(len(key))]
    for i in range(len(space)):
        decipher_letter.insert(space[i], " ")
    decipher_letter = decipher_letter[: or_height]
    return "".join(decipher_letter)

#Hill's deciphering algorithms
def decipher_hill(text, key, space, or_height):
    decipher_letter = []
    upper_text = text.replace(" ", "")
    alphabet = [chr(j) for j in range(65, 91)]
    if len(upper_text) == or_height:
        for x in range(0, len(upper_text), len(key)):
            bloc = upper_text[x:(len(key) + x)]
            for y in range(len(key)):
                ciphered = 0
                char = ""
                for z in range(len(key)):
                    if bloc[z] in alphabet:
                        ciphered += key[y][z] * alphabet.index(bloc[z])
                    else:
                        char = bloc[z]
                decipher_letter.append(char if char != "" else alphabet[(ciphered % 26)])
    else:
        for x in range(0, (len(upper_text)), len(key)):
            bloc = upper_text[x:(len(key) + x)]
            for y in range(len(key)):
                ciphered = 0
                char = ""
                for z in range(len(key)):
                    if bloc[z] in alphabet:
                        ciphered += key[y][z] * alphabet.index(bloc[z])
                    else:
                        char = bloc[z]
                decipher_letter.append(char if char != "" else alphabet[(ciphered % 26)])
    decipher_letter = decipher_letter[: or_height]
    for i in range(len(space)):
        decipher_letter.insert(space[i], " ")
    return "".join(decipher_letter)

#Vernam's deciphering algorithms
def decipher_vernam(key, text, space):
    decipher_letter = []
    upper_text = text.replace(" ", "")
    alphabet = [chr(j) for j in range(65, 91)]
    for x in range(0, len(upper_text), len(key)):
        bloc = upper_text[x:(len(key) + x)]
        decipher_letter += [alphabet[((alphabet.index(bloc[i]) - key[i]) % 25)] if bloc[i] in alphabet else bloc[i]
                            for i in range(len(key))]
    for i in range(len(space)):
        decipher_letter.insert(space[i], " ")
    return "".join(decipher_letter)


"""MAIN MENU"""
print("\n\t\t\t WELCOM TO YOUR CYPHER AND DECIPHER PROGRAM \n")
print("\n\t\t\t\t MENU \n")
print("1. SHIFT CYPHER")
print("2. AFFINE CYPHER")
print("3. SUBSTITUTION CYPHER")
print("4. PERMUTATION")
print("5. VIGENERE CYPHER")
print("6. HILL CYPHER")
print("7. VERNAM CYPHER")
while True:
    choice = input("Enter your choice (or 8 to quit): ")
    try:
        choice = int(choice)
        if 0 < choice < 9:
            break
        else:
            print("The number your entered is not on the range")
    except ValueError:
        print("what you enter is not a number\n")

if choice == 1:
    print("\t\t\tWELCOME TO THE SHIFT ENCRYPTION MODULE")
    plain_text = input("Enter your message : ")
    enc_key = gen_key_shift()
    encrypt, spaces = cypher_shift(enc_key, plain_text)
    decrypt = decipher_shift(enc_key, encrypt, spaces)

    print("Your message was : {}\nThe encrypted message is : {}\n"
          "After decryption we have : {}".format(plain_text, encrypt, decrypt))
elif choice == 2:
    print("\t\t\tWELCOME TO THE AFFINE ENCRYPTION MODULE")
    plain_text = input("Enter your message : ")
    enc_key = gen_key_affine()
    encrypt = cypher_affine(enc_key, plain_text)
    decrypt = decipher_affine(enc_key, encrypt)

    print("Your message was : {}\nWith the encryption key a = {} and b = {}\nThe encrypted message is : {}\n"
      "After decryption we have : {}".format(plain_text, enc_key[0], enc_key[1], encrypt, decrypt))
elif choice == 3:
    print("\t\t\tWELCOME TO THE SUBSTITUTION ENCRYPTION MODULE")
    plain_text = input("Enter your message : ")
    enc_key = gen_key_subs()
    encrypt = cypher_subs(enc_key, plain_text)
    decrypt = decipher_subs(enc_key, encrypt)

    print("Your message was : {}\nThe encrypted message is : {}\n"
          "After decryption we have : {}".format(plain_text, encrypt, decrypt))
elif choice == 4:
    print("\t\t\tWELCOME TO THE PERMUTATION ENCRYPTION MODULE")
    plain_text = input("Enter your message : ")
    enc_key = gen_key_perm(len(plain_text))
    encrypt = cypher_perm(enc_key, plain_text)
    decrypt = decipher_perm(enc_key, encrypt, len(plain_text))

    print("Your message was : {}\nWith the key : {}\nThe encrypted message is : {}\n"
          "After decryption we have : {}".format(plain_text, enc_key, encrypt, decrypt))
elif choice == 5:
    print("\t\t\tWELCOME TO THE VIGENERE ENCRYPTION MODULE")
    plain_text = input("Enter your message : ")
    enc_key = gen_key_vigenere(len(plain_text.replace(" ", "")))
    encrypt, spaces = cypher_vigenere(enc_key, plain_text)
    decrypt = decipher_vigenere(enc_key, encrypt, len(plain_text), spaces)

    print("Your message was : {}\nWith the key : {}\nThe encrypted message is : {}\n"
          "After decryption we have : {}".format(plain_text, enc_key, encrypt, decrypt))
elif choice == 6:
    print("\t\t\tWELCOME TO THE HILL ENCRYPTION MODULE")
    plain_text = input("Enter your message : ")
    enc_key, dec_key = gen_key_hill(len(plain_text))
    encrypt, spaces, heights = cypher_hill(plain_text, enc_key)
    decrypt = decipher_hill(encrypt, dec_key, spaces, heights)
    print("Your message was : {}\n With the encryption key \n{}\nThe encrypted message is : {} \nand with the decryption "
          "key is\n{}\nWe have : {}".format(plain_text, enc_key, encrypt, dec_key, decrypt))
elif choice == 7:
    print("\t\t\tWELCOME TO THE VERNAM ENCRYPTION MODULE")
    plain_text = input("Enter your message : ")
    enc_key = gen_key_vernam(len(plain_text.replace(" ", "")))
    encrypt, spaces = cypher_vernam(enc_key, plain_text)
    decrypt = decipher_vernam(enc_key, encrypt, spaces)

    print("Your message was : {}\nWith the key : {}\nThe encrypted message is : {}\n"
          "After decryption we have : {}".format(plain_text, enc_key, encrypt, decrypt))
else:
    pass