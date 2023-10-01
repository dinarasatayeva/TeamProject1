import string

# Constants!
ALPHABET = string.ascii_uppercase
ALPHABET_LIST = {value: i for i, value in enumerate(ALPHABET)}
ALPHABET_LIST_INDEX = {i: value for i, value in enumerate(ALPHABET)}


# Find a^-1 (the multiplicative inverse of a in the group of integers modulo m.)
# a * i mod 26
def findInverseMod(a):
    for i in range(26):
        if (a * i) % 26 == 1:
            return i
    return None


def find_coefficients(known_letters: list):
    differenceDecryptedLetters = ALPHABET_LIST[known_letters[0]['dec']]
    differenceEncryptedLetters = ALPHABET_LIST[known_letters[0]['enc']]

    for value in known_letters[1:]:
        differenceDecryptedLetters = differenceDecryptedLetters - ALPHABET_LIST[value['dec']]
        differenceEncryptedLetters = differenceEncryptedLetters - ALPHABET_LIST[value['enc']]

    inverseMod = findInverseMod(differenceDecryptedLetters)
    if inverseMod is None:
        raise ValueError("No inverse mod")

    aCoefficient = (differenceEncryptedLetters * inverseMod) % 26
    bCoefficient = (ALPHABET_LIST[known_letters[0]['enc']] - (aCoefficient * ALPHABET_LIST[known_letters[0]['dec']])) % 26

    return aCoefficient, bCoefficient


def decryption(text: str, aCoefficient: int, bCoefficient: int):
    decrypted_text = ""
    a_inv = findInverseMod(aCoefficient)
    for char in text:
        new_char = (a_inv * (ALPHABET_LIST[char] - bCoefficient)) % 26
        decrypted_text = decrypted_text + ALPHABET_LIST_INDEX[new_char]

    return decrypted_text


def known_key_attack():
    print('Known key attack: ')
    encrypted_text = input('Input encrypted text (lowercase letters will be capitalized):').upper()
    known_letters = []
    for i in range(2):
        letter_decrypted = input('Input decrypted letter (lowercase letter will be capitalized):').upper()
        letter_encrypted = input('Input encrypted letter (lowercase letter will be capitalized):').upper()
        known_letters.append({'enc': letter_encrypted, 'dec': letter_decrypted})

    try:
        aCoefficient, bCoefficient = find_coefficients(known_letters)
        print('Decrypted:')
        print("a value: " + str(aCoefficient))
        print("b value: " + str(bCoefficient))
        print(decryption(encrypted_text, aCoefficient, bCoefficient))
    except ValueError:
        print('Not decrypted')

known_key_attack()
