import string


def get_letter_index(letter) -> int:
    return ord(letter) - ord('A')


def get_letter_from_index(letter) -> str:
    return chr(letter + ord('A'))


def get_expected_freq():
    #Frequency from class slides - Classic Ciphers
    freq = {
        'A': 0.082,
        'B': 0.015,
        'C': 0.028,
        'D': 0.042,
        'E': 0.127,
        'F': 0.022,
        'G': 0.020,
        'H': 0.061,
        'I': 0.070,
        'J': 0.001,
        'K': 0.008,
        'L': 0.04,
        'M': 0.024,
        'N': 0.067,
        'O': 0.075,
        'P': 0.019,
        'Q': 0.001,
        'R': 0.06,
        'S': 0.063,
        'T': 0.09,
        'U': 0.028,
        'V': 0.01,
        'W': 0.024,
        'X': 0.01,
        'Y': 0.02,
        'Z': 0.001,
    }
    return freq


def chi_square_test(text: str):
    """
        Calculate the chi-square statistic for the given text
        http://practicalcryptography.com/cryptanalysis/text-characterisation/chi-squared-statistic/
    """
    expected_freq = get_expected_freq()

    text = text.upper()
    total_characters = len(text)
    chi_square = 0.0

    for letter in string.ascii_uppercase:
        observed_count = text.count(letter)
        expected_count = total_characters * expected_freq[letter]
        chi_square += ((observed_count - expected_count) ** 2) / expected_count

    return chi_square


def vigenere_decrypt(ciphertext: str, key: str) -> str:
    """
        Decrpyt vigenere cipher by using key
    """

    decrypted_text = ''
    key_length = len(key)

    for i in range(len(ciphertext)):
        letter = ciphertext[i]
        shift = get_letter_index(key[i % key_length])
        decrypted_index = (get_letter_index(letter) - shift) % 26
        decrypted_char = get_letter_from_index(decrypted_index)
        decrypted_text += decrypted_char

    return decrypted_text


def break_vigenere_cipher(ciphertext: str, key_length: int):
    key = ''

    for i in range(key_length):
        subtext = ''

        for j in range(i, len(ciphertext), key_length):
            subtext += ciphertext[j]

        best_shift = 0
       
        lowest_chi_square = float('inf')

        for shift in range(26):
            # decrypt the key
            # try all alphabet letters to find key
            decrypted_subtext = vigenere_decrypt(subtext, get_letter_from_index(shift))
            # check chi square
            chi_square = chi_square_test(decrypted_subtext)
            # if chi square st. is lowest, this is best shift.
            if chi_square < lowest_chi_square:
                lowest_chi_square = chi_square
                best_shift = shift

        key += get_letter_from_index(best_shift)

    return key


if __name__ == '__main__':
    ciphertext = input('Input text encrypted with Vigener cipher (lowercase letters will be capitalized and spaces will be removed):').upper().replace(" ", "")
    key_length = int(input('Input key length:'))

    # Break the Vigenère cipher and find the key
    key = break_vigenere_cipher(ciphertext, key_length)

    # Decrypt the ciphertext using the found key
    decrypted_text = vigenere_decrypt(ciphertext, key)

    print('Found key:', key)
    print('Decrypted text:', decrypted_text)
