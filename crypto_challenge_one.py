# Decode the two ciphertexts from the Instructors Box below, 
# or the C1, C2 variables - which are the same
#
# We highly recommend that you run your decoding code in the 
# programming language of your choice outside of the 
# this environment, as this system does not provide enough 
# computational resources to successfully decode
#
# After decoding the two ciphertexts, 
# replace the plaintext1 and plaintext2 variables below
# with the decoded ciphertexts

# C1 and C2 are messages in english, 
# encoded using string_to_bits, with 7bit ASCII
# and then XOR'd with a secret key
#
# In pseudo-code:
# C1 = XOR(string_to_bits(plaintext1), secret_key)
# C2 = XOR(string_to_bits(plaintext2), secret_key)

C1 = "1010110010011110011111101110011001101100111010001111011101101011101000110010011000000101001110111010010111100100111101001010000011000001010001001001010000000010101001000011100100010011011011011011010111010011000101010111111110010011010111001001010101110001111101010000001011110100000000010010111001111010110000001101010010110101100010011111111011101101001011111001101111101111000100100001000111101111011011001011110011000100011111100001000101111000011101110101110010010100010111101111110011011011001101110111011101100110010100010001100011001010100110001000111100011011001000010101100001110011000000001110001011101111010100101110101000100100010111011000001111001110000011111111111110010111111000011011001010010011100011100001011001101110110001011101011101111110100001111011011000110001011111111101110110101101101001011110110010111101000111011001111"

C2 = "1011110110100110000001101000010111001000110010000110110001101001111101010000101000110100111010000010011001100100111001101010001001010001000011011001010100001100111011010011111100100101000001001001011001110010010100101011111010001110010010101111110001100010100001110000110001111111001000100001001010100011100100001101010101111000100001111101111110111001000101111111101011001010000100100000001011001001010000101001110101110100001111100001011101100100011000110111110001000100010111110110111010010010011101011111111001011011001010010110100100011001010110110001001000100011011001110111010010010010110100110100000111100001111101111010011000100100110011111011001010101000100000011111010010110111001100011100001111100100110010010001111010111011110110001000111101010110101001110111001110111010011111111010100111000100111001011000111101111101100111011001111"

C12 = "\x08N\x0f\x06\x1d\x10A\x1b\x01\x15EC\x0eN\x07\x00\t\x00R\x04H\x04\x1cI\x03\rM\x12\x1d\x05\x0fA\x0eEM\x11\x1bH\x1d\x0b\x11O\x1b\x15\x00\x07\x1a\x0e\x10U\x07\x06\t\x14\x00\x13\x13\x0bD\x1b\x02\x00\x0c\x1c\n\x08\x1a\x00\x0cI\x12BDO/\x07\x0eO\x07\x1d\x1c\x11EN\x0eNF\x0eRS\x00\t\x11EM\x0e\x05H\x1a\x07\x0b]\x0e\x08jG+\x02A\x03\x0b\x0b\x00\x1d\r\x14\x03\x0f\x01\x00\x00"
C12_bits = '0001000100111000011110000110001110100100001000001001101100000010010101100010110000110001110100111000001110000000000100100000001010010000010010010000000100001110010010010000011000110110011010010010001110100001010001111100000100011101000101100110100100010011011100100000111010001011001000110011110011011001010100000000000111001101000011100010000101010100001110000110000100100101000000000001001100100110001011100010000110110000010000000000011000011100000101000010000011010000000000011001001001001001010000101000100100111101011110000111000111010011110000111001110100111000010001100010110011100001110100111010001100001110101001010100110000000000100100100011000101100110100011100000101100100000110100000111000101110111010001110000100011010101000111010101100000101000001000001100010110001011000000000111010001101001010000000110001111000000100000000000000'
CTHE = '  the the the the the the the the the the the the the the the the the the the the the the the the the the the the the the'
THE_BITS = '1110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100110100011001011110100'


the_hit          = '  the the the the the the the the the the the the the the the the the the the the the for the most he the the the the the'

first_hit        = "(n{nx05sd51+knshl &l-$h!f-9zx%{)ke9y~hictoo}e'nfuusnl4t{v+0sg xto(nhiif*!o[okosuy11&kn2f state f`hnon}z`\x0fg_j$#\x7fce=y|f/uhe"
actual_hit = "(n{nx05sd51+knshl &l-$h!f-9zx%{)ke9y~hictoo}e'nfuusnl4t{v+0sg xto(nhiif*!o[okosuy11 to a state av<:on}z`\x0fg_j$#\x7fce=y|f/uhe"
#####CTHE = '  the the the the the the the the the the the the the the the the the the the the the the the the the the the the the the'
original_the_hit = "the the the the the the the the the the the the the the the the the the the the the the  state the the the the the the th"
    P2 = "for for for for for for for for for for for for for for for for for for for for for for  state for for for for for for  e"

to_hit = 'to to to to to to to to to to to to to to to to to to to to to to to to to to to to to t state to to to to to to to to to'
th     = '  that that that that that that that that that that that that that that that that that t state   that that that that that'
th     = '   that that that that that that that that that that that that that that that that that  state    that that that that tha'
th     = '    that that that that that that that that that that that that that that that that tha  state     that that that that th'
th     = '     that that that that that that that that that that that that that that that that th  state      that that that that t'

wh =     'with with with with with with with with with with with with with with with with with wit state with with with with with w'
wh =     ' with with with with with with with with with with with with with with with with with wi state  with with with with with '
wh =     '  with with with with with with with with with with with with with with with with with w state   with with with with with'
wh =     '   with with with with with with with with with with with with with with with with with  state    with with with with wit'
wh =     '    with with with with with with with with with with with with with with with with with state     with with with with wi'
 
fh =     'from from from from from from from from from from from from from from from from from fro state from from from from from  '
fh =     ' from from from from from from from from from from from from from from from from from fr state  from from from from from '
fh =     '  from from from from from from from from from from from from from from from from from f state   from from from from from'
fh =     '   from from from from from from from from from from from from from from from from from  state    from from from from fro'
fh =     '    from from from from from from from from from from from from from from from from from state     from from from from fr'
       

#"the the the the the the the the the the the the the the the the the the the the the the  state the the the the the the th"

#####
# CHANGE THESE VARIABLES

plaintext1 = "decoded message"
plaintext2 = "the other decoded message"

# END
#############

#############
# Below is some code that might be useful
#

BITS = ('0', '1')
ASCII_BITS = 7

def display_bits(b):
    """converts list of {0, 1}* to string"""
    return ''.join([BITS[e] for e in b])

def seq_to_bits(seq):
    return [0 if b == '0' else 1 for b in seq]

def pad_bits(bits, pad):
    """pads seq with leading 0s up to length pad"""
    assert len(bits) <= pad
    return [0] * (pad - len(bits)) + bits
                                
def convert_to_bits(n):
    """converts an integer `n` to bit array"""
    result = []
    if n == 0:
        return [0]
    while n > 0:
        result = [(n % 2)] + result
        n = n / 2
    return result

def string_to_bits(s):
    def chr_to_bit(c):
        return pad_bits(convert_to_bits(ord(c)), ASCII_BITS)
    return [b for group in 
            map(chr_to_bit, s)
            for b in group]

def bits_to_char(b):
    assert len(b) == ASCII_BITS
    value = 0
    for e in b:
        value = (value * 2) + e
    return chr(value)

def list_to_string(p):
    return ''.join(p)

def bits_to_string(b):
    return ''.join([bits_to_char(b[i:i + ASCII_BITS]) 
                   for i in range(0, len(b), ASCII_BITS)])


def xor_list(lone, ltwo):
    return [lone[i] ^ ltwo[i]
            for i in range(0, len(lone))]

def get_the_string(c12):
    return ''.join('the' * (len(c12)/3))