#!/usr/bin/env python
# encoding: utf-8

"""
   @author: Joshua Tallman
  @license: MIT Licence
  @contact: joshua.tallman@cui.edu
     @file: cui_des.py
     @time: 2022-09-23 20:45

Copyright 2022 Joshua Tallman

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
"""


def _add_padding(message):
    """ Adds padding to the end of a byte string to make its length a multiple
        of eight. The value of each byte of padding is equal to the number of
        bytes being added to the byte string.
        For example:
          _add_padding(b"CSC428")   => b"CSC428\x02\x02"
          _add_padding(b"TALLMAN")  => b"TALLMAN\x01"
          _add_padding(b"JTALLMAN") => b"JTALLMAN\x08\x08\x08\x08\x08\x08\x08\x08"
    """
    pad_len = 8 - (len(message) % 8)
    padding = pad_len * chr(pad_len)
    message += padding.encode("utf-8")
    return message


def _rem_padding(message):
    """ Removes the padding off the end of a byte string where the last byte
        specifies the number of bytes to remove.
        For example:
          _rem_padding(b"CSC428\x02\x02") => b"CSC428"
          _rem_padding(b"TALLMAN\x01")    => b"TALLMAN"
          _rem_padding(b"JTALLMAN\x08\x08\x08\x08\x08\x08\x08\x08") => b"JTALLMAN"
    """
    byte_cnt = message[-1]
    return message[:-byte_cnt]


def _bytes_to_bit_array(byte_string):
    """ Converts a byte string into an array of bits (list of integers 0/1).
        For example:
          _bytes_to_bit_array(b"\x00") => [0, 0, 0, 0]
          _bytes_to_bit_array(b"\x05") => [0, 1, 0, 1]
          _bytes_to_bit_array(b"\xFF") => [1, 1, 1, 1]
    """
    bit_count = len(byte_string) * 8
    result = [0] * bit_count
    idx = 0
    for byte in byte_string:
        for bit_pos in [7,6,5,4,3,2,1,0]:
            mask = 1 << bit_pos
            if byte & mask > 0:
                result[idx] = 1
            idx += 1
    return result


def _bit_array_to_bytes(bit_array):
    """ Converts an array of bits (list of integers 0/1) into a byte string.
        For example:
          _bit_array_to_bytes([0, 0, 0, 0]) => b"\x00"
          _bit_array_to_bytes([0, 1, 0, 1]) => b"\x05"
          _bit_array_to_bytes([1, 1, 1, 1]) => b"\xFF"
    """
    result = []
    byte = 0
    for idx, bit in enumerate(bit_array):
        pos = idx % 8
        byte += bit << (7 - pos)
        if pos == 7:
            result += [byte]
            byte = 0
    return bytes(result)


def _nsplit(data, split_size=64):
    """ Divides the data into blocks that are 'split_size' in length, yielding
        one block at a time. If the data is not evenly divisible by the split
        size then the last block will be smaller than all the others.
        For example:
          _nsplit(b'1111222233334444', 4) => [ b'1111',b'2222',b'3333',b'4444' ]
          _nsplit(b'ABCDEFGHIJKLMN', 3) => [ b'ABC',b'DEF',b'GHI',b'JKL',b'MN' ]
    """
    full_block_count = len(data) // split_size
    last_block_size  = len(data) % split_size
    for n in range(full_block_count):
        start = n * split_size
        stop  = start + split_size
        yield data[start:stop]
    if last_block_size > 0:
        yield data[start:]


def _permute(block, table):
    """ Transposes a block of data according to the specified permutation
        table, which is simply an n-element array that specifies the index
        of each element from the source array.
        For example:
          _permute(b"ABCDEFGH", [7, 6, 5, 4, 3, 2, 1, 0]) => b"HGFEDCBA"
          _permute(b"ABCDEFGH", [2, 3, 6, 7, 1, 0, 5, 4]) => b"CDGHBAFE"
          _permute(b"TBAECEOF", [1, 3, 5, 7, 0, 2, 4, 6]) => b"BEEFTACO"
    """
    return [block[x] for x in table]


def _lshift(sequence, n):
    """ Left shifts sequence of bytes by the specified number. All elements
        that fall off the left side are rotated back around to the right side.
        For example:
          _lshift('abcdefghijklmnopqrstuvwxyz', 1) => 'bcdefghijklmnopqrstuvwxyza'
          _lshift('abcdefghijklmnopqrstuvwxyz', 2) => 'cdefghijklmnopqrstuvwxyzab'
          _lshift('abcdefghijklmnopqrstuvwxyz', 5) => 'fghijklmnopqrstuvwxyzabcde'
    """
    n = n % len(sequence)
    return sequence[n:] + sequence[:n]


def _xor(x, y):
    """ Bitwise XOR of two iterable variables. If the iterables are different
        lengths, then the function will only compute XOR over the parallel
        portion of the two sequences.
        For example:
          _xor([0,0,1,1], [0,1,0,1])       => [0,1,1,0]
          _xor([0,0,1,1], [0,1])           => [0,1]
          _xor([1,2,3,4], [1,2,3,0])       => [0,0,0,4]
          _xor([0x0F0F], [0x55AA])         => [0x5AA5]
          _xor([0x0F, 0x0F], [0x55, 0xAA]) => [0x5A, 0xA5]
          _xor(b"\x0F\x0F", b"\x55\xAA")   => [0x5A, 0xA5]
          _xor(0x0F0F, 0x55AA)             => TypeError: not iterable
    """
    return [xn ^ yn for xn, yn in zip(x, y)]


def _substitute(bit_array):
    """ Performs a DES S-BOX substitution for a 48-bit block. The input data
        should be a list of 0/1 integer values. Output will be a 32-bit block
        that is also a list of 0/1 integer values. Technically, the function
        can be used with smaller inputs as long as the length is a multiple of
        six. Smaller inputs will ignore some of the S-BOX tables.
        For example:
          _substitute([1,1,1,1,1,1,0,0,0,0,0,0]) => [1,1,0,1,1,1,1,1]
          _substitute([0,1,0,1,0,1,0,0,1,0,1,1]) => [1,1,0,0,0,0,1,0]
          _substitute([1,1,0,1,1,1,1,1,1,0,1,1]) => [1,1,1,0,0,1,0,1]
    """
    result = []
    for i, b in enumerate(_nsplit(bit_array, 6)): # [1, 0, 0, 1, 1, 0]
        ends  = [str(b[0]), str(b[-1])]           # take first and last bits...
        mids  = [str(x) for x in b[1:][:-1]]      # take the middle 4 bits...
        row   = int(''.join(ends), 2)             #   ...and turn into number
        col   = int(''.join(mids), 2)             #   ...and turn into number
        sval  = _S_BOXES[i][row][col]             # use numbers as S-BOX indices
        bstr  = bin(sval)[2:].zfill(4)            # "0101" from S-BOX
        result += [int(x) for x in bstr]          # += [0, 1, 0, 1] to int list
    return result


def _generate_subkeys(encryption_key):
    """ Generates 16 DES subkeys from a 64-bit encryption key. The encryption
        key should be given as a bytes string. Output is a 16-element list of
        bit arrays, where each array is a list of 48 ones/zeroes.
        For example:
          _generate_subkeys(b"\xEF\x00\xEF\x00\xFF\x80\xFF\x80") =>
          subkeys = [ [0,1,1,0,1,1,1,1,1,0,1,0,1,1,0,0,0,0,0,1,1,0,1,1,
                       1,0,1,1,1,0,0,0,1,1,1,0,0,1,1,0,0,0,0,0,0,0,1,0],
                       ... (middle 14 subkeys omitted)
                      [1,0,0,1,1,0,1,1,0,1,0,1,0,0,1,1,1,1,1,0,0,1,0,1,
                       0,1,0,0,0,0,1,1,0,0,0,1,1,0,0,0,1,0,1,1,1,1,0,1] ]
    """
    subkeys = []
    keybits = _bytes_to_bit_array(encryption_key)
    k_0 = _permute(keybits, _KEY_PERMUTATION1)     # 64 bits -> 56 bits
    L = k_0[:28]
    R = k_0[28:]
    for i in range(16):                            # DES is 16 rounds
        L = _lshift(L, _KEY_SHIFT[i])              # shift the left half
        R = _lshift(R, _KEY_SHIFT[i])              # shift the right half
        k_i = _permute(L + R, _KEY_PERMUTATION2)   # 56 bits -> 48 bits
        subkeys.append(k_i)
    return subkeys


def _function(R, key):
    """ Performs the DES encryption "function" on the 32-bit Right Side of a
        64-bit block. This operation is invoked 16 times for each block, each
        time with a different subkey.
        For example:
          r = [1,1,0,1,0,0,1,0,0,0,1,1,1,0,1,0,0,1,1,0,1,1,0,1,0,0,1,0,1,1,0,0]
          k = [0,1,1,0,1,1,1,0,1,0,1,0,1,1,0,1,0,0,0,1,1,0,1,1,
               1,0,1,1,1,0,0,0,1,1,1,0,0,1,1,0,0,1,0,0,0,0,0,0]
          _function(r, k) =>
              [0,0,0,0,0,1,1,1,0,0,1,0,0,0,0,1,0,0,1,0,0,0,0,1,0,1,0,1,0,1,0,1]
    """
    tmp = _permute(R, _EXPAND)                # R: 32-bit -> 48 bit
    tmp = _xor(tmp, key)                      # XOR(48-bit R, key)
    tmp = _substitute(tmp)                    # SBOX(...) -> 32-bit
    tmp = _permute(tmp, _SBOX_PERM)           # PERMUTE(SBOX(...))
    return tmp


def _crypt_block(block, subkeys):
    """ Encrypts a single 64-bit block with the DES algorithm. The input is a
        64 element array of 0/1 integers and a list of 16 subkeys, themselves
        each a 48 element array of 0/1 integers.
        For example:
          subkeys = _generate_subkeys(b'\xEF\x00\xEF\x00\xFF\x80\xFF\x80')
          _crypt_block('CompSci', subkeys) => b'\xf8i\x9d"E&\xf4\x83'
          _crypt_block('CUI', subkeys)     => b"\xa2[`Y\xfb\x0f\xac'"
          _crypt_block('CSC428', subkeys) => b'/S\xe49\xa0V4\x81'
    """
    block = _permute(block, _INIT_PERM)         # block: 64-bits
    L = block[:32]
    R = block[32:]
    for i in range(16):
        tmp = _xor(L, _function(R, subkeys[i])) # XOR(32-bit L,
        L = R                                   #     32-bit SBOX)
        R = tmp
    block = _permute(R + L, _FINI_PERM)
    return block


def _hex_print(msg, block, length=16):
    """ Prints an 8-byte long byte string in hexadecimal.
        For example:
          _hex_print("L1: ", [1,1,1,1,0,1,0,1,0,0,0,0,1,0,1,0], 6) => "L1: 00f50a"
          _hex_print("L2: ", [1,0,1,0,1,0,1,1,1,1,0,0,1,1,0,1], 4) => "L2: abcd"
    """
    string = [str(integer) for integer in block]
    binary = int("".join(string), 2)
    hexstr = hex(binary)[2:].zfill(length)
    print(f"{msg}{hexstr}")


################################################################################

class DES:
    """ Implements the original DES algorithm with a 64-bit key and three block
        modes: ECB, CBC, and OFB.
    """

    def __init__(self, key, mode="ECB", iv=None):
        """ Creates a new encryption object.

            Parameters:
              key  - 64-bit secret key given as a byte string
              mode - "ECB" or "CBC" or "OFB"
              iv   - 64-bit byte string that is required for CBC and OFB modes
        """

        # Verify that the key is a 64-bit byte string
        if key == None:
            raise ValueError(f"64-bit key required")
        if not isinstance(key, bytes):
            name = type(key).__name__
            raise ValueError(f"Key must be a byte string (got '{name}')")
        if len(key) != 8:
            raise ValueError(f"Key '{key}' is not 64-bits")

        # Verify the block cipher mode
        if mode.upper() not in [ "ECB", "CBC", "OFB" ]:
            raise ValueError(f"Mode must be ECB, CBC, or OFB (got '{mode}')")

        # Verify that the IV is a 64-bit byte string for CBC and OFB modes
        if mode.upper() in [ "CBC", "OFB" ] and iv == None:
            raise ValueError(f"64-bit IV is required for CBC and OFB modes")
        if iv != None and not isinstance(iv, bytes):
            name = type(iv).__name__
            raise ValueError(f"IV must be a byte string (got '{name}')")
        if iv != None and len(iv) != 8:
            raise ValueError(f"IV '{iv}' is not 64-bits")

        # Initialize all of the internal object attributes
        self.key = key
        self.mode = mode.upper()
        if self.mode == "CBC" or self.mode == "OFB":
            self.iv = iv
            self._iv = _bytes_to_bit_array(self.iv)
        return


    def reset(self):
        """ Resets the IV to its original value to start a new encryption or
            decryption. This function only applies to CBC and OFB modes.
        """

        if self.mode == "CBC" or self.mode == "OFB":
            self._iv = _bytes_to_bit_array(self.iv)
        return


    def encrypt(self, data):
        """ Encrypts data with the DES encryption algorithm.

            Parameters:
              data - raw byte string to be encrypted
        """

        # Verify that the plaintext data is readable
        if data == None:
            raise ValueError(f"Data is required for encryption")
        if not isinstance(data, bytes):
            name = type(data).__name__
            raise ValueError(f"Data must be a byte string (got '{name}')")

        # Generate the subkeys used for encryption
        subkeys = _generate_subkeys(self.key)

        # Convert the data into a workable format
        # OFB mode is a stream cipher so it does not require padding
        if self.mode == "ECB" or self.mode == "CBC":
            data = _add_padding(data)
        data = _bytes_to_bit_array(data)

        # Encrypt the data 64-bits at a time
        result = []
        for pt_block in _nsplit(data, 64):

            if self.mode == "ECB":
                ct_block = _crypt_block(pt_block, subkeys)
                result += ct_block

            elif self.mode == "CBC": # the previous block becomes the next IV
                ct_block = _xor(pt_block, self._iv)
                ct_block = _crypt_block(ct_block, subkeys)
                self._iv = ct_block
                result += ct_block

            elif self.mode == "OFB":
                self._iv = _crypt_block(self._iv, subkeys)
                ct_block = _xor(pt_block, self._iv)
                result += ct_block

            else:
                raise ValueError(f"Invalid block cipher mode '{self.mode}'")

        # Convert back to the original data format
        result = _bit_array_to_bytes(result)
        return result


    def decrypt(self, data):
        """ Decrypts data with the DES encryption algorithm.

            Parameters:
              data - raw byte string to be decrypted
        """

        # Verify that the ciphertext data is readable
        if data == None:
            raise ValueError(f"Data is required for encryption")
        if not isinstance(data, bytes):
            name = type(data).__name__
            raise ValueError(f"Data must be a byte string (got '{name}')")

        if self.mode in ["ECB", "CBC"] and len(data) % 8 != 0:
            raise ValueError(f"Incomplete data block, size={len(data)}")

        # Generate the subkeys used for decryption
        subkeys = _generate_subkeys(self.key)
        if self.mode == "ECB" or self.mode == "CBC":
            subkeys = list(reversed(subkeys))

        # Convert the data into a workable format
        data = _bytes_to_bit_array(data)

        # Decrypt the data 64-bits at a time
        result = []
        for ct_block in _nsplit(data, 64):

            if self.mode == "ECB":
                pt_block = _crypt_block(ct_block, subkeys)
                result += pt_block

            elif self.mode == "CBC": # the previous block becomes the next IV
                pt_block = _crypt_block(ct_block, subkeys)
                pt_block = _xor(pt_block, self._iv)
                self._iv = ct_block
                result += pt_block

            elif self.mode == "OFB":
                self._iv = _crypt_block(self._iv, subkeys)
                pt_block = _xor(ct_block, self._iv)
                result += pt_block

            else:
                raise ValueError(f"Invalid block cipher mode '{self.mode}'")

        # Convert back to the original data format
        result = _bit_array_to_bytes(result)
        if self.mode == "ECB" or self.mode == "CBC":
            result = _rem_padding(result)
        return result


################################################################################


class TDES:
    """ Implements the Triple DES algorithm with a 192-bit key and three block
        modes: ECB, CBC, and OFB.
    """

    def __init__(self, key, mode="ECB", iv=None):
        """ Creates a new encryption object.

            Parameters:
              key  - 64-bit secret key given as a byte string
              mode - "ECB" or "CBC" or "OFB"
              iv   - 64-bit byte string that is required for CBC and OFB modes
        """

        # Verify that the key is a 64-bit byte string
        if key == None:
            raise ValueError(f"192-bit key required")
        if not isinstance(key, bytes):
            name = type(key).__name__
            raise ValueError(f"Key must be a byte string (got '{name}')")
        if len(key) != 24:
            raise ValueError(f"Key '{key}' is not 192-bits")

        # Verify the block cipher mode
        if mode.upper() not in [ "ECB", "CBC", "OFB" ]:
            raise ValueError(f"Mode must be ECB, CBC, or OFB (got '{mode}')")

        # Verify that the IV is a 64-bit byte string for CBC and OFB modes
        if mode.upper() in [ "CBC", "OFB" ] and iv == None:
            raise ValueError(f"64-bit IV is required for CBC and OFB modes")
        if iv != None and not isinstance(iv, bytes):
            name = type(iv).__name__
            raise ValueError(f"IV must be a byte string (got '{name}')")
        if iv != None and len(iv) != 8:
            raise ValueError(f"IV '{iv}' is not 64-bits")

        # Initialize all of the internal object attributes
        self.key = key
        self._split_encryption_keys()
        self.mode = mode.upper()
        if self.mode == "CBC" or self.mode == "OFB":
            self.iv = iv
            self._iv = _bytes_to_bit_array(self.iv)
        return


    def _split_encryption_keys(self):
        """ Splits a Triple-DES encryption key into three 8-byte subkeys. Each
            subkey will be used for one of the DES rounds. If the original key is
            only 16 bytes, then the first 8-byte key will be used for the first
            and the third rounds of encryption. """

        # Full Triple-DES 24 byte/192 bit key
        # Shortened Triple-DES 16 byte/128 bit key
        # Ummm.... Triple-DES with an 8 byte key?
        # Triple DES cannot use a key of any other size
        if len(self.key) == 24:
            self.key1 = self.key[0:8]   # First eight bytes of key
            self.key2 = self.key[8:16]  # Second eight bytes of key
            self.key3 = self.key[16:24] # Third eight bytes of key
        elif len(self.key) == 16:
            self.key1 = self.key[0:8]   # First eight bytes of key
            self.key2 = self.key[8:16]  # Second eight bytes of key
            self.key3 = self.key[0:8]   # First eight bytes of key (repeated)
        elif len(self.key) == 8:
            self.key1 = self.key[0:8]   # First eight bytes of key
            self.key2 = self.key[0:8]   # First eight bytes of key
            self.key3 = self.key[0:8]   # First eight bytes of key (repeated)
        else:
            raise ValueError(f"Key should be 8, 16, or 24 bytes (got " +\
                             f"'{self.key}': {len(self.key)} bytes)")
        return


    def reset(self):
        """ Resets the IV to its original value to start a new encryption or
            decryption. This function only applies to CBC and OFB modes.
        """

        if self.mode == "CBC" or self.mode == "OFB":
            self._iv = _bytes_to_bit_array(self.iv)
        return


    def encrypt(self, data):
        """ Encrypts data with the Triple-DES encryption algorithm.

            Parameters:
              data - raw byte string to be encrypted
        """

        # Verify that the plaintext data is readable
        if data == None:
            raise ValueError(f"Data is required for encryption")
        if not isinstance(data, bytes):
            name = type(data).__name__
            raise ValueError(f"Data must be a byte string (got '{name}')")

        # Generate the subkeys used for encryption
        subkeys1 = _generate_subkeys(self.key1)
        subkeys2 = _generate_subkeys(self.key2)
        subkeys3 = _generate_subkeys(self.key3)

        # ** IMPORTANT **
        # 3DES uses the operations encrypt, decrypt, and encrypt... to decrypt,
        # we need to reverse the order of the subkeys
        subkeys2 = list(reversed(subkeys2))

        # Convert the data into a workable format
        # OFB mode is a stream cipher so it does not require padding
        if self.mode == "ECB" or self.mode == "CBC":
            data = _add_padding(data)
        data = _bytes_to_bit_array(data)

        # Encrypt the data 64-bits at a time
        result = []
        for pt_block in _nsplit(data, 64):

            if self.mode == "ECB":
                ct_block = _crypt_block(pt_block, subkeys1)
                ct_block = _crypt_block(ct_block, subkeys2)
                ct_block = _crypt_block(ct_block, subkeys3)
                result += ct_block

            elif self.mode == "CBC":
                ct_block = _xor(pt_block, self._iv)
                ct_block = _crypt_block(ct_block, subkeys1)
                ct_block = _crypt_block(ct_block, subkeys2)
                ct_block = _crypt_block(ct_block, subkeys3)
                self._iv = ct_block
                result += ct_block

            elif self.mode == "OFB":
                self._iv = _crypt_block(self._iv, subkeys1)
                self._iv = _crypt_block(self._iv, subkeys2)
                self._iv = _crypt_block(self._iv, subkeys3)
                ct_block = _xor(pt_block, self._iv)
                result += ct_block

            else:
                raise ValueError(f"Invalid block cipher mode '{self.mode}'")

        # Convert back to the original data format
        result = _bit_array_to_bytes(result)
        return result


    def decrypt(self, data):
        """ Decrypts data with the Triple-DES encryption algorithm.

            Parameters:
              data - raw byte string to be decrypted
        """

        # Verify that the ciphertext data is readable
        if data == None:
            raise ValueError(f"Data is required for decryption")
        if not isinstance(data, bytes):
            name = type(data).__name__
            raise ValueError(f"Data must be a byte string (got '{name}')")
        if self.mode in ["ECB", "CBC"] and len(data) % 8 != 0:
            raise ValueError(f"Incomplete data block, size={len(data)}")

        # Generate the subkeys used for decryption
        subkeys1 = _generate_subkeys(self.key1)
        subkeys2 = _generate_subkeys(self.key2)
        subkeys3 = _generate_subkeys(self.key3)

        # ** IMPORTANT **
        # 3DES uses the operations decrypt, encrypt, and decrypt... to decrypt,
        # we need to reverse the order of the subkeys
        if self.mode == "OFB":
            subkeys2 = list(reversed(subkeys2))
        else:
            subkeys1 = list(reversed(subkeys1))
            subkeys3 = list(reversed(subkeys3))

        # Convert the data into a workable format
        data = _bytes_to_bit_array(data)

        # Decrypt the data 64-bits at a time
        result = []
        for ct_block in _nsplit(data, 64):

            if self.mode == "ECB":
                pt_block = _crypt_block(ct_block, subkeys3)
                pt_block = _crypt_block(pt_block, subkeys2)
                pt_block = _crypt_block(pt_block, subkeys1)
                result += pt_block

            elif self.mode == "CBC":
                pt_block = _crypt_block(ct_block, subkeys3)
                pt_block = _crypt_block(pt_block, subkeys2)
                pt_block = _crypt_block(pt_block, subkeys1)
                pt_block = _xor(pt_block, self._iv)
                self._iv = ct_block
                result += pt_block

            elif self.mode == "OFB":
                self._iv = _crypt_block(self._iv, subkeys1)
                self._iv = _crypt_block(self._iv, subkeys2)
                self._iv = _crypt_block(self._iv, subkeys3)
                pt_block = _xor(self._iv, ct_block)
                result += pt_block

            else:
                raise ValueError(f"Invalid block cipher mode '{self.mode}'")

        # Convert back to the original data format
        result = _bit_array_to_bytes(result)
        if self.mode == "ECB" or self.mode == "CBC":
            result = _rem_padding(result)
        return result


################################################################################


# 64-bit to 56-bit permutation on the key
_KEY_PERMUTATION1 = [56, 48, 40, 32, 24, 16,  8,  0,
                     57, 49, 41, 33, 25, 17,  9,  1,
                     58, 50, 42, 34, 26, 18, 10,  2,
                     59, 51, 43, 35, 62, 54, 46, 38,
                     30, 22, 14,  6, 61, 53, 45, 37,
                     29, 21, 13,  5, 60, 52, 44, 36,
                     28, 20, 12,  4, 27, 19, 11,  3]

# 56-bit to 48-bit permutation on the key
_KEY_PERMUTATION2 = [13, 16, 10, 23,  0,  4,  2, 27,
                     14,  5, 20,  9, 22, 18, 11,  3,
                     25,  7, 15,  6, 26, 19, 12,  1,
                     40, 51, 30, 36, 46, 54, 29, 39,
                     50, 44, 32, 47, 43, 48, 38, 55,
                     33, 52, 45, 41, 49, 35, 28, 31]

# Matrix that determines the shift for each round of keys
_KEY_SHIFT = [ 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# 32-bit to 48-bit
_EXPAND = [31,  0,  1,  2,  3,  4,  3,  4,
            5,  6,  7,  8,  7,  8,  9, 10,
           11, 12, 11, 12, 13, 14, 15, 16,
           15, 16, 17, 18, 19, 20, 19, 20,
           21, 22, 23, 24, 23, 24, 25, 26,
           27, 28, 27, 28, 29, 30, 31,  0]

# 32-bit permutation after S-BOX substitution
_SBOX_PERM = [15,  6, 19, 20, 28, 11, 27, 16,
               0, 14, 22, 25,  4, 17, 30,  9,
               1,  7, 23, 13, 31, 26,  2,  8,
              18, 12, 29,  5, 21, 10,  3, 24]

# Initial permutation on incoming block
_INIT_PERM = [57, 49, 41, 33, 25, 17,  9, 1,
              59, 51, 43, 35, 27, 19, 11, 3,
              61, 53, 45, 37, 29, 21, 13, 5,
              63, 55, 47, 39, 31, 23, 15, 7,
              56, 48, 40, 32, 24, 16,  8, 0,
              58, 50, 42, 34, 26, 18, 10, 2,
              60, 52, 44, 36, 28, 20, 12, 4,
              62, 54, 46, 38, 30, 22, 14, 6]

# Final permutation on outgoing block
_FINI_PERM = [39,  7, 47, 15, 55, 23, 63, 31,
              38,  6, 46, 14, 54, 22, 62, 30,
              37,  5, 45, 13, 53, 21, 61, 29,
              36,  4, 44, 12, 52, 20, 60, 28,
              35,  3, 43, 11, 51, 19, 59, 27,
              34,  2, 42, 10, 50, 18, 58, 26,
              33,  1, 41,  9, 49, 17, 57, 25,
              32,  0, 40,  8, 48, 16, 56, 24]

_S_BOXES = [
    [[14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7],
     [ 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8],
     [ 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0],
     [15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13],
    ],
    [[15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10],
     [ 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5],
     [ 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15],
     [13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9],
    ],
    [[10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8],
     [13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1],
     [13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7],
     [ 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12],
    ],
    [[ 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15],
     [13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9],
     [10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4],
     [ 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14],
    ],
    [[ 2, 12,  4,  1,  7, 10, 11, 6,  8,  5,  3, 15, 13,  0, 14,  9],
     [14, 11,  2, 12,  4,  7, 13, 1,  5,  0, 15, 10,  3,  9,  8,  6],
     [ 4,  2,  1, 11, 10, 13, 7,  8, 15,  9, 12,  5,  6,  3,  0, 14],
     [11,  8, 12,  7,  1, 14, 2, 13,  6, 15,  0,  9, 10,  4,  5,  3],
    ],
    [[12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11],
     [10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8],
     [ 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6],
     [ 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13],
    ],
    [[ 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1],
     [13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6],
     [ 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2],
     [ 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12],
    ],
    [[13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7],
     [ 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2],
     [ 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8],
     [ 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11],
    ]
]

################################################################################

def run_unit_tests():
    """ Runs unit tests for each function in this module. Prints 'ALL UNIT
        TESTS PASSED' if all of the unit tests were successful. Raises an
        AssertionError if a unit test fails.
    """

    wout_pad1 = b'CSC428'
    with_pad1 = b'CSC428\x02\x02'
    wout_pad2 = b'TALLMAN'
    with_pad2 = b'TALLMAN\x01'
    wout_pad3 = b'JTALLMAN'
    with_pad3 = b'JTALLMAN\x08\x08\x08\x08\x08\x08\x08\x08'
    assert _add_padding(wout_pad1) == with_pad1, f"_add_padding({wout_pad1})"
    assert _add_padding(wout_pad2) == with_pad2, f"_add_padding({wout_pad2})"
    assert _add_padding(wout_pad3) == with_pad3, f"_add_padding({wout_pad3})"
    assert _rem_padding(with_pad1) == wout_pad1, f"_rem_padding({with_pad1})"
    assert _rem_padding(with_pad2) == wout_pad2, f"_rem_padding({with_pad2})"
    assert _rem_padding(with_pad3) == wout_pad3, f"_rem_padding({with_pad3})"

    str1 = b'ABCD'
    arr1 = [ 0,1,0,0,0,0,0,1,0,1,0,0,0,0,1,0,0,1,0,0,0,0,1,1,0,1,0,0,0,1,0,0 ]
    str2 = b'1234'
    arr2 = [ 0,0,1,1,0,0,0,1,0,0,1,1,0,0,1,0,0,0,1,1,0,0,1,1,0,0,1,1,0,1,0,0 ]
    str3 = b'\x01\x23\x45\x67\x89\xAB\xCD\xEF'
    arr3 = [ 0,0,0,0,0,0,0,1,0,0,1,0,0,0,1,1,0,1,0,0,0,1,0,1,0,1,1,0,0,1,1,1,
             1,0,0,0,1,0,0,1,1,0,1,0,1,0,1,1,1,1,0,0,1,1,0,1,1,1,1,0,1,1,1,1 ]
    assert _bytes_to_bit_array(str1) == arr1, f"_bytes_to_bit_array({str1})"
    assert _bytes_to_bit_array(str2) == arr2, f"_bytes_to_bit_array({str2})"
    assert _bytes_to_bit_array(str3) == arr3, f"_bytes_to_bit_array({str3})"
    assert _bit_array_to_bytes(arr1) == str1, f"_bit_array_to_bytes({arr1})"
    assert _bit_array_to_bytes(arr2) == str2, f"_bit_array_to_bytes({arr2})"
    assert _bit_array_to_bytes(arr3) == str3, f"_bit_array_to_bytes({arr3})"

    seq1 = b'11111111222222223333333344444444'
    len1 = 8
    blk1 = [ b'11111111',b'22222222',b'33333333',b'44444444' ]
    seq2 = b'11111111222222223333333344444444'
    len2 = 4
    blk2 = [ b'1111',b'1111',b'2222',b'2222',b'3333',b'3333',b'4444',b'4444' ]
    seq3 = b'ABCDEFGHIJKLMN'
    len3 = 3
    blk3 = [ b'ABC',b'DEF',b'GHI',b'JKL',b'MN' ]
    assert list(_nsplit(seq1, len1)) == blk1, f"_nsplit({seq1}, {len1})"
    assert list(_nsplit(seq2, len2)) == blk2, f"_nsplit({seq2}, {len2})"
    assert list(_nsplit(seq3, len3)) == blk3, f"_nsplit({seq3}, {len3})"

    block1 = 'abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!@'
    pinit1 = [ 'V','N','F','7','z','r','j','b','X','P','H','9','1','t','l','d',
               'Z','R','J','B','3','v','n','f','@','T','L','D','5','x','p','h',
               'U','M','E','6','y','q','i','a','W','O','G','8','0','s','k','c',
               'Y','Q','I','A','2','u','m','e','!','S','K','C','4','w','o','g' ]
    pfini1 = [ 'D','h','L','p','T','x','@','5','C','g','K','o','S','w','!','4',
               'B','f','J','n','R','v','Z','3','A','e','I','m','Q','u','Y','2',
               '9','d','H','l','P','t','X','1','8','c','G','k','O','s','W','0',
               '7','b','F','j','N','r','V','z','6','a','E','i','M','q','U','y']
    block2 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ!@abcdefghijklmnopqrstuvwxyz0123456789'
    pinit2 = [ '3','v','n','f','Z','R','J','B','5','x','p','h','@','T','L','D',
               '7','z','r','j','b','V','N','F','9','1','t','l','d','X','P','H',
               '2','u','m','e','Y','Q','I','A','4','w','o','g','!','S','K','C',
               '6','y','q','i','a','U','M','E','8','0','s','k','c','W','O','G' ]
    pfini2 = [ 'l','H','t','P','1','X','9','d','k','G','s','O','0','W','8','c',
               'j','F','r','N','z','V','7','b','i','E','q','M','y','U','6','a',
               'h','D','p','L','x','T','5','@','g','C','o','K','w','S','4','!',
               'f','B','n','J','v','R','3','Z','e','A','m','I','u','Q','2','Y' ]
    block3 = 'aaaabbbbccccddddeeeeffffgggghhhhiiiijjjjkkkkllllmmmmnnnnoooopppp'
    pinit3 = [ 'o','m','k','i','g','e','c','a','o','m','k','i','g','e','c','a',
               'p','n','l','j','h','f','d','b','p','n','l','j','h','f','d','b',
               'o','m','k','i','g','e','c','a','o','m','k','i','g','e','c','a',
               'p','n','l','j','h','f','d','b','p','n','l','j','h','f','d','b']
    pfini3 = [ 'j','b','l','d','n','f','p','h','j','b','l','d','n','f','p','h',
               'j','b','l','d','n','f','p','h','j','b','l','d','n','f','p','h',
               'i','a','k','c','m','e','o','g','i','a','k','c','m','e','o','g',
               'i','a','k','c','m','e','o','g','i','a','k','c','m','e','o','g']
    assert _permute(block1, _INIT_PERM) == pinit1, f"_permute(_INIT_PERM)"
    assert _permute(block1, _FINI_PERM) == pfini1, f"_permute(_FINI_PERM)"
    assert _permute(block2, _INIT_PERM) == pinit2, f"_permute(_INIT_PERM)"
    assert _permute(block2, _FINI_PERM) == pfini2, f"_permute(_FINI_PERM)"
    assert _permute(block3, _INIT_PERM) == pinit3, f"_permute(_INIT_PERM)"
    assert _permute(block3, _FINI_PERM) == pfini3, f"_permute(_FINI_PERM)"

    sequence = 'abcdefghijklmnopqrstuvwxyz'
    lshift01 = 'bcdefghijklmnopqrstuvwxyza'
    lshift05 = 'fghijklmnopqrstuvwxyzabcde'
    lshift25 = 'zabcdefghijklmnopqrstuvwxy'
    lshift26 = 'abcdefghijklmnopqrstuvwxyz'
    lshift27 = 'bcdefghijklmnopqrstuvwxyza'
    assert _lshift(sequence, 1) == lshift01, f"_lshift(1)"
    assert _lshift(sequence, 5) == lshift05, f"_lshift(5)"
    assert _lshift(sequence, 25) == lshift25, f"_lshift(25)"
    assert _lshift(sequence, 26) == lshift26, f"_lshift(26)"
    assert _lshift(sequence, 27) == lshift27, f"_lshift(27)"

    x1, y1, r1 = [0,0,1,1], [0,1,0,1], [0,1,1,0]
    x2, y2, r2 = [1,2,3,0], [1,2,3,4], [0,0,0,4]
    x3, y3, r3 = b"\x0F\x0F", b"\x55\xAA", [0x5A, 0xA5]
    x4, y4, r4 = [0x0F, 0x0F], [0x55, 0xAA], [0x5A, 0xA5]
    x5, y5, r5 = [0x0F0F], [0x55AA], [0x5AA5]
    x6, y6, r6 = [0,0,1,1,0], [0,1,0,1], [0,1,1,0]
    assert _xor(x1, y1) == r1, f"_xor({x1}, {y1})"
    assert _xor(x2, y2) == r2, f"_xor({x2}, {y2})"
    assert _xor(x3, y3) == r3, f"_xor({x3}, {y3})"
    assert _xor(x4, y4) == r4, f"_xor({x4}, {y4})"
    assert _xor(x5, y5) == r5, f"_xor({x5}, {y5})"
    assert _xor(x6, y6) == r6, f"_xor({x6}, {y6})"

    in1  = [ 1,1,1,1,1,1, 0,0,0,0,0,0, 1,0,0,0,0,1, 0,1,1,1,1,0,
             0,0,0,1,1,1, 1,1,1,0,0,0, 0,1,1,0,0,1, 1,0,1,0,1,0 ]
    out1 = [ 1,1,0,1,1,1,1,1,0,0,0,1,1,1,1,1,1,1,0,0,0,0,0,1,0,0,1,0,1,1,0,0 ]
    in2  = [ 0,1,0,1,0,1, 0,0,1,0,1,1, 1,1,0,1,0,0, 1,1,0,1,0,1,
             1,0,0,1,1,1, 1,1,0,1,0,1, 1,1,0,1,0,0, 0,0,1,0,1,0 ]
    out2 = [ 1,1,0,0,0,0,1,0,0,0,1,0,0,1,0,1,0,1,1,1,0,0,0,1,0,1,1,0,1,1,1,1 ]
    in3  = [ 1,1,0,1,1,1, 1,1,1,0,1,1, 1,0,0,0,1,1, 1,0,0,1,0,1,
             0,1,0,1,1,0, 0,1,1,0,1,0, 0,0,0,0,1,0, 0,0,0,1,0,0 ]
    out3 = [ 1,1,1,0,0,1,0,1,1,0,1,0,0,0,0,0,1,1,1,1,0,1,1,1,1,0,1,1,1,0,0,0 ]
    assert _substitute(in1) == out1, f"_substitute({in1})"
    assert _substitute(in2) == out2, f"_substitute({in2})"
    assert _substitute(in3) == out3, f"_substitute({in3})"

    print("ALL UNIT TESTS PASSED")


def run_integration_tests():
    """ Runs integration tests for every high level function in this module.
        Prints 'ALL SYSTEM TESTS PASSED' if all of the integration tests were
        successful. Raises an AssertionError if an integration test fails.
    """

    enc_key = b"\xEF\x00\xEF\x00\xFF\x80\xFF\x80"
    subkeys = [ [0,1,1,0,1,1,1,1,1,0,1,0,1,1,0,0,0,0,0,1,1,0,1,1,
                 1,0,1,1,1,0,0,0,1,1,1,0,0,1,1,0,0,0,0,0,0,0,1,0],
                [1,0,0,1,1,0,0,1,0,1,0,1,0,0,1,1,1,1,1,0,1,1,0,1,
                 0,0,0,0,0,0,1,1,0,0,0,1,1,0,0,1,1,0,1,1,1,1,0,1],
                [1,0,0,1,0,0,0,1,0,1,0,1,0,0,1,1,1,1,1,0,1,1,0,1,
                 0,0,0,0,0,0,1,1,0,0,0,1,1,0,0,1,1,0,1,1,0,1,0,1],
                [1,0,0,1,0,0,0,1,0,1,0,1,1,0,1,1,1,1,1,0,0,1,0,1,
                 0,1,0,0,0,0,1,1,0,0,0,0,1,0,0,1,1,0,1,1,0,1,0,1],
                [1,0,0,1,0,0,0,1,0,1,1,1,1,0,1,1,1,1,1,0,0,1,0,1,
                 0,1,0,0,0,0,1,1,0,0,0,0,1,0,0,1,1,0,0,1,1,1,0,1],
                [1,0,0,1,0,0,0,1,0,1,1,1,0,1,1,1,1,1,1,0,0,1,0,1,
                 0,1,0,0,0,0,1,1,0,0,0,1,0,0,0,1,1,0,0,1,1,1,0,1],
                [1,1,0,1,0,0,0,1,0,1,0,1,0,1,1,1,1,1,1,0,0,1,0,1,
                 0,1,0,0,0,0,1,1,0,0,0,1,0,0,0,1,1,0,1,0,1,1,0,1],
                [1,1,0,1,0,0,0,1,1,1,0,1,0,0,1,1,1,1,1,0,0,1,0,1,
                 0,1,0,0,0,0,1,0,0,0,0,1,1,0,0,1,1,0,1,0,1,1,0,1],
                [1,1,1,0,1,1,1,0,1,0,1,0,1,1,0,0,0,0,1,1,1,0,1,0,
                 0,0,1,1,1,1,0,0,1,1,1,0,0,1,0,0,0,1,0,0,0,0,1,0],
                [1,1,1,0,1,1,1,0,1,0,1,0,1,1,1,0,0,0,0,1,1,0,1,0,
                 1,0,1,0,1,1,0,0,1,1,1,0,0,1,0,0,0,1,0,0,0,0,1,0],
                [0,1,1,0,1,1,1,0,1,0,1,1,1,1,1,0,0,0,0,1,1,0,1,0,
                 1,0,1,0,1,1,0,0,1,1,1,0,0,1,1,0,0,1,0,0,0,0,1,0],
                [0,1,1,0,1,1,1,0,1,0,1,1,1,1,0,0,0,1,0,1,1,0,1,0,
                 1,0,1,1,1,1,0,0,1,1,0,0,0,1,1,0,0,1,0,0,0,0,1,0],
                [0,1,1,0,1,1,1,0,1,1,1,0,1,1,0,0,0,1,0,1,1,0,1,0,
                 1,0,0,1,1,1,0,0,1,1,0,0,0,1,1,0,0,1,0,0,0,0,1,0],
                [0,1,1,0,1,1,1,0,1,1,1,0,1,1,0,1,0,0,0,1,1,0,1,0,
                 1,0,0,1,1,1,0,0,1,1,1,0,0,1,1,0,0,1,0,0,0,0,0,0],
                [0,1,1,0,1,1,1,0,1,0,1,0,1,1,0,1,0,0,0,1,1,0,1,1,
                 1,0,1,1,1,0,0,0,1,1,1,0,0,1,1,0,0,1,0,0,0,0,0,0],
                [1,0,0,1,1,0,1,1,0,1,0,1,0,0,1,1,1,1,1,0,0,1,0,1,
                 0,1,0,0,0,0,1,1,0,0,0,1,1,0,0,0,1,0,1,1,1,1,0,1] ]
    assert _generate_subkeys(enc_key) == subkeys, f"_generate_subkeys()"

    r_side = [1,1,0,1,0,0,1,0,0,0,1,1,1,0,1,0,0,1,1,0,1,1,0,1,0,0,1,0,1,1,0,0]
    subkey = [0,1,1,0,1,1,1,0,1,0,1,0,1,1,0,1,0,0,0,1,1,0,1,1,
              1,0,1,1,1,0,0,0,1,1,1,0,0,1,1,0,0,1,0,0,0,0,0,0]
    output = [0,0,0,0,0,1,1,1,0,0,1,0,0,0,0,1,0,0,1,0,0,0,0,1,0,1,0,1,0,1,0,1]
    assert _function(r_side, subkey) == output, f"_function()"

    # subkeys was defined for a previous test
    block = [ 0,0,0,0,0,0,0,1,0,0,1,0,0,0,1,1,0,1,0,0,0,1,0,1,0,1,1,0,0,1,1,1,
              1,0,0,0,1,0,0,1,1,0,1,0,1,0,1,1,1,1,0,0,1,1,0,1,1,1,1,0,1,1,1,1 ]
    result = [ 1,1,0,0,1,0,1,1,1,1,0,1,1,1,1,0,0,1,1,0,0,1,1,1,1,1,1,1,0,0,0,0,
               1,1,1,0,0,0,0,0,1,0,1,1,0,1,0,1,0,1,0,1,1,0,0,1,1,1,1,0,1,1,0,0 ]
    assert _crypt_block(block, subkeys) == result, f"_crypt_block()"

    print("ALL INTEGRATION TESTS PASSED")


def run_system_tests():
    """ Runs system tests for every high level function in this module.
        Prints 'ALL SYSTEM TESTS PASSED' if all of the system tests were
        successful. Raises an AssertionError if a system test fails.
    """

    pt = b"COMPUTERPROGRAM"
    key  = b"\x88\x99\xaa\xbb\xcc\xdd\xee\xff"
    iv   = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    ecb1 = b"\xa1\x17\xdc\x5f\x66\xa4\x19\x70\xf5\x84\xc9\xbe\x39\x6f\xd1\xd9"
    cbc1 = b"\xde\xc8\x1b\x92\xc8\xe3\x4a\xf8\x79\xb7\x39\xe1\x85\x6e\xd1\x3c"
    ofb1 = b"\x0a\x54\x75\x6f\x25\xfd\x7c\x1c\xfe\x33\xaa\x51\x39\xa2\xe3"

    des_ecb = DES(key, "ECB")
    test1_ct = des_ecb.encrypt(pt)
    des_ecb.reset()
    test1_pt = des_ecb.decrypt(test1_ct)
    assert test1_ct == ecb1, f"DES.encrypt('ECB')"
    assert test1_pt == pt, f"DES.decrypt('ECB')"

    des_cbc = DES(key, "CBC", iv)
    test2_ct = des_cbc.encrypt(pt)
    des_cbc.reset()
    test2_pt = des_cbc.decrypt(test2_ct)
    assert test2_ct == cbc1, f"DES.encrypt('CBC')"
    assert test2_pt == pt, f"DES.decrypt('CBC')"

    des_ofb = DES(key, "OFB", iv)
    test3_ct = des_ofb.encrypt(pt)
    des_ofb.reset()
    test3_pt = des_ofb.decrypt(test3_ct)
    assert test3_ct == ofb1, f"DES.encrypt('OFB')"
    assert test3_pt == pt, f"DES.decrypt('OFB')"

    pt = b"COMPUTERPROGRAM"
    tkey = b"\x00\x11\x22\x33\x44\x55\x66\x77" +\
           b"\x88\x99\xaa\xbb\xcc\xdd\xee\xff" +\
           b"\x12\x34\x56\x78\x9a\xbc\xde\xf0"
    iv   = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    ecb3 = b"\x8e\xd9\x8e\xeb\xfb\xff\x20\x0c\xe4\xbb\xb6\x0e\xc6\x85\x47\xe1"
    cbc3 = b"\xf3\x97\xde\x8b\xdf\x16\x48\xcd\x1e\xaa\xee\x9b\xbf\xd3\x64\xcf"
    ofb3 = b"\x49\x0b\x09\x53\xcc\x7f\x24\x5c\xaa\xfe\xb5\xc2\x5e\xa1\x04"

    tdes_ecb = TDES(tkey, "ECB")
    test4_ct = tdes_ecb.encrypt(pt)
    tdes_ecb.reset()
    test4_pt = tdes_ecb.decrypt(test4_ct)
    assert test4_ct == ecb3, f"TDES.encrypt('ECB')"
    assert test4_pt == pt, f"TDES.decrypt('ECB')"

    tdes_cbc = TDES(tkey, "CBC", iv)
    test5_ct = tdes_cbc.encrypt(pt)
    tdes_cbc.reset()
    test5_pt = tdes_cbc.decrypt(test5_ct)
    assert test5_ct == cbc3, f"TDES.encrypt('CBC')"
    assert test5_pt == pt, f"TDES.decrypt('CBC')"

    tdes_ofb = TDES(tkey, "OFB", iv)
    test6_ct = tdes_ofb.encrypt(pt)
    tdes_ofb.reset()
    test6_pt = tdes_ofb.decrypt(test6_ct)
    assert test6_ct == ofb3, f"TDES.encrypt('OFB')"
    assert test6_pt == pt, f"TDES.decrypt('OFB') -> {test6_pt}"

    print("ALL SYSTEM TESTS PASSED")


if __name__ == '__main__':
    run_unit_tests()
    run_integration_tests()
    run_system_tests()
