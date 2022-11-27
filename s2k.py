import hashlib
import sys
from getpass import getpass
import cui_des

_sym_algorithms = [
    "Unencrypted Plaintext",
    "IDEA",
    "Triple DES",
    "CAST5",
    "Blowfish"
    "Reserved"
    "Reserved"
    "AES128",
    "AES192",
    "AES256",
    "Twofish"]

_hash_algorithms = [
    "Error/None",
    "MD5",
    "SHA-1",
    "RIPE-MD/160",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "SHA-256",
    "SHA-384",
    "SHA-512",
    "SHA-224"]

_ptag_reserved_invalid = 0
_ptag_pubkey_enc_session = 1
_ptag_signature = 2
_ptag_symkey_enc_session = 3
_ptag_one_pass_signature = 4
_ptag_secret_key = 5
_ptag_public_key = 6
_ptag_secret_subkey = 7
_ptag_compressed_data = 8
_ptag_sym_enc_data = 9
_ptag_marker = 10
_ptag_literal_data = 11
_ptag_trust = 12
_ptag_user_id = 13
_ptag_public_subkey = 14
_ptag_user_attribute = 17
_ptag_sym_enc_int_data = 18
_ptag_mod_detection = 19
'''
        From RFC 4880:
        3.7.  String-to-Key (S2K) Specifiers

       String-to-key (S2K) specifiers are used to convert passphrase strings
       into symmetric-key encryption/decryption keys.  They are used in two
       places, currently: to encrypt the secret part of private keys in the
       private keyring, and to convert passphrases to encryption keys for
       symmetrically encrypted messages.

        3.7.1.  String-to-Key (S2K) Specifier Types

       There are three types of S2K specifiers currently supported, and
       some reserved values:

           ID          S2K Type
           --          --------
           0           Simple S2K
           1           Salted S2K
           2           Reserved value
           3           Iterated and Salted S2K
           100 to 110  Private/Experimental S2K

       These are described in Sections 3.7.1.1 - 3.7.1.3.

        3.7.1.1.  Simple S2K
        This directly hashes the string to produce the key data.  See below
       for how this hashing is done.

           Octet 0:        0x00
           Octet 1:        hash algorithm

       Simple S2K hashes the passphrase to produce the session key.  The
       manner in which this is done depends on the size of the session key
       (which will depend on the cipher used) and the size of the hash
       algorithm's output.  If the hash size is greater than the session key
       size, the high-order (leftmost) octets of the hash are used as the
       key.

       If the hash size is less than the key size, multiple instances of the
       hash context are created -- enough to produce the required key data.
       These instances are preloaded with 0, 1, 2, ... octets of zeros (that
       is to say, the first instance has no preloading, the second gets
       preloaded with 1 octet of zero, the third is preloaded with two
       octets of zeros, and so forth).

       As the data is hashed, it is given independently to each hash
       context.  Since the contexts have been initialized differently, they
       will each produce different hash output.  Once the passphrase is
       hashed, the output data from the multiple hashes is concatenated,
       first hash leftmost, to produce the key data, with any excess octets
       on the right discarded.
    '''

def calculate_s2k_mode0(password, key_length, hash_algorithm):
    """
    Generates an encryption key from a passphrase using the given parameters.
    The key_length parameter will depend on which encryption algorithm this key
    will be used for. For instance, the Triple DES algorithm requires a 24 byte key.

    This function implements the Simple S2K algorithm described in RFC 4880 section

    The Simple S2K algorithm is used to directly hash the passphrase to produce the key data.
    The manner in which this is done depends on the size of the session key (which will depend
    on the cipher used) and the size of the hash algorithm's output. If the hash size is greater
    than the session key size, the high-order (leftmost) octets of the hash are used as the key.

    If the hash size is less than the key size, multiple instances of the hash context are created
    -- enough to produce the required key data. These instances are preloaded with 0, 1, 2, ... octets
    of zeros (that is to say, the first instance has no preloading, the second gets preloaded with 1
    octet of zero, the third is preloaded with two octets of zeros, and so forth).

    As the data is hashed, it is given independently to each hash context. Since the contexts have
    been initialized differently, they will each produce different hash output. Once the passphrase
    is hashed, the output data from the multiple hashes is concatenated, first hash leftmost, to
    produce the key data, with any excess octets on the right discarded.

    :param password: The passphrase to use to generate the key.
    :param key_length: The length of the key to generate.
    :param hash_algorithm: The hash algorithm to use to generate the key.
    :return: The generated key.
    """
    if hash_algorithm == 1:
        hash_function = hashlib.md5
    elif hash_algorithm == 2:
        hash_function = hashlib.sha1
    elif hash_algorithm == 8:
        hash_function = hashlib.sha256
    elif hash_algorithm == 9:
        hash_function = hashlib.sha384
    elif hash_algorithm == 10:
        hash_function = hashlib.sha512
    elif hash_algorithm == 11:
        hash_function = hashlib.sha224
    else:
        raise ValueError(f"Invalid hash algorithm '{hash_algorithm}'")

    # The hash size is the size of the output of the hash function
    hash_size = hash_function().digest_size

    # If the hash size is greater than the session key size, the high-order
    if hash_size > key_length:
        # The high-order (leftmost) octets of the hash are used as the key.
        password = password.encode()
        digest = hash_function(password).digest()
        return digest[:key_length]
    # If the hash size is less than the key size
    else:
        # Multiple instances of the hash context are created -- enough to produce the required key data.
        # These instances are preloaded with 0, 1, 2, ... octets of zeros (that is to say, the first instance has no preloading,
        # the second gets preloaded with 1 octet of zero, the third is preloaded with two octets of zeros, and so forth).
        # As the data is hashed, it is given independently to each hash context.  Since the contexts have been initialized
        # differently, they will each produce different hash output.  Once the passphrase is hashed, the output data from
        # the multiple hashes is concatenated, first hash leftmost, to produce the key data, with any excess octets on the
        # right discarded.
        requiredHashes = key_length // hash_size
        hash_contexts = [hash_function() for i in range(requiredHashes + 1)]# +1 because we need to include the remainder
        for i in range(len(hash_contexts)):
            hash_contexts[i].update(b"\0" * i)
            hash_contexts[i].update(password.encode())

        return b"".join([dirt.digest() for dirt in hash_contexts])[:key_length]


def calculate_s2k(password, s2k_mode, key_length, hash_algorithm):
    """
    Generates an encryption key from a passphrase using the given parameters.
    The key_length parameter will depend on which encryption algorithm this key
    will be used for. For instance, the Triple DES algorithm requires a 24 byte key.

    :param password: The passphrase to use to generate the key.
    :param s2k_mode: The S2K mode to use to generate the key.
    :param key_length: The length of the key to generate.
    :param hash_algorithm: The hash algorithm to use to generate the key.
    :return: The generated key.

    """

    if s2k_mode == 0:
        return calculate_s2k_mode0(password, key_length, hash_algorithm)

    elif s2k_mode == 1 or s2k_mode == 3:
        raise ValueError(f"S2K modes 1 and 3 are not implemented")
    elif s2k_mode == 2:
        raise ValueError(f"S2K mode 2 does not exist");
    else:
        raise ValueError(f"Invalid S2K mode '{s2k_mode}'")


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 s2k.py [-d] [-m]")
        print("  -d: Enable debug output")
        print("  -m: Manual mode (enter parameters manually)")

    MANUAL, DEBUG = False, False
    if len(sys.argv) > 1 and sys.argv[1] == "-d":
        DEBUG = True
        sys.argv.pop(1)
    if len(sys.argv) > 1 and sys.argv[1] == "-m":
        MANUAL = True
        sys.argv.pop(1)

    if DEBUG:
        passphrase = "test"
        s2k_m0_key = b"\x09\x8f\x6b\xcd\x46\x21\xd3\x73\xca\xde\x4e\x83" + \
                     b"\x26\x27\xb4\xf6\x5f\x8f\x8e\x05\xef\xdc\x22\xe8"
        x = calculate_s2k(passphrase, s2k_mode=0, key_length=len(s2k_m0_key), hash_algorithm=1)
        if x == s2k_m0_key:
            print("Success!")
        else:
            print("Failure!")
        print(x)
        assert x == s2k_m0_key

    elif MANUAL:
        # Get the password from the user
        password = getpass("Enter the password: ")

        # Get the S2K mode
        s2k_mode = int(input("0: SimpleS2k \n"
                             "1: SaltedS2k \n"
                             "2: Reserved \n"
                             "3: Iterated and Salted S2K \n"
                             "100-110: Private/Experimental S2K \n"
                             "Enter the desired S2K mode: "))
        # Get the key length
        key_length = int(input("Enter the key length: "))

        # Get the hash algorithm
        hash_algorithm = int(input("1: MD5 \n"
                                   "2: SHA1 \n"
                                   "8: SHA256 \n"
                                   "9: SHA384 \n"
                                   "10: SHA512 \n"
                                   "11: SHA224 \n"
                                   "Enter the desired hash algorithm: "))

        # Calculate the key
        key = calculate_s2k(password, s2k_mode, key_length, hash_algorithm)

        # Print the key
        print("The key is: ", key)

    else: # Automatic mode
        # Get the password from the user
        password = getpass("Enter the password: ")

        # Calculate the key
        key = calculate_s2k(password, s2k_mode=0, key_length=24, hash_algorithm=1)

        # Print the key
        print("The key is: ", key)


if __name__ == "__main__":
    main()


def decrypt(encrypted_data, key, iv, sym_algo):
    """
    Decrypts the given data using the given key and IV with the given symmetric algorithm. Using the cui_des library
    that includes regular and triple DES classes. Uses built in python libraries for MD5, etc.

    :param encrypted_data: The data to decrypt.
    :param key: The key to use to decrypt the data.
    :param iv: The IV to use to decrypt the data.
    :param sym_algo: The symmetric algorithm to use to decrypt the data.
    :return: The decrypted data.
    """

    # Get the correct cipher class
    if sym_algo == 1:
        cipher = cui_des.DES(key, iv)
    elif sym_algo == 2:
        cipher = cui_des.TDES(key, iv)
    else:
        raise ValueError(f"Invalid symmetric algorithm '{sym_algo}'")

    # Decrypt the data
    return cipher.decrypt(encrypted_data)


def get_key_iv(password, salt, count, hash_algo, sym_algo):
    """
    Generates a key and IV from a passphrase using the given parameters.

    :param password: The passphrase to use to generate the key and IV.
    :param salt: The salt to use to generate the key and IV.
    :param count: The number of iterations to use to generate the key and IV.
    :param hash_algo: The hash algorithm to use to generate the key and IV.
    :param sym_algo: The symmetric algorithm to use to generate the key and IV.

    :return: The generated key and IV.
    """

    # Get the correct hash function
    if hash_algo == 1:
        hash_function = hashlib.md5
    elif hash_algo == 2:
        hash_function = hashlib.sha1
    elif hash_algo == 8:
        hash_function = hashlib.sha256
    elif hash_algo == 9:
        hash_function = hashlib.sha384
    elif hash_algo == 10:
        hash_function = hashlib.sha512
    elif hash_algo == 11:
        hash_function = hashlib.sha224
    else:
        raise ValueError(f"Invalid hash algorithm '{hash_algo}'")

    # Get the correct cipher class
    if sym_algo == 1:
        cipher = cui_des.DES
    elif sym_algo == 2:
        cipher = cui_des.TDES
    else:
        raise ValueError(f"Invalid symmetric algorithm '{sym_algo}'")

    # Get the key length and IV length
    key_length = cipher.key_length
    iv_length = cipher.iv_length

    # Generate the key and IV
    key_iv = hashlib.pbkdf2_hmac(hash_name=hash_function.__name__,
                                 password=password.encode(),
                                 salt=salt,
                                 iterations=count,
                                 dklen=key_length + iv_length)

    # Split the key and IV
    key = key_iv[:key_length]
    iv = key_iv[key_length:]

    return key, iv

