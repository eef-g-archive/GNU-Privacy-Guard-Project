import hashlib


def calculate_s2k(password, s2k_mode, key_length, hash_alogirthm):
    """ Generates an encryption key from a passphrase using the given parameters.
        The key_length parameter will depend on which encryption algorithm this key
        will be used for. For instance, the Triple DES algorithm requires a 24 byte key.
    """

    if s2k_mode == 0:
        if hash_alogirthm == 1:
            hashobj = hashlib.md5
        elif hash_alogirthm == 2:
            hashobj = hashlib.sha1
        else:
            raise ValueError(f"Cannot use hash alrogithm {hash_alogirthm}")


        if hashobj().digest_size > key_length:                
            password = password.encode()
            hash_pass = hashobj(password).digest()
            return hash_pass[:key_length]
        else:
            hash_versions = [hashobj() for i in range(key_length // hashobj().digest_size + 1)]
            for i in range(len(hash_versions)):
                hash_versions[i].update(b"\0" * i)
                hash_versions[i].update(password.encode())
            return b"".join([char.digest() for char in hash_versions])[:key_length]
        
    elif s2k_mode == 1 or s2k_mode == 3:
        raise ValueError(f"S2K modes 1 and 3 are not implemented")
    elif s2k_mode == 2:
        raise ValueError(f"S2K mode 2 does not exist")
    else:
        raise ValueError(f"Invalid S2K mode {s2k_mode}")

passphrase = "test"
s2k_m0_key = b"\x09\x8f\x6b\xcd\x46\x21\xd3\x73\xca\xde\x4e\x83" + \
             b"\x26\x27\xb4\xf6\x5f\x8f\x8e\x05\xef\xdc\x22\xe8"

print(calculate_s2k("test", 0, len(s2k_m0_key), 1))