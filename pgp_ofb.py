'''

    13.9.  OpenPGP CFB Mode

   OpenPGP does symmetric encryption using a variant of Cipher Feedback
   mode (CFB mode).  This section describes the procedure it uses in
   detail.  This mode is what is used for Symmetrically Encrypted Data
   Packets; the mechanism used for encrypting secret-key material is
   similar, and is described in the sections above.

   In the description below, the value BS is the block size in octets of
   the cipher.  Most ciphers have a block size of 8 octets.  The AES and
   Twofish have a block size of 16 octets.  Also note that the
   description below assumes that the IV and CFB arrays start with an
   index of 1 (unlike the C language, which assumes arrays start with a
   zero index).

   OpenPGP CFB mode uses an initialization vector (IV) of all zeros, and
   prefixes the plaintext with BS+2 octets of random data, such that
   octets BS+1 and BS+2 match octets BS-1 and BS.  It does a CFB
   resynchronization after encrypting those BS+2 octets.

   Thus, for an algorithm that has a block size of 8 octets (64 bits),
   the IV is 10 octets long and octets 7 and 8 of the IV are the same as
   octets 9 and 10.  For an algorithm with a block size of 16 octets
   (128 bits), the IV is 18 octets long, and octets 17 and 18 replicate
   octets 15 and 16.  Those extra two octets are an easy check for a
   correct key.

    Step by step, here is the procedure:

       1.  The feedback register (FR) is set to the IV, which is all zeros.

       2.  FR is encrypted to produce FRE (FR Encrypted).  This is the
           encryption of an all-zero value.

       3.  FRE is xored with the first BS octets of random data prefixed to
           the plaintext to produce C[1] through C[BS], the first BS octets
           of ciphertext.

       4.  FR is loaded with C[1] through C[BS].

       5.  FR is encrypted to produce FRE, the encryption of the first BS
           octets of ciphertext.

       6.  The left two octets of FRE get xored with the next two octets of
           data that were prefixed to the plaintext.  This produces C[BS+1]
           and C[BS+2], the next two octets of ciphertext.

       7.  (The resynchronization step) FR is loaded with C[3] through
           C[BS+2].

       8.  FR is encrypted to produce FRE.

       9.  FRE is xored with the first BS octets of the given plaintext, now
           that we have finished encrypting the BS+2 octets of prefixed
           data.  This produces C[BS+3] through C[BS+(BS+2)], the next BS
           octets of ciphertext.

       10. FR is loaded with C[BS+3] to C[BS + (BS+2)] (which is C11-C18 for
           an 8-octet block).

           11. FR is encrypted to produce FRE.

           12. FRE is xored with the next BS octets of plaintext, to produce
           the next BS octets of ciphertext.  These are loaded into FR, and
           the process is repeated until the plaintext is used up.
'''
import cui_des

def OFB_decryption(data, key):
    iv = b'\x00' * 8
    decryptions = []
    # Skip first char in packet bc it checks if its valid or not
    ct = data[1:]

    # Decrypt first two blocks separately -- starting w/ first block
    first = ct[:8]
    DESobj = cui_des.TDES(key, "OFB", iv)
    curr_decrypt = DESobj.decrypt(first)
    decryptions.append(curr_decrypt)

    # Decrypt second block
    second = ct[8:16]
    DESobj.iv = first
    curr_decrypt = DESobj.decrypt(second)
    decryptions.append(curr_decrypt)


    iv = second
    for block in cui_des._nsplit(data[16:], 8):
        DESobj.iv = iv
        curr_decrypt = DESobj.decrypt(block)
        decryptions.append(curr_decrypt)
        iv = block

    # Rejoin all the blocks
    final_decrypt = "".join(decryptions)
    return final_decrypt

