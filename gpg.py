import gpg_consts
import hashlib
import cui_des
import sys
import binascii


#####################
#   PACKET PARSING  #
#####################
def packet_parse(filename):
    encrypted_data = []
    with open(filename, 'rb') as file:
        content = file.read()
    
    offset = 0
    valid_mask = 0x80
    format_mask = 0x40
    old_tag_mask = 0x3C
    new_tag_mask = 0x3F
    ltype_mask = 0x03
    while offset < len(content):
        # ATM, going to assume content is a list of strings in Hex
        # Parse individual packet
        packet = content[offset:]
        header = packet[0]
        if header & valid_mask == 0:
            print("Packet not valid")
            exit(0)
        

        #NOTES:
        # - The tag is what we use to find what type of packet it is
        # - In the OLD format, the tag will only ever be 4 bits long, so max tag number is 15, but in
        #   NEW format, then it can be more than 15 and will have more options
        # - The tags we're looking for are 3 OR 18, rest can return that we don't know what we're looking at

        # Print out the offset, the "ctb", the tag, the header length, the packet length, and note if its a new format
        # The CTB is the byte at the offset


        if header & format_mask == 0:
            #Old format
            tag = (header & old_tag_mask) >> 2
            ltype = header & ltype_mask
            if ltype == 0:
                # Get packet length as next Hex octet
                hlen = 2
                plen = packet[1]
                p_data = packet[hlen:hlen + plen]
                pass
            elif ltype == 1:
                # Get packet length as next 2 Hex octets
                hlen = 3
                plen = packet[2]
                p_data = packet[hlen:hlen + plen]
                pass
            elif ltype == 2:
                # Get packet length as next 4 octets
                hlen = 5
                plen = packet[4]
                p_data = packet[hlen:hlen + plen]
                pass
            else:
                # You're screwed my friend!
                pass
            pass
            print(f"# off={offset} ctb={content[offset]} tag={tag} hlen={hlen} plen={plen}")
        else:
            #New format
            tag = header & new_tag_mask # Do not need to shift it bc the tag in the new format is simply the remainder of the header
            plen = packet[1]
            hlen = 2
            p_data = packet[hlen:hlen + plen]
            print(f"# off={offset} ctb={content[offset]} tag={tag} hlen={hlen} plen={plen} new-ctb")
            pass

        if tag == gpg_consts._ptag_symkey_enc_session:
            print(": symkey enc packet :")
        elif tag == gpg_consts._ptag_sym_enc_int_data:
            print(": encrypted data packet :")
        else:
            print(f": No code to support packet type {tag} :")
        offset += hlen + plen
        encrypted_data.append(p_data)

    return encrypted_data
#################
#       S2K     #
#################

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


######################
#    OFB DECRYPT     #
######################

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
    DESobj = cui_des.TDES(key, "OFB", first)
    second = ct[8:16]
    curr_decrypt = DESobj.decrypt(second)
    decryptions.append(curr_decrypt)


    iv = second
    pt = data
    for block in cui_des._nsplit(data[16:], 8):
        DESobj = cui_des.TDES(key, "OFB", iv)
        curr_decrypt = DESobj.decrypt(block)
        decryptions.append(curr_decrypt)
        iv = block

    # Rejoin all the blocks
    final_decrypt = b"".join(decryptions)
    return final_decrypt


#####################
#   MISC FUNCTIONS  #
#####################
def hex_to_string(hex_data):
    """
    INPUT:
    takes in an array of hex data
    OUTPUT:
    an array of string data
    """
    #put the data in an array
    string_data = []
    for i in range(len(hex_data)):
        byte_packet = binascii.unhexlify(hex_data[i])
        string_packet = _get_output(byte_packet, "plaintext")
        string_data.append(string_packet[14:-24])
    #print the data out
    for i in range(len(string_data)):
        print("packet " + str(i + 1) + " string: " + str(string_data[i]))
    return string_data


def _get_output(final_bytes, output_type):
    """takes in bytes, and the outputtype, and then returns either plaintext or the bytes depending on the type of output"""
    output = ''
    if output_type == "plaintext":
        try:
            output = final_bytes.decode('UTF-8', 'strict')
        except:
            return final_bytes
    elif output_type == "hex":
        for byte in final_bytes:
            output += hex(byte)[2:].zfill(2)
    else:
        output == final_bytes
    return output



if __name__ == "__main__":
    # readFile, writeFile, password, s2kMode, keyLength, hashAlgorithm
    
    # NEED TO DO ERROR CHECKING FOR FINAL PROJECT
    #readFile = str(sys.argv[1]) # start w/ argv[1]
    readFile = "C:\\Users\\etan3\\OneDrive\\Documents\\GitHub\\GNU-Privacy-Guard-Project\\test.txt.gpg"
    packet_data = packet_parse(readFile)
    s2k_key = calculate_s2k("test", 0, 24, 1)
    decrypted = []
    for i in range(len(packet_data) - 1):
        decrypt_packet = OFB_decryption(packet_data[i + 1], s2k_key)
        decrypted.append(decrypt_packet)
        print(f"Decrypted Packet {str(i + 1)} : {str(decrypt_packet)}")