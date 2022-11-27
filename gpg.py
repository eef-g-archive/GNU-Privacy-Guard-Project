import gpg_consts
import argparse
import hashlib


#####################
#   PACKET PARSING  #
#####################
def packet_parse(filename):
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



if __name__ == "__main__":

    
    parser = argparse.ArgumentParser(prog="GPG Program", 
                                     description="A simple GPG program for Information Security")
    parser.add_argument('filename')
    #parser.add_argument('--s2k-mode')
    try:
        args = parser.parse_args()
    except:
        print("Please provide a filename to parse packets from.")
        exit(0)
    packet_parse(args.filename)