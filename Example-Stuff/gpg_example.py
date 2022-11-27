from getpass import getpass
import sys
import s2k
import gpgparse
import PgpOfb


def parse_packets(data):
    """
    Parses the GPG file and extracts the encrypted data.
    """
    packets = []
    i = 0
    while i < len(data):
        # Get the packet tag
        ptag = data[i]
        i += 1

        # Get the packet length
        plen = data[i]
        i += 1

        # Get the packet data
        pdata = data[i:i + plen]
        i += plen

        # Add the packet to the list
        packets.append((ptag, plen, pdata))

    return packets


def main():
    # Error checking
    if len(sys.argv) < 2:
        print("Usage: python gpg_decrypt.py <filename>")
        return
    elif not sys.argv[1].endswith(".gpg"):
        print("Error: File must be a GPG file")
        return
    elif len(sys.argv) > 2:
        print("Error: Too many arguments")
        return

    # Get the filename from the command line
    filename = sys.argv[1]

    gpg_decrypt(filename)





def gpg_decrypt(filename):
    """
    Decrypts the GPG file.
    """

    # Get the password from the user
    password = getpass("Password: ")

    # Read the file
    with open(filename, "rb") as f:
        data = f.read()

    # Part1 - Parse the GPG file and extract the encrypted data
    parser = gpgparse.PacketParser(data) # Parser object
    parser.parse() # Parse the file



    # Part2 - Decrypt the encrypted data using the password
    # Get the encrypted data
    encrypted_data = parser.get_encrypted_data()

    # Get the S2K parameters
    s2k_params = parser.get_s2k_params()


    # Get the key
    key = s2k.get_key(password, s2k_type, s2k_hash, s2k_salt, s2k_count)

    # Decrypt the data
    cipher = PgpOfb.PgpOfb(key, x)
    decrypted_data = cipher.decrypt(encrypted_data)

    # Part3 - Parse the decrypted data and extract the plaintext
    parser = gpgparse.PacketParser(decrypted_data)
    packets = parser.parse()

    # Get the plaintext
    plaintext = packets[0][2]

    # Print the plaintext
    print(plaintext)

    # Part4 - Write the plaintext to a file
    with open("plaintext.txt", "wb") as f:
        f.write(plaintext)

    print("Done")



if __name__ == "__main__":
    main()


#Example Output:
#C:\Users\{USER}\{...}> python gpg_decrypt.py test.txt.gpg
#Password: _
#
#Encrypt some files of his choice using GPG and then will try to decrypt them using your program. Here is the list of
#specific GPG command line options that Professor Tallman will use when creating the encrypted file:
#    -z 0 --symmetric --cipher-algo 3DES --s2k-digest-algo MD5 --s2k-mode 0
#
#Here (test.txt.gpg) is a sample GPG file for you to work with. It is the same example we have used during class
#exercises that contains a short UTF-8 encoded text message. The file was encrypted with the password "test". Please
#note Professor Tallman will grade your project using a different file that has been encrypted with the same GPG
#parameters. But the GPG file used for grading will contain a significantly larger plaintext file, which will require
#your packet parsing code to handle multi-byte packet sizes.
#There are four main parts to this project, many of which we will work on during class. You will need to write most of
#this code yourself (you may use other open-source tools for reference, but you must make the code your own).
#Some of the code is available already in libraries.
#
#Roadmap:
#Part 1: Parse the GPG file and extract the encrypted data
#Part 2: Decrypt the encrypted data using the password
#Part 3: Parse the decrypted data and extract the plaintext
#Part 4: Display the plaintext to the user


def x():
    print("hello")