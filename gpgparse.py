import sys
import os

def main():
	# Check to make sure enough arguments were passed through
	if len(sys.argv) != 2:
		print("Usage: python3 gpg_parser.py <filename>")
		sys.exit(1)
	filename = sys.argv[1]
	if not os.path.isfile(filename):
		print("File does not exist")
		sys.exit(1)
	# Open the file and read the data into the data variable
	with open(filename, 'rb') as f:
		data = f.read()

	# Parse the data
	# Call the PacketParser function
	PacketParser(data)

	# Create a PacketParser object
	pp = PacketParser(data)
	# Call the parse method
	pp.parse()




### Object Oriented Packet Parser
class PacketParser:
	def __init__(self, data):
		"""
		Constructor
		"""
		self.plen = 0
		self.hlen = 0 # Header length
		self.TAG_LITERAL_DATA = 11
		self.TAG_ENCRYPTED_DATA = 9
		self.TAG_SYMKEY_ENC_SESSION = 8
		self.TAG_SYMKEY_ENC_SESSION_LEN = 1
		self.TAG_SYMKEY_ENC_SESSION_DATA = 2
		self.TAG_SYMKEY_ENC_SESSION_ALGO = 3
		self.TAG_SYMKEY_ENC_SESSION_S2K = 4
		self.TAG_SYMKEY_ENC_SESSION_IV = 5
		self.TAG_SYMKEY_ENC_SESSION_VERSION = 6
		self.TAG_SYMKEY_ENC_SESSION_CHECKSUM = 7

		self.packets = []

		self.data = data
		self.offset = 0
		self.valid_mask = 0x80
		self.format_mask = 0x40
		self.old_tag_mask = 0x3C
		self.new_tag_mask = 0x3F
		self.length_type_mask = 0x03

	def parse(self):
		"""
		Parse the data

		@rtype: list
		@return: A list of packets
		"""
		while self.offset < len(self.data):
			packet = self.data[self.offset:]
			header = packet[0]
			if header & self.valid_mask == 0:
				print("Invalid packet")
				sys.exit(1)
			if header & self.format_mask == 0:
				# Old format packet
				tag = (header & self.old_tag_mask) >> 2
				length_type = header & self.length_type_mask
				if length_type < 3:
					length = packet[1:1 + length_type + 1]
					plen = int.from_bytes(length, byteorder='big')
					hlen = 1 + length_type + 1
				else:
					length = packet[1:2]
					plen = int.from_bytes(length, byteorder='big')
					hlen = 1 + 2

			else:
				# new format
				tag = header & self.new_tag_mask
				if tag == 0:
					raise ValueError("Invalid tag")
				elif tag < 16:
					length = packet[1]
					plen = length
					hlen = 2
				elif tag < 32:
					length = packet[1]
					plen = length
					hlen = 2
				elif tag < 64:
					length = packet[1:5]
					plen = int.from_bytes(length, byteorder='big')
					hlen = 5
				elif tag < 128:
					length = packet[1:9]
					plen = int.from_bytes(length, byteorder='big')
					hlen = 9
				elif tag < 192:
					plen = tag
					hlen = 1
				elif tag < 224:
					length = packet[1:2]
					plen = ((tag - 192) << 8) + length[0] + 192
					hlen = 2
				elif tag < 255:
					length = packet[1:3]
					plen = (tag - 224) << 8 + length[0]
					hlen = 3
				else:
					raise ValueError("Invalid tag")

			# Print the packet tag, ctb(in hex), header length and packet length
			print("off= %d, ctb= 0x%x, tag= %d, hlen= %d, plen= %d" % (self.offset, header, tag, hlen, plen))


			# Check to see if the packet tag is 3
			if tag == 3:
				# The packet tag is 3
				print(":symkey enc packet:")
			# Check to see if the packet tag is 18
			elif tag == 18:
				# The packet tag is 18
				print(":encrypted data packet:")
			# Check to see if the packet tag is 0
			elif tag == 0:
				# The packet tag is 0
				print(":reserved packet:")
			# Check to see if the packet tag is 1
			elif tag == 1:
				# The packet tag is 1
				print(":public key packet:")
			# Check to see if the packet tag is 2
			elif tag == 2:
				# The packet tag is 2
				print(":signature packet:")
			# Check to see if the packet tag is 4
			elif tag == 4:
				# The packet tag is 4
				print(":one pass sig packet:")
			# Check to see if the packet tag is 5
			elif tag == 5:
				# The packet tag is 5
				print(":secret key packet:")
			# Check to see if the packet tag is 6
			elif tag == 6:
				# The packet tag is 6
				print(":public subkey packet:")
			# Check to see if the packet tag is 7
			elif tag == 7:
				# The packet tag is 7
				print(":compressed data packet:")
				# Check to see if the packet tag is 8
				print(":symkey encrypted session packet:")
			# Check to see if the packet tag is 9
			elif tag == 9:
				# The packet tag is 9
				print(":marker packet:")
			# Check to see if the packet tag is 10
			elif tag == 10:
				# The packet tag is 10
				print(":literal data packet:")
			# Check to see if the packet tag is 11
			elif tag == 11:
				# The packet tag is 11
				print(":trust packet:")
			# Check to see if the packet tag is 12
			elif tag == 12:
				# The packet tag is 12
				print(":user id packet:")
			# Check to see if the packet tag is 13
			elif tag == 13:
				# The packet tag is 13
				print(":public subkey packet:")
			# Check to see if the packet tag is 14
			elif tag == 14:
				# The packet tag is 14
				print(":user attribute packet:")
			# Check to see if the packet tag is 17
			elif tag == 17:
				# The packet tag is 17
				print(":modification detection code packet:")
			# Check to see if the packet tag is 60
			elif tag == 60:
				# The packet tag is 60
				print(":experimental packet:")
			# Check to see if the packet tag is 61
			elif tag == 61:
				# The packet tag is 61
				print(":experimental packet:")
			# Check to see if the packet tag is 62
			elif tag == 62:
				# The packet tag is 62
				print(":experimental packet:")
			# Check to see if the packet tag is 63
			elif tag == 63:
				# The packet tag is 63
				print(":experimental packet:")
			# Check to see if the packet tag is 19
			elif tag == 19:
				# The packet tag is 19
				print(":private or experimental packet:")
			# Check to see if the packet tag is 20
			elif tag == 20:
				# The packet tag is 20
				print(":private or experimental packet:")
			# Check to see if the packet tag is 21
			elif tag == 21:
				# The packet tag is 21
				print(":private or experimental packet:")
			# Check to see if the packet tag is 22
			elif tag == 22:
				# The packet tag is 22
				print(":private or experimental packet:")
			# Check to see if the packet tag is 23
			elif tag == 23:
				# The packet tag is 23
				print(":private or experimental packet:")
			# Check to see if the packet tag is 24
			elif tag == 24:
				# The packet tag is 24
				print(":private or experimental packet:")

			# Increment the offset by the packet header length
			self.offset += hlen
			# Increment the offset by the packet length
			self.offset += plen

			# Append the packet with the header and packet data
			self.packets.append((header, packet[:hlen + plen]))

			# Check to see if the offset is greater than the length of the data
			if self.offset >= len(self.data):
				# The offset is greater than the length of the data
				# Break out of the loop
				break




	def _ptag_literal_data(self):
		# Print the literal data packet
		print(":literal data packet:")
		# Print the literal data packet format
		print("format: %d" % self.data[self.offset])
		# Increment the offset by 1
		self.offset += 1
		# Print the literal data packet filename
		print("filename: %s" % self.data[self.offset:self.data.find('\0', self.offset)])
		# Increment the offset by the length of the filename
		self.offset += len(self.data[self.offset:self.data.find('\0', self.offset)])
		# Increment the offset by 1
		self.offset += 1
		# Print the literal data packet data
		print("data: %s" % self.data[self.offset:])
		# Increment the offset by the length of the data
		self.offset += len(self.data[self.offset:])
		# Check to see if the offset is greater than the length of the data
		if self.offset >= len(self.data):
			# The offset is greater than the length of the data
			# Break out of the loop
			return




if __name__ == "__main__":
	main()

	"""
		From RFC 4880:
		4.  Packet Syntax

		   This section describes the packets used by OpenPGP.

		4.1.  Overview

		   An OpenPGP message is constructed from a number of records that are
		   traditionally called packets.  A packet is a chunk of data that has a
		   tag specifying its meaning.  An OpenPGP message, keyring,
		   certificate, and so forth consists of a number of packets.  Some of
		   those packets may contain other OpenPGP packets (for example, a
		   compressed data packet, when uncompressed, contains OpenPGP packets).

		   Each packet consists of a packet header, followed by the packet body.
		   The packet header is of variable length.

		4.2.  Packet Headers

		   The first octet of the packet header is called the "Packet Tag".  It
		   determines the format of the header and denotes the packet contents.
		   The remainder of the packet header is the length of the packet.
		   Note that the most significant bit is the leftmost bit, called bit 7.
		   A mask for this bit is 0x80 in hexadecimal.

					  +---------------+
				 PTag |7 6 5 4 3 2 1 0|
					  +---------------+
				 Bit 7 -- Always one
				 Bit 6 -- New packet format if set

		   PGP 2.6.x only uses old format packets.  Thus, software that
		   interoperates with those versions of PGP must only use old format
		   packets.  If interoperability is not an issue, the new packet format
		   is RECOMMENDED.  Note that old format packets have four bits of
		   packet tags, and new format packets have six; some features cannot be
		   used and still be backward-compatible.

		   Also note that packets with a tag greater than or equal to 16 MUST
		   use new format packets.  The old format packets can only express tags
		   less than or equal to 15.

		   Old format packets contain:

				 Bits 5-2 -- packet tag
				 Bits 1-0 -- length-type

		   New format packets contain:

				 Bits 5-0 -- packet tag

		4.2.1.  Old Format Packet Lengths

		   The meaning of the length-type in old format packets is:

		   0 - The packet has a one-octet length.  The header is 2 octets long.

		   1 - The packet has a two-octet length.  The header is 3 octets long.

		   2 - The packet has a four-octet length.  The header is 5 octets long.

		   3 - The packet is of indeterminate length.  The header is 1 octet
			   long, and the implementation must determine how long the packet
			   is.  If the packet is in a file, this means that the packet
			   extends until the end of the file.  In general, an implementation
			   SHOULD NOT use indeterminate-length packets except where the end
			   of the data will be clear from the context, and even then it is
			   better to use a definite length, or a new format header.  The new
			   format headers described below have a mechanism for precisely
			   encoding data of indeterminate length.
			   4.2.2.  New Format Packet Lengths

		   New format packets have four possible ways of encoding length:

		   1. A one-octet Body Length header encodes packet lengths of up to 191
			  octets.

		   2. A two-octet Body Length header encodes packet lengths of 192 to
			  8383 octets.

		   3. A five-octet Body Length header encodes packet lengths of up to
			  4,294,967,295 (0xFFFFFFFF) octets in length.  (This actually
			  encodes a four-octet scalar number.)

		   4. When the length of the packet body is not known in advance by the
			  issuer, Partial Body Length headers encode a packet of
			  indeterminate length, effectively making it a stream.

		4.2.2.1.  One-Octet Lengths

		   A one-octet Body Length header encodes a length of 0 to 191 octets.
		   This type of length header is recognized because the one octet value
		   is less than 192.  The body length is equal to:

			   bodyLen = 1st_octet;

		4.2.2.2.  Two-Octet Lengths

		   A two-octet Body Length header encodes a length of 192 to 8383
		   octets.  It is recognized because its first octet is in the range 192
		   to 223.  The body length is equal to:

			   bodyLen = ((1st_octet - 192) << 8) + (2nd_octet) + 192

		4.2.2.3.  Five-Octet Lengths

		   A five-octet Body Length header consists of a single octet holding
		   the value 255, followed by a four-octet scalar.  The body length is
		   equal to:

			   bodyLen = (2nd_octet << 24) | (3rd_octet << 16) |
						 (4th_octet << 8)  | 5th_octet

		   This basic set of one, two, and five-octet lengths is also used
		   internally to some packets.
		   4.2.2.4.  Partial Body Lengths

		   A Partial Body Length header is one octet long and encodes the length
		   of only part of the data packet.  This length is a power of 2, from 1
		   to 1,073,741,824 (2 to the 30th power).  It is recognized by its one
		   octet value that is greater than or equal to 224, and less than 255.
		   The Partial Body Length is equal to:

			   partialBodyLen = 1 << (1st_octet & 0x1F);

		   Each Partial Body Length header is followed by a portion of the
		   packet body data.  The Partial Body Length header specifies this
		   portion's length.  Another length header (one octet, two-octet,
		   five-octet, or partial) follows that portion.  The last length header
		   in the packet MUST NOT be a Partial Body Length header.  Partial Body
		   Length headers may only be used for the non-final parts of the
		   packet.

		   Note also that the last Body Length header can be a zero-length
		   header.

		   An implementation MAY use Partial Body Lengths for data packets, be
		   they literal, compressed, or encrypted.  The first partial length
		   MUST be at least 512 octets long.  Partial Body Lengths MUST NOT be
		   used for any other packet types.

		4.2.3.  Packet Length Examples

		   These examples show ways that new format packets might encode the
		   packet lengths.

		   A packet with length 100 may have its length encoded in one octet:
		   0x64.  This is followed by 100 octets of data.

		   A packet with length 1723 may have its length encoded in two octets:
		   0xC5, 0xFB.  This header is followed by the 1723 octets of data.

		   A packet with length 100000 may have its length encoded in five
		   octets: 0xFF, 0x00, 0x01, 0x86, 0xA0.

		   It might also be encoded in the following octet stream: 0xEF, first
		   32768 octets of data; 0xE1, next two octets of data; 0xE0, next one
		   octet of data; 0xF0, next 65536 octets of data; 0xC5, 0xDD, last 1693
		   octets of data.  This is just one possible encoding, and many
		   variations are possible on the size of the Partial Body Length
		   headers, as long as a regular Body Length header encodes the last
		   portion of the data.
		   Please note that in all of these explanations, the total length of
		   the packet is the length of the header(s) plus the length of the
		   body.

		4.3.  Packet Tags

		   The packet tag denotes what type of packet the body holds.  Note that
		   old format headers can only have tags less than 16, whereas new
		   format headers can have tags as great as 63.  The defined tags (in
		   decimal) are as follows:

			   0        -- Reserved - a packet tag MUST NOT have this value
			   1        -- Public-Key Encrypted Session Key Packet
			   2        -- Signature Packet
			   3        -- Symmetric-Key Encrypted Session Key Packet
			   4        -- One-Pass Signature Packet
			   5        -- Secret-Key Packet
			   6        -- Public-Key Packet
			   7        -- Secret-Subkey Packet
			   8        -- Compressed Data Packet
			   9        -- Symmetrically Encrypted Data Packet
			   10       -- Marker Packet
			   11       -- Literal Data Packet
			   12       -- Trust Packet
			   13       -- User ID Packet
			   14       -- Public-Subkey Packet
			   17       -- User Attribute Packet
			   18       -- Sym. Encrypted and Integrity Protected Data Packet
			   19       -- Modification Detection Code Packet
			   60 to 63 -- Private or Experimental Values
	"""

"""
def PacketParser(data):
	# Initialize the offset variable
	valid_mask = 0x80
	format_mask = 0x40
	old_tag_mask = 0x3C
	new_tag_mask = 0x3F
	length_type_mask = 0x03

	offset = 0

	while offset < len(data):
		packet = data[offset:]
		header = packet[0]
		if header & valid_mask == 0:
			print("Invalid packet")
			sys.exit(1)
		if header & format_mask == 0:
			# Old format packet
			tag = (header & old_tag_mask) >> 2
			length_type = header & length_type_mask
			if length_type < 3:
				length = packet[1:1+length_type+1]
				plen = int.from_bytes(length, byteorder='big')
				hlen = 1 + length_type + 1
			else:
				length = packet[1:2]
				plen = int.from_bytes(length, byteorder='big')
				hlen = 1 + 2

		else:
			# new format
			tag = header & new_tag_mask
			if tag == 0:
				raise ValueError("Invalid tag")
			elif tag < 16:
				length = packet[1]
				plen = length
				hlen = 2
			elif tag < 32:
				length = packet[1]
				plen = length
				hlen = 2
			elif tag < 64:
				length = packet[1:5]
				plen = int.from_bytes(length, byteorder='big')
				hlen = 5
			elif tag < 128:
				length = packet[1:9]
				plen = int.from_bytes(length, byteorder='big')
				hlen = 9
			elif tag < 192:
				plen = tag
				hlen = 1
			elif tag < 224:
				length = packet[1:2]
				plen = ((tag - 192) << 8) + length[0] + 192
				hlen = 2
			elif tag < 255:
				length = packet[1:3]
				plen = (tag - 224) << 8 + length[0]
				hlen = 3
			else:
				raise ValueError("Invalid tag")


		# Print the packet tag, ctb(in hex), header length and packet length
		print("off= %d, ctb= 0x%x, tag= %d,  hlen= %d, plen= %d" % (offset, header, tag, hlen, plen))

		# Check to see if the packet tag is 3
		if tag == 3:
			# The packet tag is 3
			print(":symkey enc packet:")
		# Check to see if the packet tag is 18
		elif tag == 18:
			# The packet tag is 18
			print(":encrypted data packet:")
		# Check to see if the packet tag is 0
		elif tag == 0:
			# The packet tag is 0
			print(":reserved packet:")
		# Check to see if the packet tag is 1
		elif tag == 1:
			# The packet tag is 1
			print(":public key packet:")
		# Check to see if the packet tag is 2
		elif tag == 2:
			# The packet tag is 2
			print(":signature packet:")
		# Check to see if the packet tag is 4
		elif tag == 4:
			# The packet tag is 4
			print(":one pass sig packet:")
		# Check to see if the packet tag is 5
		elif tag == 5:
			# The packet tag is 5
			print(":secret key packet:")
		# Check to see if the packet tag is 6
		elif tag == 6:
			# The packet tag is 6
			print(":public subkey packet:")
		# Check to see if the packet tag is 7
		elif tag == 7:
			# The packet tag is 7
			print(":compressed data packet:")
		# Check to see if the packet tag is 8
			print(":symkey encrypted session packet:")
		# Check to see if the packet tag is 9
		elif tag == 9:
			# The packet tag is 9
			print(":marker packet:")
		# Check to see if the packet tag is 10
		elif tag == 10:
			# The packet tag is 10
			print(":literal data packet:")
		# Check to see if the packet tag is 11
		elif tag == 11:
			# The packet tag is 11
			print(":trust packet:")
		# Check to see if the packet tag is 12
		elif tag == 12:
			# The packet tag is 12
			print(":user id packet:")
		# Check to see if the packet tag is 13
		elif tag == 13:
			# The packet tag is 13
			print(":public subkey packet:")
		# Check to see if the packet tag is 14
		elif tag == 14:
			# The packet tag is 14
			print(":user attribute packet:")
		# Check to see if the packet tag is 17
		elif tag == 17:
			# The packet tag is 17
			print(":modification detection code packet:")
		# Check to see if the packet tag is 60
		elif tag == 60:
			# The packet tag is 60
			print(":experimental packet:")
		# Check to see if the packet tag is 61
		elif tag == 61:
			# The packet tag is 61
			print(":experimental packet:")
		# Check to see if the packet tag is 62
		elif tag == 62:
			# The packet tag is 62
			print(":experimental packet:")
		# Check to see if the packet tag is 63
		elif tag == 63:
			# The packet tag is 63
			print(":experimental packet:")
		# Check to see if the packet tag is 19
		elif tag == 19:
			# The packet tag is 19
			print(":private or experimental packet:")
		# Check to see if the packet tag is 20
		elif tag == 20:
			# The packet tag is 20
			print(":private or experimental packet:")
		# Check to see if the packet tag is 21
		elif tag == 21:
			# The packet tag is 21
			print(":private or experimental packet:")
		# Check to see if the packet tag is 22
		elif tag == 22:
			# The packet tag is 22
			print(":private or experimental packet:")
		# Check to see if the packet tag is 23
		elif tag == 23:
			# The packet tag is 23
			print(":private or experimental packet:")
		# Check to see if the packet tag is 24
		elif tag == 24:
			# The packet tag is 24
			print(":private or experimental packet:")

		# Increment the offset by the packet header length
		offset += hlen
		# Increment the offset by the packet length
		offset += plen
		# Check to see if the offset is greater than the length of the data
		if offset >= len(data):
			# The offset is greater than the length of the data
			# Break out of the loop
			break
"""



