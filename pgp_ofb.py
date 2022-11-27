import cui_des

class PGPObject():
    def __init__(self, key) -> None:
        self.key = key.encode("utf-8")
        self.iv = b'\x00' * len(self.key)
        self.feedback_register = self.iv
        self.feedback_register_encrpyted = b''

    def encrypt(self, pt):
        ct = b''
    #     for i in range(0, len(pt), len(self.feedback_register)):


    # def blockEncrypt(self, ct, pt):

