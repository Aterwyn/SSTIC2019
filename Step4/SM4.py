

class SM4:

    def __init__(self):
        self.SM4_key = bytearray.fromhex("0625f824d5dc439cb4c150382078cc93")
        self.CK = [0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269, 0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9, 0xE0E7EEF5]

    def b2i(self, bytes_param, sz=4):
        s = 0
        assert sz > 1
        for i in range(0, sz, 1):
            s += bytes_param[i] << (8*(sz-1-i))
        return s

    def i2b(self, int_param, sz=4):
        s_bytes = bytearray.fromhex("")
        assert sz > 1
        for i in range(sz):
            s_bytes = bytearray.fromhex("%02x" % (int_param>>(8*(i)) & 0xFF)) + s_bytes
        return s_bytes

    def def_master_key(self, key_bytes):
        return self.b2i(key_bytes[12:]),self.b2i(key_bytes[8:12]),self.b2i(key_bytes[4:8]),self.b2i(key_bytes[:4])

    global FK, CK
    #FK are not used...
    #FK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]

    #CK is truncated to only 8 elements out of 32
    


    #consider that "11223344" = 0x11223344


    def rol4_int(self, a_i, rot):
        return ((a_i << rot) & 0xFFFFFFFF) | ((a_i>> (32-rot)) & 0xFFFFFFFF)

    def func_L(self, B_i):
        LB = B_i ^ self.rol4_int(B_i, 2) ^ self.rol4_int(B_i, 10) ^ self.rol4_int(B_i, 18) ^ self.rol4_int(B_i, 24)
        return LB

    def func_L_(self, B_i):
        #B_i is a 4-bytes int
        L_B = B_i ^ self.rol4_int(B_i, 13) ^ self.rol4_int(B_i, 23)
        return L_B

    def subs(self, val):
        S_box = {
        0: [0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05],
        1: [0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99],
        2: [0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62],
        3: [0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6],
        4: [0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8],
        5: [0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35],
        6: [0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x21, 0x78, 0x87],
        7: [0xD4, 0x00, 0x46, 0x57, 0x9F, 0xD3, 0x27, 0x52, 0x4C, 0x36, 0x02, 0xE7, 0xA0, 0xC4, 0xC8, 0x9E],
        8: [0xEA, 0xBF, 0x8A, 0xD2, 0x40, 0xC7, 0x38, 0xB5, 0xA3, 0xF7, 0xF2, 0xCE, 0xF9, 0x61, 0x15, 0xA1],
        9: [0xE0, 0xAE, 0x5D, 0xA4, 0x9B, 0x34, 0x1A, 0x55, 0xAD, 0x93, 0x32, 0x30, 0xF5, 0x8C, 0xB1, 0xE3],
        0xA: [0x1D, 0xF6, 0xE2, 0x2E, 0x82, 0x66, 0xCA, 0x60, 0xC0, 0x29, 0x23, 0xAB, 0x0D, 0x53, 0x4E, 0x6F],
        0xB: [0xD5, 0xDB, 0x37, 0x45, 0xDE, 0xFD, 0x8E, 0x2F, 0x03, 0xFF, 0x6A, 0x72, 0x6D, 0x6C, 0x5B, 0x51],
        0xC: [0x8D, 0x1B, 0xAF, 0x92, 0xBB, 0xDD, 0xBC, 0x7F, 0x11, 0xD9, 0x5C, 0x41, 0x1F, 0x10, 0x5A, 0xD8],
        0xD: [0x0A, 0xC1, 0x31, 0x88, 0xA5, 0xCD, 0x7B, 0xBD, 0x2D, 0x74, 0xD0, 0x12, 0xB8, 0xE5, 0xB4, 0xB0],
        0xE: [0x89, 0x69, 0x97, 0x4A, 0x0C, 0x96, 0x77, 0x7E, 0x65, 0xB9, 0xF1, 0x09, 0xC5, 0x6E, 0xC6, 0x84],
        0xF: [0x18, 0xF0, 0x7D, 0xEC, 0x3A, 0xDC, 0x4D, 0x20, 0x79, 0xEE, 0x5F, 0x3E, 0xD7, 0xCB, 0x39, 0x48]}
        row = (val&0xF0) >> 4
        col = val&0xF
        return S_box[row][col]


    def func_tau(self, a_i):
        a = self.i2b(a_i, 4)
        temp = (self.subs(a[0])<<24) + (self.subs(a[1]) << 16) + (self.subs(a[2]) << 8) + self.subs(a[3])
        return temp

    def func_T(self, val_i):
        return self.func_L(self.func_tau(val_i))

    def func_T_(self, val_i):
        return self.func_L_(self.func_tau(val_i))

    def func_F(self, x0, x1, x2, x3, rk):
        #xi are 4 bytes bytearray
        #rk is 4 bytes bytearray
        assert len(x0) == 4
        assert len(x1) == 4
        assert len(x2) == 4
        assert len(x3) == 4
        assert len(rk) == 4
        return self.i2b( self.b2i(x0) ^ self.func_T( self.b2i(x1) ^ self.b2i(x2) ^ self.b2i(x3) ^ self.b2i(rk)), 4)


    def key_schedule(self, k_i0, k_i1, k_i2, k_i3, ck_i):
        #consider k_i as 4-byte parametres, representing K_i as int
        return k_i0 ^ self.func_T_(k_i1 ^ k_i2 ^ k_i3 ^ ck_i)


    def decrypt(self, adr, data):
        mk0, mk1, mk2, mk3 = self.def_master_key(self.SM4_key)
        k0, k1, k2, k3 = mk0, mk1, mk2, mk3

        #data must be 16 bytes 
        #data_chunk = self.r[0x10*j:0x10*j+0x10]
        data_chunk = data
        x0, x1, x2, x3 = (data_chunk[i*4:i*4+4] for i in range(4))
        xor_val = adr


        k4 = self.key_schedule(k0, k1, k2, k3, self.CK[0]^xor_val)
        k5 = self.key_schedule(k1, k2, k3, k4, self.CK[1]^xor_val)
        k6 = self.key_schedule(k2, k3, k4, k5, self.CK[2]^xor_val)
        k7 = self.key_schedule(k3, k4, k5, k6, self.CK[3]^xor_val)
        rk3, rk2, rk1, rk0 = k4, k5, k6, k7

        """
        #remove comments for debug
        print("\nxor_val: %08x" % xor_val)
        print("\nCKs: ")
        print("%08x" % (self.CK[0]))
        print("%08x" % (self.CK[1]))
        print("%08x" % (self.CK[2]))
        print("%08x" % (self.CK[3]))

        print("\nxored values: ")
        print("%08x" % (self.CK[0]^xor_val))
        print("%08x" % (self.CK[1]^xor_val))
        print("%08x" % (self.CK[2]^xor_val))
        print("%08x" % (self.CK[3]^xor_val))

        print("\nkeys:")
        print("%08x" % k3)
        print("%08x" % k2)
        print("%08x" % k1)
        print("%08x" % k0)

        print("\nround keys:")
        print("%08x" % rk3)
        print("%08x" % rk2)
        print("%08x" % rk1)
        print("%08x" % rk0)
        """

        x4 = self.func_F(x0, x1, x2, x3, self.i2b(rk0))
        x5 = self.func_F(x1, x2, x3, x4, self.i2b(rk1))
        x6 = self.func_F(x2, x3, x4, x5, self.i2b(rk2))
        x7 = self.func_F(x3, x4, x5, x6, self.i2b(rk3))

        output = x7+x6+x5+x4
        return output

    def encrypt(self, adr, data):
        mk0, mk1, mk2, mk3 = self.def_master_key(self.SM4_key)
        k0, k1, k2, k3 = mk0, mk1, mk2, mk3

        #data must be 16 bytes 
        #data_chunk = self.r[0x10*j:0x10*j+0x10]
        data_chunk = data
        x0, x1, x2, x3 = (data_chunk[i*4:i*4+4] for i in range(4))
        xor_val = adr


        k4 = self.key_schedule(k0, k1, k2, k3, self.CK[0]^xor_val)
        k5 = self.key_schedule(k1, k2, k3, k4, self.CK[1]^xor_val)
        k6 = self.key_schedule(k2, k3, k4, k5, self.CK[2]^xor_val)
        k7 = self.key_schedule(k3, k4, k5, k6, self.CK[3]^xor_val)
        rk3, rk2, rk1, rk0 = k4, k5, k6, k7

        """
        #remove comments for debug
        print("\nxor_val: %08x" % xor_val)
        print("\nCKs: ")
        print("%08x" % (self.CK[0]))
        print("%08x" % (self.CK[1]))
        print("%08x" % (self.CK[2]))
        print("%08x" % (self.CK[3]))

        print("\nxored values: ")
        print("%08x" % (self.CK[0]^xor_val))
        print("%08x" % (self.CK[1]^xor_val))
        print("%08x" % (self.CK[2]^xor_val))
        print("%08x" % (self.CK[3]^xor_val))

        print("\nkeys:")
        print("%08x" % k3)
        print("%08x" % k2)
        print("%08x" % k1)
        print("%08x" % k0)

        print("\nround keys:")
        print("%08x" % rk3)
        print("%08x" % rk2)
        print("%08x" % rk1)
        print("%08x" % rk0)
        """

        x4 = self.func_F(x0, x1, x2, x3, self.i2b(rk3))
        x5 = self.func_F(x1, x2, x3, x4, self.i2b(rk2))
        x6 = self.func_F(x2, x3, x4, x5, self.i2b(rk1))
        x7 = self.func_F(x3, x4, x5, x6, self.i2b(rk0))

        output = x7+x6+x5+x4
        return output