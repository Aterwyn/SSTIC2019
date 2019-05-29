def minus(op1, op2):
    #compute op1-op2 on 8 bytes
    r = op1-op2

    if r<0:
        return 0x10000000000000000 + r 
    return r

def rotateRight(val, n):
    return ((val>>n) | (val<<(32-n))) & 0xFFFFFFFF

def rotateLeft(val, n):
    return ((val<<n) | (val>>(32-n))) & 0xFFFFFFFF


def MSB4(val):
    return (val>>32)&0xFFFFFFFF

def LSB4(val):
    return val&0xFFFFFFFF

def LSB8(val):
    return val & 0xFFFFFFFFFFFFFFFF


def QWORD(valMSB, valLSB):
    return (valMSB<<32) | valLSB

def split_QWORD(qword):
    return (qword>>32)&0xFFFFFFFF, qword&0xFFFFFFFF

debug_break = 0

#entered 32 times
def F(B0, B1):
    lis = [0x5963b39b, 0x30f75add, 0x103fecbc, 0x00392e7a, 0x35df7adf, 0xe19abd13, 0xdaf8b35c, 0xf8798214, 0xb30c2305, 0x067980e9, 0x6900d940, 0x035e876f, 0xa3857014, 0x56c8e162, 0xe9748f56, 0x91d4e409, 0xdcc75a09, 0xac65f52f, 0x8571dd07, 0x019edcf6, 0x51cef9eb, 0x1eb1b17d, 0x0abe446f, 0x3b277cfe, 0x843869bc, 0xb23ea298, 0x7c296f51, 0xcd799972, 0x62180a64, 0x0ac052d5, 0xf0076205, 0x13183193, 0xb908cb94, 0x4bf4cd3c, 0xdee5d48a, 0xf64f9a74, 0xd64a15d0, 0xb2cad434, 0x64e9013b, 0xf46cc1d2, 0x9d78e9db, 0x11789216, 0x335689e6, 0x074c7edb, 0xe6eb6185, 0xd020170b, 0xf304aa15, 0xbcf2b69e, 0x4eb3d2ea, 0xd78d4d5c, 0x7ed2bfc4, 0x58ebf0f3, 0x8b591c3f, 0xd3041f6b, 0x005cae88, 0xba696f5c, 0xc16c8ede, 0x9abcbb27, 0x56d78d77, 0x765b3e20, 0xcf37212d, 0x192e2dcf, 0x8caf2806, 0xbc9a575b, 0x776421ce, 0x527fb9eb, 0x69f84340, 0xadbc7bd7, 0x73f2c329, 0x737f8a7f, 0xe301d3e4, 0x057ebeb2, 0x5859b858, 0x2cc41979, 0xec69a639, 0x53b0d523, 0x39a2f532, 0x8b29e35d, 0x44e2ce81, 0xcc10a16d, 0x44d9ff58, 0x77102c14, 0xfb57817d, 0x3cf7c8c8, 0x1222868a, 0x4173d5d1, 0x3529ee32, 0x7a9df58e, 0x513525ac, 0x81954bac, 0xce53ccf5, 0x79168728, 0xa2d660f8, 0xf30cc9ce, 0xf0b89c76, 0x089fb3a9, 0xc919dba8, 0x1f9e4dc3, 0xa2594e0c, 0x34ffe178, 0xb04414fb, 0xd31fb33a, 0x184d0278, 0x2c816a9a, 0xb993f2f2, 0xe4d8601c, 0x49e2eede, 0x9cd50ce1, 0xc03e1e77, 0xa901869e, 0x7579de50, 0x726ac4ab, 0x38d04840, 0xeabe1270, 0x8c40812d, 0xe84976b7, 0x172b04ad, 0x756606c4, 0x66258491, 0xb5a0bef8, 0x6bcc5cf3, 0xa535ae94, 0xc97a87aa, 0x9103a8f6, 0xcc3b9e5f, 0xbb20be1f, 0xffcfef97, 0x90954f16, 0x501ae1a6, 0x6ed589cd, 0x6826b02b, 0x565ff263, 0x8e8c369b, 0x6990be7a, 0x3525b840, 0x1847d7bb, 0x355a40c7, 0xa3579f10, 0xe9edecae, 0xd0337ab1, 0x6355e5ba, 0x88975355, 0x5ec0f3cf, 0xa0d6213d, 0x75389387, 0xe40216f0, 0xd980cce0, 0x6c88c67c, 0x829d419c, 0x3bf6451b, 0x11f07bfa, 0xc4c1154e, 0xbd0735eb, 0x9cf8df9d, 0xe457be75, 0x63a6bd18, 0xefe77fd3, 0x83421b63, 0x7f83072d, 0x44940f61, 0xf8bdcdf7, 0x61c802ca, 0x0a30f9a8, 0x7ff03b37, 0xa26cc5a9, 0xe10e570d, 0x95ea0c16, 0xa05e6b02, 0xc81d5384, 0x7785db05, 0x92c84c5f, 0x05584617, 0x82bcfe8d, 0x559ea1da, 0x4fd5cdb0, 0x9d871fed, 0xdd6f5539, 0x4ed1ef26, 0xfe6813c4, 0x1cfa71d5, 0xd5613aea, 0x0f1c9b8c, 0x2bcac45d, 0x65d00f41, 0x689be0d8, 0x68b01100, 0x635bd280, 0x954d5d4b, 0x72887f79, 0xce027a75, 0xfcf01c66, 0x006a1bd3, 0x199a1c8e, 0x87d6ee25, 0x938e9f08, 0xd8a11d4d, 0x2b9a4d81, 0xb6f5d2e5, 0xd15c325a, 0x64eaafc1, 0xfd33b61c, 0x43c1bd57, 0x37b8f048, 0x5cba7cf2, 0x72810cd0, 0xabfef454, 0xa76384ba, 0xd8861440, 0x36de5837, 0x0f6a03f1, 0x10d48fa1, 0x5883ec2f, 0xa8c00c9b, 0x618ffea4, 0xa05da206, 0xffb9e97a, 0x8a376781, 0x3156b479, 0xe4af5ecd, 0x87d9e06f, 0xb4d4d459, 0xeb9a7d25, 0x59dffeaa, 0xdc8bf553, 0x6dce3c3a, 0x2162970e, 0xe8c9929d, 0x6c3a9bf4, 0x45da5392, 0x9ceee7b0, 0x3f68d4eb, 0xcd29434f, 0x0e4df712, 0xb1a8c69a, 0x1c190f46, 0x2b45873c, 0x46afdfc9, 0x61e8883f, 0x979118c7, 0x70f991b1, 0x1f82604d, 0xc18bf48f, 0xb327f4ff, 0x519a7508, 0xfa619b0d, 0x268d1490, 0x567e37c2, 0x25a07691, 0x424359c0, 0x13320c53, 0xeff742fd, 0x48b945ba, 0xcfa8e711, 0x8f5fb519, 0x2b7332a5, 0x10aa767c]

    value = lis[MSB4(B1)&0xFF]
    t0 = LSB4(B0) ^ (MSB4(B0) + LSB4(B1))

    t1 = LSB4(t0 + value)
    t2 = LSB4(MSB4(B0) & B1)
    val1 = QWORD(t2, t1)

    t3 = LSB4(minus(LSB4(B1), t0))
    t4 = t1 ^ (MSB4(B1)>>8)
    val2 = QWORD(t4, t3)

    return val1, val2


#entered 960 times
def F_bis(B0, B1, m):

    lis = [0xd6378fea, 0xe23ca8c4, 0x84e3b1bc, 0xce5e10bf, 0xa2b364da, 0x41f250f0, 0x0fe97040, 0x1cc05266, 0x16f87e4b, 0x515e26b7, 0xeea48dcb, 0x62b357e4, 0x39bd2041, 0x72cd387a, 0xf37aac8b]

    t0 = LSB4(MSB4(B0)+0x45786532)
    t1 = t0 ^ LSB4(B1)

    if t1 & 0x80000000:
        Zx = 0x60bf080f # 0x84653217
    else:
        Zx = 0x818f694a # 0x17246549
    
    t2 = rotateLeft(MSB4(B1), 4)
    V2 = QWORD(t2, t1)

    t3 = lis[m] ^ LSB4(B0)
    t4 = LSB4(minus(t3, t0))
    t5 = Zx^t0 ^ t2
    V1 = QWORD(t5, t4)
    
    return V1, V2

input_key = [0x4242424241414141, 0x4444444443434343, 0x4646464645454545, 0x4848484847474747]
#input_key = [0x77447b4349545353, 0x315f4d565f667234, 0x695f6c306f635f73, 0x7d74495f745f6e73]
#\x77\x44\x7b\x43\x49\x54\x53\x53\x31\x5f\x4d\x56\x5f\x66\x72\x34\x69\x5f\x6c\x30\x6f\x63\x5f\x73\x7d\x74\x49\x5f\x74\x5f\x6e\x73

v0 = input_key[0]
v1 = input_key[1]
v2 = input_key[2]
v3 = input_key[3]

#entered 240 times
def func_j(J0, J1):
    const_list = [0x489dddde, 0x00000000, 0x95bf74a9, 0x067990f1, 0x0e6d80e3, 0x77941ee7, 0xfb92cd42, 0x2dedaf8b, 0xf2b3a3fb, 0xd0e867c0, 0xe74f99e0, 0x6c39ce47, 0xd6378fea, 0x5a24f221]
    
    for j in range(6):
        J0 = LSB4(J0 ^ LSB4(J1 + const_list[2*j]))
        J1 = LSB4(J1 ^ (QWORD(const_list[2*(j+1)], const_list[2*(j+1)+1]) | J0))
    
    return J1, J0

#entered 120 times
def func_m(V1, V2, h):
    for m in range(h+1):
        V1, V2 = F_bis(V1, V2, m)
    
    return V1, V2

#entered 8 times
#half input is processed the two first times
#first, input0 and input1 (C0 and C1)
#second: input2 and input3 (C0 and C1)
def func_h(B0, B1, C0, C1):
    for h in range(15):
        V1, V2 = func_m(B0, B1, h)
        Y0, Y1 = func_j(LSB4(C1), MSB4(C1))

        temp1 = rotateLeft(LSB4(C0) ^ Y1, 4 ) ^ Y0
        temp2 = rotateLeft(MSB4(C0) ^ Y0, 14) ^ Y1

        C0 = V1 ^ QWORD(temp2, temp1)
        Y2, Y3 = func_j(LSB4(C0), MSB4(C0))

        temp3 = rotateRight(LSB4(C1)      ^ Y2, 6)
        temp4 = rotateRight(MSB4(C1) ^ Y3 ^ Y2, 14)
        C1 = V2 ^ QWORD(temp4, temp3)

    return C0, C1

#entered 8 times
#half input is only processed the first time
#only input2 and input3 are processed
def func_b(B0, B1):
    b0, b1 = B0, B1
    for b in range(4):
        b0, b1 = F(b0, b1)
    return b0, b1

#entered 4 times
def func_a(v0, v1, v2, v3):
    bf0, bf1 = func_b(v2, v3)
    vf0, vf1 = func_h(bf0, bf1, v0, v1)
    bf2, bf3 = func_b(vf0, vf1)
    vf2, vf3 = func_h(bf2, bf3, v2, v3)

    return vf0, vf1, vf2, vf3



def check_sol(v0, v1, v2, v3):
    print("\nTrying input: %08x %08x %08x %08x " %(v0, v1, v2, v3))
    s0, s1, s2, s3 = 0x65850b36e76aaed5, 0xd9c69b74a86ec613, 0xdc7564f1612e5347, 0x658302a68e8e1c24
    V0, V1, V2, V3 = v0, v1, v2, v3

    for a in range(4):
        v0, v1, v2, v3 = func_a(v0, v1, v2, v3)

    print("Solution checking")
    if v0 == s0 and v1 == s1 and v2 == s2 and v3 == s3:
        print("FLAG !!!!")
        f0 = bytearray.fromhex("%08x" % V0)
        f1 = bytearray.fromhex("%08x" % V1)
        f2 = bytearray.fromhex("%08x" % V2)
        f3 = bytearray.fromhex("%08x" % V3)
        print("Flag key to input in the binary: "+f0[::-1].hex()+" " + f1[::-1].hex() + " " + f2[::-1].hex() + " " + f3[::-1].hex())
    else:
        print("Lose :(")

#program starts here

check_sol(v0, v1, v2, v3)

#takes final C0, C1 (from 14th iteration)
#returns old C0, C1 (from 0th iteration)
def reverse_func_h(B0, B1, C0_14, C1_14):

    c1_new = C1_14
    c0_new = C0_14

    for h in range(15):

        #[1]
        V1, V2 = func_m(B0, B1, 14-h)
        """
        [1] V1, V2 = func_m(B0, B1, h)
        [2] Y0, Y1 = func_j(LSB4(C1), MSB4(C1))
        [3] temp1 = rotateLeft(LSB4(C0) ^ Y1, 4 ) ^ Y0
        [4] temp2 = rotateLeft(MSB4(C0) ^ Y0, 14) ^ Y1
        [5] C0 = V1 ^ QWORD(temp2, temp1)

        [6] Y2, Y3 = func_j(LSB4(C0), MSB4(C0))
        [7] temp3 = rotateRight(LSB4(C1)      ^ Y2, 6)
        [8] temp4 = rotateRight(MSB4(C1) ^ Y3 ^ Y2, 14)
        [9] C1 = V2 ^ QWORD(temp4, temp3)
        """

        #from [9]
        t4, t3 = split_QWORD(c1_new^V2)
        #OK

        #from [6]
        Y2, Y3 = func_j(LSB4(c0_new), MSB4(c0_new))
        #OK

        #from [7]
        tmp = rotateLeft(t3, 6)
        #LSB4(c1_old)
        c1_lsb = tmp^Y2

        #from [8]
        tmp = rotateLeft(t4, 14)
        #MSB4(c1_old)
        c1_msb = tmp^Y3^Y2

        #rebuild c1_old
        c1 = QWORD(c1_msb, c1_lsb)

        #from [5]
        t2, t1 = split_QWORD(c0_new^V1)

        #from [2]
        Y0, Y1 = func_j(LSB4(c1), MSB4(c1))

        #from [4]
        tmp = t2^Y1
        tmp = rotateRight(tmp, 14)
        c0_msb = tmp ^ Y0

        #from [3]
        tmp = t1 ^ Y0
        tmp = rotateRight(tmp, 4)
        c0_lsb = tmp ^Y1

        c0 = QWORD(c0_msb, c0_lsb)

        c1_new = c1
        c0_new = c0

    return c0, c1


print("\nREVERSE BEGINS For Solution")
#reverse solution
v0, v1, v2, v3 = 0x65850b36e76aaed5, 0xd9c69b74a86ec613, 0xdc7564f1612e5347, 0x658302a68e8e1c24

#for testing purposes:
#v0, v1, v2, v3 = 0xf9d6ac6f4a6efc9b, 0xae27798369409da2, 0x64ade40ed16e6a5d, 0x57c3d462a27cb121

for i in range(4):
    bf0, bf1 = func_b(v0, v1)
    v2_old, v3_old = reverse_func_h(bf0, bf1, v2, v3)

    bf0, bf1 = func_b(v2_old, v3_old)
    v0_old, v1_old = reverse_func_h(bf0, bf1, v0, v1)

    v0, v1, v2, v3 = v0_old, v1_old, v2_old, v3_old

print("input reversed found")
print("v0: " + hex(v0))
print("v1: " + hex(v1))
print("v2: " + hex(v2))
print("v3: " + hex(v3))

check_sol(v0, v1, v2, v3)
