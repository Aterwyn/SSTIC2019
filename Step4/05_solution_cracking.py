
from SM4 import SM4

data = [0]*16

#test input
input_data = bytearray.fromhex("a1a2a3a4a5a6a7a8a9aaabacadaeafa0b1b2b3b4b5b6b7b8b9babbbcbdbebfb0")

const0 = bytearray.fromhex("6766722e612e7270")[::-1] + bytearray.fromhex("2e76662e666e632e")[::-1]
const1 = bytearray.fromhex("6640727976706e73")[::-1] + bytearray.fromhex("7465622e70766766")[::-1]
const2 = input_data[:0x10]
const3 = input_data[0x10:]

global sm4_data
sm4_data = const0 + const1 + const2 + const3 + bytearray.fromhex("00000000")

f = open("decrypted_file",'rb')
global read
read = f.read()
f.close()
payload_offset = 0x4dbd8 
read = read[payload_offset: payload_offset+0x101010]

def get_value_from_adr(adr):
    global sm4_data, read
    if adr >= 0x100000:
        offset = adr-0x100000
        return int(sm4_data[offset:offset+4][::-1].hex(),16)
    else:
        base_adr = adr&0xFFFFF0
        #weird 0x1000 offset while debugging... removed to make things work
        #mod_adr = base_adr+0x1000
        mod_adr = base_adr

        base_offset = adr&0xF
        data = read[mod_adr:mod_adr+0x10]
        data2 = read[mod_adr+0x10: mod_adr+0x20]

        sm4 = SM4()
        dec_data1 = sm4.decrypt(base_adr, data)
        sm4 = SM4()
        dec_data2 = sm4.decrypt(base_adr+0x10, data2)
        dec_data = dec_data1 + dec_data2
        return int(dec_data[base_offset:base_offset+4][::-1].hex(), 16)


def l2i(l):
    #list to int
    return int(bytearray(l).hex(),16)

def i2l(i):
    #int to list
    return i.to_bytes(4, "big")

def e2i(e1, e2, e3, e4):
    #elements to int
    return l2i([e1, e2, e3, e4])

def print_data():
    global data
    print("")
    for i in range(0,16,4):
        print("%08x %08x %08x %08x" % (data[i], data[i+1], data[i+2], data[i+3]))

#########################

Z1, Z2, Z3, Z4 = input_data[0], input_data[1], input_data[2], input_data[3]
Z5, Z6, Z7, Z8 = input_data[4], input_data[5], input_data[6], input_data[7]

Y1 = Z1
Y2 = Z2
Y3 = Z3
Y4 = Z4
Y5 = Z5
Y6 = Z6
Y7 = Z7
Y8 = Z8


data[0x04] = 0x0010
data[0x04] = data[0x04] << 0x0010
data[0x04] += 0x0020                #data[0x04] = 0x100020  #input
data[0x0d] = 0x0010
data[0x0d] = data[0x0d] << 0x0010
data[0x0d] += 0x0020                #data[0x0d] = 0x100020  #input
data[0x0c] = 0x0004

data[0x00] = get_value_from_adr(data[0x04])    

data[0x00] = data[0x00] << 0x0010 & 0xFFFFFFFF                         
data[0x00] = data[0x00] >> 0x0010                           #data[0x00] = 0 0 Z2 Z1
data[0x00] = (data[0x00]>>8) + ((data[0x00] & 0xff)<<8)     #data[0x00] = 0 0 Z1 Z2
data[0x04] += 0x0002                                        #data[0x04] = 0x100022
data[0x01] = get_value_from_adr(data[0x04])          

data[0x01] = data[0x01] << 0x0010 & 0xFFFFFFFF                          
data[0x01] = data[0x01] >> 0x0010                           
data[0x01] = (data[0x01]>>8) + ((data[0x01] & 0xff)<<8)     #data[0x01] = 0 0 Z3 Z4
data[0x04] += 0x0002                                        #data[0x04] = 0x100024
data[0x02] = get_value_from_adr(data[0x04])                 

data[0x02] = data[0x02] << 0x0010 & 0xFFFFFFFF                          
data[0x02] = data[0x02] >> 0x0010                           
data[0x02] = (data[0x02]>>8) + ((data[0x02] & 0xff)<<8)     #data[0x02] = 0 0 Z5 Z6
data[0x04] += 0x0002                                        #data[0x04] = 0x100026
data[0x03] = get_value_from_adr(data[0x04])                 

data[0x03] = data[0x03] << 0x0010 & 0xFFFFFFFF                          
data[0x03] = data[0x03] >> 0x0010                           
data[0x03] = (data[0x03]>>8) + ((data[0x03] & 0xff)<<8)     #data[0x03] = 0 0 Z7 Z8
data[0x0e] = 0x0020                                         
data[0x07] = 0x0007   

print_data()

print("Y1: %02x" % Y1)
print("Y2: %02x" % Y2)
print("Y3: %02x" % Y3)
print("Y4: %02x" % Y4)
print("Y5: %02x" % Y5)
print("Y6: %02x" % Y6)
print("Y7: %02x" % Y7)
print("Y8: %02x" % Y8)

data0, data1, data2, data3 = [], [], [], []

data0.append(data[0])
data1.append(data[1])
data2.append(data[2])
data3.append(data[3])

security = 0
while(data[0x0e] != 0):

    _, _, Y1, Y2 = i2l(data[0x00])
    _, _, Y3, Y4 = i2l(data[0x01])
    _, _, Y5, Y6 = i2l(data[0x02])
    _, _, Y7, Y8 = i2l(data[0x03])

    data[0x0e] -=1
    security += 1

    #don't forget the data[0x07] = (data[0x07] - 1) % 10

    adr1 = e2i(0, data[0x07], Y4, Y3) + 0x1000
    X1 = get_value_from_adr(adr1) & 0xFF

    print("")
    print("adr: %06x" % adr1)
    print("data06: %02x" % X1)

    data[0x07] = (data[0x07] - 1) % 10
    #print("DEBUG: " + str(data[0x07]))
    adr2 = e2i(0, data[0x07], Y3, X1) + 0x1000
    X2 = get_value_from_adr(adr2) & 0xFF

    print("")
    print("adr: %06x" % adr2)
    print("data06: %02x" % X2)

    data[0x07] = (data[0x07] - 1) % 10
    #print("DEBUG: " + str(data[0x07]))
    adr3 = e2i(0, data[0x07], X1, X2) + 0x1000
    X3 = get_value_from_adr(adr3) & 0xFF

    print("")
    print("adr: %06x" % adr3)
    print("data06: %02x" % X3)

    data[0x07] = (data[0x07] - 1) % 10
    #print("DEBUG: " + str(data[0x07]))
    adr4 = e2i(0, data[0x07], X2, X3) + 0x1000
    X4 = get_value_from_adr(adr4) & 0xFF

    print("")
    print("adr: %06x" % adr4)
    print("data06: %02x" % X4)
    print("X1: %02x" % X1)
    print("X2: %02x" % X2)
    print("X3: %02x" % X3)
    print("X4: %02x" % X4)
    print("Y1: %02x" % Y1)
    print("Y2: %02x" % Y2)
    print("Y3: %02x" % Y3)
    print("Y4: %02x" % Y4)

    data[0x07] = (data[0x07] - 1) % 10
    data[0x09] = X4
    data[0x09] = e2i(0, 0, X4, X3)
    data[0x08] = (data[0x0e] >> 0x3) & 1 #divide by 8, then look at the parity

    if data[0x08] == 0:
        print("even")
        data[0x08] = e2i(0, 0, Y7, Y8)
        data[0x00] = e2i(0, 0, X4, X3)
        data[0x01] = e2i(0, 0, Y5, Y6)
        data[0x02] = e2i(0, 0, Y7, Y8)
        data[0x03] = e2i(0, 0, Y1^Y3, (data[0x0e]+1)^Y2^Y4)
    else:
        data[0x08] = e2i(0, 0, Y1, Y2)
        data[0x00] = e2i(0, 0, X4, X3)
        data[0x01] = e2i(0, 0, X4^Y5, (data[0x0e]+1)^X3^Y6)
        data[0x02] = e2i(0, 0, Y7, Y8)
        data[0x03] = e2i(0, 0, Y1, Y2)

    data0.append(data[0])
    data1.append(data[1])
    data2.append(data[2])
    data3.append(data[3])

    #print("data[0x0e]+1 = " + str(data[0x0e]+1))
    #print("data[0x07]+1 = " + str((data[0x07]+1)%10))
    print(str(security))
    print_data()

    if security == 33:
        break

#to crack
s1 = 0x70
s2 = 0x72
s3 = 0x2e
s4 = 0x61
s5 = 0x2e
s6 = 0x72
s7 = 0x66
s8 = 0x67


def print_debug(s):
    DEBUG = False
    if DEBUG:
        print(s)

def crack_loop(s):

    S1, S2, S3, S4, S5, S6, S7, S8 = s

    data_0e = 0
    data_07 = 9
    while data_0e != 0x20:

        X1, X2, X3, X4 = [None]*4
        Y1, Y2, Y3, Y4, Y5, Y6, Y7, Y8 = [None]*8

        if (data_0e >> 3) & 1 == 0:
            X4, X3 = S1, S2
            Y5, Y6 = S3, S4
            Y7, Y8 = S5, S6
        else:
            #other init
            X4, X3 = S1, S2
            Y7, Y8 = S5, S6
            Y1, Y2 = S7, S8

            Y5 = S3^X4
            Y6 = S4^(data_0e+1)^X3

        data_07 = (data_07 + 1) % 0xa

        start_adr = 0x10000*data_07 + 0x1000 + X3
        end_adr = start_adr + 0x10000
        found_adr = []
        print_debug("\nSearching for X2 from %06x to %06x" % (start_adr, end_adr))

        for i in range(start_adr, end_adr, 0x100):
            res = get_value_from_adr(i)
            if res & 0xFF == X4:
                print_debug("adr: %06x" % i)
                found_adr.append(i)
                print_debug("res: %08x" % res)

        if len(found_adr) == 1:
            X2 = (found_adr[0]-0x1000)>>8 & 0xFF
            print_debug("found X2: %02x" % X2)
        else:
            raise Exception("X2 not found")

        data_07 = (data_07 + 1) % 0xa
        start_adr = 0x10000*data_07 + 0x1000 + X2
        end_adr = start_adr + 0x10000
        found_adr = []
        print_debug("\nSearching for X1 from %06x to %06x" % (start_adr, end_adr))

        for i in range(start_adr, end_adr, 0x100):
            res = get_value_from_adr(i)
            if (res & 0xFF) == X3:
                print_debug("adr: %06x" % i)
                found_adr.append(i)
                print_debug("res: %08x" % res)

        if len(found_adr) == 1:
            X1 = (found_adr[0]-0x1000)>>8 & 0xFF
            print_debug("found X1: %02x" % X1)
        else:
            raise Exception("X1 not found")


        data_07 = (data_07 + 1) % 0xa
        start_adr = 0x10000*data_07 + 0x1000 + X1
        end_adr = start_adr + 0x10000
        found_adr = []
        print_debug("\nSearching for Y3 from %06x to %06x" % (start_adr, end_adr))

        for i in range(start_adr, end_adr, 0x100):
            res = get_value_from_adr(i)
            if res & 0xFF == X2:
                print_debug("adr: %06x" % i)
                found_adr.append(i)
                print_debug("res: %08x" % res)

        if len(found_adr) == 1:
            Y3 = (found_adr[0]-0x1000)>>8 & 0xFF
            print_debug("found Y3: %02x" % Y3)
        else:
            raise Exception("Y3 not found")


        data_07 = (data_07 + 1) % 0xa
        start_adr = 0x10000*data_07 + 0x1000 + Y3
        end_adr = start_adr + 0x10000
        found_adr = []
        print_debug("\nSearching for Y4 from %06x to %06x" % (start_adr, end_adr))

        for i in range(start_adr, end_adr, 0x100):
            res = get_value_from_adr(i)
            if res & 0xFF == X1:
                print_debug("adr: %06x" % i)
                found_adr.append(i)
                print_debug("res: %08x" % res)

        if len(found_adr) == 1:
            Y4 = (found_adr[0]-0x1000)>>8 & 0xFF
            print_debug("found Y4: %02x" % Y4)
        else:
            print_debug(found_adr)
            raise Exception("Y4 not found")

        if (data_0e >> 3) & 1 == 0:
            Y1 = S7^Y3
            Y2 = S8^Y4^(data_0e+1)
        
        data_0e += 1

        S1, S2 = Y1, Y2
        S3, S4 = Y3, Y4
        S5, S6 = Y5, Y6
        S7, S8 = Y7, Y8

    print("S1: %02x" % S1)
    print("S2: %02x" % S2)
    print("S3: %02x" % S3)
    print("S4: %02x" % S4)
    print("S5: %02x" % S5)
    print("S6: %02x" % S6)
    print("S7: %02x" % S7)
    print("S8: %02x" % S8)
    print("")
    return bytearray([S1, S2, S3, S4, S5, S6, S7, S8])

#to crack
s1 = 0x70
s2 = 0x72
s3 = 0x2e
s4 = 0x61
s5 = 0x2e
s6 = 0x72
s7 = 0x66
s8 = 0x67

print("\nCracking 8/32 bytes")
sol1 = crack_loop(bytearray.fromhex("6766722e612e7270")[::-1])

print("Cracking 16/32 bytes")
sol2 = crack_loop(bytearray.fromhex("2e76662e666e632e")[::-1])

print("Cracking 24/32 bytes")
sol3 = crack_loop(bytearray.fromhex("6640727976706e73")[::-1])

print("Cracking 32/32 bytes")
sol4 = crack_loop(bytearray.fromhex("7465622e70766766")[::-1])


print("Found solution: ")
print(sol1.hex())
print(sol2.hex())
print(sol3.hex())
print(sol4.hex())