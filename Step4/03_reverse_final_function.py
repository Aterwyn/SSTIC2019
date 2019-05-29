from SM4 import SM4

def b2i(bytes_param, sz=3):
    s = 0
    assert sz > 1
    for i in range(0, sz, 1):
        s += bytes_param[i] << (8*(sz-1-i))
    return s

f = open("decrypted_payload.bin","rb")
r = f.read()
f.close()

print(r[0x100010:0x100020][::-1].hex())

r = r[:442]
print(r[:442].hex())
print("")

r_split = [r[3*i:3*i+3][::-1].hex() for i in range(0, int(len(r)/3))]

for i in range(147):
    print("%02x: %s" % (i*3, r_split[i]))
print(len(r_split))


print("")
s=0
s2 = 0

for i in range(147):
    if (r[3*i+2]>>4)&0xF == 0xc:
        s+=1
        print(hex(r[3*i+2]))
        print(("%02x: "% i) + r[3*i:3*i+3][::-1].hex())

        if s == 10:
            break
    elif (r[3*i+2]>>4)&0xF == 0xa:
        s2+=1
        print(("%02x: "% i) + r[3*i:3*i+3][::-1].hex())

print("")


global data_mem
data_mem = [0]*16
###############
# Warning: data are stored at a offset*0x10 from 0xe04a5d8
# should be 8 bytes per address
# #############
#global special_data_comment
#special_data_comment = ""

def print_data_mem(data_mem_list):
    print("")
    for i in range(0,16,4):
        print("\t%08x %08x %08x %08x " % (data_mem_list[i], data_mem_list[i+1], data_mem_list[i+2], data_mem_list[i+3]))



global input_data
input_data = [
    0xa1,0xa2,0xa3,0xa4,0xa5,0xa6,0xa7,0xa8,
    0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf,0xa0,
    0xb1,0xb2,0xb3,0xb4,0xb5,0xb6,0xb7,0xb8,
    0xb9,0xba,0xbb,0xbc,0xbd,0xbe,0xbf,0xb0,
    0,0,0,0] #add 4 dummy bytes in order to avoid any problems

global sm4_data_0x513000
global sm4_data_0x513010, sm4_data_0x513040
global sm4_data_0x513020, sm4_data_0x513030
sm4_data_0x513010 = bytearray.fromhex("00000000000000000000000000000000")

#does not matter
sm4_data_0x513040 = bytearray.fromhex("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")

sm4 = SM4()
adr = 0x100000
base_adr = adr & 0xFFFFF0
#OKAY
sm4_data_0x513000 = bytearray.fromhex("1498b460273844c92d1bd060a9284c2f")

sm4 = SM4()
adr = 0x100020
base_adr = adr & 0xFFFFF0
#data_offset = adr&0xF
data = bytearray(input_data)[:0x10]
sm4_data_0x513020 = sm4.encrypt(base_adr,data)
#print(sm4_data_0x513020.hex())

adr = 0x100030
base_adr = adr & 0xFFFFF0
#data_offset = adr&0xF
data = bytearray(input_data)[0x10:0x20]
sm4_data_0x513030 = sm4.encrypt(base_adr, data)

print(sm4_data_0x513000[:8][::-1].hex()+ " " + sm4_data_0x513000[8:][::-1].hex())
print(sm4_data_0x513020[:8][::-1].hex()+ " " + sm4_data_0x513020[8:][::-1].hex())
print(sm4_data_0x513020.hex())
print(sm4_data_0x513030[:8][::-1].hex()+ " " + sm4_data_0x513030[8:][::-1].hex())


DEBUG_OFFSET=False

def print_debug_offset(s):
    if DEBUG_OFFSET:
        print(s)

global trace_ins, trace_offset, trace_counter
trace_ins, trace_offset, trace_counter = [], [], []

def print_save(s):
    global trace_ins, trace_offset, trace_counter
    trace_counter.append(security)
    trace_ins.append(s)
    trace_offset.append(data_mem[0xf])
    #trace_ins += s+"\n"


def print_sm4_mem():
    print("")
    print("\t0x513000: " + sm4_data_0x513000[:8][::-1].hex()+ " " + sm4_data_0x513000[8:][::-1].hex())
    print("\t0x513010: " + sm4_data_0x513010[:8][::-1].hex()+ " " + sm4_data_0x513010[8:][::-1].hex())
    print("\t0x513020: " + sm4_data_0x513020[:8][::-1].hex()+ " " + sm4_data_0x513020[8:][::-1].hex())
    print("\t0x513030: " + sm4_data_0x513030[:8][::-1].hex()+ " " + sm4_data_0x513030[8:][::-1].hex())

def print_plain_sm4_mem():
    print("")
    base_adr = 0x100000
    data_list = [sm4_data_0x513000, sm4_data_0x513010, sm4_data_0x513020, sm4_data_0x513030, sm4_data_0x513040]

    adr_list = [base_adr+adr for adr in range(0, 0x50, 0x10)]
    for adr, data in zip(adr_list[:-1], data_list[:-1]):
        sm4 = SM4()
        dec_data = sm4.decrypt(adr, data)
        print(("\t0x%06x: " % adr) + dec_data[:8][::-1].hex() + " " + dec_data[8:][::-1].hex())

    print("")

#raise Exception("TEST")

global data_0x9010000
global data_0x9010008
data_0x9010000 = 0 ####TIMER: anti-debug
data_0x9010008 = 0x100000000

global debug_list
debug_list = []

def data_abort_exception(adr):
    global sm4_data_0x513000, sm4_data_0x513010
    global sm4_data_0x513020, sm4_data_0x513030, sm4_data_0x513040
    base_adr = adr & 0xFFFFF0
    base_adr2 = base_adr + 0x10
    data_offset = adr&0xF

    if base_adr == 0x100010:
        data = sm4_data_0x513010
        data2 = sm4_data_0x513020
    elif base_adr== 0x100020:
        data = sm4_data_0x513020
        data2 = sm4_data_0x513030
    elif base_adr == 0x100030:
        data = sm4_data_0x513030
        data2 = sm4_data_0x513040
    elif base_adr == 0x100000:
        data = sm4_data_0x513000
        data2 = sm4_data_0x513010
    elif base_adr < 0x100000:

        #TRY
        mod_adr = base_adr
        mod_adr2 = mod_adr + 0x10
        #mod_adr = base_adr + 0x1000
        #mod_adr2 = mod_adr + 0x10

    
    if base_adr >=0x100000:
        print("\tread ciphered data at adr %06x" % base_adr)
        print("\t" + data.hex())
        sm4 = SM4()
        dec_data = sm4.decrypt(base_adr, data)
        print("\tdecrypted: " + dec_data.hex())
        
        sm4 = SM4()
        print("\tread ciphered data2 at adr %06x" % base_adr2)
        print("\t" + data2.hex())
        dec_data2 = sm4.decrypt(base_adr2, data2)
        print("\tdecrypted2 : " + dec_data2.hex())
        
        #if base_adr >= 0x100030:
            #print(data_offset)
            #import time
            #time.sleep(1)
        dec_data3 = dec_data + dec_data2
        data = dec_data3[data_offset:data_offset+4][::-1]

        """
        if base_adr == 0x100000:
            print(hex((data[0]<<24) + (data[1]<<16) + (data[2]<<8) + data[3]))
            print_sm4_mem()
            raise Exception("To investigate")
        """

    else:
        f = open("decrypted_file",'rb')
        read = f.read()
        f.close()
        payload_offset = 0x4dbd8 
        read = read[payload_offset: payload_offset+0x101010]
        print("\tread ciphered data at adr %06x" % base_adr)
        print("\t"+ read[mod_adr:mod_adr+0x10].hex())
        sm4 = SM4()
        dec_data = sm4.decrypt(base_adr, read[mod_adr:mod_adr+0x10])
        print("\tto decrypt: " + read[mod_adr:mod_adr+0x10].hex())
        print("\tdecrypted: " + dec_data.hex())

        sm4 = SM4()
        dec_data2 = sm4.decrypt(base_adr2, read[mod_adr2:mod_adr2+0x10])
        print("\tto decrypt: " + read[mod_adr2:mod_adr2+0x10].hex())
        print("\tdecrypted: " + dec_data2.hex())
        data = (dec_data + dec_data2)[data_offset:data_offset+4][::-1]
    
    print("\toutput data: " + data.hex())
    return (data[0]<<24) + (data[1]<<16) + (data[2]<<8) + data[3]

def data_abort_exception_insert_const(adr, const):
    global sm4_data_0x513000, sm4_data_0x513010
    global sm4_data_0x513020, sm4_data_0x513030, sm4_data_0x513040
    base_adr = adr & 0xFFFFF0
    base_adr2 = base_adr + 0x10
    data_offset = adr&0xF

    if base_adr == 0x100010:
        data = sm4_data_0x513010[:]
        data2 = sm4_data_0x513020[:]
    elif base_adr== 0x100020:
        data = sm4_data_0x513020[:]
        data2 = sm4_data_0x513030[:]
    elif base_adr == 0x100030:
        data = sm4_data_0x513030[:]
        data2 = sm4_data_0x513040[:]
    elif base_adr == 0x100000:
        data = sm4_data_0x513000[:]
        data2 = sm4_data_0x513010[:]
    elif base_adr < 0x100000:
        raise Exception("TODO TO INVESTIGATE 2")
    
    if base_adr >=0x100000:
        print("\tread ciphered data at adr %06x" % base_adr)
        print("\t" + data.hex())
        sm4 = SM4()
        dec_data = sm4.decrypt(base_adr, data)
        print("\tdecrypted: " + dec_data.hex())
        print("")
        sm4 = SM4()
        print("\tread ciphered data2 at adr %06x" % base_adr2)
        print("\t" + data2.hex())
        dec_data2 = sm4.decrypt(base_adr2, data2)
        print("\tdecrypted2 : " + dec_data2.hex())
        print("")
        
        data = dec_data + dec_data2
        print("\tdecrypted data: " + data.hex())

    else:
        raise Exception("TODO TO INVESTIGATE 3")

    if (data_offset % 4 ) != 0:
        raise Exception("Error DAE insert const")

    print("\tinsert constant %08x at data offset %02x" % (const, data_offset))
    data2 = data[:data_offset] + bytearray.fromhex("%08x" % const)[::-1] + data[data_offset+4:0x10]
    print("\tdata2: " + data2[:8][::-1].hex() + " " + data2[8:0x10][::-1].hex())
    sm4 = SM4()
    res = sm4.encrypt(base_adr, data2[:0x10])
    print("\tencrypt " + data2[:0x10].hex() + " at adr %06x" % base_adr)
    print("\tencrypted " + res.hex())
    
    #save
    print_save("insert 0x%08x at adr 0x%06x, offset 0x%02x" % (const, base_adr, data_offset))

    if base_adr == 0x100010:
        sm4_data_0x513010 = res
    elif base_adr== 0x100020:
        sm4_data_0x513020 = res
    elif base_adr == 0x100030:
        sm4_data_0x513030 = res
    elif base_adr == 0x100000:
        sm4_data_0x513000 = res
    else:
        raise Exception("should not happen")
    
    return 0

def smc_01(x1):
    #AESE decrypt
    global data_mem
    #global data_c_d_e04a618
    #global offset_ins
    #get ciphered offset to decrypt
    if x1 <= 0xf:
        print("\tdecrypt %08x at offset %04x" % (data_mem[x1], x1))
        return data_mem[x1]   
    else:
        raise Exception("Need to check smc_01")

def smc_02(x1, x2):
    #AESD encrypt
    #x1 is the offset <<4
    #x2 is the value to be encrypted

    #func_e205230(ins_17_14, ins_13_0)
    #print("\tdebug smc_02 %04x %08x " % (x1, x2))
    global data_mem
    print("\tencrypt %08x at offset %04x"% (x2, x1))
    
    if x1<=0xf:
        data_mem[x1] = x2
    else:
        raise Exception("Not implemented smc_02")

#def smc_11(ins_17_14, ins_13_10):
def smc_11(ins_17_14):
    global data_mem
    data = data_mem[ins_17_14]
    print("\tdecipher data %08x at offset %04x" % (data, ins_17_14))
    
    #print("\tperform weird macc to do minus 1")
    print("\tMINUS 1")
    data2 = data -1
    print("\tdata minus 1: %08x" % data2)
    print("\tencrypt data %08x at offset %04x" % (data2, ins_17_14))
    data_mem[ins_17_14] = data2

    #save
    print_save("data[0x%02x] -= 1" % ins_17_14)

    print_debug_offset("\toffset += 3")
    data_mem[0xf] += 3  

def smc_12(ins_17_14, ins_13_10):
    global data_mem

    data = data_mem[ins_17_14]
    print("\tdecipher data %08x at offset %02x" % (data, ins_17_14))
    data2 = data_mem[ins_13_10]
    print("\tdecipher data2 %08x at offset %02x" % (data2, ins_13_10))
    
    data3 = data + data2
    print("\tdata + data2 = %08x " % data3)
    
    #save
    print_save("data[0x%02x] += data[0x%02x]" % (ins_17_14, ins_13_10))

    data_mem[ins_17_14] = data3
    print("\tencrypt data %08x at offset %02x" % (data3, ins_17_14))
    
    print_debug_offset("\toffset += 3")
    data_mem[0xf] += 3

def smc_13(ins_17_14, ins_13_10):
    global data_mem
    data = data_mem[ins_17_14]
    print("\tdecipher data %08x at offset %04x" % (data, ins_17_14))
    data2 = data_mem[ins_13_10]
    print("\tdecipher data2 %08x at offset %04x" % (data2, ins_13_10))
    #print("\tweird minus fcadd %08x - %08x" % (data, data2))
    print("\tminus fcadd %08x - %08x" % (data, data2))
    
    data3 = abs(data-data2)

    print("\tres = %08x" % data3)
    
    #save
    print_save("data[0x%02x] = abs(data[0x%02x] - data[0x%02x])" % (ins_17_14, ins_17_14, ins_13_10))

    #debug list
    #debug_list.append("%08x - %08x = %08x" % (data, data2, data3))

    print("\tencrypt %08x at offset %04x" % (data3, ins_17_14))
    data_mem[ins_17_14] = data3
    
    print_debug_offset("\toffset+=3")
    data_mem[0xf] += 3

def smc_16(ins_17_14, ins_13_10):
    global data_mem
    data = data_mem[ins_17_14]
    print("\tdecipher data %08x at offset %02x" % (data, ins_17_14))
    data2 = data_mem[ins_13_10]
    print("\tdecipher data2 %08x at offset %02x" % (data2, ins_13_10))
    data3 = data^data2
    print("\tdata1 ^ data2 = %08x" % data3)

    #save
    print_save("data[0x%02x] ^= data[0x%02x]" % (ins_17_14, ins_13_10))
    
    print("\tencrypt data %08x at offset %02x" % (data3, ins_17_14))
    data_mem[ins_17_14] = data3

    print_debug_offset("\toffset += 3")
    data_mem[0xf] += 3

def smc_22(ins_17_14, ins_13_0):
    global data_mem
    print("\tdecipher data %06x, and add value %02x" % (data_mem[ins_17_14], ins_13_0))

    assert ins_17_14 <= 0xf
    res = data_mem[ins_17_14] + ins_13_0
    print("\tcomputed: %08x" % res)
    print("\tcipher data %08x at offset %02x" % (res, ins_17_14))
    data_mem[ins_17_14] = res

    #save
    print_save("data[0x%02x] += 0x%04x" % (ins_17_14, ins_13_0))
    
    print_debug_offset("\toffset += 3")
    data_mem[0xf] += 3

def smc_23(ins_17_14, ins_13_0):
    global data_mem
    data = data_mem[ins_17_14]
    print("\tdecrypt %08x at offset %04x" % (data, ins_17_14))
    
    print("\tweird subtract fcadd %08x - %08x" % (data, ins_13_0))
    res = data - ins_13_0
    print("\tsubtract res: %08x" % res)
    
    #save
    print_save("data[0x%02x] -= 0x%04x" % (ins_17_14, ins_13_0))

    data_mem[ins_17_14] = res
    print("\tencrypt %08x at offset %04x" % (res, ins_17_14))

    print_debug_offset("\toffset += 3")
    data_mem[0xf] += 3

def smc_27(ins_17_14, ins_13_0):
    global data_mem
    assert ins_17_14 <= 0xf
    res = data_mem[ins_17_14]
    print("\tdecipher data %08x at offset %02x" % (res, ins_17_14))
    print("\tdo AND %04x" % ins_13_0)
    
    #save
    print_save("data[0x%02x] &= 0x%04x" % (ins_17_14, ins_13_0))

    res2 = res & ins_13_0
    print("\tcipher data %08x at data_mem + %02x<<4" % (res2, ins_17_14))
    data_mem[ins_17_14] = res2

    print_debug_offset("\toffset += 3")
    data_mem[0xf] += 3

def smc_28(ins_17_14, ins_13_0):
    global data_mem
    
    if ins_17_14 == 0:
        #print("\tcipher %08x at offset %04x" % (ins_13_0, ins_17_14))
        
        #save
        if data_mem[0xf] < ins_13_0:
            print_save("advance offset to %04x " % ins_13_0)
        else:
            print_save("back offset to %04x" % ins_13_0)
        
        print("\tmodify offset to %04x" % ins_13_0)
        data_mem[0xf] = ins_13_0
    else:
        raise Exception("smc_28 Not implemented")


def func_e205078_offplus3():
    #decrypt offset, add 3, encrypt offset back
    print_debug_offset("\toffset += 3")
    res = smc_01(0xf)
    smc_02(0xf, res+3)

def func_e2050c0_offplus3(ins_13_0):
    #decrypt offset, add 3, encrypt offset back
    res = smc_01(0xf)
    #global data_0x9010000
    #print("\tretrieve data at 0x9010008: %08x" % data_0x9010000)
    print_debug_offset("\toffset += 3")
    smc_02(0xf, res+3)

def func_e205108(ins_17_14, ins_13_0):
    print("\tshift value ins_13_0: %03x" % ins_13_0)

    #decrypt data
    res = smc_01(ins_17_14)
    print("\tdecrypted: %08x at offset %02x" % (res, ins_17_14))
    res2 = (res << ins_13_0)&0xFFFFFFFF
    
    print("\tres2 = res << %03x: %08x" % (ins_13_0, res2))
    smc_02(ins_17_14, res2)

    print_save("data[0x%02x] = data[0x%02x] << 0x%04x" % (ins_17_14, ins_17_14, ins_13_0))

def func_e205150(ins_17_14, ins_13_0):
    res = smc_01(ins_17_14)
    print("\tdecrypted: %08x at offset %02x" % (res, ins_17_14))
    res2 = res>>ins_13_0

    #save
    print_save("data[0x%02x] = data[0x%02x] >> 0x%04x" % (ins_17_14, ins_17_14, ins_13_0))
    print("\tres2 = res >> %03x: %06x" % (ins_13_0, res2))
    smc_02(ins_17_14, res2)

def func_e205198(ins_13_10, ins_17_14):
    print("\tsmc_01 %04x" % ins_13_10)
    res = smc_01(ins_13_10)

    #save
    print_save("data[0x%02x] = data[0x%02x]" % (ins_17_14, ins_13_10))

    print("\tsmc_02 %04x %08x" % (ins_17_14, res))
    smc_02(ins_17_14, res)

def func_e2051d8(ins_17_14):
    res = smc_01(ins_17_14)
    assert res <= 0x10000
    r4 = res>>8
    r1 = (res&0xff)<<8
    res2 = r4 | r1
    print("\tres2 = perm LSB2: %08x" % res2)
    
    #save
    print_save("data[0x%02x] = (data[0x%02x]>>8) + ((data[0x%02x] & 0xff)<<8)" % (ins_17_14, ins_17_14, ins_17_14))

    smc_02(ins_17_14, res2)

def func_e205230(ins_17_14, ins_13_0):
    print("\tencrypt %04x at offset %02x" % (ins_13_0, ins_17_14))
    
    #save
    print_save("data[0x%02x] = 0x%04x" % (ins_17_14, ins_13_0))

    smc_02(ins_17_14, ins_13_0)

def func_e205250_offplus3(ins_13_0):
    #global data_0x9010008
    #data_0x9010008 = ins_13_0

    print_debug_offset("\toffset += 3")
    res = smc_01(0xf)
    smc_02(0xf, res + 3)

def get_adr_constant(res):
    adr_list = [i for i in range(0x100004, 0x100020, 4)]
    adr_list.append(0x100000)
    #print("".join("%08x " % i for i in adr_list))
    const_list = [0x6766722e, 0x666e632e, 0x2e76662e, 0x76706e73, 0x66407279, 0x70766766, 0x7465622e, 0x612e7270]
    if res < 8:
        return adr_list[res], const_list[res]
    else:
        raise Exception("get_adr_constant error offset")


i = 0
security = -1
debug = 0
while (i!=148):
    security += 1
    instruction_bytes = r[i:i+3][::-1]
    nb = ((instruction_bytes[0])<<16) + ((instruction_bytes[1])<<8) + (instruction_bytes[2])
    ins_23_20 = (nb>>20) & 0xf
    ins_19_18 = (nb>>18) & 3
    ins_17_14 = (nb>>14) & 0xf
    ins_13_10 = (nb>>10) & 0xf
    ins_13_0 = nb & 0x3fff

    print("\nINS: " + instruction_bytes.hex() + "\tins_offset: %04x (%02x)" % (i, ins_19_18)+ "\titeration: %d" % security)

    if ins_23_20 == 0xc:
        print("\tDEBUG 1")
        print("\tsmc_01 %02x" % ins_17_14)
        res = smc_01(ins_17_14)
        print("\tres: %08x" % res)
        res2 = int(res/4)-1
        adr, const = get_adr_constant(res2 % 8)

        print("\tres2 = (res/4)-1: %04x" % res2)
        print("\tadr  : %08x" % adr)
        print("\tconst: %08x" % const)

        #save
        print_save("get adr[data[0x%02x]/4 - 1], const[data[0x%02x]/4 - 1]" % (ins_17_14, ins_17_14))

        res = data_abort_exception_insert_const(adr, const)
        
        if res != 0:
            raise Exception("Error DAE")

        print("\toffset += 3")
        data_mem[0xf] += 3            

        #print("WAAAARNING, NOT FULLY IMPLEMENTED")
    elif ins_23_20 == 0xa:
        print("\tDEBUG 2")
        print("\tsmc_01 0")
        res = smc_01(0x0)

        #save
        print_save("return data[0x0]")

        print_debug_offset("\toffset + 3")
        off = smc_01(0xf)
        smc_02(0xf, off+3)
        print("\t###############################")
        print("\t###############################")
        print("RES: %01d" % res)
        if res==1:
            print("LOOSE")
        else:
            print("WIN")
        break

    elif ins_23_20 == 0xd:
        print("\tDEBUG 3")
        print("\tarm32: e205250 %04x" % ins_13_0)
        func_e205250_offplus3(ins_13_0)

    elif ins_23_20 == 0xe:
        print("\tDEBUG 4")
        print("\tarm32: e2050c0 %02x %04x" % (ins_17_14, ins_13_0))
        func_e2050c0_offplus3(ins_13_0)
        
    else:
        if ins_19_18 == 2:
            print("\tDEBUG 5")
            print("\tsmc_01 %02x " % ins_17_14)
            res = smc_01(ins_17_14)

            print("\tsmc_01 %02x " % ins_13_10)
            res2 = smc_01(ins_13_10)
            x0 = res
            x1 = res2
            x2 = 1
            
            print("\tDAE !!!")
            res = data_abort_exception_insert_const(res, res2)
            if res != 0:
                raise Exception("should not happen")
            
            print("\toffset += 3")
            res = smc_01(0xf)
            smc_02(0xf, res+3)

        elif ins_19_18 == 1:
            print("\tDEBUG 6")
            print("\tsmc_01 %04x " % (ins_13_10))
            res = smc_01(ins_13_10)
            print("\tres: %06x" % res)
            print("\tDataAbortException ! adr: %06x" % res)
            data = data_abort_exception(res)

            print("\tsmc_02 %04x %08x" % (ins_17_14, data))
            
            #save
            print_save("data[0x%02x] = get_value_from_adr(data[0x%02x]) " % (ins_17_14, ins_13_10))

            smc_02(ins_17_14, data)

            print_debug_offset("\toffset += 3")
            data_mem[0xf] += 3
            

        elif ins_19_18 == 0:
            if ins_23_20 == 0:
                print("\tDEBUG 7")
                print("\tarm32: e205198 %02x %02x" % (ins_13_10, ins_17_14))
                #data[ins_13_10] = data[ins_17_14]
                func_e205198(ins_13_10, ins_17_14)

                print_debug_offset("\toffset += 3")
                func_e205078_offplus3()
                print("")

            elif ins_23_20 == 1:
                print("\tDEBUG 8")
                print("\tsmc_11 %02x %02x" % (ins_17_14, ins_13_10))
                #MINUS 1 data[13_10] = data[ins_17_14] -1
                #smc_11(ins_17_14, ins_13_10)
                smc_11(ins_17_14)
                if ins_13_10 != 0:
                    raise Exception("ins_13_10 is not 0 as expected")
                
            elif ins_23_20 == 2:
                print("\tDEBUG 9")
                print("\tsmc_12 %02x %02x" % (ins_17_14, ins_13_10))
                #PLUS data[ins_17_14] += data[ins_13_10]    
                smc_12(ins_17_14, ins_13_10)

            elif ins_23_20 == 3:
                print("\tDEBUG 10")
                print("\tsmc_13 %02x %02x" % (ins_17_14, ins_13_10))
                #MINUS data[ins_17_14] = abs(data[ins_17_14] - data[ins_13_10])
                smc_13(ins_17_14, ins_13_10)

            elif ins_23_20 == 6:
                print("\tDEBUG 11")
                print("\tsmc_16 %02x %02x" % (ins_17_14, ins_13_10))
                #XOR data[ins_17_14] ^= data[ins_13_10]
                smc_16(ins_17_14, ins_13_10)
                
            elif ins_23_20 == 0xb:
                print("\tDEBUG 12")
                #print("\tarm32: e2051d8 %02x "% (ins_17_14))
                #perm last 2 bytes data[ins_17_14]
                func_e2051d8(ins_17_14)
                print_debug_offset("\toffset += 3")
                func_e205078_offplus3()
                print("")
            else:
                raise Exception("error ins_19_18 0, ins_23_20 %d" % ins_23_20)
        elif ins_19_18 == 3:
            if ins_23_20 == 0:
                #encrypt given value at given offset
                #then, step by 3
                print("\tDEBUG 13")
                #print("\tarm32: e205230 %02x %04x "% (ins_17_14, ins_13_0))
                #set data[ins_17_14] = ins_13_0
                func_e205230(ins_17_14, ins_13_0)
                print_debug_offset("\toffset += 3")
                func_e205078_offplus3()

            elif ins_23_20 == 2:
                print("\tDEBUG 14")
                print("\tsmc_22 %02x %04x "% (ins_17_14, ins_13_0))
                #PLUS data[ins_17_14] += ins_13_0
                smc_22(ins_17_14, ins_13_0)

            elif ins_23_20 == 3:
                print("\tDEBUG 15")
                print("\tsmc_23 %02x %04x " % (ins_17_14, ins_13_0))
                #MINUS data[ins_17_14] -= ins_13_0
                smc_23(ins_17_14, ins_13_0)

            elif ins_23_20 == 6:
                #t += "26"
                print("\tDEBUG 16")
                raise Exception("not implemented")

            elif ins_23_20 == 4:
                print("\tDEBUG 17")
                print("\tarm32: e205108 %02x %04x "% (ins_17_14, ins_13_0))
                #LSL data[ins_17_14] << ins_13_0
                func_e205108(ins_17_14, ins_13_0)
                print_debug_offset("\toffset += 3")
                func_e205078_offplus3()

            elif ins_23_20 == 5:
                print("\tDEBUG 18")
                #print("\tarm32: e205150 %02x %04x " % (ins_17_14, ins_13_0))
                #LSR data[ins_17_14] >> ins_13_0
                func_e205150(ins_17_14, ins_13_0)
                print_debug_offset("\toffset += 3")
                #print("\tarm32: e205078")
                #offset +=3
                func_e205078_offplus3()

            elif ins_23_20 == 7:
                print("\tDEBUG 19")
                print("\tsmc_27 %02x %04x" % (ins_17_14, ins_13_0))
                #perform AND op between data_mem[ins_17_14] and ins_13_0
                smc_27(ins_17_14, ins_13_0)
                
            elif ins_23_20 == 8:
                print("\tDEBUG 20")
                print("\tsmc_28 %02x %04x" % (ins_17_14, ins_13_0))
                #move offset to ins_13_0
                smc_28(ins_17_14, ins_13_0)

            elif ins_23_20 == 9:
                print("\tDEBUG 21")
                print("\tsmc_01 %02x " % ins_17_14)
                #print("\tins_13_0 %04x" % ins_13_0)
                res = smc_01(ins_17_14)
                print("\tdecrypt %08x at offset %02x" % (res, ins_17_14))

                if res: 
                    print("\tTHUMB-mode code execution since %02x is not null" % res)
                    print_debug_offset("\tsmc_02 advance offset to %04x" % ins_13_0)
                    
                    if data_mem[0xf] < ins_13_0:
                        print_save("advance offset to %04x since data[0x%02x] is not null" % (ins_13_0, ins_17_14))
                    else:
                        print_save("back offset to %04x since data[0x%02x] is not null" % (ins_13_0, ins_17_14))
                    
                    smc_02(0xf, ins_13_0)
                else:
                    print("\tARM32-mode code execution")
                    print_debug_offset("\toffset += 3")
                    res = smc_01(0xf)
                    smc_02(0xf, res+3)

            else:
                raise Exception("error ins_19_18 3, ins_23_20 %d" % ins_23_20)
    
    
    print("\n\tRegisters")
    print_data_mem(data_mem)
    
    print("\n\tMemory SM4-ciphered")
    print_sm4_mem()

    print("\n\tMemory SM4-deciphered")
    print_plain_sm4_mem()
    i = data_mem[0xf]
    print("%06x" % i)
    
    #test
    #i+=3

    """
    if data_mem[0xe] == 1:
        break
    """
    if security == 10000:
        break

#for i in debug_list:
#    print(i)


print("%d" % len(trace_ins))

print("End of script")