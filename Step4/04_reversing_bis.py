from SM4 import SM4

input_data = "a1a2a3a4a5a6a7a8a9aaabacadaeafa0b1b2b3b4b5b6b7b8b9babbbcbdbebfb0"
input_data = "acadaa8b5b55306fb3c6dfc3b2d1c80770084644225febd71a9189aa26ec740e"
#input_data = "0000000000000000000000000000000000000000000000000000000000000000"
global input_list
input_list = bytearray.fromhex(input_data)

global data
data = [0]*16

#plain data, written in little-endian
#const0 = bytearray.fromhex("08251587e988e8de")[::-1] + bytearray.fromhex("5fa89078ee10390f")[::-1]
#const1 = bytearray.fromhex("d73f7a649d78f7f4")[::-1] + bytearray.fromhex("f556dc27813a05a1")[::-1]
const0 = bytearray.fromhex("6766722e612e7270")[::-1] + bytearray.fromhex("2e76662e666e632e")[::-1]
const1 = bytearray.fromhex("6640727976706e73")[::-1] + bytearray.fromhex("7465622e70766766")[::-1]
const2 = input_list[:0x10]
const3 = input_list[0x10:]

global sm4_data
sm4_data = const0 + const1 + const2 + const3 + bytearray.fromhex("00000000")
#0 encrypted

def print_sm4_data():
    global sm4_data
    print("")
    for i in range(4):
        print("0x" + sm4_data[i*0x10:i*0x10+8][::-1].hex() + " 0x" + sm4_data[i*0x10+8:(i+1)*0x10][::-1].hex())

def print_data():
    global data
    print("")
    for i in range(0,16,4):
        print("%08x %08x %08x %08x" % (data[i], data[i+1], data[i+2], data[i+3]))

#0x100000: 08251587e988e8de 5fa89078ee10390f
#0x100010: d73f7a649d78f7f4 f556dc27813a05a1
#0x100020: a8a7a6a5a4a3a2a1 a0afaeadacabaaa9
#0x100030: b8b7b6b5b4b3b2b1 b0bfbebdbcbbbab9

print_sm4_data()

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
        sm4 = SM4()
        base_adr = adr&0xFFFFF0
        #debug
        #mod_adr = base_adr+0x1000
        mod_adr = base_adr

        base_offset = adr&0xF
        data = read[mod_adr:mod_adr+0x10]
        data2 = read[mod_adr+0x10: mod_adr+0x20]

        dec_data1 = sm4.decrypt(base_adr, data)
        sm4 = SM4()
        dec_data2 = sm4.decrypt(base_adr+0x10, data2)
        dec_data = dec_data1 + dec_data2
        return int(dec_data[base_offset:base_offset+4][::-1].hex(), 16)

def insert_value_at_adr(val_int, adr):
    global sm4_data
    assert 0x100000<=adr and adr <=0x100040
    #0159: insert 0x22926dbf (data[0x00]) at adr 0x100020 (adr pointed by data[0x0d]) <<<<
    val_hex = (val_int).to_bytes(4, byteorder="little")
    off = adr-0x100000
    #print("%08x" % val_int)
    #print(val_hex.hex())
    #print("before: " + sm4_data.hex())
    sm4_data = sm4_data[:off] + val_hex + sm4_data[off+4:]
    #print(sm4_data.hex())
    #print("offset: " + str(off))
    #print("after : " + sm4_data.hex())


def loop():

    data[0x04] = 0x0010
    data[0x04] = data[0x04] << 0x0010
    data[0x04] += 0x0020                #data[0x04] = 0x100020  #input
    data[0x0d] = 0x0010
    data[0x0d] = data[0x0d] << 0x0010
    data[0x0d] += 0x0020                #data[0x0d] = 0x100020  #input
    data[0x0c] = 0x0004


    #Z1Z2Z3Z4Z5Z6Z7Z8Z9ZAZBZCZDZEZFZ0
    #Y1Y2Y3Y4Y5Y6Y7Y8Y9YAYBYCYDYEYFY0


    while (data[0xc] != 0): #counter C on 4
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
        data[0x07] = 0x0007                                         #data[0x07] = 7

        """
        #first time
        data[0x00] = 0 0 Z1 Z2
        data[0x01] = 0 0 Z3 Z4
        data[0x02] = 0 0 Z5 Z6
        data[0x03] = 0 0 Z7 Z8
        data[0x07] = 7

        #second time
        data[0x00] = 0 0 X4 X3                              0 0 Y1 Y2
        data[0x01] = 0 0 0 20 ^ 0 0 X4 X3 ^ 0 0 Z5 Z6       0 0 Y3 Y4
        data[0x02] = 0 0 Z7 Z8                              0 0 Y5 Y6
        data[0x03] = 0 0 Z1 Z2                              0 0 Y7 Y8
        data[0x07] = 3

        #third time

        """

        print("%08x %08x %08x %08x" % (data[0], data[1], data[2], data[3]))

        print("\n\n")
        print("0")
        #print_data()
        #print_sm4_data()
        security = 0

        while(data[0x0e] != 0): #counter E on 32
            
            data[0x0e] -= 1                                     #decrement data[0x0e]-=1   = 0x1f       decrement data[0x0e]-=1    =0x1e            
            data[0x04] = data[0x01]                             #data[0x04] = 0 0 Z3 Z4                 data[0x04] = 0 0 Y3 Y4                  
            data[0x05] = data[0x04]                             #data[0x05] = 0 0 Z3 Z4                 data[0x05] = 0 0 Y3 Y4                  
            data[0x04] = data[0x04] >> 0x0008                   #data[0x04] = 0 0 0 Z3                  data[0x04] = 0 0 0 Y3                   
            data[0x04] &= 0x00ff                                                                                                                
            data[0x05] &= 0x00ff                                #data[0x05] = 0 0 0 Z4                  data[0x05] = 0 0 0 Y4                   
            data[0x0b] = data[0x05]                                                                                                             
            data[0x0b] = data[0x0b] << 0x0008                   #data[0x0b] = 0 0 Z4 0                  data[0x0b] = 0 0 Y4 0                   
            data[0x0a] = data[0x07]                                                                                                             
            data[0x0a] = data[0x0a] << 0x0010 & 0xFFFFFFFF      #data[0x0a] = 0 7 0 0                   data[0x0a] = 0 3 0 0                    
            data[0x0a] += data[0x0b]                                                                                                            
            data[0x0a] += data[0x04]                            #data[0x0a] = 0 7 Z4 Z3                 data[0x0a] = 0 3 Y4 Y3                  
            data[0x0a] += 0x1000                                #data[0x0a] = 0 7 Z4 Z3 + 0x1000        data[0x0a] = 0 3 Y4 Y3                  
            data[0x06] = get_value_from_adr(data[0x0a])         #data[0x06] = *(0 7 Z4 Z3 +0x1000  )    data[0x06] = *(0 3 Y4 Y3)               
            data[0x06] &= 0x00ff                                #data[0x06] &= 0xFF (1 byte)   = X1     data[0x06] &= 0xFF                      

            #print("")
            #print("adr: %06x" % data[0x0a])
            #print("data06: %02x" % data[0x06])

            data[0x07] -= 1                                     #data[0x07] -= 1   = 6                  data[0x07] -= 1 = 2                     
            data[0x0b] = data[0x04]                             #data[0x0b] = 0 0 0 Z3                  data[0x0b] = 0 0 0 Y3                   
            data[0x0b] = data[0x0b] << 0x0008                   #data[0x0b] = 0 0 Z3 0                  data[0x0b] = 0 0 Y3 0                   
            data[0x0a] = data[0x07]                                                                             
            data[0x0a] = data[0x0a] << 0x0010 & 0xFFFFFFFF      #data[0x0a] = 0 6 0 0                   data[0x0a] = 0 2 0 0                    
            data[0x0a] += data[0x0b]                            #data[0x0a] = 0 6 Z3 0                  data[0x0a] = 0 2 Y3 0                   
            data[0x0a] += data[0x06]                            #data[0x0a] = 0 6 Z3 X1                 data[0x0a] = 0 2 Y3 X1                  
            data[0x0a] += 0x1000                                #data[0x0a] = 0 6 Z3 X1  +0x1000               data[0x0a] = 0 2 Y3 X1                  
            data[0x05] = get_value_from_adr(data[0x0a])         #data[0x05] = *(0 6 Z3 X1 +0x1000)      data[0x05] = *(0 2 Y3 X1)               
            data[0x05] &= 0x00ff                                #data[0x05] &= 0xFF (byte)     = X2     data[0x05] &= 0xFF (byte)  = X2         

            #print("")
            #print("adr: %06x" % data[0x0a])
            #print("data05: %02x" % data[0x05])

            if data[0x07] == 0:
                data[0x07] = 0xa

            data[0x07] -= 1                                     #data[0x07] -= 1   = 5                  data[0x07] -= 1 = 1                     
            data[0x0b] = data[0x06]                             #data[0x0b] = X1                        data[0x0b] = X1                         
            data[0x0b] = data[0x0b] << 0x0008                   #data[0x0b] = 0 0 X1 0                  data[0x0b] = 0 0 X1 0                   
            data[0x0a] = data[0x07]                             
            data[0x0a] = data[0x0a] << 0x0010 & 0xFFFFFFFF      #data[0x0a] = 0 5 0 0                   data[0x0a] = 0 1 0 0                    
            data[0x0a] += data[0x0b]                            #data[0x0a] = 0 5 X1 0                  data[0x0a] = 0 1 X1 0                   
            data[0x0a] += data[0x05]                            #data[0x0a] = 0 5 X1 X2                 data[0x0a] = 0 1 X1 X2                  
            data[0x0a] += 0x1000                                #data[0x0a] = 0 5 X1 X2  +0x10000       data[0x0a] = 0 1 X1 X2                  
            data[0x04] = get_value_from_adr(data[0x0a])         #data[0x04] = *(0 5 X1 X2 + 0x1000)     data[0x04] = *(0 1 X1 X2)               

            data[0x04] &= 0x00ff                                #data[0x04] &= 0xFF (byte)    = X3      data[0x04] = X3                         

            #print("")
            #print("adr: %06x" % data[0x0a])
            #print("data04: %02x" % data[0x04])

            data[0x07] -= 1                                     #data[0x07] -= 1   = 4                  data[0x07] -= 1 = 0                     
            data[0x0b] = data[0x05]                             #data[0x0b] = X2                        data[0x0b] = X2                         
            data[0x0b] = data[0x0b] << 0x0008                   #data[0x0b] = 0 0 X2 0                  data[0x0b] = 0 0 X2 0                   
            data[0x0a] = data[0x07]                             
            data[0x0a] = data[0x0a] << 0x0010 & 0xFFFFFFFF      #data[0x0a] = 0 4 0 0                   data[0x0a] = 0 0 0 0                    
            data[0x0a] += data[0x0b]                            #data[0x0a] = 0 4 X2 0                  data[0x0a] = 0 0 X2 0                   
            data[0x0a] += data[0x04]                            #data[0x0a] = 0 4 X2 X3                 data[0x0a] = 0 0 X2 X3                  
            data[0x0a] += 0x1000                                #data[0x0a] = 0 4 X2 X3  +0x1000        data[0x0a] = 0 0 X2 X3                  
            data[0x06] = get_value_from_adr(data[0x0a])         #data[0x06] = *(0 4 X2 X3 +0x1000)      data[0x06] = *(0 0 X2 X3)               
            data[0x06] &= 0x00ff                                #data[0x06] &= 0xFF (byte)    = X4      data[0x06] &= 0xFF (byte)    = X4               

            #print("")
            #print("adr: %06x" % data[0x0a])
            #print("data06: %02x" % data[0x06])

            if data[0x07] == 0:
                data[0x07] = 0xa                                #                                       data[0x07] = 0xa                    

            data[0x07] -= 1                                     #data[0x07] -= 1   = 3                  data[0x07] -= 1 = 9                             5th time: data[0x07] = 8
            data[0x09] = data[0x06]                             #data[0x09] = X4                        data[0x09] = X4                         
            data[0x09] = data[0x09] << 0x0008                   #data[0x09] = 0 0 X4 0                  data[0x09] = 0 0 X4 0                   
            data[0x09] += data[0x04]                            #data[0x09] = 0 0 X4 X3                 data[0x09] = 0 0 X4 X3                  
            data[0x08] = data[0x0e]                             #data[0x08] = 0 0 0 1f                  data[0x08] = 0 0 0 1e                           0 0 0 1b
            data[0x08] = data[0x08] >> 0x0003                   #data[0x08] = 0 0 0 7                   data[0x08] = 0 0 0 7                            0 0 0 6
            data[0x08] &= 0x0001                                #data[0x08] = 0 0 0 1                   data[0x08] = 0 0 0 1                            0 0 0 0
            #print("debug: " + str(data[0x08]))

            #010b get adr[data[0x0e]/4 - 1], const[data[0x0e]/4 - 1]
            
                #010b: insert 0x7465622e at adr 0x100010, offset 0x0c   #4
                #010b: insert 0x70766766 at adr 0x100010, offset 0x08   #4
                #010b: insert 0x66407279 at adr 0x100010, offset 0x04   #4
                #010b: insert 0x76706e73 at adr 0x100010, offset 0x00   #4
                #010b: insert 0x2e76662e at adr 0x100000, offset 0x0c   #4
                #010b: insert 0x666e632e at adr 0x100000, offset 0x08   #4
                #010b: insert 0x6766722e at adr 0x100000, offset 0x04   #4
                #010b: insert 0x612e7270 at adr 0x100000, offset 0x00   #1

            if data[0x08] == 0:
                #print("even")
                data[0x08] = data[0x03]               #                                                                                      data[0x08] = 0 0 Y7 Y8           
                data[0x03] = data[0x0e]               #                                                                                      data[0x03] = 0 0 0 1b            
                data[0x03] += 0x0001                  #                                                                                      data[0x03] = 0 0 0 1c            
                data[0x03] ^= data[0x00]              #                                                                                      data[0x03] = 0 0 Y1 1c^Y2            
                data[0x03] ^= data[0x01]              #                                                                                      data[0x03] = 0 0 Y1^Y3 1c^Y2^Y4            
                data[0x00] = data[0x09]               #                                                                                      data[0x00] = 0 0 X4 X3            
                data[0x01] = data[0x02]               #                                                                                      data[0x01] = 0 0 Y5 Y6            
                data[0x02] = data[0x08]               #                                                                                      data[0x02] = 0 0 Y7 Y8            
            else: #data[x08] == 1
                data[0x08] = data[0x00]               #data[0x08] = 0 0 Z1 Z2                          data[0x08] = 0 0 Y1 Y2                     
                data[0x00] = data[0x09]               #data[0x00] = 0 0 X4 X3                          data[0x00] = 0 0 X4 X3               
                data[0x01] = data[0x0e]               #data[0x01] = 0 0 0 1f                           data[0x01] = 0 0 0 1e                 
                data[0x01] += 0x0001                  #data[0x01] = 0 0 0 20                           data[0x01] = 0 0 0 1f               
                data[0x01] ^= data[0x00]              #data[0x01] = 0 0 X4 20^X3                       data[0x01] = 0 0 X4 1f^X3            
                data[0x01] ^= data[0x02]              #data[0x01] = 0 0 X4^Z5 20^X3^Z6                 data[0x01] = 0 0 X4^Y5 1f^X3^Y6      
                data[0x02] = data[0x03]               #data[0x02] = 0 0 Z7 Z8                          data[0x02] = 0 0 Y7 Y8               
                data[0x03] = data[0x08]               #data[0x03] = 0 0 Z1 Z2                          data[0x03] = 0 0 Y1 Y2               
            

            #print("\n\n")
            #print(str(32-data[0xe]) + " " + str(data[0xe]))
            #print_data()
            #print("DEBUG %02x %02x" % (data[0xe], data[0x7]))

            security += 1
            #if security == 33:
            #    raise Exception


        data[0x00] = (data[0x00]>>8) + ((data[0x00] & 0xff)<<8)     
        data[0x01] = (data[0x01]>>8) + ((data[0x01] & 0xff)<<8)     
        data[0x01] = data[0x01] << 0x0010 & 0xFFFFFFFF                          
        data[0x00] += data[0x01]     

        insert_value_at_adr(data[0x00], data[0xd])                               

        #print("\n\n")
        #print_data()
        #print_sm4_data()
        #raise Exception

        #0159: insert 0x22926dbf (data[0x00]) at adr 0x100020 (adr pointed by data[0x0d]) <<<<
        #0159: insert 0x6ffeed4d (data[0x00]) at adr 0x100028 (adr pointed by data[0x0d])
        #0159: insert 0x10874ea1 (data[0x00]) at adr 0x100030 (adr pointed by data[0x0d])
        #0159: insert 0x60e53499 (data[0x00]) at adr 0x100038 (adr pointed by data[0x0d])

        data[0x0d] += 0x0004                                        #0x100024
        data[0x02] = (data[0x02]>>8) + ((data[0x02] & 0xff)<<8)
        data[0x03] = (data[0x03]>>8) + ((data[0x03] & 0xff)<<8)
        data[0x03] = data[0x03] << 0x0010
        data[0x02] += data[0x03]

        insert_value_at_adr(data[0x02], data[0xd])

        #print("\n\n")
        #print_data()
        #print_sm4_data()
        #raise Exception
        #016b: insert 0x4a7caf04 (data[0x02]) at adr 0x100024 (adr pointed by data[0xd]) <<<<
        #016b: insert 0xd5ea9bc1 (data[0x02]) at adr 0x10002c (adr pointed by data[0xd])
        #016b: insert 0x2e8e57d8 (data[0x02]) at adr 0x100034 (adr pointed by data[0xd])
        #016b: insert 0xdc0bfbf0 (data[0x02]) at adr 0x10003c (adr pointed by data[0xd])

        data[0x0d] += 0x0004                                        #0x100028
        data[0x04] = data[0x0d]
        data[0x0c] -= 1

    data[0x0c] = 0x0010
    data[0x0c] = data[0x0c] << 0x0010 & 0xFFFFFFFF  #initialize data[0x0c] to 0x100000
    data[0x0b] = 0x0020
    data[0x0d] -= 0x0020       #set data[0x0d] to 0x100020

    data[0x04] = 0x0000 #default result is set to correct


    while (data[0x0b] != 0): #comparison over 32 bytes

        data[0x00] = get_value_from_adr(data[0x0d]) #0x100020
        data[0x00] &= 0x00ff
        data[0x01] = get_value_from_adr(data[0x0c]) #0x100000   #reference key
        data[0x01] &= 0x00ff
        data[0x00] = abs(data[0x00] - data[0x01])
        #advance offset to 01a1 since data[0x00] is not null
        #comparison byte per byte
        if data[0x00] != 0:
            data[0x04] = 0x0001 #wrong result
        else:
            data[0x04] = data[0x04]
        data[0x0d] += 0x0001
        data[0x0c] += 0x0001
        data[0x0b] -= 1

    data[0x0] = data[0x04]

    #deactivate for now
    #if data[0x0] == 0:
    #    print("WIN !")
    #else:
    #    print("LOOSE !")


#print_data()
#print_sm4_data()

print("")


loop()

print_data()
print_sm4_data()