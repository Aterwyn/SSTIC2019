from SM4 import SM4
sm4 = SM4()

#read SM4-ciphered data
f = open("ciphered_payload.bin","rb")
r = f.read()
f.close()

print(r[:10].hex())

input_data = r[:0x10]


output_data = bytearray.fromhex("")

#SM4-decipher data

for j in range(0x10101):
    data_chunk = r[0x10*j:0x10*j+0x10]
    x0, x1, x2, x3 = (data_chunk[i*4:i*4+4] for i in range(4))
    xor_val = j*0x10
    output_data += sm4.decrypt(xor_val, data_chunk)

    if (j%0x1000 == 0):
        print(hex(j)+"/0x10101")


fo = open("decrypted_payload.bin","wb")
fo.write(output_data)
fo.close()