
f = open("flash.bin","rb")

data = f.read()
f.close()

file_data_e1 = data[0xd8:0x9508+0x20]
file_data_e2 = data[0x9508:0x0125a8+0x20]
file_data_e3 = data[0x0125a8:0x017918+0x20]

#build separated encrypted files

new_file1 = open("file_e1.bin", "wb")
new_file1.write(file_data_e1)
new_file1.close()


new_file2 = open("file_e2.bin", "wb")
new_file2.write(file_data_e2)
new_file2.close()

new_file3 = open("file_e3.bin", "wb")
new_file3.write(file_data_e3)
new_file3.close()

key1 = 'SSTIC{a947d6980ccf7b87cb8d7c246}'
key2 = 'SSTIC{Dw4rf_VM_1s_co0l_isn_t_It}'

from Crypto.Cipher import AES

iv1 = file_data_e1[:16]
iv2 = file_data_e2[:16]
iv3 = file_data_e3[:16]

#use AES in CBC mode
aescbc_1 = AES.new(key = key1, mode=AES.MODE_CBC, IV=iv1)

#handle encrypted file 1

f_temp_1 = open("file_e1.bin","rb")
data_temp_1 = f_temp_1.read()
f_temp_1.close()

data_1 = aescbc_1.decrypt(data_temp_1[0x10:])
print("file 1")
print(hex(len(data_temp_1)))
print("starting bytes")
#print(data_temp_1[:0x10].encode("hex"))
print(data_temp_1[:0x10].hex())
#print(data_temp_1[0x10:0x20].encode("hex"))
print(data_temp_1[0x10:0x20].hex())
print("")

new_file1 = open("bl2.bin", "wb")
new_file1.write(data_1)
new_file1.close()


aescbc_2 = AES.new(key = key1, mode=AES.MODE_CBC, IV=iv2)

f_temp_2 = open("file_e2.bin","rb")
data_temp_2 = f_temp_2.read()
f_temp_2.close()

print("file 2")
print(hex(len(data_temp_2)))
print("starting bytes")
#print(data_temp_2[:0x10].encode("hex"))
print(data_temp_2[:0x10].hex())
#print(data_temp_2[0x10:0x20].encode("hex"))
print(data_temp_2[0x10:0x20].hex())
print("")

data_2 = aescbc_2.decrypt(data_temp_2[0x10:])
new_file2 = open("bl31.bin", "wb")
new_file2.write(data_2)
new_file2.close()

aescbc_3 = AES.new(key=key2, mode=AES.MODE_CBC, IV=iv3)

f_temp_3 = open("file_e3.bin","rb")
data_temp_3 = f_temp_3.read()
f_temp_3.close()

print("file ")
print(hex(len(data_temp_3)))
print("starting bytes")
#print(data_temp_3[:0x10].encode("hex"))
print(data_temp_3[:0x10].hex())
#print(data_temp_3[0x10:0x20].encode("hex"))
print(data_temp_3[0x10:0x20].hex())
print("iv")
#print(iv3.encode("hex"))
print(iv3.hex())
print("key")
print(key2)
print("")

data_3 = aescbc_3.decrypt(data_temp_3[0x10:])
new_file3 = open("bl32.bin", "wb")
new_file3.write(data_3)
new_file3.close()