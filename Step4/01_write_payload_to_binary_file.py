

#copied 0x101010 bytes from adr 0x413000 of decrypted_file using Ghidra
#aim: write these bytes into ciphered_payload.bin

payload_length = int(len(payload_str)/2)

assert payload_length == 0x101010

payload_int_list = [int(payload_str[i*2:i*2+2],16) for i in range(payload_length)]
print(hex(len(payload_int_list)))

print("".join(["%02x" % i for i in payload_int_list[:10]]))

b = bytes(payload_int_list)
print(b[:10])

f = open("ciphered_payload.bin","wb")
f.write(b)
f.close()