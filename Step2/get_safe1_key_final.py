
import hashlib
import sys
import binascii
from Crypto.Cipher import AES

def info(msg):
	print("[\033[34;1mi\033[0m] %s" % (msg))

def ok(msg):
	print("[\033[32;1m+\033[0m] %s" % (msg))

def warn(msg):
	print("[\033[33;1mw\033[0m] %s" % (msg))

def error(msg):
	print("[\033[31;1m!\033[0m] %s" % (msg))


def secure_device(a,b,op):
	global BUTTONS
	buttons = int(BUTTONS)

	bop = (buttons & 0x3 ^ op)
	A = "%02x" % a
	B = "%02x" % b
	if (buttons & 0x4):
		a = ((a<<1) + (a>>7)) & 0xFF
	
	if (buttons & 0x8):
		b = ((b<<1) + (b>>7)) & 0xFF
	
	if (bop == 0):
		return a&b
	if (bop == 1):
		return a|b
	if (bop==2):
		return a^b
	if (bop==3):
		return (a+b)&0xFF

def step1():
	r = secure_device(0x35,0x27,3)
	r = secure_device(0x7e,r,3)
	r = secure_device(0x66,r,2)
	r = secure_device(0x8,r,1)
	r = secure_device(0x13,r,0)
	r = secure_device(0x1f,r,1)
	r = secure_device(0xa,r,2)
	r = secure_device(0xd3,r,0)
	r = secure_device(0xc6,r,3)

	return r

def step2():
	r= secure_device(0xde,0xab,0)
	r= secure_device(0x67,r,3)
	r= secure_device(0x2a,r,2)
	r= secure_device(0x6d,r,1)
	r= secure_device(0x4a,r,3)
	r= secure_device(0xe7,r,0)
	r= secure_device(0x1c,r,1)
	r= secure_device(0x35,r,0)
	r= secure_device(0xde,r,3)
	r= secure_device(0xf7,r,0)
	r= secure_device(0xda,r,2)
	return r

def step3():
	r = secure_device(0x14,0x23,3)
	r = secure_device(0x72,r,0)
	r = secure_device(0x48,r,3)
	r = secure_device(0x53,r,1)
	r = secure_device(0xa7,r,0)
	r = secure_device(0x5f,r,1)
	r = secure_device(0x3,r,3)
	r = secure_device(0xb7,r,3)
	r = secure_device(0x73,r,1)
	r = secure_device(0x37,r,3)
	r = secure_device(0xc5,r,2)
	r = secure_device(0xa4,r,1)
	r = secure_device(0x30,r,0)
	r = secure_device(0xdd,r,2)
	return r


def step4():
	r = secure_device(0xb0,0x42,2)
	r = secure_device(0xbc,r,2)
	r = secure_device(0xfc,r,2)
	r = secure_device(0x54,r,3)
	r = secure_device(0x30,r,2)
	r = secure_device(0x97,r,1)
	r = secure_device(0xe8,r,2)
	r = secure_device(0xd6,r,0)
	r = secure_device(0x26,r,0)
	r = secure_device(0xeb,r,0)
	r = secure_device(0x68,r,1)
	r = secure_device(0x26,r,0)
	r = secure_device(0x9,r,3)
	r = secure_device(0x2a,r,2)
	r = secure_device(0xa9,r,3)
	return r


def step5():
	r = secure_device(0xff,0x12,0)
	r = secure_device(0xfd,r,1)
	r = secure_device(0xe5,r,1)
	r = secure_device(0x26,r,3)
	r = secure_device(0x85,r,3)
	r = secure_device(0x63,r,1)
	r = secure_device(0x93,r,3)
	r = secure_device(0xba,r,2)
	r = secure_device(0x97,r,0)
	r = secure_device(0xab,r,1)
	r = secure_device(0x6e,r,3)
	r = secure_device(0xfd,r,0)
	r = secure_device(0x4c,r,3)
	r = secure_device(0x50,r,0)
	r = secure_device(0xa,r,2)
	r = secure_device(0xfc,r,3)
	r = secure_device(0xe3,r,2)
	r = secure_device(0xa6,r,3)
	r = secure_device(0x64,r,2)
	r = secure_device(0x8e,r,3)
	r = secure_device(0xc1,r,1)
	return r

def step6():
	r = secure_device(0x90,0x77,1)
	r = secure_device(0x8e,r,0)
	r = secure_device(0xbd,r,2)
	r = secure_device(0x39,r,2)
	r = secure_device(0x4c,r,2)
	r = secure_device(0xc5,r,2)
	r = secure_device(0xb6,r,3)
	r = secure_device(0x93,r,1)
	r = secure_device(0x9f,r,3)
	r = secure_device(0xd6,r,3)
	r = secure_device(0x6e,r,2)
	r = secure_device(0x39,r,3)
	r = secure_device(0x40,r,1)
	r = secure_device(0x14,r,2)
	r = secure_device(0xe6,r,3)
	return r

def step7():
	r = secure_device(0xf,0xab,3)
	r = secure_device(0xa2,r,1)
	r = secure_device(0x7c,r,0)
	r = secure_device(0x34,r,1)
	r = secure_device(0x14,r,1)
	r = secure_device(0xe7,r,0)
	r = secure_device(0xb9,r,0)
	r = secure_device(0xf1,r,2)
	r = secure_device(0xd5,r,1)
	r = secure_device(0x4e,r,2)
	r = secure_device(0xe,r,2)
	r = secure_device(0x6,r,0)
	r = secure_device(0x7d,r,2)
	r = secure_device(0x87,r,3)
	r = secure_device(0xbc,r,0)
	r = secure_device(0xd4,r,3)
	r = secure_device(0x8a,r,1)
	r = secure_device(0xe7,r,3)
	r = secure_device(0x9e,r,1)
	r = secure_device(0x58,r,0)
	r = secure_device(0x24,r,2)
	r = secure_device(0x44,r,3)
	r = secure_device(0xc9,r,1)
	r = secure_device(0xd4,r,1)
	r = secure_device(0x1d,r,3)
	r = secure_device(0xcd,r,0)
	r = secure_device(0xde,r,1)
	r = secure_device(0x54,r,0)
	r = secure_device(0x5e,r,2)
	r = secure_device(0x46,r,1)
	r = secure_device(0x21,r,0)
	r = secure_device(0xff,r,1)
	r = secure_device(0x51,r,0)
	r = secure_device(0x78,r,1)
	r = secure_device(0x2f,r,3)
	r = secure_device(0xed,r,2)
	r = secure_device(0x4b,r,3)
	r = secure_device(0x4d,r,2)
	return r

def step8():
	r = secure_device(0x88,0x74,0)
	r = secure_device(0x48,r,2)
	r = secure_device(0x11,r,2)
	r = secure_device(0x76,r,0)
	r = secure_device(0x2b,r,3)
	r = secure_device(0xf8,r,2)
	return r


def init():
	r = secure_device(0x46,0x92,0)
	r = secure_device(0xdf,r,2)
	r = secure_device(0x3e,r,0)
	r = secure_device(0x3a,r,3)
	r = secure_device(0x36,r,2)
	r = secure_device(0x8e,r,2)
	r = secure_device(0xc9,r,3)
	r = secure_device(0xe7,r,1)
	r = secure_device(0x29,r,2)
	r = secure_device(0xc2,r,2)
	r = secure_device(0x79,r,0)
	r = secure_device(0x2a,r,2)
	r = secure_device(0x4c,r,3)
	r = secure_device(0xde,r,0)
	r = secure_device(0x88,r,0)
	r = secure_device(0x8b,r,2)
	r = secure_device(0x97,r,3)
	r = secure_device(0x6a,r,2)
	r = secure_device(0x60,r,1)
	r = secure_device(0x0f,r,0)
	r = secure_device(0x5b,r,3)
	r = secure_device(0xd0,r,2)
	r = secure_device(0xa9,r,1)
	r = secure_device(0xe3,r,3)
	r = secure_device(0xd0,r,1)
	r = secure_device(0x27,r,0)
	r = secure_device(0x90,r,0)
	r = secure_device(0x3b,r,1)
	r = secure_device(0x66,r,2)
	r = secure_device(0xe2,r,0)
	r = secure_device(0x24,r,3)
	r = secure_device(0xee,r,1)
	r = secure_device(0xf2,r,3)
	return r

def main():
    """
    global BUTTONS
    info("Dechiffrement du conteneur\n")
    info("Initialisation du secure element")
    info("Merci d'appuyer les 4 boutons du secure element puis appuyer sur entrée")
    BUTTONS = input()
    if init()!=0xa1:
        error("Mauvaise initialisation, vérifiez l'état du sécure élement")
        sys.exit(0)
    else:
        ok("Initialisation, check 1 OK")

    info("Merci de relâcher les 4 boutons du secure element puis appuyer sur entrée")
    BUTTONS = input()
    if init()!=0xe0:
        error("Mauvaise initialisation, vérifiez l'état du sécure élement")
        sys.exit(0)
    else:
        ok("Initialisation, check 2 OK")
    """
    s1_l = []
    s2_l = []
    s3_l = []
    s4_l = []
    s5_l = []
    s6_l = []
    s7_l = []
    s8_l = []
    print("Pre-computing...")
    global BUTTONS
    for i in range(16):
        BUTTONS = i
        s1_l.append(step1())
        s2_l.append(step2())
        s3_l.append(step3())
        s4_l.append(step4())
        s5_l.append(step5())
        s6_l.append(step6())
        s7_l.append(step7())
        s8_l.append(step8())
    s = 0
    print("Pre-compute done\n")
    
    print("Bruteforcing...")
    total = pow(2,32)
    try:
        for s1 in s1_l[::-1]:
            for s2 in s2_l:
                for s3 in s3_l:
                    for s4 in s4_l:
                        for s5 in s5_l:
                            for s6 in s6_l:
                                for s7 in s7_l:
                                    for s8 in s8_l:
                                        key = bytearray([s1,s2,s3,s4,s5,s6,s7,s8])
                                        h = hashlib.sha256(key).hexdigest()
                                        if "00c8bb35d44dcbb2712a11799d8e1316045d64404f337f4ff653c27607f436ea" == h:
                                            print("WIN")
                                            print("key: " + key.hex())
                                            raise Exception("Key found")
                    s+=1048576
                    if ((s+1) %1000000) == 0:
                        print("%0.2f %%" % (s*100/total))
    except:
        pass
	
    key = bytearray(key)
    h = hashlib.sha256(key).hexdigest()

    if "00c8bb35d44dcbb2712a11799d8e1316045d64404f337f4ff653c27607f436ea" == h:
        ok("Hash ok")
        info("Dérivation de la clef AES safe_01")
        aes_key = hashlib.scrypt(key,salt =b"sup3r_s3cur3_k3y_d3r1v4t10n_s4lt",n=1<<0xd,r=1<<3,p=1<<1,dklen=32)
        info("aes key : %s" % aes_key.hex())
        info("Vous pouvez sauvegarder cette clef en utilisant /root/tools/add_key.py key")
    else:
        error("Mauvais hash, déchiffrement impossible")

main()