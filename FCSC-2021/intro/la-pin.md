# La PIN

## Énoncé

**20 \| crypto**

J'ai protégé le flag en le chiffrant avec des algorithmes modernes. Pourrez-vous le retrouver ?

## Analyse & Résolution

#### fichier reçu : output.txt

```text
f049de59cbdc9189170787b20b24f7426ccb9515e8b0250f3fc0f0c14ed7bb1d4b42c09d02fe01e0973a7233d99af55ce696f599050142759adc26796d64e0d6035f2fc39d2edb8a0797a9e45ae4cd55074cf99158d3a64dc70a7e836e3b30382df30de49ba60a
```

#### fichier reçu : lapin.py

```python
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.number import long_to_bytes

while True:
	pin = int(input(">>> PIN code (4 digits): "))
	if 0 < pin < 9999:
		break

flag = open("flag.txt", "rb").read()
k = scrypt(long_to_bytes(pin), b"FCSC", 32, N = 2 ** 10, r = 8, p = 1)
aes = AES.new(k, AES.MODE_GCM)
c, tag = aes.encrypt_and_digest(flag)

enc = aes.nonce + c + tag
print(enc.hex())
```



#### Résolution avec python 3

```python
# pip3 uninstall pycryto
# pip3 install pycryptodome

from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Util.number import long_to_bytes

with open("output.txt", "r") as file:
	output = file.read()

# bytes.fromhex() ou bytearray.fromhex() ou binascii.unhexlify() font sensiblement la même chose.
base = bytes.fromhex(output)
Nonce, c, tag = base[:16], base[16:-16], base[-16:]

pin = 0
verify = False
while pin < 10000 and not verify:
	k = scrypt(long_to_bytes(pin), b"FCSC", 32, N = 2 ** 10, r = 8, p = 1)
	cipher = AES.new(k, AES.MODE_GCM, nonce=Nonce)
	plaintext = cipher.decrypt(c)
	try:
		cipher.verify(tag)
		print("pin =", pin, ":", plaintext)
		verify = True
	except ValueError:
		print("pin =", pin, ": failed")
		pass
	pin += 1
```

#### flag

```text
pin = 6273 : b'FCSC{c1feab88e6c6932c57fbaf0c1ff6c32e51f07ae87197fcd08956be4408b2c802}\n'

FCSC{c1feab88e6c6932c57fbaf0c1ff6c32e51f07ae87197fcd08956be4408b2c802}
```

## Sources & Aides

[https://docs.python.org/fr/3.7/library/stdtypes.html](https://docs.python.org/fr/3.7/library/stdtypes.html)  
[https://stackoverflow.com/questions/5649407/hexadecimal-string-to-byte-array-in-python](https://stackoverflow.com/questions/5649407/hexadecimal-string-to-byte-array-in-python)  
[https://stackoverflow.com/questions/443967/how-to-create-python-bytes-object-from-long-hex-string](https://stackoverflow.com/questions/443967/how-to-create-python-bytes-object-from-long-hex-string)  
[https://pycryptodome.readthedocs.io/en/latest/src/introduction.html](https://pycryptodome.readthedocs.io/en/latest/src/introduction.html)  
[https://www.google.com/search?q=aes+gcm+decryption+python&oq=aes+gcm+decryption+python&aqs=chrome..69i57j0i19j0i19i22i30l2j0i10i19i22i30j0i19i22i30j0i8i13i19i30.284j0j9&sourceid=chrome&ie=UTF-8](https://www.google.com/search?q=aes+gcm+decryption+python&oq=aes+gcm+decryption+python&aqs=chrome..69i57j0i19j0i19i22i30l2j0i10i19i22i30j0i19i22i30j0i8i13i19i30.284j0j9&sourceid=chrome&ie=UTF-8)  
[https://meowmeowxw.gitlab.io/ctf/utctf-2020-crypto/](https://meowmeowxw.gitlab.io/ctf/utctf-2020-crypto/)  
[https://rctcwyvrn.github.io/posts/2020-03-12-galois\_writeup.html](https://rctcwyvrn.github.io/posts/2020-03-12-galois_writeup.html)  
[https://github.com/pycrypto/pycrypto/issues/233](https://github.com/pycrypto/pycrypto/issues/233)  
[https://stackoverflow.com/questions/52021391/aes-gcm-decryption-in-python](https://stackoverflow.com/questions/52021391/aes-gcm-decryption-in-python)  
[https://nitratine.net/blog/post/python-gcm-encryption-tutorial/](https://nitratine.net/blog/post/python-gcm-encryption-tutorial/)  
[https://stackoverflow.com/questions/730764/how-to-properly-ignore-exceptions](https://stackoverflow.com/questions/730764/how-to-properly-ignore-exceptions)  
[https://docs.python.org/fr/3.5/tutorial/errors.html](https://docs.python.org/fr/3.5/tutorial/errors.html)  

