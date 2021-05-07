# File Format

## Énoncé

**20 \| hardware \| radio**

Lorsqu'un signal radio est représenté numériquement, il est composé d'une suite d'échantillons. L'une des méthodes d'échantillonnage très utilisée est l'échantillonnage I/Q, où chaque échantillon est représenté par une composante I \(composante de phase\) et une composante Q \(composante de quadrature\).

L'une des représentations numérique d'un signal I/Q supportée par les principaux outils est d'avoir une succession d'échantillons, avec chaque composante I et Q de chaque échantillon représentée par un nombre flottant compris entre 0 et 1, sur 32 bits, en mode petit-boutiste. Le schéma ci-dessous montre ce format :

```text
+-------+-------+-------+-------+-------+-------+     +-------+-------+
|  i_0  |  q_0  |  i_1  |  q_1  |  i_2  |  q_2  | ... |  i_n  |  q_n  |
| (f32) | (f32) | (f32) | (f32) | (f32) | (f32) | ... | (f32) | (f32) |
+-------+-------+-------+-------+-------+-------+     +-------+-------+
```

 Le fichier `challenge.iq` contient un signal représenté sous la forme décrite plus haut. Vous devez séparer les composantes I et Q et calculer le hash SHA256 résultant :

```text
hash = SHA256(i_0 | i_1 | ... | i_n | q_0 | q_1 | ... | q_n)
flag = FCSC{<hash>}
```

_Note :_ `|` dénote la concaténation, exemple : `i_0 | q_0 = 20cebb3e | df342a3f = 20cebb3edf342a3f`.

_Note 2 :_ Pour résoudre ce challenge, il faut bouger des octets et aucun décodage de nombre flottant n'est nécessaire.

SHA256\(`challenge.iq`\) = `fe4ea6b35841a0107555f1eb18c9f2fbcdef848116750040c2a80c384e6be932`.

## Analyse & Résolution

#### Aperçu du fichier converti en hexadécimal

Pour pouvoir travailler sur l'hexadécimal comme demandé j'ai fait un xxd \(-p = plain hex dump\) du fichier et j'ai retiré les caractères de saut de ligne avec tr pour avoir le hexa brute et facile à manipuler.

```text
$ xxd -p challenge.iq | tr -d '\n' > challenge.hex
$ cat challenge.hex
20cebb3edf342a3f96f09f3ec1ec213ff6fd213ed8061e3fef84513f570a813e2661753f4c47693ffbc7443f3e39913da6855e3e4626d73dfb40fc3eeeae4e3fab0c6f3fedf77c3ff0ec3e3e4c8d1b3fa4e4b43e9d0c243fd756bb3ed18e0a3f0902283fdd84b13efeed943ed812063f73423f3fb3b3843e13ca5f3fb35ae53e4f7dd03e3648783fa289323f20e79c3e0cbed73e109f773fe4f6ac3ea3fe9f3ec47ff23eb213a63ea4d36d3ea299a23dfeaa883eaf14113eb0804c3f5ae6c23ef5f8113e7cd7533fd170093f8d312a3f21c9693f8973663f64cb7a3f1bdf243f9f50793fe59dfb3ea045583ff6ea873ee4272f3ed4f1723c9344243f9e10173d17de293ffa53d73b3629863ef5663a3fab24423fb4e2843d9298883e5747d13ee2e4cd3dbd4a0b3e16e5e33ea33b913cf43e7c3f4604813e92684c3f6c47313f73865e3f52fb0f3f444bb73ecb97393ed3ba2c3eff13a23e532c6c3f479f393ea83e143f6c65463e70a82c3d3d04ad3c642df33df224763f476e473eaf45263f91e0223f087ad33edb136b3f003cc63e02655a3f19322d3fa8c5133f0a51e23e2de0653ffa8d893d1618593f3a82303f20ac213fa385723f96d42f3e3eed343fd8a3cb3e9e0bf03ded87183d6968283e42c7d33c61d11c3f
```

#### Raisonnement

En suivant les instructions de l'énoncé voici comment devrait être découpé l'hexadécimal :

|  | i | q |
| :---: | :---: | :---: |
| 0 | `20cebb3e` | `df342a3f` |
| 1 | `96f09f3e` | `c1ec213f` |
| 2 | `f6fd213e` | `d8061e3f` |
| `...` | `...` | `...` |

cela nous donnerait donc :

```text
SHA256(20cebb3e96f09f3ef6fd213e...df342a3fc1ec213fd8061e3f...)
```

#### Résolution avec python 3

```python
import hashlib

string_all = ""
string_i = ""
string_g = ""

# ouverture du fichier challenge.hex et stockage de la ligne dans un string
with open("challenge.hex", "r") as file:
	string_all = file.read()

# déplacement sur la string caractère par caractère
# à chaque tour on ajoute le charactère dans une liste en fonction de l'état de swap
# swap change d'état tous les huit tours/charactères
i = 0
swap = True
while i < len(string_all):
	if i % 8 == 0 and i != 0 :
		swap = not swap
	if swap :
		string_i += string_all[i]
	else :
		string_g += string_all[i]
	i += 1

# concaténation de la string_i avec la string_g
string_end = string_i + string_g
# print(sting_end)

# conversion de la string en hex python et calcule du hash de cette dernière
string_fromhex = bytes.fromhex(string_end)
string_tosha256 = hashlib.sha256(string_fromhex)

print(string_tosha256.hexdigest())
```

Le hash du résultat `string_end` peut aussi être calculé avec [CyberChef](https://gchq.github.io/CyberChef/) de cette manière :

![](.gitbook/assets/fileformat_cyberchef.jpg)

#### Flag

```text
FCSC{843161934a8e53da8723047bed55e604e725160b868abb74612e243af94345d7}
```

### Documentation

[https://thispointer.com/python-open-a-file-using-open-with-statement-benefits-explained-with-examples/](https://thispointer.com/python-open-a-file-using-open-with-statement-benefits-explained-with-examples/)  
[https://www.geeksforgeeks.org/python-program-to-convert-a-list-to-string/](https://www.geeksforgeeks.org/python-program-to-convert-a-list-to-string/)  
[https://www.pythonpool.com/python-sha256/](https://www.pythonpool.com/python-sha256/)  
[https://stackoverflow.com/questions/5649407/hexadecimal-string-to-byte-array-in-python](https://stackoverflow.com/questions/5649407/hexadecimal-string-to-byte-array-in-python)  
[https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/)

