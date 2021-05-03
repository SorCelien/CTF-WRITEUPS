# Ordiphone 2

## Énoncé

**200 \| forensics \| Android**

Pour avancer sur cette investigation, vous devez analyser cette capture mémoire et une copie du stockage interne d'un téléphone _Android_ utilisé par un cybercriminel.

Votre mission est de retrouver les secrets que ce dernier stocke sur son téléphone.

`lime.dump.7z` \(180MB\) : [https://files.france-cybersecurity-challenge.fr/dl/android/lime.dump.7z](https://files.france-cybersecurity-challenge.fr/dl/android/lime.dump.7z)

`sdcard.zip` \(17MB\) : [https://files.france-cybersecurity-challenge.fr/dl/android/sdcard.zip](https://files.france-cybersecurity-challenge.fr/dl/android/sdcard.zip)

* SHA256\(`lime.dump`\) = `21575c12bcb8d67e6ca269bac6c3d360847b16922f2f44b0b360790862afe46d`.
* SHA256\(`sdcard.zip`\) = `e19e449c3bc7a9d04cc7f665fb494d857b9f019d8fec2ba08ab40c117fa2f8d8`.

## Analyse & Résolution

#### Analyse du fichier `lime.dump`

```text
xxd lime.dump | head
00000000: 454d 694c 0100 0000 0010 0000 0000 0000  EMiL............
```

En recherchant un peu sur internet grâce aux info ci-dessus on se rend vite compte que c'est un fichier dump mémoire réalisé avec lime. _\(écrit dans le nom du fichier mais au moins on est sur\)_.

> **LiME ~ Linux Memory Extractor**  
> A Loadable Kernel Module \(LKM\) which allows for volatile memory acquisition from Linux and Linux-based devices, such as Android. This makes LiME unique as it is the first tool that allows for full memory captures on Android devices. It also minimizes its interaction between user and kernel space processes during acquisition, which allows it to produce memory captures that are more forensically sound than those of other tools designed for Linux memory acquisition.   
> source : [https://github.com/504ensicsLabs/LiME](https://github.com/504ensicsLabs/LiME)

Voici un exemple de commande pour capturer la mémoire d'un téléphone Android présent sur leur GitHub.

```text
$ adb push lime.ko /sdcard/lime.ko
$ adb forward tcp:4444 tcp:4444
$ adb shell
$ su
# insmod /sdcard/lime.ko "path=tcp:4444 format=lime"
ou bien sur une carte sd :
# insmod /sdcard/lime.ko "path=/sdcard/ram.lime format=lime"
```

J'ai commencé par faire un `grep "insmod"` \(insmod - simple program to insert a module into the Linux Kernel - [linux.die.net](https://linux.die.net/man/8/insmod)\) étant donné qu'elle a surement été utilisée pour faire le dump.

```text
$ grep -a "insmod" lime.dump
...
cd /sd	
mknod /dev/loop0 b 7 0
losetup /dev/loop0 /sdcard/secrets
/data/data/com.termux/files/usr/bin/cryptsetup luksOpen /dev/loop0 secrets
p33larudsb0jrflbmr90l6ikdbb4lcdaym7k5s3a6u28rx8sut7kp1347h6c4v78
mkdir /sdcard/very_secret
mount /dev/mapper/secrets /sdcard/very_secret
cd /sdcard/very_secret
sh script.sh
insmod /sdcard/lime.ko "path=/sdcard/lime.dump format=lime"
...
```

Voila des informations intéressantes. Sous nos yeux nous avons les commandes utilisées pour déchiffrer le fichier secret luks présent sur le carte SD dont la passphrase.

#### Analyse du dossier `sdcard`

```text
$ tree sdcard 
sdcard
├── Alarms
├── Android
│   └── data
│       ├── com.google.android.apps.maps
│       │   ├── cache
│       │   │   └── cache_r.m
│       │   ├── files
│       │   └── testdata
│       ├── com.google.android.apps.nexuslauncher
│       │   └── files
│       ├── com.google.android.gms
│       │   └── files
│       ├── com.google.android.googlequicksearchbox
│       │   └── files
│       │       ├── download_cache
│       │       └── pending_blobs
│       └── com.google.android.youtube
│           ├── cache
│           │   └── exo
│           │       └── 6861aa5b4dd5f9fd.uid
│           └── files
├── DCIM
├── Download
├── Movies
├── Music
├── Notifications
├── Pictures
├── Podcasts
├── Ringtones
└── secrets
```

```text
$ xxd secrets|head    
00000000: 4c55 4b53 babe 0002 0000 0000 0000 4000  LUKS..........@.
```

> The Linux Unified Key Setup \(LUKS\) is a disk encryption specification created by Clemens Fruhwirth in 2004 and was originally intended for Linux.  
> [https://en.wikipedia.org/wiki/Linux\_Unified\_Key\_Setup](https://en.wikipedia.org/wiki/Linux_Unified_Key_Setup)

Nous allons essayer de monter le fichier secret luks comme trouvé dans le grep un peu plus haut avec la passphrase `p33larudsb0jrflbmr90l6ikdbb4lcdaym7k5s3a6u28rx8sut7kp1347h6c4v78`.

```text
$ sudo mknod /dev/loop0 b 7 0
$ sudo losetup /dev/loop0 ./secrets
$ sudo cryptsetup luksOpen /dev/loop0 ./secrets
```

Une fois monté on y trouve 2 fichiers :

`flag.enc` étant un fichier chiffré et `script.sh` étant un script bash.

```bash
aleatoire=$(cat /dev/urandom | head | xxd -p -l 30 | tr -d " ")
echo $aleatoire > /dev/kmsg
aleatoirebis="$aleatoire$(pidof adbd | tr -d ' ')$(pidof vold | tr -d ' ')$(pidof logd | tr -d ' ')"
echo $aleatoirebis | /data/data/com.termux/files/usr/bin/openssl aes-256-cbc -in flag -out flag.enc -pass stdin
/data/data/com.termux/files/usr/bin/shred flag
rm flag
```

Ce script nous montre comment le flag a été chiffré pour créer le `flag.enc`.Tout d'abord il génère une valeur hexadécimal pseudo aléatoire qu'il stocke dans la variable `aleatoire` et qu'il `echo` dans `/dev/kmsg`. Ensuite il concatène `aleatoire` avec les process id de `adbd`, `vold`, et `logd` et stock le résultat dans `aleatoirebis`. C'est ce `aleatoirebis` qui a été utilisé comme clé pour chiffrer le flag avec de l'aes-256-cbc.

Vu que nous pouvons déterminer la longueur nous pouvons retrouver la chaine hexadécimal stocké dans aléatoire grâce à un simple `grep`.

```text
$ strings lime.dump|egrep '^[a-f0-9]{60}$'
387e8985bd75be1b922eddaadde934e70465424ab4b0c3da98763c094432
4100038121f20004150605040710000041637469766174653a64743d3135
```

Il nous retourne 2 chaines hexadécimales. Pas besoin d'investiguer plus loin, nous testerons les deux.

Pour les pids il est possible d'en retrouver certain avec des `grep` mais je n'ai pas réussi à tous les trouvés.

J'ai donc du me documenter sur Volatility et sur comment créer un profil linux \(Android\) pour Volatility étant donné que je vais devoir l'utiliser pour explorer le dump mémoire.

#### Qu'est ce qu'un profil Volatility linux?

C'est un zip contenant deux choses, une fichier `module.dwraf` et un fichier `System.map`.

Fichier System.map :

> In Linux, the System.map file is a symbol table used by the kernel.  
> A symbol table is a look-up between symbol names and their addresses in memory. A symbol name may be the name of a variable or the name of a function. The System.map is required when the address of a symbol name, or the symbol name of an address, is needed. It is especially useful for debugging kernel panics and kernel oopses. The kernel does the address-to-name translation itself when CONFIG\_KALLSYMS is enabled so that tools like ksymoops are not required.  
> [https://en.wikipedia.org/wiki/System.map](https://en.wikipedia.org/wiki/System.map)

Fichier `module.dwraf` :

> DWARF is a widely used, standardized debugging data format. DWARF was originally designed along with Executable and Linkable Format \(ELF\), although it is independent of object file formats. The name is a medieval fantasy complement to "ELF" that had no official meaning, although the backronym "Debugging With Arbitrary Record Formats" has since been proposed.  
> [https://en.wikipedia.org/wiki/DWARF](https://en.wikipedia.org/wiki/DWARF)

Étant donné que ces deux fichiers sont dépendant du Kernel et que Volatility en a besoin pour "comprendre" comment est structuré le dump mémoire nous allons devoir compiler le kernel correspond nous même.

#### Compilation du Kernel Linux Android

Voici quelque lien qui m'ont été très utile pour réaliser cette étape :  
[https://gabrio-tognozzi.medium.com/run-android-emulator-with-a-custom-kernel-547287ef708c](https://gabrio-tognozzi.medium.com/run-android-emulator-with-a-custom-kernel-547287ef708c)  
[https://gabrio-tognozzi.medium.com/lime-on-android-avds-for-volatility-analysis-a3d2d89a9dd0](https://gabrio-tognozzi.medium.com/lime-on-android-avds-for-volatility-analysis-a3d2d89a9dd0)  
[https://github.com/volatilityfoundation/volatility/wiki/Android\#cross-compile-the-kernel](https://github.com/volatilityfoundation/volatility/wiki/Android#cross-compile-the-kernel)

Tout d'abord j'ai du déterminer sous quelle version de kernel Linux et de gcc tournait le smartphone.

```text
$ strings lime.dump|egrep 'Linux version'
Linux version 4.4.124+ (forensics@fcsc2021) (gcc version 4.9.x 20150123 (prerelease) (GCC) ) #3 SMP PREEMPT Sun Mar 21 19:15:33 CET 2021
```

De base j'ai voulu compiler le kernel sur une ubuntu 20.04 mais ca n'a jamais marché donc je me suis tourné vers une bonne vieille debian 10.9.0 en cli root.

Voici comment je m'y suis pris.

Téléchargement du kernel et du bon gcc. J'ai du prendre une autre branch du gcc car la master à été déprécié et le /bin/x86\_64-linux-android-4.9-gcc n'est plus dedans.

```text
# git clone https://android.googlesource.com/kernel/goldfish/ -b android-goldfish-4.4-dev
# git clone https://android.googlesource.com/platform/prebuilts/gcc/linux-x86/x86/x86_64-linux-android-4.9 -b pie-b4s4-release
```

j'ai installé quelques paquets pour pouvoir make et le `libssl-dev` pour par avoir d'erreur lors de la compilation.

```text
# apt update
# apt-get install build-essential dkms linux-headers-$(uname -r) libssl-dev
```

Export des variables utilisé par le Makefile \(possible de ne pas le faire et de les passer en argument des makes comme vu sur les sites de doc\).

```text
# export PATH=/root/x86_64-linux-android-4.9/bin:$PATH
# export CROSS_COMPILE=x86_64-linux-android-
# export ARCH=x86_64
```

Ensuite nous allons faire les deux make. Le premier pour créer le `.config` et le deuxième pour  build le kernel le tout dans le dossier `Goldfish`.

```text
make x86_64_ranchu_defconfig
make -j16
```

Une fois le kernel build nous pouvons installer Volatility et créer le profil.

#### Installation de Volatility

source : [https://dmfrsecurity.com/2020/12/18/volatility-on-ubuntu-20-04/](https://dmfrsecurity.com/2020/12/18/volatility-on-ubuntu-20-04/)

```text
# apt update
# apt install -y python2 python-dev dwarfdump build-essential yara zip git
# wget https://bootstrap.pypa.io/get-pip.py
# python2 get-pip.py
# get-pip.py
# pip2 install pycrypto yara-python distorm3==3.4.4 # https://github.com/volatilityfoundation/volatility/issues/719
# clone https://github.com/volatilityfoundation/volatility.git 
# cd volatility
# python2 setup.py install
```

#### Création du profil Volatility

Pour ce faire nous allons éditer le Makfile qui créera notre module.dwarf qui se situe dans `volatility/tools/linux`. Et enfin nous copierons dans un zip le module.dwarf et le System.map de notre Goldfish.

Voici mon Makefile :

```text
obj-m += module.o
KDIR := /root/goldfish
CCPATH := /root/x86_64-linux-android-4.9/bin
DWARFDUMP := dwarfdump

-include version.mk

all: dwarf

dwarf: module.c
	$(MAKE) ARCH=x86_64 CROSS_COMPILE=$(CCPATH)/x86_64-linux-android- -C $(KDIR) CONFIG_DEBUG_INFO=y M=$(PWD) modules
	$(DWARFDUMP) -di module.ko > module.dwarf

clean:
	rm -f module.dwarf
```

Enfin nous allons zipper le module.dwarf et le System.map et mettre le zip au bon endroit sur le système.

```text
# zip Goldfish.zip ./module.dwarf ~/goldfish/System.map
# cp Goldfish.zip /usr/local/lib/python2.7/dist-packages/volatility-2.6.1-py2.7.egg/volatility/plugins/overlays/linux/
```

et voila.

#### Exploration du dump

La commande ci-dessus nous permet de voir si notre profil est bien présent dans la section profil et elle nous permet aussi de voir toute les commandes possibles avec un profil Linux. Un exemple des principales commandes linux de Volatility se trouve sur leur [Github](https://github.com/volatilityfoundation/volatility/wiki/Linux-Command-Reference).

```text
# vol.py --info
```

```text
# vol.py -f lime.dump --profile=LinuxGoldfishx64 linux-pstree
Name                 Pid             Uid            
init                 1                              
.ueventd             1169                           
.logd                1529            1036           
.servicemanager      1530            1000           
.hwservicemanage     1531            1000           
.vndservicemanag     1532            1000           
.keymaster@3.0-s     1538            1000           
.vold                1539                           
.adbd                1581            2000           
..sh                 4289            2000           
...sh                4292                           
....insmod           4752
...
```

Du coup le pid de adbd = 1581, pid de vold = 1539 et pid de logd = 1529

Testons avec `387e8985bd75be1b922eddaadde934e70465424ab4b0c3da98763c094432` comme première partie :

`387e8985bd75be1b922eddaadde934e70465424ab4b0c3da98763c094432|1581|1539|1529 387e8985bd75be1b922eddaadde934e70465424ab4b0c3da98763c094432158115391529`

J'ai donc testé de déchiffrer et j'ai passé la passphrase une fois la commande executée.

```text
openssl enc -aes-256-cbc -d -in flag.enc
```

Et voici un beau PNG

#### Flag

![](.CTF-WRITEUPS/FCSC-2021/forensics/src/flag.png)

## Sources & Aides

[https://unix.stackexchange.com/questions/184519/how-to-grep-for-line-length-in-a-given-range](https://unix.stackexchange.com/questions/184519/how-to-grep-for-line-length-in-a-given-range) [https://stackoverflow.com/questions/39399595/using-grep-to-get-12-letter-alphabet-only-lines](https://stackoverflow.com/questions/39399595/using-grep-to-get-12-letter-alphabet-only-lines) [https://askubuntu.com/questions/590384/grep-searching-two-words-in-a-line](https://askubuntu.com/questions/590384/grep-searching-two-words-in-a-line)  
[https://gabrio-tognozzi.medium.com/run-android-emulator-with-a-custom-kernel-547287ef708c](https://gabrio-tognozzi.medium.com/run-android-emulator-with-a-custom-kernel-547287ef708c)  
[https://gabrio-tognozzi.medium.com/lime-on-android-avds-for-volatility-analysis-a3d2d89a9dd0](https://gabrio-tognozzi.medium.com/lime-on-android-avds-for-volatility-analysis-a3d2d89a9dd0)  
[https://github.com/volatilityfoundation/volatility/wiki/Android\#cross-compile-the-kernel](https://github.com/volatilityfoundation/volatility/wiki/Android#cross-compile-the-kernel)  
[https://beguier.eu/nicolas/articles/security-tips-3-volatility-linux-profiles.html](https://beguier.eu/nicolas/articles/security-tips-3-volatility-linux-profiles.html) [https://www.cyberciti.biz/faq/debian-linux-install-gnu-gcc-compiler/](https://www.cyberciti.biz/faq/debian-linux-install-gnu-gcc-compiler/) [https://www.youtube.com/watch?v=enKqmD\_8VWw](https://www.youtube.com/watch?v=enKqmD_8VWw)  
[https://faui1-files.cs.fau.de/filepool/gruhn/thesis\_waechter.pdf](https://faui1-files.cs.fau.de/filepool/gruhn/thesis_waechter.pdf)  
[https://faui1-files.cs.fau.de/filepool/publications/Live\_Memory\_Forensics\_on\_Android\_with\_Volatility.pdf](https://faui1-files.cs.fau.de/filepool/publications/Live_Memory_Forensics_on_Android_with_Volatility.pdf)  
[https://www.andreafortuna.org/2019/08/22/how-to-generate-a-volatility-profile-for-a-linux-system/](https://www.andreafortuna.org/2019/08/22/how-to-generate-a-volatility-profile-for-a-linux-system/)  
[https://countuponsecurity.com/2019/10/14/notes-on-linux-memory-analysis-lime-volatility-and-lkms/](https://countuponsecurity.com/2019/10/14/notes-on-linux-memory-analysis-lime-volatility-and-lkms/)  
[https://dmfrsecurity.com/2020/12/18/volatility-on-ubuntu-20-04/](https://dmfrsecurity.com/2020/12/18/volatility-on-ubuntu-20-04/)  
[https://covert.sh/2020/08/24/volatility-ubuntu-setup/](https://covert.sh/2020/08/24/volatility-ubuntu-setup/)  
[https://github.com/volatilityfoundation/volatility/wiki/Linux-Command-Reference](https://github.com/volatilityfoundation/volatility/wiki/Linux-Command-Reference)

