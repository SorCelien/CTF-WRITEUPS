# Ordiphone 1

## Énoncé

**200 \| forensics \| Android**

Le maître d’apprentissage, un peu fou, veut savoir depuis combien de nanosecondes l'ordiphone était allumé lors du lancement de la capture mémoire. Retrouvez cette information, contenue dans la variable `real_start_time` du processus ayant effectué la capture !

Le flag est au format `FCSC{real_start_time}`, où `real_start_time` est un nombre entier.

lime.dump.7z \(180MB\) : [https://files.france-cybersecurity-challenge.fr/dl/android/lime.dump.7z](https://files.france-cybersecurity-challenge.fr/dl/android/lime.dump.7z)

SHA256\(`lime.dump`\) = `21575c12bcb8d67e6ca269bac6c3d360847b16922f2f44b0b360790862afe46d`.

## Analyse & Résolution

La variable qui nous est demandé de trouver est une variable 

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

Ensuite nous allons faire les deux make. Le premier pour créer le `.config` et le deuxième pour build le kernel le tout dans le dossier `Goldfish`.

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

En cherchant un peu sur internet je me suis rendu compte que `real_start_time` est une variable `task_struct` de chaque process.

> Sous Linux, la structure noyau task\_struct représente un processus.  
> Les champs pid et comm correspondent respectivement au PID du processus et au nom de l'exécutable. Le parent du processus est pointé par parent. Ces structures forment une liste doublement chaînée, chacune d'entre elles possédant une structure list\_head. Celle-ci contient deux pointeurs, next et prev, qui pointent vers les éléments suivant et précédent. À vrai dire, ils pointent en réalité vers le début des structures list\_head ; pour récupérer la task\_struct correspondante, il faut soustraire son offset à la valeur du pointeur.  
> [https://connect.ed-diamond.com/MISC/MISC-054/Challenge-SSTIC-et-analyse-de-la-memoire-physique-des-systemes-Linux](https://connect.ed-diamond.com/MISC/MISC-054/Challenge-SSTIC-et-analyse-de-la-memoire-physique-des-systemes-Linux)

la commande `linux_vollshell` nous permet des nous balader des les process et d'afficher les différentes variables kernel liées a ces derniers.

```text
root@debian:~# vol.py -f lime.dump --profile=LinuxGoldfishx64 linux_volshell
```

```text
>>> hh()

Use addrspace() for Kernel/Virtual AS
Use addrspace().base for Physical AS
Use proc() to get the current process object
  and proc().get_process_address_space() for the current process AS
  and proc().get_load_modules() for the current process DLLs

addrspace()                              : Get the current kernel/virtual address space. 
cc(offset=None, pid=None, name=None, physical=False) : Change current shell context.
db(address, length=128, space=None)      : Print bytes as canonical hexdump.
dd(address, length=128, space=None)      : Print dwords at address.
dis(address, length=128, space=None, mode=None) : Disassemble code at a given address.
dq(address, length=128, space=None)      : Print qwords at address.
dt(objct, address=None, space=None, recursive=False, depth=0) : Describe an object or show type info.
find(needle, max=1, shift=0, skip=0, count=False, length=128) : 
getmods()                                : Generator for kernel modules (scripting).
getprocs()                               : Generator of process objects (scripting).
hh(cmd=None)                             : Get help on a command.
list_entry(head, objname, offset=-1, fieldname=None, forward=True, space=None) : Traverse a _LIST_ENTRY.
modules()                                : Print loaded modules in a table view.
proc()                                   : Get the current process object.
ps()                                     : Print active processes in a table view.
sc()                                     : Show the current context.

For help on a specific command, type 'hh(<command>)'
```

Affichage des offsets mémoire de chaque process.

```text
>>> ps()
Name             PID    Offset                                                                                      
init             1      0xffff88004b0d8000                                                                           
kthreadd         2      0xffff88004b0d92c0                                                                           
...
d.process.acore  4669   0xffff88002bdaddc0
insmod           4752   0xffff880011da12c0
```

Affichage de la `task_struct` de notre process `insmod`

```text
>>> dt("task_struct", 0xffff880011da12c0)
[task_struct task_struct] @ 0xFFFF880011DA12C0
0x0   : state                          0
0x8   : stack                          18446612132542087168
...
0x8c8 : start_time                     63951047172
0x8d0 : real_start_time                63951047224
...
0xfb8 : pagefault_disabled             1
0xfc0 : thread                         18446612132613726848
```

#### Flag

```text
FCSC{63951047224}
```

## Sources & Aides

[https://www.reddit.com/r/kernel/comments/bg6sj5/find\_start\_time\_of\_a\_process\_given\_pid/](https://www.reddit.com/r/kernel/comments/bg6sj5/find_start_time_of_a_process_given_pid/)  
[https://people.cs.umass.edu/~liberato/courses/2019-spring-compsci590f/lecture-notes/19-intro-to-memory-forensics/](https://people.cs.umass.edu/~liberato/courses/2019-spring-compsci590f/lecture-notes/19-intro-to-memory-forensics/)  
[https://stackoverflow.com/questions/23178888/age-of-a-process-in-the-linux-kernel](https://stackoverflow.com/questions/23178888/age-of-a-process-in-the-linux-kernel)  
[https://connect.ed-diamond.com/MISC/MISC-054/Challenge-SSTIC-et-analyse-de-la-memoire-physique-des-systemes-Linux](https://connect.ed-diamond.com/MISC/MISC-054/Challenge-SSTIC-et-analyse-de-la-memoire-physique-des-systemes-Linux)  
[https://core.ac.uk/download/pdf/36696662.pdf](https://core.ac.uk/download/pdf/36696662.pdf)  
[https://github.com/volatilityfoundation/volatility/wiki/Linux-Command-Reference\#linux\_volshell](https://github.com/volatilityfoundation/volatility/wiki/Linux-Command-Reference#linux_volshell)  
[https://tunnelix.com/linux-memory-analysis-with-lime-and-volatility/](https://tunnelix.com/linux-memory-analysis-with-lime-and-volatility/)  
[https://connect.ed-diamond.com/MISC/MISC-076/Volatilisons-Linux-partie-2](https://connect.ed-diamond.com/MISC/MISC-076/Volatilisons-Linux-partie-2)  


