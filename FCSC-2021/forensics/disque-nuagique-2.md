# Disque nuagique 2

## Énoncé

**500 \| forensics \| réaliste \| dfir**

Pour cette étape de l'investigation, vous devez retrouver un élément pouvant être lié au nom ou au pseudo de l'administrateur. L'élément à rechercher a été remplacé par un flag au format `FCSC{xxx}`.

La copie du disque est identique à l'épreuve `Disque nuagique 1`.

SHA256\(`data.zip`\) = `f25ad71798caa9a7c1a1bdb57cd4b189251b6fbcee116a0def914750de2aff70`.

`data.zip` \(1.6GB\) : [https://files.france-cybersecurity-challenge.fr/dl/cloudisk/data.zip](https://files.france-cybersecurity-challenge.fr/dl/cloudisk/data.zip)

## Analyse & Résolution

nous avons 2 fichiers ewf e01 et e02 qui à deux font un et un seul disque.

pour convertir un ewf en .img

```text
$ ewfexport disque.e0?
```

Montage du disque .img

```text
$ sudo apt update
$ sudo apt install kpartx
$ sudo kpartx -av disque.raw
```

Il est aussi possible d'ouvrir les .e0? sur Autopsy pour parcourir les fichiers et faire des recherches de strings.

Une fois monté il y a deux partitions, une /boot accessible et contenant des fichiers et une partition de type luks donc chiffrée. On peut voir que c'est du luks2 avec `cryptsetup luksDump partition`.

Dans le boot à première vue il n'y a rien de bizarre a part des fichiers supprimés irrécupérables.

#### je me suis penché sur le format ewf

```text
$ ewfinfo disque.e0?
ewfinfo 20140807

Acquiry information
 Case number:  42
 Description:  FCSC
 Examiner name:  x
 Evidence number: 1
 Acquisition date: Wed Mar 17 01:03:44 2021
 System date:  Wed Mar 17 01:03:44 2021
 Password:  N/A

EWF information
 File format:  EnCase 1
 Sectors per chunk: 64
 Compression method: deflate
 Compression level: no compression

Media information
 Media type:  removable disk
 Is physical:  no
 Bytes per sector: 512
 Number of sectors: 20971520
 Media size:  10 GiB (10737418240 bytes)

Digest hash information
 MD5:   66a962d1edfee0fd53af52cb05cbfaf1
```

La description et le examiner name m'ont bayte. J'ai chercher dans le hex des deux fichier ewf pour essayer de trouver un flag avec des grep et des strings dans tous les sens mais  j'ai rien trouvé.

#### Du coup j'ai essayé la suite de commande de SleuthKit

tout d'abord un mmls \(Display the partition layout of a volume system \(partition tables\)\)

```text
$ mmls disque.e0?                     
DOS Partition Table
Offset Sector: 0
Units are in 512-byte sectors

      Slot      Start        End          Length       Description
000:  Meta      0000000000   0000000000   0000000001   Primary Table (#0)
001:  -------   0000000000   0000002047   0000002048   Unallocated
002:  000:000   0000002048   0000999423   0000997376   Linux (0x83)
003:  -------   0000999424   0001001471   0000002048   Unallocated
004:  Meta      0001001470   0020969471   0019968002   DOS Extended (0x05)
005:  Meta      0001001470   0001001470   0000000001   Extended Table (#1)
006:  001:000   0001001472   0020969471   0019968000   Linux (0x83)
007:  -------   0020969472   0020971519   0000002048   Unallocated
```

puis un fls \(lists allocated and unallocated file names within a file system.\) sur la seul partition qui marchait \(partition boot\).

```text
$ fls disque.e01 -o 2048              
d/d 11: lost+found
r/r 13: config-4.19.0-14-amd64
r/r 14: vmlinuz-4.19.0-14-amd64
d/d 112641: grub
r/r * 17: initrd.img-4.19.0-14-amd64.dpkg-bak
r/r 12: System.map-4.19.0-14-amd64
r/r 15: initrd.img-4.19.0-14-amd64
r/r * 15(realloc): initrd.img-4.19.0-14-amd64.new
V/V 124929: $OrphanFiles
```

j'ai voulu extract le 17 mais ca ne me sortait rien donc j'ai essayé d'extract le 15 initrd.img-4.19.0-14-amd64

```text
$ icat disque.e01 -o 2048 15 > oui.zip
```

En dézippant le `test.zip` une fois nous avons encore un zip et quand je rentre dans je vois cette architecture :

```text
total 68K
drwxr-xr-x 9 kali kali 4.0K May  1 07:17 .
drwxr-xr-x 4 kali kali 4.0K May  1 07:17 ..
-rw-r--r-- 1 kali kali    7 Mar 13 12:12 bin
drwx------ 3 kali kali 4.0K Mar 13 12:12 conf
drwx------ 2 kali kali 4.0K Mar 13 12:12 cryptroot
drwx------ 8 kali kali 4.0K Mar 13 12:12 etc
-rw-r--r-- 1 kali kali 6.2K Aug 22  2019 init
-rw-r--r-- 1 kali kali    7 Mar 13 12:12 lib
-rw-r--r-- 1 kali kali    9 Mar 13 12:12 lib32
-rw-r--r-- 1 kali kali    9 Mar 13 12:12 lib64
-rw-r--r-- 1 kali kali   10 Mar 13 12:12 libx32
drwx------ 3 kali kali 4.0K Mar 13 12:12 root-LfekH8
drwx------ 2 kali kali 4.0K Mar 13 12:12 run
-rw-r--r-- 1 kali kali    8 Mar 13 12:12 sbin
drwx------ 9 kali kali 4.0K Mar 13 12:12 scripts
drwx------ 8 kali kali 4.0K Mar 13 12:12 usr
```

j'ai donc fait un grep sur le fichier extrait une fois mais qui est encore un zip :

```text
$ grep -a "FCSC" oui.zip
07070100041B940000A1FF000000000000000000000001604CF26300000007000000FE0000000100000000000000000000000400000000libusr/lib07070100041B950000A1FF000000000000000000000001604CF26300000009000000FE0000000100000000000000000000000600000000lib32usr/lib3207070100041B960000A1FF000000000000000000000001604CF26300000009000000FE0000000100000000000000000000000600000000lib64usr/lib6407070100041B970000A1FF000000000000000000000001604CF2630000000A000000FE0000000100000000000000000000000700000000libx32usr/libx3207070100041B9E000041C0000000000000000000000003604CF26600000000000000FE0000000100000000000000000000000C00000000root-LfekH807070100041B9F000041C0000000000000000000000002604CF26600000000000000FE0000000100000000000000000000001100000000root-LfekH8/.ssh07070100041BA000008180000000000000000000000001604CF2660000019A000000FE0000000100000000000000000000002100000000root-LfekH8/.ssh/authorized_keysssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCugzXip0c9+5DUxpTsJV1s9kLjiF4+inMOzziGnc4uj1UpguzouJQ7S614xBWqCjD93GKSibD11S/x+t95KLxQh9iQeHSgtqT7eROSsrEoy8fY/XW75IR7GLBI/5dWmPMu/1Mo4q819GEVe8y9OrcWkTh46Ua027v5Q4ziE0PYzPW9orm8TaVDYZW0DZrGLliGGI+iXM3jQ+3PerROCG52HvQinq4NDq0Vq4dwfqhq85KOdTHaoGiZvJ/9Z/xv11odeTVEw6exhx8iECOrNS5OZsvpiKmVMmwnkuAjGcWGRMiPxMqpGvprlz4KEqHx8buB3pJ6F75mml+IpHCQ2iQt
FCSC{0fb01eb22d4f812dcbdfcb}
```

et voila le flag.

#### Flag

```text
FCSC{0fb01eb22d4f812dcbdfcb}
```

#### Comprend comment cela se fait

je voulais savoir d'où venait le flag donc j'ai dézippé une deuxième fois le fichier pour avoir accès directement à l'arborescence.Il était en faite dans :

```text
root-LfekH8/.ssh:
total 12K
drwx------ 2 kali kali 4.0K Mar 13 12:12 .
drwx------ 3 kali kali 4.0K Mar 13 12:12 ..
-rw-r--r-- 1 kali kali  410 Mar 13 12:12 authorized_keys
```

et voici le contenu de `authorized_keys` :

```text
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCugzXip0c9+5DUxpTsJV1s9kLjiF4+inMOzziGnc4uj1UpguzouJQ7S614xBWqCjD93GKSibD11S/x+t95KLxQh9iQeHSgtqT7eROSsrEoy8fY/XW75IR7GLBI/5dWmPMu/1Mo4q819GEVe8y9OrcWkTh46Ua027v5Q4ziE0PYzPW9orm8TaVDYZW0DZrGLliGGI+iXM3jQ+3PerROCG52HvQinq4NDq0Vq4dwfqhq85KOdTHaoGiZvJ/9Z/xv11odeTVEw6exhx8iECOrNS5OZsvpiKmVMmwnkuAjGcWGRMiPxMqpGvprlz4KEqHx8buB3pJ6F75mml+IpHCQ2iQt
FCSC{0fb01eb22d4f812dcbdfcb}
```

j'ai voulu comprends d'où ca venait et en faite j'ai remarqué qu'on aurait pu trouvé juste en montant le disque et en allant dans la partition boot de 511 MB

```text
$ sudo file initrd.img-4.19.0-14-amd64 
initrd.img-4.19.0-14-amd64: gzip compressed data, last modified: Sat Mar 13 17:12:07 2021, from Unix, original size modulo 2^32 101766656
```

le initrd était la devant nos yeux. Lorsque qu'on greppait on ne trouvait rien parce que c'est un zip et donc que ce n'est pas le texte brute à l'intérieur

si on cp le initrd et qu'on s'accord les permissions dessus puis qu'on le renomme avec .zip a la fin on a le même fichier que ce qu'on a eu avec le icat, un fichier gzip.

après l'avoir dézippé avec engrampa on a encore un fichier zip mais on peut déjà grep dessus et voir le flag mais voici son format :

initrd: ASCII cpio archive \(SVR4 with no CRC\)

en rajoutant .zip et en dézippant celui si on retrouve l'architecture comme plus haut et donc le flag aussi.

#### Pourquoi ce fichier `authorized_keys`

Ce fichier est surement la car Dropbear à surement été installé sur la machine pour pouvoir déverrouiller un disque Luks à distance en ssh comme dans ce lien.  
[https://www.cyberciti.biz/security/how-to-unlock-luks-using-dropbear-ssh-keys-remotely-in-linux/](https://www.cyberciti.biz/security/how-to-unlock-luks-using-dropbear-ssh-keys-remotely-in-linux/)  
[https://www.ssh.com/academy/ssh/authorized-keys-file](https://www.ssh.com/academy/ssh/authorized-keys-file)

## Sources & Aides

[https://www.binarytides.com/linux-command-check-disk-partitions/](https://www.binarytides.com/linux-command-check-disk-partitions/)  
[https://www.jaiminton.com/Defcon/DFIR-2019/\#01-hello-my-name-is---1-point](https://www.jaiminton.com/Defcon/DFIR-2019/#01-hello-my-name-is---1-point)  
[https://sigalpes.re/?p=112](https://sigalpes.re/?p=112)  
[http://aaforensics.blogspot.com/2014/04/basic-xmount-use.html](http://aaforensics.blogspot.com/2014/04/basic-xmount-use.html)  
[https://diverto.github.io/2019/11/18/Cracking-LUKS-passphrases?fbclid=IwAR17-SLUIEDpKwXl0vOdHIcXwjVNVcofPVW-AI16KZXoCwYZHP3fdGPjQt8](https://diverto.github.io/2019/11/18/Cracking-LUKS-passphrases?fbclid=IwAR17-SLUIEDpKwXl0vOdHIcXwjVNVcofPVW-AI16KZXoCwYZHP3fdGPjQt8)  
[https://github.com/krx/CTF-Writeups/blob/master/CSAW%2016%20Quals/for100%20-%20Clams%20Dont%20Dance/README.md](https://github.com/krx/CTF-Writeups/blob/master/CSAW%2016%20Quals/for100%20-%20Clams%20Dont%20Dance/README.md)  
[https://medium.com/hackstreetboys/defcon-dfir-ctf-2018-lessons-learned-890ef781b96c](https://medium.com/hackstreetboys/defcon-dfir-ctf-2018-lessons-learned-890ef781b96c)  
[https://or10nlabs.tech/defcon-dfir-ctf-2018/](https://or10nlabs.tech/defcon-dfir-ctf-2018/)  
[https://digitalcorpora.org/corpora/disk-images/format-conversion](https://digitalcorpora.org/corpora/disk-images/format-conversion)  
[https://ramslack.wordpress.com/2011/03/31/e01%E2%80%99s-and-sift-%E2%80%93-a-forbidden-love-affair%E2%80%A6/](https://ramslack.wordpress.com/2011/03/31/e01%E2%80%99s-and-sift-%E2%80%93-a-forbidden-love-affair%E2%80%A6/)  
[https://www.coursehero.com/file/p1eue1j/Forensic-Format-Image-Files-The-ewflib-software-package-includes-a-tool-called/](https://www.coursehero.com/file/p1eue1j/Forensic-Format-Image-Files-The-ewflib-software-package-includes-a-tool-called/)  
[https://www.giac.org/paper/gcfa/10182/forensic-images-viewing-pleasure/126976](https://www.giac.org/paper/gcfa/10182/forensic-images-viewing-pleasure/126976)  
[https://www.cyberciti.biz/faq/linux-list-disk-partitions-command/](https://www.cyberciti.biz/faq/linux-list-disk-partitions-command/)  
[https://www.andreafortuna.org/2018/04/11/how-to-mount-an-ewf-image-file-e01-on-linux/](https://www.andreafortuna.org/2018/04/11/how-to-mount-an-ewf-image-file-e01-on-linux/)  
[https://community.malforensics.com/t/how-to-mount-an-expert-witness-compression-format-ewf-file-in-ubuntu/57](https://community.malforensics.com/t/how-to-mount-an-expert-witness-compression-format-ewf-file-in-ubuntu/57)  
[https://github.com/libyal/libewf/blob/main/documentation/Expert%20Witness%20Compression%20Format%20\(EWF\).asciidoc](https://github.com/libyal/libewf/blob/main/documentation/Expert%20Witness%20Compression%20Format%20%28EWF%29.asciidoc)  
[https://books.google.be/books?id=ZZC7DQAAQBAJ&lpg=PA233&dq=ewfmount%20e02&hl=fr&pg=PA233\#v=onepage&q=ewfmount%20e02&f=false](https://books.google.be/books?id=ZZC7DQAAQBAJ&lpg=PA233&dq=ewfmount%20e02&hl=fr&pg=PA233#v=onepage&q=ewfmount%20e02&f=false)  
[https://www.sans.org/blog/digital-forensic-sifting-mounting-evidence-image-files/](https://www.sans.org/blog/digital-forensic-sifting-mounting-evidence-image-files/)  
[https://askubuntu.com/questions/604175/how-to-mount-disk-image-taken-in-linux-and-run-in-virtual-box](https://askubuntu.com/questions/604175/how-to-mount-disk-image-taken-in-linux-and-run-in-virtual-box)  
[https://www.cyberciti.biz/security/how-to-unlock-luks-using-dropbear-ssh-keys-remotely-in-linux/](https://www.cyberciti.biz/security/how-to-unlock-luks-using-dropbear-ssh-keys-remotely-in-linux/)  
[https://www.ssh.com/academy/ssh/authorized-keys-file](https://www.ssh.com/academy/ssh/authorized-keys-file)  
  
