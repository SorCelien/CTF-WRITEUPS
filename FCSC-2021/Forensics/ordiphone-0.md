# Ordiphone 0

## Énoncé

**50 \| forensics \| Android**

Un nouvel apprenti vient d'effectuer une capture mémoire mais a oublié de noter la date du lancement de celle-ci.

Pour valider cette première étape, vous devez retrouver la date à laquelle le processus permettant la capture a été lancé. Le flag est au format `FCSC{sha256(date)}`, avec la date au format `YYYY-MM-DD HH:MM` en UTC.

lime.dump.7z \(180MB\) : [https://files.france-cybersecurity-challenge.fr/dl/android/lime.dump.7z](https://files.france-cybersecurity-challenge.fr/dl/android/lime.dump.7z)

SHA256\(`lime.dump`\) = `21575c12bcb8d67e6ca269bac6c3d360847b16922f2f44b0b360790862afe46d`.

## Analyse & Résolution

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

Grâce à `strings`, `grep` et `egrep` nous allons pouvoir découvrir beaucoup de chose.

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

Voila des informations intéressantes, dont des informations qui nous aiderons pour [Ordiphone 2](ordiphone-0.md#ordiphone-2). Comme par exemple la clé utilisée pour déchiffrer le fichier secret luks présent sur le carte SD. On y vois aussi la commande `insmod` utilisé pour le dump.

Ensuite pour avoir un peu plus de clarté j'ai fait un `strings | grep` et ces lignes la ont retenu mon attention.

```text
$ strings lime.dump|grep -a "insmod"
...
type=1400 audit(0.0:11968): avc: denied { module_load } for comm="insmod" path="/storage/emulated/0/lime.ko" dev="sdcardfs" ino=57349 scontext=u:r:su:s0 tcontext=u:object_r:sdcardfs:s0 tclass=system permissive=1
type=1400 audit(1616526815.693:11968): avc: denied { module_load } for pid=4752 comm="insmod" path="/storage/emulated/0/lime.ko" dev="sdcardfs" ino=57349 scontext=u:r:su:s0 tcontext=u:object_r:sdcardfs:s0 tclass=system permissive=1
type=1400 audit(1616526815.693:11968): avc: denied { module_load } for pid=4752 comm="insmod" path="/storage/emulated/0/lime.ko" dev="sdcardfs" ino=57349 scontext=u:r:su:s0 tcontext=u:object_r:sdcardfs:s0 tclass=system permissive=1
type=1400 audit(1616526815.693:11968): avc: denied { module_load } for pid=4752 comm="insmod" path="/storage/emulated/0/lime.ko" dev="sdcardfs" ino=57349 scontext=u:r:su:s0 tcontext=u:object_r:sdcardfs:s0 tclass=system permissive=1
type=1400 audit(1616526815.693:11968): avc: denied { module_load } for pid=4752 comm="insmod" path="/storage/emulated/0/lime.ko" dev="sdcardfs" ino=57349 scontext=u:r:su:s0 tcontext=u:object_r:sdcardfs:s0 tclass=system permissive=1
type=1400 audit(0.0:13): avc: denied { write } for commName:    insmod
...
```

Ces lignes d'audits viennent potentiellement de log kernel comme peut nous afficher `dmesg` \(dmesg - print or control the kernel ring buffer - [man7.org](https://man7.org/linux/man-pages/man1/dmesg.1.html)\). En se renseignant un peu sur le contenu de ces lignes j'ai trouvé ceci :

> `msg=audit(1364481363.243:24287):`The `msg` field records:  
> - a time stamp and a unique ID of the record in the form `audit(`_`time_stamp`_`:`_`ID`_`)`. Multiple records can share the same time stamp and ID if they were generated as part of the same Audit event.  
> - various event-specific _`name`_`=`_`value`_ pairs provided by the kernel or user space applications  
> source : [https://access.redhat.com/documentation/en-us/red\_hat\_enterprise\_linux/6/html/security\_guide/sec-understanding\_audit\_log\_files](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/sec-understanding_audit_log_files)

On comprend donc que le `1616526815.693` est un timestamp linux.

Le site [EpochConverter](https://www.epochconverter.com/) m'a permit de traduire ce timestamp en date humaine la commande `date -d@1616526815` fait de même :

```text
Assuming that this timestamp is in seconds:
GMT: Tuesday 23 March 2021 19:13:35.693
Your time zone: mardi 23 mars 2021 20:13:35.693 GMT+01:00
Relative: A month ago
```

Et voila nous avons notre réponse.

#### Flag

```text
FCSC{sha256(date)}
FCSC{sha256(YYYY-MM-DD HH:MM en UTC)}
FCSC{sha256(2021-03-23 19:13)}
FCSC{b7dc08558ee16d1acbf54db67263c1d92e9a9d9603e6a1345550c825527adc06}
```

### Sources & Aides

[https://github.com/504ensicsLabs/LiME](https://github.com/504ensicsLabs/LiME)  
[https://linux.die.net/man/8/insmod](https://linux.die.net/man/8/insmod)  
[https://man7.org/linux/man-pages/man1/dmesg.1.html](https://man7.org/linux/man-pages/man1/dmesg.1.html)  
[https://www.howtogeek.com/449335/how-to-use-the-dmesg-command-on-linux/](https://www.howtogeek.com/449335/how-to-use-the-dmesg-command-on-linux/)  
[https://access.redhat.com/documentation/en-us/red\_hat\_enterprise\_linux/6/html/security\_guide/sec-understanding\_audit\_log\_files](https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/6/html/security_guide/sec-understanding_audit_log_files)  
[https://www.epochconverter.com/](https://www.epochconverter.com/)

