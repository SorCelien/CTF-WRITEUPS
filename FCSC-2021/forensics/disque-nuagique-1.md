# Disque nuagique 1

## Énoncé

**50 \| forensics**

Vous trouverez ci-joint la copie d'un disque \(1.6GB\).

Pour commencer cette investigation, vous devez retrouver l'offset du début de la partition qui possède l'UUID `e61a1da4-b95d-4df5-ab40-bbffc505b3f2`.

Format du flag : `FCSC{offset_en_hexadécimal}` \(exemple : `FCSC{123abc}`\).

SHA256\(`data.zip`\) = `f25ad71798caa9a7c1a1bdb57cd4b189251b6fbcee116a0def914750de2aff70`.

`data.zip` \(1.6GB\) : [https://files.france-cybersecurity-challenge.fr/dl/cloudisk/data.zip](https://files.france-cybersecurity-challenge.fr/dl/cloudisk/data.zip)

## Analyse & Résolution

Dans le fichier zip nous avons de fichier `ewf` 

```text
$ sudo apt update
$ sudo apt install ewf-tools kpartx
```

il y a plusieurs possibilités pour extraire/monter une image ewf.

convertir les ewf en img raw avec `ewfexport disque.e0? et ensuite le monter` av

```text
$ ewfexport disque.e0?
$ sudo kpartx -av disque.raw
```

```text
$ sudo fdisk -l /dev/loop0 # ou sudo fdisk -l disque.raw
Disk /dev/loop0: 10 GiB, 10737418240 bytes, 20971520 sectors
Units: sectors of 1 * 512 = 512 bytes
Sector size (logical/physical): 512 bytes / 512 bytes
I/O size (minimum/optimal): 512 bytes / 512 bytes
Disklabel type: dos
Disk identifier: 0xb69e7b6d

Device       Boot   Start      End  Sectors  Size Id Type
/dev/loop0p1 *       2048   999423   997376  487M 83 Linux
/dev/loop0p2      1001470 20969471 19968002  9.5G  5 Extended
/dev/loop0p5      1001472 20969471 19968000  9.5G 83 Linux
```

```text
$ lsblk -o NAME,SIZE,TYPE,MOUNTPOINT,UUID,FSTYPE
NAME       SIZE TYPE MOUNTPOINT UUID                                 FSTYPE
loop0       10G loop                                                 
├─loop0p1  487M part            2a4d5e03-caa8-4070-ac62-dc42b0d8b82d ext2
├─loop0p2    1K part                                                 
└─loop0p5  9.5G part            e61a1da4-b95d-4df5-ab40-bbffc505b3f2 crypto_LUKS
sda         80G disk                                                 
├─sda1      79G part /          d1fa2eb5-318c-4a1f-879a-f230abf45cd3 ext4
├─sda2       1K part                                                 
└─sda5     975M part [SWAP]     76a2be20-235e-4abe-b906-35256de7e1e0 swap
sr0       1024M rom
```

```text
$ sudo blkid
/dev/sda1: UUID="d1fa2eb5-318c-4a1f-879a-f230abf45cd3" BLOCK_SIZE="4096" TYPE="ext4" PARTUUID="42136559-01"
/dev/sda5: UUID="76a2be20-235e-4abe-b906-35256de7e1e0" TYPE="swap" PARTUUID="42136559-05"
/dev/mapper/loop0p1: UUID="2a4d5e03-caa8-4070-ac62-dc42b0d8b82d" BLOCK_SIZE="1024" TYPE="ext2" PARTUUID="b69e7b6d-01"
/dev/mapper/loop0p5: UUID="e61a1da4-b95d-4df5-ab40-bbffc505b3f2" TYPE="crypto_LUKS" PARTUUID="b69e7b6d-05"
/dev/loop0: PTUUID="b69e7b6d" PTTYPE="dos"
```

```text
$ sudo xxd /dev/mapper/loop0p5 | head
00000000: 4c55 4b53 babe 0002 0000 0000 0000 4000  LUKS..........@.
00000010: 0000 0000 0000 0003 0000 0000 0000 0000  ................
00000020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000030: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000040: 0000 0000 0000 0000 7368 6132 3536 0000  ........sha256..
00000050: 0000 0000 0000 0000 0000 0000 0000 0000  ................
00000060: 0000 0000 0000 0000 8724 5f1f 736c eb8c  .........$_.sl..
00000070: dc4a 16e6 72f6 b32f b12c cb7c b9ed c4da  .J..r../.,.|....
00000080: 5ba3 3938 5137 88e1 2351 6e29 5878 306b  [.98Q7..#Qn)Xx0k
00000090: f0f9 1f03 04d6 5816 c8df d938 6b0f 00d1  ......X....8k...
```

```text
$ sudo xxd /dev/loop0 | grep -C 2 "LUKS" # ou sudo xxd disque.raw | grep -C 2 "LUKS"
00463250: 0a00 6261 6420 6469 6765 7374 0a00 536c  ..bad digest..Sl
00463260: 6f74 2025 6420 6f70 656e 6564 0a00 6163  ot %d opened..ac
00463270: 6365 7373 2064 656e 6965 6400 4c55 4b53  cess denied.LUKS
00463280: babe 0025 7320 213d 2025 730a 0043 6970  ...%s != %s..Cip
00463290: 6865 7220 2573 2069 736e 2774 2061 7661  her %s isn't ava
--
1e8fffe0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
1e8ffff0: 0000 0000 0000 0000 0000 0000 0000 0000  ................
1e900000: 4c55 4b53 babe 0002 0000 0000 0000 4000  LUKS..........@.
1e900010: 0000 0000 0000 0003 0000 0000 0000 0000  ................
1e900020: 0000 0000 0000 0000 0000 0000 0000 0000  ................
```

#### flag

```text
1e900000
FCSC{1e900000}
```

## Sources & Aides

