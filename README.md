# xiaomi/redmi ax router tool


Backup your mtd9

`nanddump -f /tmp/bdata_mtd9.img /dev/mtd9`

Unlock the partition lock(automatic reboot)

`/tmp/mitool unlock`

Set ssh/uart/telnet to enable and show the default username/password(automatic reboot and relock the partition lock)

`/tmp/mitool hack`

Show password only

`/tmp/mitool password`

Show model only

`/tmp/mitool model`
