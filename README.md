# xiaomi/redmi ax router tool

cr660x is contributed by ericwang2006

Backup your mtd9(cr660x is mtd2)

`nanddump -f /tmp/bdata_mtd9.img /dev/mtd9`

Unlock the partition lock(automatic reboot)

`/tmp/mitool.sh unlock`

Set ssh/uart/telnet to enable and show the default username/password(automatic reboot and relock the partition lock)

`/tmp/mitool.sh hack`

Show password only

`/tmp/mitool.sh password`

Show model only

`/tmp/mitool.sh model`

Show sn only

`/tmp/mitool.sh sn`

set sn(automatic reboot and relock the partition lock)

`/tmp/mitool.sh setsn xxxxxxxxxxxxx`
