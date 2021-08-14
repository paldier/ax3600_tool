# xiaomi/redmi ax router tool


backup your mtd9

`nanddump -f /tmp/bdata_mtd9.img /dev/mtd9`

unlock the partition lock(automatic reboot)

`/tmp/mitool unlock`

set ssh/uart/telnet to enable and display the default username/password

`/tmp/mitool hack`

relock the partition lock, otherwise the wifi will not work normally(automatic reboot)

`/tmp/mitool lock`

show password only

`/tmp/mitool password`

show model only

`/tmp/mitool model`
