# ax3600_tool


backup your mtd9

`nanddump -f /tmp/bdata_mtd9.img /dev/mtd9`

unlock the partition lock(automatic reboot)

`/tmp/fuckax3600 unlock`

set ssh/uart/telnet to enable and display the default username/password

`/tmp/fuckax3600 hack`

relock the partition lock, otherwise the wifi will not work normally(automatic reboot)

`/tmp/fuckax3600 lock`

show password only

`/tmp/fuckax3600 password`
