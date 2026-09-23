sed -i 's/getprogname()/"file2c"/g' /root/sluraproj/slurabsd/usr.bin/file2c/file2c.c
cc -o /usr/bin/file2c /root/sluraproj/slurabsd/usr.bin/file2c/file2c.c
echo "file2c compiled and installed"
