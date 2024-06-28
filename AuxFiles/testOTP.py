#! /bin/bash
echo -n "NEVER   GONNA   GIVE   YOU   UP" > key.txt

xxd -p -c0 key.txt > key.hex

cat key.hex | wc -c

./ft_otp -g key.hex
Key was successfully saved in ft_otp.key.
./ft_otp -k ft_otp.key
# 836492
sleep 60
./ft_otp -k ft_otp.key



#For Python
echo -n "NEVER   GONNA   GIVE   YOU    UP" > key.txt

xxd -p -c0 key.txt > key.hex

cat key.hex | wc -c

~/Documents/myPython/venv/bin/python ft_otp.py -g key.hex
Key was successfully saved in ft_otp.key.
~/Documents/myPython/venv/bin/python ft_otp.py -k ft_otp.key
# 836492
sleep 60
~/Documents/myPython/venv/bin/python ft_otp.py -k ft_otp.key
