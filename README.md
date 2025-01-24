# ㊙️ OTP - One Time Password

*Resumen: Nada es para siempre, decían tus ojos tristes.*

En este proyecto, el objetivo es implementar un sistema de TOTP (Time-based One-Time Password), que sea capaz de generar contraseñas efímeras a partir de una clave
maestra.\
Estará basado en el RFC: https://datatracker.ietf.org/doc/html/rfc6238, por lo
que podrías utilizarlo en tu día a día.\


## ❗ Parte Obligatoria:

En el lenguaje de tu elección, debes implementar un programa que permita registrar una clave inicial, y sea capaz de generar una nueva contraseña cada vez que se solicite.
Puedes utilizar cualquier librería que facilite la implementación del algoritmo, siempre que no hagan el trabajo sucio, es decir, queda terminantemente prohibido hacer uso de cualquier librería TOTP. Por supuesto, puedes y debes hacer uso de alguna librería o
función que te permita acceder al tiempo del sistema.
Un ejemplo del uso del programa sería:\
• El programa deberá llamarse ft_otp.\
• Con la opción -g , el programa recibirá como argumento una clave hexadecimal de al menos 64 caracteres. El programa guardará a buen recaudo esta clave en un archivo llamado ft_otp.key, que estará cifrado en todo momento.\
• Con la opción -k, el programa generará una nueva contraseña temporal y la mostrará en la salida estándar.\

```bash
$ echo -n "NEVER GONNA GIVE YOU UP" > key.txt
$ ./ft_otp -g key.txt
./ft_otp: error: key must be 64 hexadecimal characters.
$ xxd -p key.txt > key.hex
$ cat key.hex | wc -c
64
$ ./ft_otp -g key.hex
Key was successfully saved in ft_otp.key.
$ ./ft_otp -k ft_otp.key
836492
$ sleep 60
$ ./ft_otp -k ft_otp.key
123518
```
- Easy run it
```
echo -n "NEVER GONNA    GIVE    YOU   UP" > key.txt
cat key.txt | wc -c
xxd -p key.txt > key.hex
cat key.hex | wc -c
python3 ft_otp.py -g key.hex
python3 ft_otp.py -k ft_otp.key
sleep 60
python3 ft_otp.py -k ft_otp.key
python3  ft_otp.py -k ft_otp.key -u MarioGG -a ggmario93@gmail.com -d 7 -H 4 -S 45 -f AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaaaaaaaaaaaaaaa -QC
```

Puedes comprobar si tu programa funciona correctamente comparando las contraseñas
generadas con Oathtool o cualquier herramienta de tu elección.


## ➕ Parte Bonus

La evaluación de los bonus se hará SI Y SOLO SI la parte obligatoria es PERFECTA.\
De lo contrario, los bonus serán totalmente IGNORADOS.
Puedes mejorar tu proyecto con las siguientes características:\
• Permitir escoger la contraseña de cifrado de la clave maestra ft_otp.key y solicitarla cada vez que se genere una contraseña temporal nueva.
• Desarrollar un cliente que genere la contraseña maestra y valide los resultados con una interfaz gráfica.\
• Cualquier otra característica que consideres útil. Tus compañeros juzgarán si lo es realmente.\



# ㊗️ My OTP 

## ❓ Help of the program

In order to see the help of the ft_otp program:
```bash
python3 ft_otp.py -h
```

Or using a virtual environment:
```bash
~/Documents/myPython/venv/bin/python ft_otp.py -h
```

The help is as follows:
```
 Program Name - fto_otp
    Program Version - 0.001

    ft_otp program is used in order to generate a One Time Password follwing rfc6238 standard (https://datatracker.ietf.org/doc/html/rfc6238)
    
    The options/flags of the program are the following:

        -g          --> Recieves as argument an hex key at least 64 characters long, which will be saved into a file named "ft_otp.key". This file will be always encryted.
        -k          --> The program generates a new temporal password (otp) and will show it into console.
        -h          --> specifies tha the help must be printed
        -u          --> specifies the user for the creation of the QR code
        -a          --> specified the acount for the creation of the QR code
        -d          --> Specifies the number of digits of the One Time Password (from 6 to 12)
        -Q          --> The program will generate a QR code with the needed information and show it into screen()
        -H         --> Specifies the hashing function used
            Values of -e argument can be:
                1 --> sha1
                2 --> sha224
                3 --> sha256
                4 --> sha384
                5 --> sha512
        -S          --> specifies time step in seconds (from 15 seconds to 10 min or 600 seconds)
    
    Use Examples:

        $ echo -n "NEVER GONNA GIVE YOU UP" > key.txt
        $ ./ft_otp -g key.txt
        ./ft_otp: error: key must be 64 hexadecimal characters.
        $ xxd -p key.txt > key.hex
        $ cat key.hex | wc -c
        64
        $ ./ft_otp -g key.hex
        Key was successfully saved in ft_otp.key.
        $ ./ft_otp -k ft_otp.key
        836492
        $ sleep 60
        $ ./ft_otp -k ft_otp.key
        123518  
```

## 🔨 Setup [Without Docker] - Previous Installation 

```bash
pip install pycrypto
pip install pyqrcode
pip install opencv-python
pip install cryptography
pip install pypng
pip  install pysimplegui
```

Or using virtual environment:

```bash
~/Documents/myPython/venv/bin/pip install pycrypto
~/Documents/myPython/venv/bin/pip  install pyqrcode
~/Documents/myPython/venv/bin/pip install opencv-python
~/Documents/myPython/venv/bin/pip  install cryptography
~/Documents/myPython/venv/bin/pip  install pypng
~/Documents/myPython/venv/bin/pip  install pysimplegui
~/Documents/myPython/venv/bin/pip  install tkinter
```

Install dependencies in Linux:
```bash
apt-get install python3-tk
```

## 🔧 Setup [Docker]

1. Build the Dockerfile using the docker-compose.yml

- In the root folder of the project:
```
docker-compose up
```

2. Allow communication with the X11 Host GUI in order to see the GUI and be able to run the program from Docker
- In the host system run (Debian based OSs)
```
xhost +local:
```

3. Now you can run the program from the Docker container!



## 🎯 Tests

### In the virtual environment

```bash
~/Documents/myPython/venv/bin/python ft_otp.py -h
```

```bash
echo -n "NEVER GONNA GIVE YOU UP" > key.txt
xxd -p key.txt > key.hex
python3 ft_otp.py -g key.hex
cat key.hex | wc -c
python3 ft_otp.py -k ft_otp.key 
```

```bash
python3 ft_otp.py -g key.hex -f AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABB
python3 ft_otp.py -k ft_otp.key  -f AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABB
oathtool –totp $(cat key.hex)
```

### In Docker Container
```
echo -n "NEVER   GONNA   GIVE   YOU    UP" > key.txt
xxd -p -c0 key.txt > key.hex
cat key.hex | wc -c
python ft_otp.py -g key.hex
sleep 60
python ft_otp.py -k ft_otp.key
python ft_otp.py -k ft_otp.key -I
```

## Examples

```bash
python3 ft_otp.py -k ft_otp.key -u MyUser -a mymail@mail.com -d 7 -H 4 -S 45 -f AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaaaaaaaaaaaaaaa -QC
```

Or using python virtual environment:
```bash
~/Documents/myPython/venv/bin/python  ft_otp.py -k ft_otp.key -u MyUser -a mymail@mail.com  -d 7 -H 4 -S 45 -f AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaaaaaaaaaaaaaaa -QC
```

## Use example:
```bash
echo -n "NEVER GONNA GIVE YOU UP" > key.txt && \
xxd -p key.txt > key.hex  && \
~/Documents/myPython/venv/bin/python  ft_otp.py -g key.hex  && \
cat key.hex | wc -c  && \
~/Documents/myPython/venv/bin/python  ft_otp.py -k ft_otp.key -I
```

## 📚 Sources
- [RFC 6238 - TOTP: Time-Based One-Time Password Algorithm](https://datatracker.ietf.org/doc/html/rfc6238)
- [Python 3 - Official Documentation](https://docs.python.org/3/)
- [SympleGUI - Python Library- Official Documentation](https://docs.pysimplegui.com/en/latest/)


## 📜  ToDo - Version 0.002

- [ ] Fix BUG: Not possible to call GUI with flag -I at the first attempt, must call with -k first to create the QR file.
- [ ] Clean & Improve README for new structure and Docker Installation with ALL working examples
- [ ] Add Photo GUI to Readme
- [ ] Imrpove Testing For the program.
- [ ] Clean code, improve functions descriptions, comment and change variables and function names to follow standards
- [ ] Add Simple GUI (Not just showing QR with info) with all possible inputs and showing QR (flag -I)
- [ ] Brute Force Function (discover Hex Key with all values given) [Is it even possible?]
- [ ] Reversed OTP Function (not Brute force) (fully understand otp and reverse engineer the hex key) [Is it even possible?]
- [ ] Check All HASH options (sadly did not find a source to check them oathtool does not want to work in my computer)
- [ ] WebSite with All Parameters and working "off-line" written in javascript















