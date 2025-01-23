import PySimpleGUI as sg
import pyqrcode
import sys # to access the system
import cv2
import os
import datetime
import time
from cryptography.fernet import Fernet
import random
import base64
import secrets
from Crypto.Hash import SHA, HMAC
import hashlib
from hashlib import sha1, sha224, sha256, sha384, sha512
import hmac
import codecs
import math

import signal

def handler(signum, frame):
    print('Signal received, shutting down gracefully...')
    sys.exit(0)

signal.signal(signal.SIGTERM, handler)
signal.signal(signal.SIGINT, handler)

optionGSaveG  = False
optionKNewTokenG = False
keyHexFilePath = ""
secretKeyGlobal = None
gl_fernetKeyStandard = b'68usNvbZs_KIsyfdyDhPUyzin70bBpZttJjwYUxkp9U=asdwf'
fernetKeyG = None
inputKeyFilePath = None
inputPathG = ""

#New variables:
gl_helpBool = False
gl_userBool = False
gl_userString = ""
gl_accountBool = False
gl_accountString = ""
gl_digitsNumberBool = False
gl_digitsNumberInt = 6
gl_qrCodeBool = False
gl_hashOptBool = False
gl_hashOptSelInt = 1
gl_hashOptInputString = ""
gl_timeStepSecondBool = False
gl_timeStepSecondInt = 30
gl_continuousQRBool = False
gl_fernetParaphraseBool = False
gl_fernetParaphraseString = ""
gl_optionGUI = False

gl_QRPath = "myActQR.png"
gl_issuer = "LaRanaGustavo"

gl_wrongUserInput = False


def argumentsRead(*args,**kwargs):

    global keyHexFilePath, optionGSaveG, optionKNewTokenG, secretKeyGlobal, inputKeyFilePath, inputPathG


    global gl_helpBool, gl_userBool, gl_userString, gl_accountBool, gl_accountString, gl_digitsNumberBool, gl_digitsNumberInt, gl_qrCodeBool, gl_hashOptBool, gl_hashOptSelInt, gl_hashOptInputString, gl_timeStepSecondBool
    global gl_timeStepSecondInt, gl_continuousQRBool, gl_fernetParaphraseBool, gl_fernetParaphraseString, gl_fernetKeyStandard
    global gl_optionGUI
    global fernetKeyG

    gl_wrongUserInput = False
    gl_noMoreArgExpected = False

    newArgumentExpected = False
    fileArg = False
    actCounter = 0
    if(args):

        for counter, listVars in enumerate(args):

            counterVars = 0
            for el in listVars:


                #For the options of the program starting by "-"
                if(el.startswith("-")):

                    listEl = list(el)[1:]

                    #If there is more than one option selected return False because wrong input
                    #Maybe Out this if
                    #OLD VERSION
                    """
                    if(len(listEl)>1):
                        print("The input for the program is wrong, maximmum 1 option allowed per call.")
                        return False
                    """ 
                    for char in listEl:

                        if(newArgumentExpected == False):
							
                            #-g          --> Recieves as argument an hex key at least 64 characters long, which will be saved into a file named "ft_otp.key". This file will be always encryted.
                            if(char == "g"):
                                optionGSaveG = True
                                newArgumentExpected = True
                            #-k          --> The program generates a new temporal password (otp) and will show it into console.
                            elif(char == "k"):
                                optionKNewTokenG = True
                                newArgumentExpected = True
                            #-I          --> The program generates a Graphic User Interface (GUI) In order to change data dynamically.
                            elif(char == "I"):
                                gl_optionGUI = True
                                newArgumentExpected = True

                            #-h          --> specifies tha the help must be printed
                            elif(char == "h"):
                                gl_helpBool = True
                                gl_noMoreArgExpected = True

                            #-u          --> specifies the user for the creation of the QR code
                            elif(char == "u"):
                                gl_userBool = True
                                newArgumentExpected = True

                            #-a          --> specified the acount for the creation of the QR code
                            elif(char == "a"):
                                gl_accountBool = True
                                newArgumentExpected = True
                                
                            #-d          --> Specifies the number of digits of the One Time Password (from 6 to 12)
                            elif(char == "d"):
                                gl_digitsNumberBool = True
                                newArgumentExpected = True

                            #-Q          --> The program will generate a QR code with the needed information and show it into screen()
                            elif(char == "Q"):
                                gl_qrCodeBool = True

                            #-H         --> Specifies the hashing function used
                            elif(char == "H"):
                                gl_hashOptBool = True
                                newArgumentExpected = True

                            #-S          --> specifies time step in seconds (from 15 seconds to 10 min or 600 seconds)
                            elif(char == "S"):
                                gl_timeStepSecondBool = True
                                newArgumentExpected = True

                            #-f          --> specifies the paraphrase with the key is encrypted
                            elif(char == "f"):
                                gl_fernetParaphraseBool = True
                                newArgumentExpected = True

                            #-C          --> Continuous - shows a QR with a new calculated key everytime the key changes
                            elif(char == "C"):
                                gl_continuousQRBool = True
                                
                            else:
                                print("The input for the program is wrong, the option '", char , "' is not recognized")
                                gl_wrongUserInput = True
                                return False
                        else:
                            print("User input is NOT appropiate")
                            gl_wrongUserInput = True
                
                elif(newArgumentExpected  == True):
            
                    #depending on las char checked:
                    #-g          --> Recieves as argument an file with an hex key at least 64 characters long, which will be saved into a file named "ft_otp.key". This file will be always encryted.
                    if(char == "g" and optionGSaveG == True):
                        keyHexFilePath = el
                        inputPathG = el
                        
                    #-k          --> The program generates a new temporal password (otp) and will show it into console.
                    elif(char == "k"):
                        inputKeyFilePath = el
                        inputPathG = el

                    #-u          --> specifies the user for the creation of the QR code
                    elif(char == "u"):
                        gl_userString = el
                        
                    #-a          --> specified the acount for the creation of the QR code
                    elif(char == "a"):
                        gl_accountString = el
                        
                    #-d          --> Specifies the number of digits of the One Time Password (from 6 to 12)
                    elif(char == "d"):
                        try:    
                            gl_digitsNumberInt = int(el)
                            #Check the integer to be in range (6-12)
                            if (gl_digitsNumberInt > 12 or gl_digitsNumberInt < 6):
                                gl_wrongUserInput = True
                                print("The given integer for password lenght must be in te range [6-12]")
                        
                        except:
                            gl_wrongUserInput = True
                            print("The number of digits is not an integer")

                    #-H         --> Specifies the hashing function used
                    elif(char == "H"):
                        gl_hashOptInputString = el
                        
                    #-S          --> specifies time step in seconds (from 15 seconds to 10 min or 600 seconds, MUST BE AN INTEGER)
                    elif(char == "S"):
                        try:    
                            gl_timeStepSecondInt = int(el)

                            #Check the integer to be in range (6-12)
                            if (gl_timeStepSecondInt > 600 or gl_timeStepSecondInt < 15):
                                gl_wrongUserInput = True
                                print("The given integer for time step must be in te range [15-600]")
                        
                        except:
                            gl_wrongUserInput = True
                            print("The number of digits for the step is not an integer")

                    #-f          --> specifies the paraphrase with the key is encrypted
                    elif(char == "f"):
                        gl_fernetParaphraseString = el

                        if(len(gl_fernetParaphraseString) < 12):
                            gl_wrongUserInput = True
                            print("It is recommended to use a string of more than 32 character for encypting the key.hex file using fernet.")
                            print("The program will NOT run with shorter encryption keys, because security will be compromissed.")
                        
                    else:
                        print("The input for the program is wrong, the option '", char , "' is not recognized")
                        return False

                    newArgumentExpected = False

                else:
                    print("The user input is not correct.")
                    gl_wrongUserInput = True
                
                #For the path containing the key
                """elif (optionGSaveG ==  True):
                    keyHexFilePath = el
                    inputPathG = el
                elif (optionKNewTokenG ==  True):
                    inputKeyFilePath = el
                    inputPathG = el"""


    #Check if input file path with key exists and has a 64 hexadecimal characters key:
    if(optionKNewTokenG == True or optionGSaveG == True):
        if(os.path.exists(inputPathG)):

            with fileOutput(inputPathG, "r") as inputKeyFile:

                if(optionGSaveG == True):


                    secretKeyRead= inputKeyFile.read()

                    #If the secret key is 64 values
                    if(len(secretKeyRead) >= 64 and checkStrIsHex(secretKeyRead)):
                        #Check that all characters are in the hexadecimal range
                        secretKeyGlobal = secretKeyRead.lower()

                    else:
                        print("The secret key contained in the file is not at least a 64 characters hexadecimal value.")
                        print("Secret Key length : ", len(secretKeyRead))
                        print("Therefore the program will STOP")
                        return False

                elif(optionKNewTokenG == True):

                    if not len(keyHexFilePath) == 0 :
                        outputKeyFilePath = keyHexFilePath
                    else:
                        #Declare the file path
                        outputKeyFilePath = "./ft_otp.key"

                """
                elif(optionGOldKeyG == True):

                    if not len(keyHexFilePath) == 0 :
                        inputKeyFilePath = keyHexFilePath
                    else:
                        #Declare the file path
                        inputKeyFilePath = "./ft_otp.key"
                """
        else:
            print("The given path does not exists. Given path : ", keyHexFilePath)
            gl_wrongUserInput = True
            return False

    if(gl_hashOptBool == True):

        if(gl_hashOptInputString == "sha1" or gl_hashOptInputString == "1"):
            gl_hashOptSelInt = 1
        elif(gl_hashOptInputString == "sha224" or gl_hashOptInputString == "2"):
            gl_hashOptSelInt = 2
        elif(gl_hashOptInputString == "sha256" or gl_hashOptInputString == "3"):
            gl_hashOptSelInt = 3
        elif(gl_hashOptInputString == "sha384" or gl_hashOptInputString == "4"):
            gl_hashOptSelInt = 4
        elif(gl_hashOptInputString == "sha512" or gl_hashOptInputString == "5"):
            gl_hashOptSelInt = 5
        else:
            print("Wrong Hash Parameter for the flag -H")
            gl_wrongUserInput = True
    else:
        gl_hashOptSelInt = 1
    
    #-d          --> Specifies the number of digits of the One Time Password (from 6 to 12)
    #If number of digits is not specified set as standard 6
    if(gl_digitsNumberBool == False):
        gl_digitsNumberInt = 6

    #-S          --> specifies time step in seconds (from 15 seconds to 10 min or 600 seconds, MUST BE AN INTEGER)
    #If timeStep is not specified set as standard 30
    if(gl_timeStepSecondBool ==  False):
        gl_timeStepSecondInt = 30

    #-f          --> specifies the paraphrase with the key is encrypted
    #If fernet key is not given use a hard coded paraphrase
    if(gl_fernetParaphraseBool == False):
        fernetKeyG = gl_fernetKeyStandard

    #If fernet key is given use the user input fernet key
    #It will never call the if (for future version maintain code)
    else:
        keyAux = gl_fernetParaphraseString.encode("utf-8")

        while len(keyAux)<32 :
            keyAux += keyAux

        fernetKeyG = base64.urlsafe_b64encode(keyAux[:32])

    if(gl_wrongUserInput == True):
        return False

    return True



def checkStrIsHex(inputHex):
	
    hexValues = ["0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"]
    inputHexAux = inputHex.lower()
    inputHexAuxList = list(inputHexAux)

    try:
        int(inputHex, 16)
        return True
    except Exception as error:
        return False



#Class for file creation for output data
class fileOutput(object):

    def __init__(self, filename, method):
        self.method = method
        try:
            self.filename = filename
            #print("File is open:", filename, self.method)
            #return True
        except:
            print("It was not possible to open the file :", filename, "In the mode", method)
            #return False
        return None

    def __enter__(self):
        try:
            self.file_obj= open(self.filename, self.method)
            return self.file_obj
        except Exception as e:
            print("Exception: ",e)


    def __exit__(self, type, value, traceback):
        self.file_obj.close()
        #print("Exit Object")
        #print(Exception)
        return False

    def writeLine(self, strLine):
        try:
            self.file_obj.write(strLine)
            return True
        except:
            print("It was not possible to write into the file")
            return False

    def myRead(self):
        myLecture = self.file_obj.read()
        return myLecture


def get_T_Int(inputUnixTime0, stepIntSec):
    """ 
    This function gives the Unix time  in time steps using the following equation:
        T = (Current Unix Time - T0)/ X
            where:
            T --> Value to return
            Current Unix Time --> System parameter corresponding to the Unix Time since Unix epoch
            T0 --> Unix Time to start counting time steps (default = 0 correspinding to the Unix Epoch)
            X --> Time step in seconds, normally X=30 s is used.
    """

    if not isinstance(inputUnixTime0, int):
        print("ERROR - In get_T_Int - Error: inputUnixTime0 MUST BE an integer")
        return False

    if not isinstance(stepIntSec, (int, float)):
        print("ERROR - In get_T_Int - Error: stepIntSec MUST BE an integer OR a float")
        return False

    try:
        date_time = datetime.datetime.now()
        unixTime = time.mktime(date_time.timetuple())
        T_Output = ( unixTime - inputUnixTime0 ) / stepIntSec
        T_Output = math.floor(T_Output)
    except Exception as error:
        print("ERROR -  IN get_T_Int - Exception: ", error)
        return False

    return T_Output


def convertToHex(inputInt):
    """This function convert an integer to an hexadecimal number"""

    if not isinstance(inputInt, int):
        print("ERROR - In convertToHex - This function only allows integers as input.")
        return False

    hexOutput = hex(inputInt)

    return hexOutput


def convertTo32B(inputHex):

    myByteArray = bytearray.fromhex(inputHex)
    outputList = base64.b32encode(myByteArray)

    return outputList


def getLast4BitsInt(inputHex):
    lengthAux = len(inputHex)

    importantBits = inputHex[lengthAux-1]
    outputInt = int(importantBits, 16)

    return outputInt


def getBytesByOffset( inputHex, inputOffset):

    if not isinstance(inputOffset,int):
        print("The offset must be an integer")
        return False

    first =   inputOffset*2
    second =   (inputOffset+4)*2
    selectedHexs = inputHex[first:second]
    
    return selectedHexs


def operateHexNumbers(inputHex):
    
    if(len(inputHex) != 8):
        print("The given hexadecimat value is not of correct length")
        return False

    firstVal= int(inputHex[0:2],16)
    secondVal= int(inputHex[2:4],16)
    thirdVal= int(inputHex[4:6],16)
    fourthVal= int(inputHex[6:8],16)

    outputStringHex = format(firstVal,'02x') +format(secondVal) +  format(thirdVal, '02x') +format(fourthVal, '02x')
    firstValOper = firstVal & int("7f",16)
    secondValOper = secondVal & int("ff",16)
    thirdValOper = thirdVal & int("ff",16)
    fourthValOper = fourthVal & int("ff",16)

    outputStringHex = format(firstValOper,'02x') +format(secondValOper, '02x') +  format(thirdValOper, '02x') +format(fourthValOper, '02x')
    
    return outputStringHex


def calculateToken(intInput, n):
    token = intInput % 10**n
    stringToken = f'{token:0n}'

    return stringToken


def makeOTP(secretKeyB32, timeStepInt):
    """ 
    Generates the OTP using the hash function sha1
    This funtion only receives a shared secret key in base32 format.
    It uses the system time in order to calculate the OTP, wich gives in base32 format	
    """
    global gl_hashOptSelInt, gl_digitsNumberInt

    #1. Convert the timeStepInt into an hexadecimal
    hexTimeSteps = convertToHex(timeStepInt)
    #2. Padd the hetTimeSteps in order to obtain a constant length variable of 20
    hexTimePadded = hexTimeSteps[2:].zfill(16)
    #* Convert hexTimePadded into a 8 bytes array
    prefixHexTimePadded = "0x"+hexTimePadded
    timeBytesArray = bytearray.fromhex(hexTimePadded)
    message = timeBytesArray
    #*Convert the Base 32 secret key into a 20 bytes array and call it K
    decodedB32SecretKey = base64.b32decode(secretKeyB32)
    #Bytes to string Hex
    bytesSecretKey = decodedB32SecretKey.hex()
    secretKeyBytesArray = bytearray.fromhex(bytesSecretKey)
    #3. Call to the Hash function in order to create the token
    #sha1
    if(gl_hashOptSelInt == 1):
        myHMAC = hmac.new(secretKeyBytesArray, message, hashlib.sha1)
    #sha224
    elif(gl_hashOptSelInt == 2):
        myHMAC = hmac.new(secretKeyBytesArray, message, hashlib.sha224)
    #sha256
    elif(gl_hashOptSelInt == 3):
        myHMAC = hmac.new(secretKeyBytesArray, message, hashlib.sha256)
    #sha384
    elif(gl_hashOptSelInt == 4):
        myHMAC = hmac.new(secretKeyBytesArray, message, hashlib.sha384)
    #sha512
    elif(gl_hashOptSelInt == 5):
        myHMAC = hmac.new(secretKeyBytesArray, message, hashlib.sha512)

    #4. Save the given hash in a variable:
    hexHashHMACH = myHMAC.hexdigest()
    #Calculate the token
    #5. From the hash take the offset from the last 4 bites
    offsetToken = getLast4BitsInt(hexHashHMACH)
    #6. Select 4 bytes by ofset
    selHex = getBytesByOffset( hexHashHMACH, offsetToken)
    #7. Operate the selected Hex in order to obtain a number
    hexValue = operateHexNumbers(selHex)
    #8. Calculate the token or OTP with the hexValue
    tokenStr = calculateToken(int(hexValue,16), gl_digitsNumberInt)


    return tokenStr


def PrintProgramGlobalVariables():
    """ 
    PrintProgramGlobalVariables is a function that prints the program global variables into console in order to debug the program.
    """
    global keyHexFilePath, optionGSaveG, optionKNewTokenG, secretKeyGlobal, inputKeyFilePath, inputPathG
    global gl_helpBool, gl_userBool, gl_userString, gl_accountBool, gl_accountString, gl_digitsNumberBool, gl_digitsNumberInt, gl_qrCodeBool, gl_hashOptBool, gl_hashOptSelInt, gl_hashOptInputString, gl_timeStepSecondBool
    global gl_timeStepSecondInt, gl_continuousQRBool, gl_fernetParaphraseBool, gl_fernetParaphraseString

    strAux = "optionGSaveG = " + str(optionGSaveG) + "\n"
    strAux += "optionKNewTokenG = " + str(optionKNewTokenG) + "\n"

    strAux += "keyHexFilePath = " + str(keyHexFilePath) + "\n"
    strAux += "secretKeyGlobal = " + str(secretKeyGlobal) + "\n"
    strAux += "fernetKeyG = " + str(fernetKeyG) + "\n"
    strAux += "inputKeyFilePath = " + str(inputKeyFilePath) + "\n"
    strAux += "inputPathG = " + str(inputPathG) + "\n"

    strAux += "gl_helpBool = " + str(gl_helpBool) + "\n"
    strAux += "gl_userBool = " + str(gl_userBool) + "\n"
    strAux += "gl_userString = " + str(gl_userString) + "\n"
    strAux += "gl_accountBool = " + str(gl_accountBool) + "\n"
    strAux += "gl_accountString = " + str(gl_accountString) + "\n"

    strAux += "gl_digitsNumberBool = " + str(gl_digitsNumberBool) + "\n"
    strAux += "gl_digitsNumberInt = " + str(gl_digitsNumberInt) + "\n"
    strAux += "gl_qrCodeBool = " + str(gl_qrCodeBool) + "\n"
    strAux += "gl_hashOptBool = " + str(gl_hashOptBool) + "\n"
    strAux += "gl_hashOptSelInt = " + str(gl_hashOptSelInt) + "\n"

    strAux += "gl_hashOptInputString = " + str(gl_hashOptInputString) + "\n"
    strAux += "gl_timeStepSecondBool = " + str(gl_timeStepSecondBool) + "\n"
    strAux += "gl_timeStepSecondInt = " + str(gl_timeStepSecondInt) + "\n"
    strAux += "gl_continuousQRBool = " + str(gl_continuousQRBool) + "\n"
    strAux += "gl_fernetParaphraseBool = " + str(gl_fernetParaphraseBool) + "\n"

    strAux += "gl_fernetParaphraseString = " + str(gl_fernetParaphraseString) + "\n"
    strAux += "gl_wrongUserInput = " + str(gl_wrongUserInput) + "\n"

    print(strAux)



def PrintProgramHelp():
    """
    PrintProgramHelp is a function that prints into console the program help and some author notes.
    """
    
    auxStr = """
    Program Name - fto_otp
    Program Version - 0.001

    ft_otp program is used in order to generate a One Time Password follwing rfc6238 standard (https://datatracker.ietf.org/doc/html/rfc6238)
    
    The options/flags of the program are the following:

        -g          --> Recieves as argument an hex key at least 64 characters long, which will be saved into a file named "ft_otp.key". This file will be always encryted.
        -k          --> The program generates a new temporal password (otp) and will show it into console.

    ToDo
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

        ADD MORE EXAMPLES

    ToDo for version 0.002
        - Clean code, improve functions descriptions, comment and change variables and function names to follow standards
        - Add Simple GUI (Not just showing QR with info) with all possible inputs and showing QR (flag -I)
        - Brute Force Function (discover Hex Key with all values given) [Is it even possible?]
        - Reversed OTP Function (not Brute force) (fully understand otp and reverse engineer the hex key) [Is it even possible?]
    """

    print(auxStr)



def ShowQRCode(secretKeyBase32Str):

    global gl_QRPath, gl_issuer
    
    try:
        stringQRAux = "otpauth://totp/"+gl_userString+":"+gl_accountString+"?secret="+secretKeyBase32Str+"&issuer="+gl_issuer
        url = pyqrcode.create(stringQRAux)
        url.png(gl_QRPath, scale = 7)
        imgQR = cv2.imread(gl_QRPath, cv2.IMREAD_ANYCOLOR)
        cv2.startWindowThread()
        cv2.namedWindow("preview")
        cv2.imshow("QR", imgQR)
        
        # Use a loop to periodically check for termination signals
        while True:
            key = cv2.waitKey(100)  # Wait 100ms and check for termination
            if key != -1:  # If any key is pressed, exit
                break
            time.sleep(0.1)

        cv2.destroyAllWindows()


    except Exception as e:
        print("Error while doing the QR Code")
        print("Exxception: ", e)
        return False


def ComputeQRCode(secretKeyBase32Str):
    
    global gl_QRPath, gl_issuer
    
    try:
        stringQRAux = "otpauth://totp/"+gl_userString+":"+gl_accountString+"?secret="+secretKeyBase32Str+"&issuer="+gl_issuer
        url = pyqrcode.create(stringQRAux)
        url.png(gl_QRPath, scale = 7)
        imgQR = cv2.imread(gl_QRPath, cv2.IMREAD_ANYCOLOR)

    except Exception as e:
        print("Error while doing the QR Code")
        print("Exxception: ", e)
        return False


def otpGUI():
	"""
	function used in order to use the Graphical User Interface
	"""
	
	global gl_QRPath
	global gl_issuer, gl_userString, gl_accountString, gl_timeStepSecondInt, gl_digitsNumberInt, gl_hashOptSelInt
	global gl_decryptedKey32B

	sectionOTP =  [						
						[sg.Text('Hexadecimal Key'), sg.Push()],
						[sg.Multiline( default_text=gl_decryptedKey32B , key='-HEXKEY-', expand_x=True, expand_y=True, enable_events=True), sg.Push()],
						
						[sg.Text('Time Step [s] (tipical 30s)'), sg.Push()],
						[sg.Input(default_text=gl_timeStepSecondInt, key='-TIMESTEP-', expand_x=True, expand_y=True, enable_events=True), sg.Push()],
						
						[sg.Text('Number Of Digits'), sg.Push()],
						[sg.Slider(range=(6,12), default_value=6, size=(40,15), orientation='horizontal', key='-NUMDIGITS-', enable_events=True),  sg.Push()],
						
						[sg.Text('Hashing Method'), sg.Push()],
						[sg.R(f'SHA1', 1, key='-SHA1-', default=True, enable_events=True), sg.Push()],
						[sg.R(f'SHA224', 1, key='-SHA224-', enable_events=True), sg.Push()],
						[sg.R(f'SH256', 1,  key='-SHA256-', enable_events=True),  sg.Push()],
						[sg.R(f'SHA384', 1, key='-SHA384-', enable_events=True),  sg.Push()],
						[sg.R(f'SHA512', 1, key='-SHA512-', enable_events=True), sg.Push()], 
						 
						[sg.Push(),sg.Text('OTP - One Time Password'), sg.Push()],
						[sg.Push(),sg.Text( key='-OTP-', font=("Calibri", 34), enable_events=True), sg.Push()],
						[sg.Push(),sg.Button('Compute OTP'), sg.Push()],
					]
   
	sectionQR = [
					[sg.VPush()],
					[sg.Text('Issuer'), sg.Push()],
					[sg.Input(key='-ISSUER-',default_text=gl_issuer,size=(40,15), enable_events=True), sg.Push()],
					
					[sg.Text('User'),  sg.Push()],
					[sg.Input(key='-USER-',default_text=gl_userString,size=(40,15), enable_events=True), sg.Push()],
					
					[sg.Text('Account'),  sg.Push()],
					[sg.Input(key='-ACCOUNT-',default_text=gl_accountString,size=(40,15), enable_events=True),  sg.Push()],
					
					[sg.VPush()],
					[sg.Push(),sg.Text('QR To Scan'),  sg.Push()],
					[ sg.Push(), sg.Image(filename=gl_QRPath, key='-IMAGE-', enable_events=True, subsample=2), sg.Push()]
				]
	
	sectionErrors = [
						[sg.Text('ERRORS'),  sg.Push()],
						[sg.Input(key='-ERRORS-',default_text='NO ERRORS', expand_x=True, expand_y=True)]
					]
				

	layout = [[ sg.Frame('QR Section' ,sectionQR, element_justification='r', expand_x=True, expand_y=True), 
			sg.Frame('OTP Section', sectionOTP, element_justification='r', expand_x=True, expand_y=True) ],
			[sg.Frame('Errors:' ,sectionErrors, element_justification='center', expand_x=True)],
			[sg.VPush(), sg.Sizegrip()]    
			]
	
	# Create the window
	window = sg.Window("OTP - One Time Password Generator", layout, resizable=True)

	# Create an event loop
	while True:
		event, values = window.read()
		# End program if user closes window or
		# presses the OK button
		if event == "OK" or event == sg.WIN_CLOSED or event == 'Exit':
			break

		try:
			
			if values['-SHA1-'] == True :
				gl_hashOptSelInt = 1
			elif values['-SHA224-'] == True :
				gl_hashOptSelInt = 2
			elif values['-SHA256-'] == True :
				gl_hashOptSelInt = 3
			elif values['-SHA384-'] == True :
				gl_hashOptSelInt = 4
			elif values['-SHA512-'] == True :
				gl_hashOptSelInt = 5
			gl_digitsNumberInt = int(values['-NUMDIGITS-'])
			gl_issuer = values['-ISSUER-']
			gl_userString = values['-USER-']
			gl_accountString = values['-ACCOUNT-']
			gl_decryptedKey32B = values['-HEXKEY-'].replace(" ","").encode()
			gl_timeStepSecondInt = int(values['-TIMESTEP-'])
			
			timeStepsInt = get_T_Int(0,gl_timeStepSecondInt)
			
			newOTP =  makeOTP(gl_decryptedKey32B, timeStepsInt)
			myPaddedOTP = newOTP.zfill(gl_digitsNumberInt)
			QRBool = ComputeQRCode(gl_decryptedKey32B.decode())
			
			window['-OTP-'].update(myPaddedOTP)
			window['-IMAGE-'].update(filename=gl_QRPath, subsample=2)
			
			window['-ERRORS-'].update('NO ERRORS')
			window.refresh()
			window.read()
			
		except Exception as e:
			window['-ERRORS-'].update(e)


	window.close()



if __name__==  "__main__":
    """
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
    

    ToDo for version 0.002
        - Clean code, improve functions descriptions, comment and change variables and function names to follow standards
        - Add Simple GUI (Not just showing QR with info) with all possible inputs and showing QR (flag -I)
        - Brute Force Function (discover Hex Key with all values given) [Is it even possible?]
        - Reversed OTP Function (not Brute force) (fully understand otp and reverse engineer the hex key) [Is it even possible?]
    """


    if(argumentsRead(sys.argv[1:]) and gl_helpBool == False):

        #PrintProgramGlobalVariables()

        #If the program is called in order to save the private key
        if(optionGSaveG ==  True and gl_optionGUI == False):

            #Encrypt the given key
            myFernet = Fernet(fernetKeyG)

            #Encrypt the file with a constant fernet key
            encryptedKey = myFernet.encrypt(secretKeyGlobal.encode())

            #Save the ecnrypted key in the ft_otp_key file:
            #Declare the file path
            outputKeyFilePath = "./ft_otp.key"
            with fileOutput(outputKeyFilePath, "w+") as outputKeyFile:
                outputKeyFile.write(str(encryptedKey.hex()))

            print("The encrypted key has been saved in the path:",outputKeyFilePath)
            print("The key was: ",secretKeyGlobal)
            
		#If the program is called in order to show a GUI
        elif(gl_optionGUI == True):
            with fileOutput(inputKeyFilePath, "r") as inputKeyFile:
                encryptedKeyInputHex = inputKeyFile.read()

            BytesEncryptedKeyInput = bytes.fromhex(encryptedKeyInputHex)
            #Create an isntance of a fermet object with the global encryption key to decrypt the secret Key
            myFernet = Fernet(fernetKeyG)
            gl_decryptedKey = myFernet.decrypt(BytesEncryptedKeyInput).hex()#.decode()
            gl_decryptedKey32B = convertTo32B(gl_decryptedKey).decode('utf-8')
            #Open GUI Mode
            otpGUI()

        #If the program is called in order to give another OTP
        elif(optionKNewTokenG == True):
            with fileOutput(inputKeyFilePath, "r") as inputKeyFile:
                encryptedKeyInputHex = inputKeyFile.read()

            BytesEncryptedKeyInput = bytes.fromhex(encryptedKeyInputHex)
            #Create an isntance of a fermet object with the global encryption key to decrypt the secret Key
            myFernet = Fernet(fernetKeyG)
            decryptedKey = myFernet.decrypt(BytesEncryptedKeyInput).hex()#.decode()

            #Call the OTP creaetion token in order to give an OTP
            #Convert the secretKey to 32 Base:
            decryptedKey32B = convertTo32B(decryptedKey)
            #Obtain the Unix time steps:
            timeStepsInt = get_T_Int(0,gl_timeStepSecondInt)
            #CAll the function that make the otp:
            myOTP = makeOTP(decryptedKey32B, timeStepsInt)
            #Padded the OTP in order to have 6 ziffers:
            myPaddedOTP = myOTP.zfill(gl_digitsNumberInt)
            #Print the OTP into console
            print("SecretKey Base 32 STR = ", decryptedKey32B.decode())
            print("My OTP is : ", myPaddedOTP)
            ShowQRCode(decryptedKey32B.decode())

    else:
        #Here I still print global variables for Debugging
        PrintProgramGlobalVariables()
        PrintProgramHelp()
