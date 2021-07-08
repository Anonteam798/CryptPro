__author__: "MrRobot"
import sys, time, os
try:
    import argparse as arg 
    from Crypto.Cipher import AES  
    from Crypto.Hash import SHA256 
    from Crypto import Random 
    from colorama import * 
    from cowsay import *
    #import getpass as gt

except Exception as e:
    print("\n====== Porfavor ejecuta el comando: ======\n\t ** pip install -r requirements.txt **")
    sys.exit() 

init(autoreset=True)

#Establecer colores
green = Fore.GREEN
red = Fore.RED
purpura = Fore.MAGENTA
amarillo = Fore.YELLOW
##################################################
parse = arg.ArgumentParser(description="Reverse String")

parse.add_argument("-f","--file",
                    help="Ruta del fichero",
                    type = str,
                    default = None)
parse.add_argument(
                    "-m", "--mode", help="Cipher Mode [c = crypt, d= decrypt]",
                    type = str,
                    default = None)
parse = parse.parse_args()
##################################################

#clase principal del Script
class CryptoPro:
    def __init__(self, passw_):
        self.password = passw_

    #se genera un haash de la contraseña
    def establish_pasword(self):
        p = SHA256.new(self.password.encode("utf-8"))
        return p.digest()
    ##################################################
    #Se rellena con bytes a los datos del fichero para el bloque de 16bytes
    def padding_data(self, data):
        return data+ b"\0" * (AES.block_size - len(data) % AES.block_size) 
    ##################################################
    #Funcion principal para encriptar los ficheros
    def encrypt_data(self,key,clean_data):
        #Rellenar los datos
        complete_block_data = self.padding_data(clean_data)
        # Establecer el vector inicializante
        iv = Random.new().read(AES.block_size)
        # Iniciar el cifrado
        cipher = AES.new(key, AES.MODE_CBC, iv)
        # Armar el cifrado de los datos
        cipher_data = iv + cipher.encrypt(complete_block_data)
        #retornar los datos cifrados
        return cipher_data 
    ##################################################
    def decrypt_data(self,key, cipher_data):
        #Buscar el vector
        iv = cipher_data[:AES.block_size]
        #Crear una instancia de AES 
        decipher = AES.new(key, AES.MODE_CBC, iv)
        #Descifrar datos 
        clear_data =  decipher.decrypt(cipher_data[AES.block_size:])
        #Retornar los datos decifrados
        return clear_data.rstrip(b"\0")
    ##################################################
    #Funcion que decubre los ficheros de un directorio 
    def discover_files(self, path):
        tpaths = []
        for abs_path, sub_path, files in os.walk(path):
            for file in files:
                tpaths.append(os.path.join(abs_path, file))
        if tpaths == []:
            return path, False
        else:
            return tpaths, True

if __name__ == "__main__":
    print(green + "\t\t       ___                 _            ___             __           _       _   ")
    print(green + "\t\t      / __\ __ _   _ _ __ | |_ ___     / _ \_ __ ___   / _\ ___ _ __(_)_ __ | |_ ")
    print(green + "\t\t     / / | '__| | | | '_ \| __/ _ \   / /_)/ '__/ _ \  \ \ / __| '__| | '_ \| __|")
    print(green + "\t\t    / /__| |  | |_| | |_) | || (_) | / ___/| | | (_) | _\ \ (__| |  | | |_) | |_ ")
    print(green + "\t\t    \____/_|   \__, | .__/ \__\___/  \/    |_|  \___/  \__/\___|_|  |_| .__/ \__|")
    print(green + "\t\t               |___/|_|                                               |_|        ")
    print(red + "                                                            ||= Developed by MrROBOT =||\n")

    if parse.file == None and parse.mode == None:
        print(green + " ::===============================================================::")
        print(green + " ||        Cifra tu archivo de rapidamente con CryptoPro V1       ||")
        print(green + " ::===============================================================::")
        print(green + " ::   -h => Muestra la Ayuda del Script                           ::")
        print(green + " ::        -f => Establece la ruta del fichero o Folder           ::")
        print(green + " ::             -m =>> Establece el modo                          ::")
        print(green + " ::                                   |-> c : Cifrar Fichero      ::")
        print(green + " ::                                   |-> d : Decifrar Fichero    ::")
        print(green + " ::<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>::") 
        print(green + " ::         python CryptoPro.py -f RUTA -m c o d                  ::")
        print(green + " <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<>>>>>>>>>>>>>>>>>>>>>>>>>>>>::")

    else:
        mess = """  
        # ============================================ #
        # =           Aviso muy importante           = #
        # ============================================ #
        # -Recuerda muy bien la contraseña con la que  #
        #  cifrar el fichero, ya que si decifras con   #
        #  una contraseña difente:                     #
        #   "Corromperas el fichero" y nomas podras    #
        #    utilizarlo. :) By_MrROBOT                 #
        # ============================================ #"""

        print(amarillo + mess)
        input("\n\tEnter[] ")
        #Input a password
        #semi_password = gt.getpass(prompt="Introduce tu contraseña: ")
        semi_password = input("Introduce tu contraseña: ")
        #Make an object from CryptoPro class
        cryptor = CryptoPro(semi_password)
        key = cryptor.establish_pasword()
        all_paths, verification = cryptor.discover_files(parse.file)

        if parse.mode.lower() == "c":
            try:
                if verification:
                    for x in all_paths:
                        with open(x, "rb+") as f:
                            c_d = f.read()

                        data_crypt = cryptor.encrypt_data(key, c_d)

                        with open(x,"wb+") as d:
                            d.write(data_crypt)

                else:
                    with open(all_paths, "rb+") as f:
                        c_d = f.read()

                    data_crypt = cryptor.encrypt_data(key, c_d)

                    with open(all_paths,"wb+") as d:
                        d.write(data_crypt)
                ghost = get_output_string("ghostbusters", "Cifrado Exitosamente")
                print(green + ghost)
            except Exception as e:
                print(red + get_output_string("dragon",f"Uppp! Un error a Ocurrido: {e}"))
        
        elif parse.mode.lower() == "d":
            try:
                if verification:
                    for x in all_paths:
                        with open(x, "rb+") as f:
                            c_d = f.read()

                        data_crypted = cryptor.decrypt_data(key, c_d)

                        with open(x,"wb+") as d:
                            d.write(data_crypted)

                else:
                    with open(all_paths, "rb+") as f:
                        c_d = f.read()

                    data_crypted = cryptor.decrypt_data(key, c_d)

                    with open(all_paths,"wb+") as d:
                        d.write(data_crypted)
                print(green + get_output_string("trex","Descifrado Exitosamente"))
            except Exception as e:
                print(red + get_output_string("daemon",f"Uppp! Un error a Ocurrido: {e}"))

        else:
            mesagge = "Has Introducido el argumento de cifrado/decifrado incorrecto\nVisualiza la ayuda!!!!"
            print(purpura + get_output_string("tux",mesagge))
            

         
