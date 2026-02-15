import argparse
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

def derivar_clave(password, salt):
    return PBKDF2(password, salt, dkLen=32)

def cifrar_archivo(archivo, password):
    salt = get_random_bytes(16)
    clave = derivar_clave(password, salt)

    with open(archivo, "rb") as f:
        datos = f.read()

    cipher = AES.new(clave, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(datos)

    with open(archivo + ".enc", "wb") as f:
        f.write(salt)
        f.write(cipher.nonce)
        f.write(tag)
        f.write(ciphertext)

    print(f"[+] Archivo cifrado: {archivo}.enc")

def descifrar_archivo(archivo_enc, password):
    with open(archivo_enc, "rb") as f:
        salt = f.read(16)
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()

    clave = derivar_clave(password, salt)
    cipher = AES.new(clave, AES.MODE_GCM, nonce=nonce)

    datos = cipher.decrypt_and_verify(ciphertext, tag)

    salida = archivo_enc.replace(".enc", ".dec")
    with open(salida, "wb") as f:
        f.write(datos)

    print(f"[+] Archivo descifrado: {salida}")

def main():
    parser = argparse.ArgumentParser(description="Cifrado AES para archivos")
    parser.add_argument("modo", choices=["encrypt", "decrypt"], help="Modo de operación")
    parser.add_argument("archivo", help="Archivo a procesar")
    parser.add_argument("-p", "--password", required=True, help="Contraseña")

    args = parser.parse_args()

    if args.modo == "encrypt":
        cifrar_archivo(args.archivo, args.password)
    else:
        descifrar_archivo(args.archivo, args.password)

if __name__ == "__main__":
    main()
