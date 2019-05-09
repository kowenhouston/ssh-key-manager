import sys
import os
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend as crypto_default_backend
from settings import private_key_filename, public_key_filename, key_location

def private_key_to_bytes(key):
    """Convert RSA Private Key to byte string
    
    Arguments:
        key {cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey} 
    
    Returns:
        bytes -- Byte string ready to parse or to put into file
    """
    return key.private_bytes(
            crypto_serialization.Encoding.PEM,
            crypto_serialization.PrivateFormat.PKCS8,
            crypto_serialization.NoEncryption())

def public_key_to_bytes(key):
    """Convert RSA Public Key to byte string

    Arguments:
        key {cryptography.hazmat.backends.openssl.rsa._RSAPublicKey}

    Returns:
        bytestring -- Byte string ready to parse or to put into file
    """
    return key.public_bytes(
        crypto_serialization.Encoding.OpenSSH,
        crypto_serialization.PublicFormat.OpenSSH
    )

def private_key_bytes_to_key(kbytes, password=None):
    """Convert bytes (usually from file) to RSA private key
    
    Arguments:
        kbytes {bytestring} -- Byte string to convert
    
    Keyword Arguments:
        password {[type]} -- If decryption requires password (default: {None})
    
    Returns:
        {cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey}
    """
    return crypto_serialization.load_pem_private_key(
        kbytes,
        password=password,
        backend=crypto_default_backend()
    )

def public_key_bytes_to_key(kbytes):
    """Convert bytes (usually from file) to RSA public key

    Arguments:
        kbytes {bytestring} -- Byte string to convert

    Returns:
        {cryptography.hazmat.backends.openssl.rsa._RSAPublicKey}
    """
    return crypto_serialization.load_ssh_public_key(
        kbytes,
        backend=crypto_default_backend()
    )

def generate_keys(key_size=4096):
    """Generate RSA Key pair
    
    Keyword Arguments:
        key_size {int} -- RSA Key size (default: {4096})
    
    Returns:
        public_key, private_key -- cryptography.hazmat.backends.openssl.rsa._RSAPublicKey, 
                                   cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey
    """
    key = rsa.generate_private_key(
        backend=crypto_default_backend(),
        public_exponent=65537,
        key_size=key_size
    )
    return key.public_key(), key

def write_keys(public_key, private_key, public_key_filename, private_key_filename):
    """Write keys to a file
    
    Arguments:
        public_key {cryptography.hazmat.backends.openssl.rsa._RSAPublicKey} -- Key generated from generate keys function
        private_key {cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey} -- Key generated from generate keys function
        public_key_filename {str/filename (os.join)} -- Where do you want the public key to go?
        private_key_filename {str/filename (os.join)} -- Where do you want the private key to go?
    """
    with open(private_key_filename, 'wb') as f:
        f.write(private_key_to_bytes(private_key))
    os.chmod(private_key_filename, 0o600)

    public_key_bytes = public_key_to_bytes(public_key)
    with open(public_key_filename, 'wb') as f:
        f.write(public_key_bytes)

def read_private_key(filename):
    """Reads private key file and converts using the private_key_bytes_to_key function
    
    Arguments:
        filename {str/filename (os.join)} -- Where is the file to convert?
    
    Returns:
        {cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey} or None
    """
    try:
        with open(filename, "rb") as key_file:
            private_key_file = key_file.read()
        return private_key_bytes_to_key(private_key_file)
    except (FileNotFoundError, ValueError):
        return None

def read_public_key(filename):
    """Reads public key file and converts using the public_key_bytes_to_key function

    Arguments:
        filename {str/filename (os.join)} -- Where is the file to convert?

    Returns:
        {cryptography.hazmat.backends.openssl.rsa._RSAPublicKey} or None
    """
    try:
        with open(filename, "rb") as key_file:
            public_key_file = key_file.read()
        return public_key_bytes_to_key(public_key_file)
    except (FileNotFoundError, ValueError):
        return None

def read_keypair(private_key_filename, public_key_filename):
    """Run read_public_key and read_private_key
    
    Arguments:
        private_key_filename {str/filename (os.join)} -- Where is the private key to convert?
        public_key_filename {str/filename (os.join)} -- Where is the public key to convert?
    
    Returns:
        {cryptography.hazmat.backends.openssl.rsa._RSAPublicKey} or None,
        {cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey} or None
    """
    private_key = read_private_key(private_key_filename)
    public_key = read_public_key(public_key_filename)
    return public_key, private_key

def yes_no(question):
    """Function to return true/false depending on what the user responds to the question provided.
    
    Arguments:
        question {str} -- Question you want to ask the user
    
    Returns:
        [bool]
    """
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    prompt = " [y/N] "
    default = "no"
    while True:
        sys.stdout.write(question + prompt)
        choice = input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")

def main():
    """Main App, if run standalone does all the goodies but if called from another
    script then returns the keys
    
    Returns:
        {cryptography.hazmat.backends.openssl.rsa._RSAPublicKey} or None,
        {cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey} or None
    """
    if not os.path.isdir(key_location):
        os.mkdir(key_location)
        print("Path is created: " + key_location)

    public_key, private_key = read_keypair(
        private_key_filename, public_key_filename)

    if not private_key and not public_key:
        print(
            "Could not find Public and Private Key (or are corrupt), generating new pair...")
        public_key, private_key = generate_keys()
        write_keys(public_key, private_key,
                public_key_filename, private_key_filename)
    elif not public_key:
        print(
            "Could not find Public Key (or is corrupt), generating new one and saving it...")
        public_key = private_key.public_key()
        write_keys(public_key, private_key,
                    public_key_filename, private_key_filename)
    elif not private_key:
        if yes_no(
            "Could not find Private Key (or is corrupt), do you want to create new pair?"):
            if yes_no(
                    "Are you sure? This means overwriting your public key?"):
                public_key, private_key = generate_keys()
                write_keys(public_key, private_key,
                        public_key_filename, private_key_filename)
    else: 
        if __name__ == "__main__":
            print("You already have a Public and Private Key!")
        else:
            pass
    return public_key, private_key

if __name__ == "__main__":
    """ Prints the keys if run as standalone script
    """
    public_key, private_key = main()
    if private_key:
        print(private_key_to_bytes(private_key).decode("utf-8"))
    if public_key:
        print(public_key_to_bytes(public_key).decode("utf-8"))