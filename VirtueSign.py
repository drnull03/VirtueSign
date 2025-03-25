import sys
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import PKCS1_v1_5
from colorama import Fore
import argparse
import os

args=None
VERSION= "0.1"



class CustomParser(argparse.ArgumentParser):
    def print_usage(self, file=None):
        if file is None:
            file = sys.stdout
        file.write(usage())
    
    def print_help(self, file=None):
        if file is None:
            file = sys.stdout
        file.write(usage())
    
    def error(self, message):
        sys.stderr.write(f"Error: {message}\n\n")
        self.print_usage(sys.stderr)
        sys.exit(2)

def parse_argument():
    parser = CustomParser(add_help=False,prog='VirtueSign',description='This program is a python demo for digtal signature.')
    parser.add_argument("-s","--sign",nargs=3,help="sign your data using a private key")
    parser.add_argument("-v","--verify",nargs=3,help="verfiy signature using the private key")
    parser.add_argument("-g","--generate",action="store_true",help="generate keys")
    parser.add_argument("-V","--version",action="store_true",help="print VirtueSign version")
    global args
    args=parser.parse_args()
    




def usage():
    return Fore.RED + "Usage: \n VirtueSign -s|--sign  <priv-key> <data-file> <signature-file> \n VirtueSign -v|--verfiy  <PUB-key> <data-file> <signature-file> \n VirtueSign -g|--generate \n VirtueSign -V|--version" # to generate RSA keys VirtueSign -v or --version"  






def generate_keys():
    try:
        key_size = 2048
        private_key_file = 'private.pem'
        public_key_file = 'public.pem'
        passphrase = None  # for future use
        
        print(Fore.YELLOW + "Generating Keys....")
        
        # Generate keys
        key = RSA.generate(key_size)
        private_key = key.export_key()
        public_key = key.publickey().export_key()
        
        # Write private key
        print(Fore.YELLOW + "Writing private key to private.pem")
        try:
            with open(private_key_file, 'wb') as f:
                f.write(private_key)
            os.chmod(private_key_file, 0o600)  # Set restrictive permissions
        except IOError as e:
            raise IOError(f"Failed to write private key: {str(e)}")
        
        # Write public key
        print(Fore.YELLOW + "Writing public key to public.pem")
        try:
            with open(public_key_file, 'wb') as f:
                f.write(public_key)
        except IOError as e:
            raise IOError(f"Failed to write public key: {str(e)}")
            
        print(Fore.GREEN + "Key generation completed successfully!")
        
    except Exception as e:
        print(Fore.RED + f"Key generation failed: {str(e)}")
        sys.exit(1)



def generate_signature(private_key, data,signature_file):
    print(Fore.YELLOW + "Generating Signature")
    try:
        h = SHA256.new(data)
        rsa = RSA.importKey(private_key)
        if not rsa.has_private():
            raise ValueError("A private key is required for signing")
        signer = PKCS1_v1_5.new(rsa)
        signature = signer.sign(h)
        with open(signature_file, 'wb') as f: 
            f.write(signature)
        print(Fore.GREEN + "Signature successfully generated and saved")
    except Exception as e:
        print(Fore.RED + f"Signature generation failed: {str(e)}")
        sys.exit(1)

def verify_signature(public_key, data,signature_file):
    print(Fore.YELLOW + "Verifying Signature")
    try:
        h = SHA256.new(data)
        rsa = RSA.importKey(public_key)
        signer = PKCS1_v1_5.new(rsa)
        with open(signature_file, 'rb') as f: signature = f.read()
        rsp = Fore.GREEN + "Success" if (signer.verify(h, signature)) else Fore.RED + "Verification Failure"
        print(rsp)
    except Exception as e:
        print(Fore.RED + f"Signature verfication failed: {str(e)}")


if __name__ == '__main__':
    parse_argument()
    #print(args.sign) debug line
    
    if(args.version):
        print(Fore.GREEN + "VirtueSign version:",VERSION)
        sys.exit(0)
    elif(args.generate):
            try:
                generate_keys()
            except Exception as e:
                print(Fore.RED + f"Error !!! {e}")
    
    elif(args.sign is not None):
        key_file=args.sign[0]
        data_file=args.sign[1]
        signature_file=args.sign[2]
        with open(key_file, 'rb') as f: key = f.read()
        with open(data_file, 'rb') as f: data = f.read()
        generate_signature(key,data,signature_file)
    elif(args.verify is not None):
        key_file=args.verify[0]
        data_file=args.verify[1]
        signature_file=args.verify[2]
        with open(key_file, 'rb') as f: key = f.read()
        with open(data_file, 'rb') as f: data = f.read()
        verify_signature(key,data,signature_file)
    else:
        print(Fore.RED + "please provide arguments !!")
        print(usage())
    
else:
    print(Fore.RED + "VirtueSign only works as a program not as a library ")
    sys.exit(2)  
    
    
    