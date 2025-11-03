import random

def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True

def generate_prime(bits):
    while True:
        n = random.getrandbits(bits)
        n |= 1
        if is_prime(n):
            return n

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

def mod_inverse(e, phi):
    gcd, x, _ = extended_gcd(e, phi)
    if gcd != 1:
        raise Exception('Modular inverse does not exist')
    return x % phi

def generate_keypair(key_size=64):
    p = generate_prime(key_size // 2)
    q = generate_prime(key_size // 2)
    
    n = p * q
    phi = (p - 1) * (q - 1)
    
    e = generate_prime(key_size // 4)
    while e < phi:
        if extended_gcd(e, phi)[0] == 1:
            break
        e += 2
    
    d = mod_inverse(e, phi)
    
    return ((e, n), (d, n))



# AES key generation and encryption/decryption
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def generate_aes_key(key_size=16):
    return random.getrandbits(key_size * 8).to_bytes(key_size, byteorder='big')

def aes_encrypt(plaintext, key):
    if not isinstance(key, bytes) or len(key) != 16:
        raise ValueError(f"Invalid key format or length. Expected 16 bytes, got {len(key)} bytes")
    try:
        cipher = AES.new(key, AES.MODE_CBC)
        padded_data = pad(plaintext.encode('utf-8'), AES.block_size)
        ct_bytes = cipher.encrypt(padded_data)
        return cipher.iv + ct_bytes
    except Exception as e:
        raise ValueError(f"Encryption failed: {str(e)}")

def aes_decrypt(ciphertext, key):
    if not isinstance(key, bytes) or len(key) != 16:
        raise ValueError(f"Invalid key format or length. Expected 16 bytes, got {len(key)} bytes")
    if len(ciphertext) < AES.block_size:
        raise ValueError("Invalid ciphertext length")
    try:
        iv = ciphertext[:AES.block_size]
        ct = ciphertext[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(ct)
        unpadded_data = unpad(decrypted_data, AES.block_size)
        return unpadded_data.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Decryption failed: {str(e)}")

# # Example usage:
# if __name__ == "__main__":
#     # RSA Keypair Generation
#     public_key, private_key = generate_keypair(64)
#     print("Public Key:", public_key)
#     print("Private Key:", private_key)

#     # AES Encryption/Decryption
#     aes_key = generate_aes_key(16)
#     message = "Hello, World!"
#     encrypted_msg = aes_encrypt(message, aes_key)
#     print("Encrypted Message:", encrypted_msg)

#     decrypted_msg = aes_decrypt(encrypted_msg, aes_key)
#     print("Decrypted Message:", decrypted_msg)