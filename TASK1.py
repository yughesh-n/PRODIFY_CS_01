def caesar_cipher_encrypt(plaintext, shift):
    ciphertext = ""
    for char in plaintext:
        if char.isalpha():  
            if char.isupper():
                start = ord('A')
            else:
                start = ord('a')
            shifted_char = chr((ord(char) - start + shift) % 26 + start)
            ciphertext += shifted_char
        else:
            ciphertext += char  
    return ciphertext

def caesar_cipher_decrypt(ciphertext, shift):
    return caesar_cipher_encrypt(ciphertext, -shift)  

def main():
    print("Welcome to the Caesar Cipher program!")
    while True:
        choice = input("\nEnter 'e' for encryption, 'd' for decryption, or 'q' to quit: ").lower()
        
        if choice == 'e':
            plaintext = input("Enter the message to encrypt: ")
            shift = int(input("Enter the shift value (1-25): "))
            encrypted_message = caesar_cipher_encrypt(plaintext, shift)
            print("Encrypted message:", encrypted_message)
        
        elif choice == 'd':
            ciphertext = input("Enter the message to decrypt: ")
            shift = int(input("Enter the shift value (1-25): "))
            decrypted_message = caesar_cipher_decrypt(ciphertext, shift)
            print("Decrypted message:", decrypted_message)
        
        elif choice == 'q':
            print("Thank you for using the Caesar Cipher program. Goodbye!")
            break
        
        else:
            print("Invalid choice! Please enter 'e', 'd', or 'q'.")

if _name_ == "_main_":
    main()