# Import required libraries
import streamlit as st
from cryptography.hazmat.primitives import hashes, padding, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature
from PIL import Image
import os
import json
from datetime import datetime
from io import BytesIO

class Steganography:
    """
    This class provides methods for hiding and extracting binary data within an image using LSB steganography.
    """
    @staticmethod
    def calculate_image_hash(image):
        """
        Calculates the SHA-256 hash of an image excluding the least significant bit of each pixel channel.

        Args:
            image: PIL.Image object - The original image to calculate the hash for.

        Returns:
            image_hash: bytes - The SHA-256 hash of the image.
        """
        image_data = list(image.getdata())
        significant_bits_data = [(channel & ~1 for channel in pixel) for pixel in image_data]
        flattened_data = [bit for pixel in significant_bits_data for bit in pixel]
        data_bytes = bytes(flattened_data)
        hasher = hashes.Hash(hashes.SHA256())
        hasher.update(data_bytes)
        image_hash = hasher.finalize()
        return image_hash
    
    @staticmethod
    def embed_data(image, data):
        """
        Embeds binary data into an image using LSB steganography.

        Args:
            image: PIL.Image object - The original image to hide data in.
            data: bytes - The binary data to hide.

        Returns:
            modified_image: PIL.Image object - The image with embedded data.
        """
        binary_data = ''.join(format(byte, '08b') for byte in data)
        image_data = list(image.getdata())
        modified_image_data = []

        for i, pixel in enumerate(image_data):
            if i < len(binary_data):
                modified_pixel = tuple((channel & ~1) | int(binary_data[i]) for channel in pixel)
                modified_image_data.append(modified_pixel)
            else:
                modified_image_data.append(pixel)

        modified_image = Image.new(image.mode, image.size)
        modified_image.putdata(modified_image_data)
        return modified_image

    @staticmethod
    def extract_data(image, data_length):
        """
        Extracts embedded binary data from an image.

        Args:
            image: PIL.Image object - The image with embedded data.
            data_length: int - The length of the data to extract.

        Returns:
            extracted_data: bytearray - The extracted data.
        """
        image_data = list(image.getdata())
        binary_data = ''.join(str(pixel[0] & 1) for pixel in image_data[:data_length * 8])
        extracted_data = bytearray(int(binary_data[i:i+8], 2) for i in range(0, len(binary_data), 8))
        return extracted_data


class Cryptography:
    """
    This class encapsulates cryptographic functionalities like signing messages, verifying signatures, 
    and encryption and decryption of messages.
    """
    def __init__(self, private_key, public_key):
        self.private_key = private_key
        self.public_key = public_key

    def sign_message(self, message):
        """
        Signs a given message using the user's private key.

        Args:
            message: bytes - The message to be signed.

        Returns:
            signature: bytes - The signature of the message.
        """
        signature = self.private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
        return signature

    def verify_signature(self, message, signature):
        """
        Verifies a given message's signature using the sender's public key.

        Args:
            message: bytes - The original message.
            signature: bytes - The signature of the message to verify.
        """
        try:
            self.public_key.verify(
                bytes(signature),
                bytes(message),
                ec.ECDSA(hashes.SHA256())
            )
            #print("The signature is valid.")
            return True
        except InvalidSignature:
            #print("The signature is invalid.")
            #st.error("The signature is invalid.")
            return False

class User:
    """
    This class represents a user of the system, holding an instance of the Cryptography class.
    """
    def __init__(self, private_key, public_key):
        self.crypto = Cryptography(private_key, public_key)


# Generate new keys if they don't exist
def generate_and_save_keys(file_path):
    # Generate private and public keys
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()

    # Serialize the keys
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Convert the keys to strings
    private_key_str = private_key_bytes.decode('utf-8')
    public_key_str = public_key_bytes.decode('utf-8')

    # Create a dictionary to store the keys
    keys = {
        'private_key': private_key_str,
        'public_key': public_key_str
    }

    # Save the keys to a JSON file
    with open(file_path, 'w') as f:
        json.dump(keys, f)

# Load keys
def load_keys(user_name):
    file_path = f'keys_{user_name}.json'
    # Check if already file path
    if not os.path.isfile(file_path):
        generate_and_save_keys(file_path)
    
    # Load the keys from the JSON file
    with open(file_path, 'r') as f:
        keys = json.load(f)

    # Convert the keys to bytes
    private_key_pem = keys['private_key'].encode('utf-8')
    public_key_pem = keys['public_key'].encode('utf-8')

    # Load the keys
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None
    )
    public_key = serialization.load_pem_public_key(
        public_key_pem
    )

    return private_key, public_key


# Load in keys from JSON or generate new ones if they don't exist
private_key_alice, public_key_alice = load_keys('Alice')
private_key_bob, public_key_bob = load_keys('Bob')
private_key_charlie, public_key_charlie = load_keys('Charlie')
private_key_trusted_entity, public_key_trusted_entity = load_keys('Trusted_Entity')

# Initialize users
alice = User(private_key_alice, public_key_alice)
bob = User(private_key_bob, public_key_bob)
charlie = User(private_key_charlie, public_key_charlie)
trusted_entity = User(private_key_trusted_entity, public_key_trusted_entity)

# Create a user dictionary for easy access
users = {"Alice": alice, "Bob": bob, "Charlie": charlie, "Trusted_Entity": trusted_entity}


def encrypt_page():
    st.title("Hidden in Plain Byte - Encryption Page")
    
    st.markdown("""
    **Instructions** - 
    This page allows you to write a message and embed it in an image. 
    1. Here you are the `Sender`, you may select any of the three (Alice, Bob, or Charlie).
    2. Upload an image or take a picture via the camera.
    3. Write a message (This message will be publically viewable to anyone that extracts that data from the image)
    4. Click `Sign and Embed Message`
    5. Once the image has finished loading, click `Download image`
    """)

    sender_name = st.selectbox("Select the sender", ["Alice", "Bob", "Charlie"])
    sender = users[sender_name]
    
    source_selection = st.radio("Choose your image source", ('Upload', 'Camera'))

    img_file = None
    original_image = None
    image_hash = None
    image_origin = None

    if source_selection == 'Upload':
        img_file = st.file_uploader("Upload an image for steganography", type=['png'])
        # get the hash of the non-lsb image bytes
        if img_file:
            original_image = Image.open(img_file)
            image_hash = Steganography.calculate_image_hash(original_image)
            image_origin = f"{sender_name}'s photo library"

    elif source_selection == 'Camera':
        img_file = st.camera_input(disabled=False, label="camera")
        # get the hash of the non-lsb image bytes
        if img_file:
            original_image = Image.open(img_file)
            image_hash = Steganography.calculate_image_hash(original_image)
            image_origin = "In-app Camera"

    message = st.text_input("Enter your message here:")
    encrypt_btn = st.button("Sign and Embed Message")

    if encrypt_btn and img_file and message and image_hash is not None:

        trusted_entity_data = {
            "timestamp": str(datetime.now()),
            "nonce": os.urandom(16).hex(),
            "image_hash": image_hash.hex(),
            "verification_data": {
                "image_origin": image_origin,
                "time_taken": str(datetime.now()),
                "filters_applied": [],
                "cropping_info": [],
                "edit_history": [],
                "biometric_verification": "Approved"
            }
        }
        
        # Sign this data with the trusted entity's key
        trusted_entity_json = json.dumps(trusted_entity_data)
        trusted_signature = trusted_entity.crypto.sign_message(trusted_entity_json.encode())
        
        # Prepare the data to be sent by the user
        data = {
            "message": message,
            "trusted_entity_data": trusted_entity_data,
            "trusted_signature": trusted_signature.hex()
        }
        
        json_data = json.dumps(data)
        signature = sender.crypto.sign_message(json_data.encode())

        # Combine lengths, encrypted message, and signature
        message_length_bytes = len(json_data).to_bytes(4, 'big')
        signature_length_bytes = len(signature).to_bytes(4, 'big')
        combined_data = message_length_bytes + signature_length_bytes + json_data.encode() + signature

        # Embed the data into an image and save the modified image
        modified_image = Steganography.embed_data(original_image, combined_data)
        modified_image.save("output.png")
        st.success("Message signed and embedded into image successfully!")

        st.image(modified_image, caption='Modified Image Thumbnail', width=150)
        with open("output.png", "rb") as file:
            btn = st.download_button(
                    label="Download image",
                    data=file,
                    file_name="output.png",
                    mime="image/png"
                  )


def decrypt_page():
    img_file = None
    decrypt_btn = None
    st.title("Hidden in Plain Byte - Decryption Page")
    
    st.markdown("""
    **Instructions** - 
    This page allows you to extract and decrypt embedded data from an image to verify the integrity of the image and data embedded within it.
    1. Here you are a viewer of the image, it is important however that you select the correct image `sender` so that you can verify that the sender verified and authorized the embedded message.
    2. Upload the image with the embeded message (the image you downloaded on the encryption page)
    3. Click `Decrypt Message from Image`
    4. If `sender`'s signature, the `trusted entity`'s sinature, and the image hash verfications are successful, the decrypted metadata will be revealed displaying the image origin and modifications if any.
    """)

    sender_name = st.selectbox("Select the sender", ["Alice", "Bob", "Charlie"])
    sender = users[sender_name]

    img_file = st.file_uploader("Upload an encrypted image for extraction", type=['png'])
    if img_file != None:
        modified_image = Image.open(img_file)
    decrypt_btn = st.button("Decrypt Message from Image")

    if decrypt_btn and img_file:

        # Extract the data from the modified image
        header = Steganography.extract_data(Image.open(img_file), 8) 
        message_length = int.from_bytes(header[:4], 'big')
        signature_length = int.from_bytes(header[4:], 'big')

        extracted_data = Steganography.extract_data(Image.open(img_file), 8 + message_length + signature_length)
        json_data_out = extracted_data[8:8+message_length].decode()
        signature_out = bytes(extracted_data[8+message_length:8+message_length+signature_length])
        
        # Sender Signature Verification
        sender_verified = sender.crypto.verify_signature(json_data_out.encode(), signature_out)

        # Load output data
        data_out = json.loads(json_data_out)

        # Trusted Entity Signature Verification
        try:
            trusted_entity_json = json.dumps(data_out["trusted_entity_data"])
            trusted_signature = bytes.fromhex(data_out["trusted_signature"])
            trusted_entity_verified = trusted_entity.crypto.verify_signature(trusted_entity_json.encode(), trusted_signature)
        except InvalidSignature:
            #st.error("The trusted entity signature is invalid.")
            return
        
        # Image Hash Verification
        image_hash_out = bytes.fromhex(data_out["trusted_entity_data"]["image_hash"])
        hash_verification_image = Steganography.calculate_image_hash(modified_image)
            
        if hash_verification_image != image_hash_out:
            st.error("The image has been tampered with or is not the original image.")
            
        if not trusted_entity_verified:
            st.error("The trusted entity signature is invalid.")

        if not sender_verified:
            st.error("The sender's signature is invalid.")
            
        if sender_verified and trusted_entity_verified and hash_verification_image == image_hash_out:
            st.success("✅ All verifications passed!") 
            # If all checks pass, display extracted message
            st.json(data_out)

        
def home_page():
    st.title("Hidden in Plain Byte")
    st.header("`Public Image Verification with Trusted Entities`")
    
    st.image("header.png")

    st.markdown(
    """
    The concept illustrated in this demo was specifically crafted for scenarios where maintaining the authenticity and integrity of data within an image is critically important. This includes any situation where images are shared publicly, allowing us to confirm their original source as well as track any changes made after their creation. For example, a social media platform could use it to ensure that an image has not been artificially created, providing a verification step that the uploader cannot circumvent.
    """)
    
    
    st.markdown("""

    ### Public Visibility of the Embedded Data
    All the information embedded in the image is publicly visible but is cryptographically secured. This ensures that any tampering with the data can be easily detected and verified by any viewer.

    ### Sender Signature
    The sender signature is generated by the sender using their private key. It provides the guarantee that the message has indeed originated from the sender, and the message has not been tampered with in transit.

    ### Trusted Entity Signature
    The trusted entity signature is a cryptographic stamp provided by a trusted third-party, such as a certifying authority, which confirms the origin of the image. It adds an extra layer of security to the image and the data embedded within.

    ### Image Hash Verification
    Image hash verification is used to verify that the image has not been tampered with. This is done by comparing the hash of the image (with the embeded data) excluding the least significant bit of each pixel channel with the original hash stored in the trusted entity data.

    ### Biometric Verification of Real Human
    The script includes a placeholder for biometric verification of a real human. This is a measure to ensure that the image and the data embedded within it are not products of a synthetic media or deceptive AI.

    ### Modification and Filters Documentation
    Any modifications or filters applied to the image are documented in the trusted entity data. This is a prophylactic way to combat synthetic media and deceptive AI. It ensures that any changes to the image are transparently recorded and verifiable by any viewer.
    """)

    st.markdown("![Alt Text](https://media2.giphy.com/media/v1.Y2lkPTc5MGI3NjExOWU4ZGVlNjIxNjE0OTk1NGFiNWNjZmUzM2ZiYTljY2IzYTFlOTQyOSZlcD12MV9pbnRlcm5hbF9naWZzX2dpZklkJmN0PWc/xFyxZjsX4ItgERKObC/giphy.gif)")

    
    st.markdown("""
    ## How it works
    ### Encryption Page

    On this page, you (Alice, Bob, or Charlie) can select an image and enter a message that you want to hide within the image.

    Here's how it works:

    1. Choose an image file or use the camera to capture an image.
    2. Enter your secret message.
    3. Press the `Sign and Embed Message` button. This triggers the encryption and embedding process:
    - The application calculates the SHA-256 hash of the image, excluding the least significant bit of each pixel channel.
    - A set of trusted entity data is created and signed using the trusted entity's key.
    - Your message, the trusted entity data, and the trusted entity's signature are combined and signed using your private key.
    - The combined data is then embedded into the image using the LSB steganography technique.
    4. The modified image is then displayed and you can download it for further use.
    """)

    
    st.image("diagram-1.png")
    
    st.markdown("""
### Decryption Page

On this page, you can upload the encrypted image to reveal the hidden message.

Here's how the decryption process works:

1. Upload the encrypted image.
2. Press the `Decrypt Message from Image` button:
   - The application extracts the embedded data (message, original image hash, signatures) from the image.
   - It verifies the authenticity and integrity of the message by checking the sender's signature using their public key.
   - It checks the signature of the trusted entity to ensure the authenticity and integrity of the trusted entity data.
   - It verifies the integrity of the image by comparing the image's hash (excluding the least significant bit of each pixel channel) with the original image hash stored in the trusted entity data.
3. If all verifications pass, the original data, including the hidden message, is displayed on the page.

## Potential Weaknesses of this Demo

While this application uses robust cryptographic techniques, it is a conceptual demo and should only be used as such. With that said, here are some of the potential weaknesses of the demo:

* **Encryption Key Security:** If the shared secret key from the ECC-based Diffie-Hellman exchange is compromised, an attacker could decrypt the hidden messages.
  
* **Image Transmission:** The image must be transmitted without any form of lossy compression (such as JPEG compression), which could remove or alter the hidden data, so for the time being this demo is focused on `.png` images.
  
* **Limited Message Size:** The length of the hidden message is limited by the size of the image. Large messages may require larger images.

* **Digital Signature Compromise:** If the sender's private key is compromised, an attacker could forge digital signatures.

* **Steganography Technique:** LSB Steganography is one of the less advanced forms of Steganography, there are some forms that may be better suited for this type of application.

* **RGB Channel:** While the Image hash function creates a hash of the image bits, excluding the least significant bits, of all three color channels Red, Green, and Blue, the encrypted data was only embedded in the Red Channel for this demo; however, this is a minor fix that allows for larger embedded files that wasn't necessary for this demo. 


**Additional notes:**
- For future improvement I would look into applying steganography alternatives to LSB. 
- The hash verification currently is inefficient especially with larger image sizes. 
- The trusted entity metadata is arbitrary for the sake of the demo, it could include more or less fields to survey the image history.

**Contact:**
- Author: **Preston Kirschner**
- Socials: [LinkedIn](https://www.linkedin.com/in/preston-kirschner/) | [Github](https://github.com/P-carth) | [Twitter](https://twitter.com/Prestonk_)
- Opensource project: [Huggingface](https://huggingface.co/spaces/P-carth/hidden_in_plain_byte-public_image_verification/blob/main/app.py)
- I would love to hear your feedback (positive or negative)! Please reach out on one of the socials above if you have questions or comments.
""")

def main():
    st.sidebar.title("Navigation")
    app_mode = st.sidebar.selectbox("Choose the task", ["Home Page","Encryption Page", "Decryption Page"])

    
    if app_mode == "Home Page":
        home_page()
    if app_mode == "Encryption Page":
        encrypt_page()
    elif app_mode == "Decryption Page":
        decrypt_page()

if __name__ == "__main__":
    main()
