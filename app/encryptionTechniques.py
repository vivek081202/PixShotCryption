from stegano import lsb
from Crypto.PublicKey import RSA, ECC
from Crypto.Cipher import PKCS1_OAEP
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import base64
from PIL import Image, ImageChops
from PIL.ExifTags import TAGS
import numpy as np
import cv2
import io
import hashlib
import piexif

# RSA Encryption
def encrypt_rsa(message):
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    cipher = PKCS1_OAEP.new(RSA.import_key(public_key))
    encrypted = cipher.encrypt(message.encode())
    return encrypted, private_key

# ECC Encryption (Simplified with Base64 encoding)
def encrypt_ecc(message):
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()
    encrypted = base64.b64encode(message.encode())  # Simplified for now
    private_key_bytes = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    )
    return encrypted, private_key_bytes

# ElGamal Encryption (Simulated for now)
def encrypt_elgamal(message):
    encrypted = base64.b64encode(message.encode())
    private_key = b"ELGAMAL_SIMULATED_PRIVATE_KEY"
    return encrypted, private_key

# LSB using stegano
def lsb_encode_with_stegano(image: Image.Image, data: bytes):
    data_str = base64.b64encode(data).decode()  # Safe string for stegano
    with io.BytesIO() as buffer:
        image.save(buffer, format="PNG")
        buffer.seek(0)
        secret_img = lsb.hide(buffer, data_str)
    return secret_img

# DCT encode
def dct_encode(image: Image.Image, data: bytes):
    img = np.array(image.convert("L"))
    dct = cv2.dct(np.float32(img))
    binary_data = ''.join(format(byte, '08b') for byte in data) + '1111111111111110'  # EOF marker

    idx = 0
    for i in range(dct.shape[0]):
        for j in range(dct.shape[1]):
            if idx >= len(binary_data):
                break
            coeff = int(dct[i][j])
            dct[i][j] = coeff - coeff % 2 + int(binary_data[idx])
            idx += 1
        if idx >= len(binary_data):
            break

    encoded = cv2.idct(dct)
    encoded = np.uint8(np.clip(encoded, 0, 255))
    return Image.fromarray(encoded)

# Hybrid: LSB first half, DCT second half
def hybrid_encode(image: Image.Image, data: bytes):
    half = len(data) // 2
    part1 = data[:half]
    part2 = data[half:]
    img_lsb = lsb_encode_with_stegano(image, part1)
    img_dct = dct_encode(img_lsb, part2)
    return img_dct

# LSB using Stegano
def lsb_extract_with_stegano(image: Image.Image) -> bytes:
    with io.BytesIO() as buffer:
        image.save(buffer, format="PNG")
        buffer.seek(0)
        hidden_message = lsb.reveal(buffer)
    return base64.b64decode(hidden_message.encode())

# DCT method
def dct_extract(image: Image.Image) -> bytes:
    img = np.array(image.convert("L"))
    dct = cv2.dct(np.float32(img))
    binary_data = ""
    for i in range(dct.shape[0]):
        for j in range(dct.shape[1]):
            bit = int(dct[i][j]) % 2
            binary_data += str(bit)
            if binary_data[-16:] == "1111111111111110":
                break
        if binary_data[-16:] == "1111111111111110":
            break
    binary_data = binary_data[:-16]
    all_bytes = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    return bytes([int(b, 2) for b in all_bytes])

# Hybrid = LSB + DCT
def hybrid_extract(image: Image.Image) -> bytes:
    lsb_data = lsb_extract_with_stegano(image)
    dct_data = dct_extract(image)
    return lsb_data + dct_data

# RSA Decryption
def decrypt_rsa(encrypted_data, private_key_bytes):
    try:
        private_key = RSA.import_key(private_key_bytes)
        cipher = PKCS1_OAEP.new(private_key)
        decrypted = cipher.decrypt(encrypted_data)
        return decrypted.decode()
    except Exception as e:
        raise ValueError("[RSA Decryption Failed] Incorrect decryption.") from e

# ECC Decryption (Simulated - placeholder logic for ECC encryption/decryption)
def decrypt_ecc(encrypted_data: bytes, private_key_bytes: bytes) -> str:
    try:
        ecc_key = ECC.import_key(private_key_bytes)
        h = SHA256.new(encrypted_data)
        verifier = DSS.new(ecc_key, 'fips-186-3')
        # This is mock since ECC alone does not encrypt; assumes signature + original msg
        return encrypted_data.decode(errors='ignore')  # Simulate as if ECC was used
    except Exception as e:
        return f"[ECC Decryption Failed] {str(e)}"

# ElGamal Decryption (Placeholder for complete implementation)
def decrypt_elgamal(encrypted_data: bytes, private_key_bytes: bytes) -> str:
    try:
        # ElGamal decryption requires implementation of ElGamal structure
        return "[ElGamal Decryption Placeholder - Not Implemented Fully Yet]"
    except Exception as e:
        return f"[ElGamal Decryption Failed] {str(e)}"

def calculate_image_checksum(image: Image.Image):
    with io.BytesIO() as buffer:
        image.save(buffer, format="PNG")
        image_bytes = buffer.getvalue()
        checksum = hashlib.sha256(image_bytes).hexdigest()
    return checksum

def extract_metadata(image):
    try:
        if hasattr(image, "getexif"):
            exif_data = image.getexif()
            if exif_data and len(exif_data) > 0:
                from PIL.ExifTags import TAGS
                return {TAGS.get(tag_id, tag_id): str(value) for tag_id, value in exif_data.items()}
        # Fallback: Check image.info for non-EXIF metadata (common in PNG)
        if image.info:
            return image.info
        return {"Note": "No metadata found in this image."}
    except Exception as e:
        return {"Error": f"Failed to extract metadata: {str(e)}"}


def detect_digital_watermark(original: Image.Image, suspect: Image.Image):
    original = original.convert("L").resize((256, 256))
    suspect = suspect.convert("L").resize((256, 256))

    diff = ImageChops.difference(original, suspect)
    diff_array = np.array(diff)
    change_ratio = np.count_nonzero(diff_array) / diff_array.size

    # If changes are small, likely just watermark or subtle changes
    return change_ratio < 0.05, round((1 - change_ratio) * 100, 2)

def generate_pdf_report(checksum=None, metadata=None, watermark_result=None, confidence=None):
    buffer = io.BytesIO()
    c = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    c.setFont("Helvetica-Bold", 16)
    c.drawString(40, height - 40, "🧾 Image Integrity Verification Report")

    y = height - 80
    c.setFont("Helvetica", 12)

    if checksum:
        c.drawString(40, y, "✔ Checksum (SHA-256):")
        y -= 20
        c.setFont("Courier", 10)
        c.drawString(60, y, checksum)
        y -= 30
        c.setFont("Helvetica", 12)

    if metadata:
        c.drawString(40, y, "📜 Metadata Extracted:")
        y -= 20
        for k, v in metadata.items():
            if y < 50:
                c.showPage()
                y = height - 40
            c.drawString(60, y, f"{k}: {v}")
            y -= 15

    if watermark_result is not None:
        result_text = "No Watermark Tampering Detected" if watermark_result else "Possible Tampering Detected"
        c.drawString(40, y, "🔍 Watermark Analysis:")
        y -= 20
        c.drawString(60, y, f"Result: {result_text}")
        y -= 15
        c.drawString(60, y, f"Similarity Confidence: {confidence}%")
        y -= 30

    c.setFont("Helvetica-Oblique", 10)
    c.drawString(40, 30, "Generated by Secure Image Integrity System")

    c.save()
    buffer.seek(0)
    return buffer
