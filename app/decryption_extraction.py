import streamlit as st
from streamlit_extras.colored_header import colored_header
from streamlit_extras.metric_cards import style_metric_cards
from streamlit_lottie import st_lottie
import requests
from PIL import Image
from encryptionTechniques import (
    lsb_extract_with_stegano, dct_extract, hybrid_extract,
    decrypt_rsa, decrypt_ecc, decrypt_elgamal
)

# Set page title
st.title("📨 Decryption & Extraction")
st.subheader("Retrieve your hidden messages securely from encrypted images")

# Load Lottie Animation
def load_lottie_url(url):
    r = requests.get(url)
    if r.status_code != 200:
        return None
    return r.json()

lottie_animation = load_lottie_url("https://assets10.lottiefiles.com/packages/lf20_w51pcehl.json")
if lottie_animation:
    st_lottie(lottie_animation, speed=1, width=800, height=400, key="decryption")

# File Upload Section
st.markdown("### 📥 Upload Encrypted Image")
enimage = st.file_uploader("Choose an image containing hidden data", type=["png", "jpg", "jpeg"])

# Steganography Method Selection
st.markdown("### 🖼️ Choose Steganography Extraction Method")
steganography_method = st.selectbox("Select a method used for encoding", [
    "Least Significant Bit (LSB) Insertion",
    "Discrete Cosine Transform (DCT)",
    "LSB + DCT (Hybrid)"])

# Decryption Algorithm Selection
st.markdown("### 🔑 Choose Decryption Algorithm")
decryption_method = st.selectbox("Select a decryption method", ["RSA"])

# Key Input Section
# Upload private key
st.markdown("### 🔐 Upload Your Private Key (.pem)")
private_key = st.file_uploader("Upload the private key used for encryption", type=["pem"])

# Extract & Decrypt Button
if st.button("🔓 Extract & Decrypt Message"):
    if enimage and private_key:
        st.image(enimage, caption="Encrypted Image", width = 200)
        image = Image.open(enimage)

        private_key_bytes = private_key.read()

        try:
            # Step 1: Extract hidden encrypted data
            if steganography_method == "Least Significant Bit (LSB) Insertion":
                encrypted_data = lsb_extract_with_stegano(image)
            elif steganography_method == "Discrete Cosine Transform (DCT)":
                encrypted_data = dct_extract(image)
            elif steganography_method == "LSB + DCT (Hybrid)":
                encrypted_data = hybrid_extract(image)

            # Step 2: Decrypt using selected method
            if decryption_method == "RSA":
                decrypted_message = decrypt_rsa(encrypted_data, private_key_bytes)
            elif decryption_method == "ECC (Elliptic Curve Cryptography)":
                decrypted_message = decrypt_ecc(encrypted_data, private_key_bytes)
            elif decryption_method == "ElGamal":
                decrypted_message = decrypt_elgamal(encrypted_data, private_key_bytes)

            # Step 3: Display result
            st.success("Hidden message successfully extracted and decrypted!")
            st.text_area("Decrypted Message", decrypted_message, height=200)

        except Exception as e:
            st.error(f"Error during extraction or decryption: {str(e)}")
    else:
        st.warning("Please upload an encrypted image and enter a private key.")

# Information Section
colored_header(label="How Decryption & Extraction Works", description="A brief explanation of the process", color_name="blue-70")
st.markdown(
    """
    The extraction and decryption process involves:
    
    ✅ **Steganography Extraction**: Retrieves hidden data using the selected method (LSB, DCT, or Hybrid).\n
    ✅ **Decryption Using RSA**: Uses your private key to decrypt the extracted message.\n
    ✅ **Integrity Check**: Ensures the extracted data hasn't been tampered with.
    \n
    Ensure you use the correct steganography method and private key used during encryption.
    """
)

# Simple Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; font-size: 14px; padding: 10px; color: #666;">
    <p><strong>🔐 PixShotCryption</strong></p>
    <p>
        Advanced Image-Based Encryption & Secure Communication System. 🔑
    </p>
    <p>© 2025 | Developed with ❤️ and responsibility by PixShotCryption Team.</p>
</div>
""", unsafe_allow_html=True)

style_metric_cards()
