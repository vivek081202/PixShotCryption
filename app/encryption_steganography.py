import streamlit as st
from streamlit_extras.colored_header import colored_header
from streamlit_extras.metric_cards import style_metric_cards
from streamlit_lottie import st_lottie
import requests
from PIL import Image
from encryptionTechniques import encrypt_rsa, encrypt_ecc, encrypt_elgamal, lsb_encode_with_stegano, dct_encode, hybrid_encode
import io

# Set page title
st.title("📩 Encryption & Steganography")
st.subheader("Securely hide your messages within images using advanced encryption and steganography")

# Load Lottie Animation
@st.cache_data
def load_lottie_url(url):
    r = requests.get(url)
    if r.status_code != 200:
        return None
    return r.json()

lottie_animation = load_lottie_url("https://assets10.lottiefiles.com/packages/lf20_w51pcehl.json")
if lottie_animation:
    st_lottie(lottie_animation, speed=1, width=800, height=400, key="steganography")

# File Upload Section
st.markdown("### 📤 Upload an Image")
uploaded_image = st.file_uploader("Choose an image to hide your secret message", type=["png", "jpg", "jpeg"])

# Secret Message Input
st.markdown("### 🔑 Enter Your Secret Message")
secret_message = st.text_area("Type your confidential message here...")

# Steganography Algorithm Selection
st.markdown("### 🖼️ Choose Steganography Algorithm")
steganography_method = st.selectbox("Select a steganography method", [
    "Least Significant Bit (LSB) Insertion",
    "Discrete Cosine Transform (DCT)",
    "LSB + DCT (Hybrid)",
])

# Encryption Algorithm Selection
st.markdown("### 🔐 Choose Encryption Algorithm")
encryption_method = st.selectbox("Select an encryption method", ["RSA", "ECC (Elliptic Curve Cryptography)", "ElGamal"])

# Encrypt & store keys only once
if st.button("🔄 Encrypt & Hide Message"):
    if uploaded_image and secret_message:
        image = Image.open(uploaded_image)
        st.image(image, caption="Original Image", width=100)

        # Encrypt only if not already stored
        if encryption_method == "RSA":
            encrypted, priv_key = encrypt_rsa(secret_message)
        elif encryption_method == "ECC (Elliptic Curve Cryptography)":
            encrypted, priv_key = encrypt_ecc(secret_message)
        elif encryption_method == "ElGamal":
            encrypted, priv_key = encrypt_elgamal(secret_message)

        # Save keys in session
        st.session_state["encrypted_data"] = encrypted
        st.session_state["private_key"] = priv_key

        # Steganography
        if steganography_method == "Least Significant Bit (LSB) Insertion":
            result_img = lsb_encode_with_stegano(image, encrypted)
        elif steganography_method == "Discrete Cosine Transform (DCT)":
            result_img = dct_encode(image, encrypted)
        elif steganography_method == "LSB + DCT (Hybrid)":
            result_img = hybrid_encode(image, encrypted)

        # Store image
        img_bytes = io.BytesIO()
        result_img.save(img_bytes, format="PNG")
        img_bytes.seek(0)
        st.session_state["encoded_image"] = img_bytes

        st.image(result_img, caption="Encrypted & Hidden Image", width=100)
        st.success("Message successfully encrypted and hidden within the image!")
    else:
        st.warning("Please upload an image and enter a secret message.")

# Show download buttons **outside** the button callback
if "encoded_image" in st.session_state:
    st.download_button("📥 Download Encrypted Image", data=st.session_state["encoded_image"].getvalue(), file_name="encrypted_image.png")

if "private_key" in st.session_state:
    st.download_button("📥 Download Private Key", data=st.session_state["private_key"], file_name="private_key.pem")

# Information Section
colored_header(label="How Steganography Works", description="A brief explanation of the technique", color_name="blue-70")
st.markdown(
    """
    Steganography is a method of concealing a secret message within an image so that it remains undetectable. 
    This technique ensures that data remains private and is securely transmitted over open channels.

    ✅ **Least Significant Bit (LSB) Insertion** replaces the least significant bits of an image with secret data.\n
    ✅ **Hybrid Methods** combine multiple techniques for enhanced security.\n
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
