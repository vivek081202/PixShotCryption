import streamlit as st
from streamlit_extras.colored_header import colored_header
from streamlit_extras.let_it_rain import rain
from streamlit_extras.metric_cards import style_metric_cards
from streamlit_lottie import st_lottie
import requests

# Title and Subtitle
st.title("🔐 PixShotCryption")
st.subheader("Advanced Image-Based Encryption & Secure Communication System")

# Background Animation
#rain(emoji="🔐", font_size=20, falling_speed=10, animation_length="infinite")

# Load Lottie Animation
@st.cache_data
def load_lottie_url(url):
    r = requests.get(url)
    if r.status_code != 200:
        return None
    return r.json()

lottie_animation = load_lottie_url("https://lottie.host/72287056-1422-43d9-bd17-1905b395d71b/kgWh7aSDRr.json")

if lottie_animation:
    st_lottie(lottie_animation, speed=1, width=750, height=550, key="encryption")

# About Section
st.markdown(
    """
    **PixShotCryption** is an innovative security platform that merges encryption, steganography, and AI-based anomaly detection 
    to safeguard sensitive data. By embedding encrypted messages and files into images, it ensures confidentiality and authenticity.
    
    🔹 **Multi-Image Steganography** - Securely distribute encrypted data across multiple images.  
    🔹 **AES & RSA Encryption** - Ensuring end-to-end data security.  
    🔹 **Image Integrity Verification** - Prevent unauthorized tampering.  
    🔹 **AI-Based Anomaly Detection** - Identify suspicious activities in communication.  
    """
)

# Features Section
colored_header(label="Key Features", description="Essential capabilities of PixShotCryption", color_name="blue-70")

col1, col2, col3 = st.columns(3)

with col1:
    st.image("../Images/data-encryption.png", width=80)
    st.markdown("**Multi-Image Steganography**")
    st.write("Distribute encrypted messages or files across multiple images for enhanced security.")

with col2:
    st.image("../Images/encryption.png", width=80)
    st.markdown("**Encryption & Secure Key Management**")
    st.write("AES & RSA encryption techniques ensure safe transmission and storage of sensitive data.")

with col3:
    st.image("../Images/anomaly.png", width=80)
    st.markdown("**AI-Based Anomaly Detection**")
    st.write("AI-powered monitoring to detect unauthorized access and modifications.")

# Additional System Components
colored_header(label="Additional Functionalities", description="Enhancing security and usability",  color_name="blue-70")

col4, col5 = st.columns(2)

with col4:
    st.image("https://cdn-icons-png.flaticon.com/512/5025/5025157.png", width=80)
    st.markdown("**Secure Key Sharing**")
    st.write("Exchange encryption keys securely via QR codes or encrypted files.")

    st.image("https://cdn-icons-png.flaticon.com/512/2920/2920244.png", width=80)
    st.markdown("**Metadata Steganography**")
    st.write("Hide sensitive messages within image metadata for additional security.")

with col5:
    st.image("../Images/error.png", width=80)
    st.markdown("**Error Detection & Correction**")
    st.write("Ensure reliable transmission of encoded images with error correction techniques.")

    st.image("https://cdn-icons-png.flaticon.com/512/2953/2953433.png", width=80)
    st.markdown("**Network Optimization**")
    st.write("Optimize image size for seamless and efficient data transmission.")

# Call to Action
st.markdown(
    """
    ---
    🎯 **Get Started Today!** 
    Select a module from the navigation panel and explore PixShotCryption’s functionalities.
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
