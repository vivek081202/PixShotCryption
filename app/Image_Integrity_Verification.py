import streamlit as st
from streamlit_extras.colored_header import colored_header
from streamlit_lottie import st_lottie
import requests
from PIL import Image
from encryptionTechniques import generate_pdf_report, calculate_image_checksum, extract_metadata, detect_digital_watermark
import time
import io
import hashlib

# Set page title
st.title("📳 Image Integrity Verification")
st.subheader("Ensure the authenticity and security of your encrypted images")

# Load Lottie Animation
def load_lottie_url(url):
    r = requests.get(url)
    if r.status_code != 200:
        return None
    return r.json()

lottie_animation = load_lottie_url("https://assets4.lottiefiles.com/packages/lf20_fyye8szy.json")
if lottie_animation:
    st_lottie(lottie_animation, speed=1, width=800, height=400, key="integrity_verification")

# Tabs
tab1, tab2 = st.tabs(["🔍 Image Integrity Verification", "🧮 Checksum Comparison"])

# ---- Tab 1: Image Integrity Verification ----
with tab1:
    # File Upload Section
    st.markdown("### 📤 Upload Image for Verification")
    uploaded_image = st.file_uploader("Choose an encrypted image to verify", type=["png", "jpg", "jpeg"])

    # Additional Verification Options
    st.markdown("### 🛠 Advanced Verification Options")
    checksum_verification = st.checkbox("✔ Perform Checksum Verification")
    metadata_verification = st.checkbox("📜 Extract & Verify Metadata")
    digital_watermark_check = st.checkbox("🔍 Check for Digital Watermark")

    # Process Image Integrity Verification
    if st.button("🔄 Verify Integrity"):
        if uploaded_image:
            image = Image.open(uploaded_image)
            st.image(image, caption="Uploaded Image", width=200)

            with st.spinner("Verifying image integrity..."):
                time.sleep(1)
                # ✅ Checksum Verification
                if checksum_verification:
                    checksum = calculate_image_checksum(image)
                    st.markdown(f"**SHA-256 Checksum:** `{checksum}`")

                # ✅ Metadata Verification
                if metadata_verification:
                    metadata = extract_metadata(image)
                    st.markdown("### 📜 Extracted Metadata")
                    st.json(metadata)

                # ✅ Watermark Check (Placeholder comparison with self, update if you want original image)
                if digital_watermark_check:
                    watermark_detected, confidence = detect_digital_watermark(image, image)
                    result_text = "✅ No Watermark Tampering Detected" if watermark_detected else "⚠ Possible Watermark Tampering"
                    st.markdown(f"### 🔍 Watermark Analysis: {result_text}")
                    st.metric(label="Similarity Confidence", value=f"{confidence}%")

                st.success("✅ Image integrity check completed.")
        else:
            st.warning("⚠ Please upload an encrypted image to verify.")

    # Footer Information
    colored_header(label="Why Image Integrity Matters?", description="Understanding the importance of verification", color_name="blue-70")
    st.markdown(
        """
        Ensuring the integrity of encrypted images is critical for security and authentication. This feature helps:\n
        ✅ **Detect unauthorized modifications** and tampering.\n
        ✅ **Verify encryption methods** used for encoding data.\n
        ✅ **Enhance security** by checking embedded metadata and watermarks.\n
        ✅ **Maintain trustworthiness** of transmitted images.\n
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

# ---- Tab 2: Checksum Comparison ----
with tab2:
    st.markdown("## 🔐 Image Checksum Matcher")
    st.markdown("Verify whether the SHA-256 checksum of the uploaded image matches the expected value.")

    uploaded_image_for_checksum = st.file_uploader("📤 Upload Image", type=["png", "jpg", "jpeg"], key="checksum")

    expected_checksum = st.text_input("✏️ Enter Expected SHA-256 Checksum")

    if uploaded_image_for_checksum and expected_checksum:
        image = Image.open(uploaded_image_for_checksum)
        st.image(image, caption="Uploaded Image", width=200)

        def calculate_sha256(img):
            with io.BytesIO() as buffer:
                img.save(buffer, format="PNG")
                return hashlib.sha256(buffer.getvalue()).hexdigest()

        actual_checksum = calculate_sha256(image)
        st.markdown(f"**🧮 Calculated SHA-256 Checksum:** `{actual_checksum}`")

        if expected_checksum.strip().lower() == actual_checksum.lower():
            st.success("✅ Checksum matches! Image is intact.")
        else:
            st.error("❌ Checksum mismatch. Image might be tampered.")

    elif not uploaded_image_for_checksum and expected_checksum:
        st.warning("⚠️ Please upload an image to verify its checksum.")

    elif uploaded_image_for_checksum and not expected_checksum:
        st.info("ℹ️ Please enter the expected checksum to begin verification.")

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