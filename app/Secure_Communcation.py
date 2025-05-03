import streamlit as st
from streamlit_extras.colored_header import colored_header
import socket
import hashlib
import time
from PIL import Image
import io
from cryptography.fernet import Fernet
import plotly.express as px
import pandas as pd
import base64
import qrcode

# --- Session State for Key Management and Payload ---
if "key" not in st.session_state:
    st.session_state["key"] = None
if "payload" not in st.session_state:
    st.session_state["payload"] = None
if "encrypted_size" not in st.session_state:
    st.session_state["encrypted_size"] = 0
if "data_transfer_rates" not in st.session_state:
    st.session_state["data_transfer_rates"] = []
if "time_intervals" not in st.session_state:
    st.session_state["time_intervals"] = []

# Sidebar: Key Management
st.sidebar.header("🔑 Key Management")
key_action = st.sidebar.selectbox("Key Action", ("Generate New Key", "Upload Key File", "Use Existing Key"))

if key_action == "Generate New Key":
    key = Fernet.generate_key()
    st.session_state["key"] = key
    st.sidebar.success("New encryption key generated.")
elif key_action == "Upload Key File":
    uploaded_key = st.sidebar.file_uploader("Upload .key file", type=["key"])
    if uploaded_key:
        key = uploaded_key.read()
        st.session_state["key"] = key
        st.sidebar.success("Encryption key loaded from file.")
elif key_action == "Use Existing Key":
    if st.session_state.get("key"):
        key = st.session_state["key"]
    else:
        st.sidebar.warning("No existing key found. Please generate or upload.")
        key = None

# Show key download and QR if available
if st.session_state.get("key"):
    key = st.session_state["key"]
    st.sidebar.download_button(
        label="Download Key File",
        data=key,
        file_name="encryption_key.key",
        mime="application/octet-stream"
    )
    encoded_key = base64.urlsafe_b64encode(key).decode()
    qr = qrcode.make(encoded_key)
    buf = io.BytesIO()
    qr.save(buf, format="PNG")
    st.sidebar.image(buf.getvalue(), caption="Key QR Code", use_container_width=True)

# Initialize cipher if key available
cipher = Fernet(key) if key else None

# Page Title
st.title("📡 PixShotCryption - Secure Image Sharing") 
st.subheader("Establish a safe and verified channel to share images securely.")

# Network Connection Setup
colored_header(label="🔗 Connection Setup", description="Configure peer-to-peer communication", color_name="blue-70")
mode = st.radio("Select Mode", ("Sender", "Receiver"))
protocol = st.radio("Select Protocol", ("TCP", "UDP"))
ip_address = st.text_input("Enter IP Address", "127.0.0.1")
port = st.number_input("Enter Port Number", min_value=1024, max_value=65535, value=12345)

# Network Speed & Latency Graph
def plot_network_stats():
    if st.session_state["data_transfer_rates"]:
        df = pd.DataFrame({
            "Time (s)": st.session_state["time_intervals"],
            "Speed (KB/s)": st.session_state["data_transfer_rates"]
        })
        fig = px.line(df, x="Time (s)", y="Speed (KB/s)", title="Network Transfer Speed", markers=True)
        st.plotly_chart(fig, use_container_width=True)

# Main App Logic
if cipher is None:
    st.error("Please generate or upload an encryption key from the sidebar.")
elif mode == "Sender":
    st.markdown("### 📤 Upload an Image to Send")
    uploaded_image = st.file_uploader("Choose an image", type=["png", "jpg", "jpeg"])

    if uploaded_image:
        image = Image.open(uploaded_image)
        st.image(image, caption="Selected Image", use_container_width=True)

        if st.button("🔐 Encrypt & Prepare for Sending"):
            try:
                image_bytes = uploaded_image.read()
                st.write(f"Image size: {len(image_bytes)} bytes")
                encrypted = cipher.encrypt(image_bytes)
                checksum = hashlib.md5(encrypted).hexdigest().encode()
                st.session_state["payload"] = encrypted + checksum
                st.session_state["encrypted_size"] = len(encrypted)
                st.success("Image encrypted and ready to send.")
                st.text(f"MD5 Checksum: {checksum.decode()}")
            except Exception as e:
                st.error(f"❌ Error during encryption: {e}")

        if st.session_state.get("payload"):
            st.download_button(
                label="Download Encrypted File",
                data=st.session_state["payload"],
                file_name="encrypted_image.enc",
                mime="application/octet-stream"
            )

        if st.session_state.get("payload"):
            if st.button("📡 Send Image to Receiver"):
                start = time.time()
                try:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if protocol == "UDP" else socket.SOCK_STREAM) as s:
                        if protocol == "TCP":
                            st.info(f"🔄 Connecting to {ip_address}:{port}…")
                            s.connect((ip_address, port))
                            st.success(f"✅ Connected to {ip_address}:{port}")
                            st.info("📡 Sending encrypted image...")
                            s.sendall(st.session_state["payload"])

                        else:
                            if len(st.session_state["payload"]) > 65000:
                                st.warning("⚠️ Payload too large for UDP. Try TCP for large files.")
                            st.info(f"📡 Sending encrypted image via UDP to {ip_address}:{port}...")
                            s.sendto(st.session_state["payload"], (ip_address, port))

                    duration = time.time() - start
                    kbps = st.session_state["encrypted_size"] / duration / 1024
                    st.session_state["data_transfer_rates"].append(kbps)
                    st.session_state["time_intervals"].append(duration)
                    st.success("🎉 Image sent successfully!")
                    plot_network_stats()

                except socket.error as err:
                    st.error(f"❌ Socket error during send: {err}")
                except Exception as e:
                    st.error(f"❌ Unexpected error during send: {e}")

elif mode == "Receiver":
    st.markdown("### 📥 Receive and Decrypt an Image")

    if st.button("Start Receiving" if protocol == "TCP" else "Wait for Incoming UDP"):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM if protocol == "UDP" else socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((ip_address, port))

                if protocol == "TCP":
                    s.listen(1)
                    st.info("Waiting for TCP connection...")
                    conn, addr = s.accept()
                    with conn:
                        st.success(f"✅ Connected by {addr}")
                        buffer = b""
                        while True:
                            chunk = conn.recv(40000)
                            if not chunk:
                                break
                            buffer += chunk
                        data = buffer
                else:
                    st.info("Waiting for incoming UDP data...")
                    data, addr = s.recvfrom(65507)

                if len(data) <= 32:
                    st.error("❌ Received data is too small or corrupted.")
                else:
                    received_checksum = data[-32:].decode()
                    encrypted_image = data[:-32]
                    calculated_checksum = hashlib.md5(encrypted_image).hexdigest()

                    if received_checksum == calculated_checksum:
                        st.success("✅ Checksum verified. Image received correctly!")

                        try:
                            decrypted = cipher.decrypt(encrypted_image)

                            # --- ✨ Corrected Image Opening ✨ ---
                            img_bytes = io.BytesIO(decrypted)

                            try:
                                test_img = Image.open(img_bytes)
                                #test_img.verify()  # Only verify, don't use this object
                                #img_bytes.seek(0)  # Reset after verify
                                final_img = Image.open(img_bytes)  # Proper re-open

                                st.success("✅ Decrypted Image Loaded Successfully!")
                                st.image(final_img, caption="Decrypted Image", use_container_width=True)

                                st.download_button(
                                    label="Download Decrypted Image",
                                    data=img_bytes.getvalue(),
                                    file_name="received_image.png",
                                    mime="image/png"
                                )

                            except (IOError, SyntaxError) as e_img:
                                st.error(f"❌ Decrypted data is not a valid image: {e_img}")

                                st.download_button(
                                    label="Download Decrypted Raw Bytes",
                                    data=decrypted,
                                    file_name="decrypted_output.raw",
                                    mime="application/octet-stream"
                                )

                        except Exception as e:
                            st.error(f"❌ Error decrypting image: {e}")

                    else:
                        st.error("❌ Checksum mismatch! Data may be corrupted.")

        except Exception as e:
            st.error(f"❌ Error during receive: {e}")
