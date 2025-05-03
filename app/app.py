import streamlit as st
from streamlit_extras.colored_header import colored_header

# Set page configuration
st.set_page_config(
    page_title="PixShotCryption: Multi-Layered Image-Based Encryption and Secure Communication System",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

pages = {
    "App Navigations": [
        st.Page("home.py", title="Home", icon='🏠' ,default=True),
    ],
    "Modules": [
        st.Page("encryption_steganography.py", title="Encryption & Steganography", icon='📩'),
        st.Page("decryption_extraction.py", title="Decryption & Extraction",  icon='📨'),
        st.Page("Image_Integrity_Verification.py", title="Image Integrity Verification",  icon='📳'),
        st.Page("Secure_Communcation.py", title="Secure Communication",  icon='🔐'),
        st.Page("AI_AnamolyDetection.py", title="AI_Monitoring Anamoly Detection",  icon='🤖')
    ]
}

pg = st.navigation(pages)
pg.run()
