# PixShotCryption: AI-Based Anomaly Detection

PixShotCryption is a Streamlit web application for real-time detection of suspicious behavior in text communications and unauthorized image modifications using advanced Machine Learning (ML) and Computer Vision (CV) techniques.

![image](https://github.com/user-attachments/assets/94df684f-371a-4f69-92a1-fca915b6f442)

## Features

### 1. Suspicious Text Communication Detection
- Upload communication logs (TXT format) to identify anomalous lines.
- Uses TF-IDF vectorization and Isolation Forest for anomaly detection.
- Visualizes anomaly scores over time, score distributions, and top terms in anomalies.
- Provides heatmaps and word clouds for deeper insights.
- Calculates time gaps between suspicious messages.

![image](https://github.com/user-attachments/assets/ee83b87a-9693-47fd-9171-6c7b5e7dae10)
<br>
![image](https://github.com/user-attachments/assets/6e5d396a-b76d-4807-8cbe-1f1e15f1d700)

### 2. Unauthorized Image Modification Detection
- Upload and compare two images (original and suspect) to detect tampering or alterations.
- Uses perceptual hashing, Structural Similarity Index (SSIM), and edge detection for comparison.
- Visualizes SSIM heatmaps, score distributions, and comparison metrics.
- Provides a final verdict and confidence metric for image integrity.

![image](https://github.com/user-attachments/assets/1a191620-9486-44b8-b767-940a88f644d0)
<br>
![image](https://github.com/user-attachments/assets/11f4adfa-3cc4-41e1-9b57-2d3feb63dfef)
<br>
![image](https://github.com/user-attachments/assets/a60d4a17-55c7-4316-9597-788a668b06eb)
<br>
![image](https://github.com/user-attachments/assets/5a59c803-1579-46bd-ba41-344cc031bb9a)

### 3. Secure Communication
- Secure communication features for encrypted messaging and data transfer.

![image](https://github.com/user-attachments/assets/ce559199-3eeb-4081-880a-7db36f053c1b)

### 4. Image Integrity Verification
- Tools for verifying the integrity of images and detecting unauthorized modifications.

![image](https://github.com/user-attachments/assets/d8710d13-01f3-4b55-a09f-b32ccd210ebb)
<br>
![image](https://github.com/user-attachments/assets/5c88d6f6-21fc-4482-856f-89147f77228d)
<br>
![image](https://github.com/user-attachments/assets/3ce7c13d-d153-4f80-b311-1f612a346cf1)
<br>
![image](https://github.com/user-attachments/assets/5796c2bc-0b3c-4158-b421-89a71b04e094)

### 5. Encryption Techniques
- Various encryption methods for securing data and communications.
![image](https://github.com/user-attachments/assets/0baa1435-963e-44a9-9953-1b26a6934b76)
![image](https://github.com/user-attachments/assets/7931bfde-1f67-4fa3-be7a-18e760614fbb)

### 6. Steganography and Decryption
- Tools for embedding and extracting hidden data within images.
![image](https://github.com/user-attachments/assets/4e60b002-d234-4330-90ab-2c4f87ee5a96)


## How to Run

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
2. **Start the Streamlit app:**
   ```bash
   streamlit run app/AI_AnamolyDetection.py
   ```

## File Structure
- `app/`: Contains all modules and the main Streamlit application.
  - `AI_AnamolyDetection.py`: Main Streamlit application for anomaly detection.
  - `Secure_Communcation.py`: Secure communication features.
  - `Image_Integrity_Verification.py`: Image integrity verification tools.
  - `encryptionTechniques.py`: Various encryption methods.
  - `encryption_steganography.py`: Steganography tools.
  - `decryption_extraction.py`: Decryption and extraction tools.
  - `home.py`: Home page for the application.
  - `app.py`: Application entry point.

## Requirements
See `requirements.txt` for all dependencies.

### Designed and Developed by:
> **Vivek Kumar Singh**
> [LinkedIn](https://www.linkedin.com/in/vivek-singh-858941201/)
