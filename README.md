# PixShotCryption: AI-Based Anomaly Detection

PixShotCryption is a Streamlit web application for real-time detection of suspicious behavior in text communications and unauthorized image modifications using advanced Machine Learning (ML) and Computer Vision (CV) techniques.

## Features

### 1. Suspicious Text Communication Detection
- Upload communication logs (TXT format) to identify anomalous lines.
- Uses TF-IDF vectorization and Isolation Forest for anomaly detection.
- Visualizes anomaly scores over time, score distributions, and top terms in anomalies.
- Provides heatmaps and word clouds for deeper insights.
- Calculates time gaps between suspicious messages.

### 2. Unauthorized Image Modification Detection
- Upload and compare two images (original and suspect) to detect tampering or alterations.
- Uses perceptual hashing, Structural Similarity Index (SSIM), and edge detection for comparison.
- Visualizes SSIM heatmaps, score distributions, and comparison metrics.
- Provides a final verdict and confidence metric for image integrity.

### 3. Secure Communication
- Secure communication features for encrypted messaging and data transfer.

### 4. Image Integrity Verification
- Tools for verifying the integrity of images and detecting unauthorized modifications.

### 5. Encryption Techniques
- Various encryption methods for securing data and communications.

### 6. Steganography and Decryption
- Tools for embedding and extracting hidden data within images.

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

## License
MIT License 