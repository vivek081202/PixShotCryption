import streamlit as st
from streamlit_extras.colored_header import colored_header
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.feature_extraction.text import TfidfVectorizer, CountVectorizer
from PIL import Image
import imagehash
import plotly.express as px
import numpy as np
import cv2
from skimage.metrics import structural_similarity as ssim
from wordcloud import WordCloud
import matplotlib.pyplot as plt

# === AI-Based Anomaly Detection Module ===
st.title("🧠 AI-Based Anomaly Detection")
st.subheader("Real-time detection of suspicious behavior and visual tampering with ML and CV enhancements")

# --- Tabs for Separation ---
tab1, tab2 = st.tabs([
    "🔎 Suspicious Text Communication",
    "🖼 Unauthorized Image Modification"
])

# --- TAB 1: TEXT ANOMALY DETECTION ---
with tab1:
    colored_header(
        label="Detect Suspicious Communication Patterns",
        description="Upload communication logs to identify anomalous lines",
        color_name="violet-70"
    )

    uploaded_log = st.file_uploader(
        "📤 Upload Text Log (TXT format)", type=["txt"], key="log_file"
    )
    contamination_rate = st.slider(
        "Anomaly Sensitivity (Contamination Rate)",
        min_value=0.01, max_value=0.5, value=0.1
    )

    if uploaded_log:
        # Read and preprocess logs
        raw_lines = uploaded_log.read().decode("utf-8").splitlines()
        if len(raw_lines) > 5:
            # Parse timestamps assuming ISO format at start
            timestamps = []
            messages = []
            for line in raw_lines:
                parts = line.split(' ', 2)
                try:
                    ts = pd.to_datetime(f"{parts[0]} {parts[1]}")
                    msg = parts[2]
                except:
                    ts = pd.NaT
                    msg = line
                timestamps.append(ts)
                messages.append(msg)

            # TF-IDF + Isolation Forest
            vect = TfidfVectorizer(stop_words='english', max_features=500)
            X = vect.fit_transform(messages)
            iso = IsolationForest(contamination=contamination_rate, random_state=42)
            preds = iso.fit_predict(X.toarray())
            scores = iso.decision_function(X.toarray())

            # Compile DataFrame
            df = pd.DataFrame({
                "Timestamp": timestamps,
                "Message": messages,
                "Anomaly Score": scores,
                "Flag": ["❌ Anomaly" if p == -1 else "✅ Normal" for p in preds]
            })

            # Display table
            st.markdown("### 📄 Detection Results")
            st.dataframe(df, use_container_width=True)

            # 1️⃣ Time Series of Anomaly Scores
            st.markdown("### 📈 Anomaly Score Over Time")
            fig_time = px.line(
                df.dropna(subset=['Timestamp']),
                x='Timestamp', y='Anomaly Score',
                title='Anomaly Score Timeline'
            )
            st.plotly_chart(fig_time, use_container_width=True)

            # 2️⃣ Distribution of Scores
            st.markdown("### 📊 Anomaly Score Distribution")
            fig_hist = px.histogram(df, x='Anomaly Score', nbins=30, title='Score Distribution')
            st.plotly_chart(fig_hist, use_container_width=True)

            # 3️⃣ Top Terms in Anomalous Messages
            anomaly_msgs = df[df['Flag']=='❌ Anomaly']['Message']
            if not anomaly_msgs.empty:
                cv = CountVectorizer(stop_words='english', ngram_range=(1,2), max_features=15)
                Xc = cv.fit_transform(anomaly_msgs)
                terms = cv.get_feature_names_out()
                counts = np.array(Xc.sum(axis=0)).flatten()
                df_terms = pd.DataFrame({'Term': terms, 'Count': counts}).sort_values('Count', ascending=True)
                st.markdown("### 📝 Top Terms in Anomalies")
                fig_terms = px.bar(df_terms, x='Count', y='Term', orientation='h', title='Frequent Terms in Anomalies')
                st.plotly_chart(fig_terms, use_container_width=True)

            # 4️⃣ Anomalies by Hour Heatmap
            if df['Timestamp'].notna().any():
                df['Hour'] = df['Timestamp'].dt.hour
                heat = df.groupby('Hour')['Anomaly Score'].mean().reset_index()
                st.markdown("### 🌡️ Average Anomaly Score by Hour")
                fig_heat = px.bar(heat, x='Hour', y='Anomaly Score', title='Score by Hour of Day')
                st.plotly_chart(fig_heat, use_container_width=True)

            if not anomaly_msgs.empty:
                wordcloud = WordCloud(width=800, height=400, background_color='white').generate(' '.join(anomaly_msgs))
                st.markdown("### ☁️ Word Cloud of Anomalous Communications")
                fig_wc, ax = plt.subplots(figsize=(10, 5))
                ax.imshow(wordcloud, interpolation='bilinear')
                ax.axis('off')
                st.pyplot(fig_wc)

            # 6️⃣ Time between Suspicious Messages
            df_anomaly_time = df[df['Flag']=='❌ Anomaly'].dropna(subset=['Timestamp'])
            if len(df_anomaly_time) >= 2:
                df_anomaly_time = df_anomaly_time.sort_values('Timestamp')
                time_diffs = df_anomaly_time['Timestamp'].diff().dropna().dt.total_seconds() / 60  # minutes

                st.markdown("### ⏱️ Time Gap Between Anomalies (Minutes)")
                fig_diff = px.histogram(
                    time_diffs, nbins=20,
                    labels={'value': 'Minutes'},
                    title='Distribution of Time Gaps Between Anomalies'
                )
                st.plotly_chart(fig_diff, use_container_width=True)

            # 6️⃣ Time between Suspicious Messages
            df_anomaly_time = df[df['Flag']=='❌ Anomaly'].dropna(subset=['Timestamp'])
            if len(df_anomaly_time) >= 2:
                df_anomaly_time = df_anomaly_time.sort_values('Timestamp')
                time_diffs = df_anomaly_time['Timestamp'].diff().dropna().dt.total_seconds() / 60  # minutes

                st.markdown("### ⏱️ Time Gap Between Anomalies (Minutes)")
                fig_diff = px.histogram(
                    time_diffs, nbins=20,
                    labels={'value': 'Minutes'},
                    title='Distribution of Time Gaps Between Anomalies'
                )
                st.plotly_chart(fig_diff, use_container_width=True)

# --- TAB 2: IMAGE TAMPERING DETECTION with CV Enhancements ---
with tab2:
    colored_header(
        label="Detect Unauthorized Modifications",
        description="Compare two images to detect tampering or alteration",
        color_name="red-70"
    )

    original_img = st.file_uploader(
        "🖼 Upload Original Image", type=["png", "jpg", "jpeg"], key="orig_img"
    )
    suspect_img = st.file_uploader(
        "🖼 Upload Suspect Image", type=["png", "jpg", "jpeg"], key="suspect_img"
    )
    threshold = st.slider(
        "Tampering Sensitivity Threshold", min_value=1, max_value=30, value=10
    )

    if original_img and suspect_img:
        orig = Image.open(original_img).convert('RGB')
        suspect = Image.open(suspect_img).convert('RGB')

        # Perceptual Hash
        hash1 = imagehash.phash(orig)
        hash2 = imagehash.phash(suspect)
        diff = hash1 - hash2
        similarity = max(0, 1 - diff/64)

        # Structural Similarity (SSIM)
        orig_gray = np.array(orig.convert('L'))
        sus_gray = np.array(suspect.convert('L'))
        score, ssim_map = ssim(orig_gray, sus_gray, full=True)
        ssim_map_norm = (ssim_map - ssim_map.min()) / (ssim_map.max() - ssim_map.min())

        # Edge Detection Difference (Canny)
        edges1 = cv2.Canny(orig_gray, 100, 200)
        edges2 = cv2.Canny(sus_gray, 100, 200)
        edge_diff = np.abs(edges1.astype(int) - edges2.astype(int))
        edge_diff_pct = edge_diff.sum() / edge_diff.size

        # Display images and SSIM heatmap
        st.markdown("### 🔬 Visual Comparison")
        col_orig, col_sus, col_heat = st.columns(3)
        col_orig.image(orig, caption="Original", use_container_width=True)
        col_sus.image(suspect, caption="Suspect", use_container_width=True)
        fig_heat = px.imshow(
            ssim_map_norm, color_continuous_scale='RdBu',
            title='SSIM Heatmap', aspect='equal'
        )
        col_heat.plotly_chart(fig_heat, use_container_width=True)

        # Display hash diff and SSIM score
        st.markdown(f"**🔍 Perceptual Hash Difference:** `{diff}`")
        st.markdown(f"**📈 Structural Similarity Index (SSIM):** `{score:.4f}`")

        # SSIM distribution plot
        st.markdown("### 📊 SSIM Score Distribution")
        ssim_flat = ssim_map_norm.flatten()
        fig_ssim_hist = px.histogram(
            x=ssim_flat, nbins=50,
            title='SSIM Value Distribution'
        )
        st.plotly_chart(fig_ssim_hist, use_container_width=True)

        # Edge difference metric and bar
        st.markdown(f"**🖇️ Edge Difference Percentage:** `{edge_diff_pct*100:.2f}%`")
        df_edge = pd.DataFrame({
            'Metric': ['Hash Diff', 'Edge Diff %', 'SSIM Score'],
            'Value': [int(diff), edge_diff_pct*100, score]
        })
        fig_metrics = px.bar(
            df_edge, x='Metric', y='Value', text='Value',
            title='Comparison Metrics'
        )
        st.plotly_chart(fig_metrics, use_container_width=True)

        # Final Verdict
        st.markdown("### 🚦 Final Verdict")
        if diff <= threshold and score > 0.9 and edge_diff_pct < 0.02:
            st.success("✅ No unauthorized modifications detected.")
        else:
            st.error("🚨 Possible tampering or visual alteration detected.")

        # Confidence metric and progress
        conf_pct = f"{(similarity+score-edge_diff_pct)/2*100:.2f}%"
        st.metric("🔢 Overall Integrity Confidence", conf_pct)
        safe_progress = max(0, min(100, int(float(conf_pct.replace('%','')))))
        st.progress(safe_progress)


    elif original_img or suspect_img:
        st.info("ℹ️ Please upload both original and suspect images to proceed.")
