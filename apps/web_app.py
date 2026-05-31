"""
Streamlit web app for PowerShell malicious script detection
Run with: streamlit run apps/web_app.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / 'training'))

import streamlit as st
import joblib
from feature_extractor import PowerShellFeatureExtractor


@st.cache_resource
def load_model():
    """Load model and scaler"""
    models_dir = Path('./models')
    model = joblib.load(models_dir / 'random_forest_model.pkl')
    scaler = joblib.load(models_dir / 'scaler.pkl')
    return model, scaler


def predict_script(content, model, scaler):
    """Predict if script is malicious"""
    features_dict = PowerShellFeatureExtractor.extract_all_features(content)
    features_array = PowerShellFeatureExtractor.features_to_array(features_dict)
    features_scaled = scaler.transform([features_array])
    
    prediction = model.predict(features_scaled)[0]
    probability = model.predict_proba(features_scaled)[0]
    
    return prediction, probability


def main():
    # Page config
    st.set_page_config(
        page_title="PowerShell Malicious Script Detector",
        page_icon=None,
        layout="wide"
    )
    
    # Header
    st.title("PowerShell Malicious Script Detector")
    st.markdown("---")
    
    # Load model
    model, scaler = load_model()
    
    # Tabs
    tab1, tab2 = st.tabs(["Text Input", "File Upload"])
    
    with tab1:
        st.subheader("Paste PowerShell Script")
        script_text = st.text_area(
            "Enter PowerShell script content:",
            height=300,
            placeholder="Paste your PowerShell script here..."
        )
        
        if st.button("Analyze Script", key="analyze_text"):
            if script_text.strip():
                with st.spinner("Analyzing script..."):
                    prediction, probability = predict_script(script_text, model, scaler)
                    
                    # Display results
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        if prediction == 1:
                            st.error("MALICIOUS")
                        else:
                            st.success("BENIGN")
                    
                    with col2:
                        confidence = max(probability) * 100
                        st.metric("Confidence", f"{confidence:.2f}%")
                    
                    # Probabilities
                    st.markdown("---")
                    st.subheader("Prediction Probabilities")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.metric("Benign Probability", f"{probability[0]:.4f} ({probability[0]*100:.2f}%)")
                    with col2:
                        st.metric("Malicious Probability", f"{probability[1]:.4f} ({probability[1]*100:.2f}%)")
                    
                    # Script info
                    st.markdown("---")
                    st.subheader("Script Information")
                    
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("File Size", f"{len(script_text)} bytes")
                    with col2:
                        st.metric("Lines", len(script_text.split('\n')))
                    with col3:
                        st.metric("Words", len(script_text.split()))
            else:
                st.warning("Please enter a PowerShell script")
    
    with tab2:
        st.subheader("Upload PowerShell File")
        uploaded_file = st.file_uploader("Choose a .ps1 file", type=['ps1', 'txt'])
        
        if uploaded_file is not None:
            script_content = uploaded_file.read().decode('utf-8', errors='ignore')
            
            st.text_area("File content preview:", value=script_content[:500], height=100, disabled=True)
            
            if st.button("Analyze File", key="analyze_file"):
                with st.spinner("Analyzing file..."):
                    prediction, probability = predict_script(script_content, model, scaler)
                    
                    # Display results
                    col1, col2 = st.columns(2)
                    
                    with col1:
                        if prediction == 1:
                            st.error("MALICIOUS")
                        else:
                            st.success("BENIGN")
                    
                    with col2:
                        confidence = max(probability) * 100
                        st.metric("Confidence", f"{confidence:.2f}%")
                    
                    # Probabilities
                    st.markdown("---")
                    st.subheader("Prediction Probabilities")
                    
                    col1, col2 = st.columns(2)
                    with col1:
                        st.metric("Benign Probability", f"{probability[0]:.4f} ({probability[0]*100:.2f}%)")
                    with col2:
                        st.metric("Malicious Probability", f"{probability[1]:.4f} ({probability[1]*100:.2f}%)")
                    
                    # File info
                    st.markdown("---")
                    st.subheader("File Information")
                    
                    col1, col2, col3 = st.columns(3)
                    with col1:
                        st.metric("File Size", f"{len(script_content)} bytes")
                    with col2:
                        st.metric("Lines", len(script_content.split('\n')))
                    with col3:
                        st.metric("Words", len(script_content.split()))
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center; color: gray; font-size: 12px;'>
    <p>PowerShell Malicious Script Detector | Random Forest Model | Accuracy: 93.44%</p>
    </div>
    """, unsafe_allow_html=True)


if __name__ == '__main__':
    main()
