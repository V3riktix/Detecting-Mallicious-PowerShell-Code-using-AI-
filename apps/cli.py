"""
CLI tool to detect malicious PowerShell scripts
Usage: python apps/cli.py <script_path>
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / 'training'))

import joblib
from feature_extractor import PowerShellFeatureExtractor


def predict_script(script_path):
    """Predict if a PowerShell script is malicious"""
    
    models_dir = Path('./models/')
    
    # Load model and scaler
    model = joblib.load(models_dir / 'random_forest_model.pkl')
    scaler = joblib.load(models_dir / 'scaler.pkl')
    
    # Read script
    with open(script_path, 'r', encoding='utf-8', errors='ignore') as f:
        script_content = f.read()
    
    # Extract features
    features_dict = PowerShellFeatureExtractor.extract_all_features(script_content)
    features_array = PowerShellFeatureExtractor.features_to_array(features_dict)
    features_scaled = scaler.transform([features_array])
    
    # Predict
    prediction = model.predict(features_scaled)[0]
    probability = model.predict_proba(features_scaled)[0]
    
    return prediction, probability, script_content


def main():
    if len(sys.argv) < 2:
        print("=" * 70)
        print("PowerShell Malicious Script Detector - CLI")
        print("=" * 70)
        print("\nUsage: python cli.py <script_path>")
        print("\nExample:")
        print("  python cli.py /path/to/script.ps1")
        print("  python cli.py malicious_pure/1.ps1")
        print("=" * 70)
        sys.exit(1)
    
    script_path = sys.argv[1]
    
    if not Path(script_path).exists():
        print(f" Error: File not found: {script_path}")
        sys.exit(1)
    
    print("\n" + "=" * 70)
    print("PowerShell Malicious Script Detector")
    print("=" * 70)
    
    prediction, probability, content = predict_script(script_path)
    
    # Results
    label = " MALICIOUS" if prediction == 1 else " BENIGN"
    confidence = max(probability) * 100
    
    print(f"\nScript: {script_path}")
    print(f"File size: {len(content)} bytes")
    print(f"Lines: {len(content.split(chr(10)))}")
    print("\n" + "-" * 70)
    print(f"Classification: {label}")
    print(f"Confidence: {confidence:.2f}%")
    print("-" * 70)
    print(f"Benign probability:    {probability[0]:.4f} ({probability[0]*100:.2f}%)")
    print(f"Malicious probability: {probability[1]:.4f} ({probability[1]*100:.2f}%)")
    print("=" * 70 + "\n")
    
    return 0 if prediction == 1 else 1


if __name__ == '__main__':
    sys.exit(main())
