"""
Flask REST API for PowerShell malicious script detection
Run with: python apps/flask_api.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / 'training'))

from flask import Flask, request, jsonify
import joblib
import json
from feature_extractor import PowerShellFeatureExtractor

app = Flask(__name__)

# Load model and scaler on startup
models_dir = Path('./models')
model = joblib.load(models_dir / 'random_forest_model.pkl')
scaler = joblib.load(models_dir / 'scaler.pkl')


@app.route('/', methods=['GET'])
def index():
    """API information"""
    return jsonify({
        'name': 'PowerShell Malicious Script Detector API',
        'version': '1.0',
        'endpoints': {
            'POST /predict': 'Predict if script is malicious (JSON body with "script" field)',
            'POST /predict/file': 'Predict from uploaded file',
            'GET /health': 'Health check'
        },
        'model_accuracy': '93.44%',
        'example': {
            'method': 'POST',
            'url': '/predict',
            'body': {
                'script': 'your_powershell_script_here'
            }
        }
    })


@app.route('/health', methods=['GET'])
def health():
    """Health check"""
    return jsonify({'status': 'healthy'}), 200


@app.route('/predict', methods=['POST'])
def predict():
    """Predict if script is malicious from JSON"""
    try:
        data = request.get_json()
        
        if not data or 'script' not in data:
            return jsonify({'error': 'Missing "script" field in JSON body'}), 400
        
        script_content = data['script']
        
        if not isinstance(script_content, str) or len(script_content) == 0:
            return jsonify({'error': 'Script content must be a non-empty string'}), 400
        
        # Extract features and predict
        features_dict = PowerShellFeatureExtractor.extract_all_features(script_content)
        features_array = PowerShellFeatureExtractor.features_to_array(features_dict)
        features_scaled = scaler.transform([features_array])
        
        prediction = model.predict(features_scaled)[0]
        probability = model.predict_proba(features_scaled)[0]
        
        response = {
            'prediction': 'MALICIOUS' if prediction == 1 else 'BENIGN',
            'confidence': float(max(probability)),
            'benign_probability': float(probability[0]),
            'malicious_probability': float(probability[1]),
            'script_info': {
                'size_bytes': len(script_content),
                'lines': len(script_content.split('\n')),
                'words': len(script_content.split())
            }
        }
        
        return jsonify(response), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/predict/file', methods=['POST'])
def predict_file():
    """Predict if script is malicious from uploaded file"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Read file content
        script_content = file.read().decode('utf-8', errors='ignore')
        
        if len(script_content) == 0:
            return jsonify({'error': 'File is empty'}), 400
        
        # Extract features and predict
        features_dict = PowerShellFeatureExtractor.extract_all_features(script_content)
        features_array = PowerShellFeatureExtractor.features_to_array(features_dict)
        features_scaled = scaler.transform([features_array])
        
        prediction = model.predict(features_scaled)[0]
        probability = model.predict_proba(features_scaled)[0]
        
        response = {
            'filename': file.filename,
            'prediction': 'MALICIOUS' if prediction == 1 else 'BENIGN',
            'confidence': float(max(probability)),
            'benign_probability': float(probability[0]),
            'malicious_probability': float(probability[1]),
            'script_info': {
                'size_bytes': len(script_content),
                'lines': len(script_content.split('\n')),
                'words': len(script_content.split())
            }
        }
        
        return jsonify(response), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/predict/batch', methods=['POST'])
def predict_batch():
    """Predict for multiple scripts"""
    try:
        data = request.get_json()
        
        if not data or 'scripts' not in data:
            return jsonify({'error': 'Missing "scripts" field in JSON body'}), 400
        
        scripts = data['scripts']
        
        if not isinstance(scripts, list):
            return jsonify({'error': '"scripts" must be a list'}), 400
        
        results = []
        malicious_count = 0
        benign_count = 0
        
        for i, script in enumerate(scripts):
            try:
                features_dict = PowerShellFeatureExtractor.extract_all_features(script)
                features_array = PowerShellFeatureExtractor.features_to_array(features_dict)
                features_scaled = scaler.transform([features_array])
                
                prediction = model.predict(features_scaled)[0]
                probability = model.predict_proba(features_scaled)[0]
                
                is_malicious = prediction == 1
                if is_malicious:
                    malicious_count += 1
                else:
                    benign_count += 1
                
                results.append({
                    'index': i,
                    'prediction': 'MALICIOUS' if is_malicious else 'BENIGN',
                    'confidence': float(max(probability)),
                    'benign_probability': float(probability[0]),
                    'malicious_probability': float(probability[1])
                })
            except Exception as e:
                results.append({
                    'index': i,
                    'error': str(e)
                })
        
        response = {
            'total': len(scripts),
            'malicious_count': malicious_count,
            'benign_count': benign_count,
            'results': results
        }
        
        return jsonify(response), 200
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    print("=" * 70)
    print("PowerShell Malicious Script Detector - Flask API")
    print("=" * 70)
    print("\nServer running on http://localhost:5000")
    print("\nAPI Endpoints:")
    print("  GET  /              - API information")
    print("  GET  /health        - Health check")
    print("  POST /predict       - Predict from JSON (script field)")
    print("  POST /predict/file  - Predict from uploaded file")
    print("  POST /predict/batch - Batch predict multiple scripts")
    print("\n" + "=" * 70 + "\n")
    
    app.run(debug=True, host='0.0.0.0', port=5000)
