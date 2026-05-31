# PowerShell Malicious Script Detector - Applications

This folder contains 4 different applications to use the trained model:

## 1. **CLI Tool** - Command Line Interface
Simple single-script analysis from terminal.

**Usage:**
```bash
python apps/cli.py /path/to/script.ps1
python apps/cli.py malicious_pure/1.ps1
```

**Output:**
- Classification (MALICIOUS/BENIGN)
- Confidence percentage
- Individual probabilities

---

## 2. **Batch Scanner** - Directory Scanning
Scan entire directories and generate CSV reports.

**Installation:**
```bash
pip install tqdm
```

**Usage:**
```bash
# Scan single directory
python apps/batch_scanner.py ./scripts

# Scan with subdirectories
python apps/batch_scanner.py ./scripts --recursive

# Scan dataset
python apps/batch_scanner.py malicious_pure
```

**Output:**
- `scan_report.csv` - Detailed results for each file
- Console summary with malicious files list

---

## 3. **Web App** - Streamlit UI
User-friendly web interface for easy analysis.

**Installation:**
```bash
pip install streamlit
```

**Usage:**
```bash
streamlit run apps/web_app.py
```

**Features:**
- Text input tab for pasting scripts
- File upload tab for .ps1 files
- Real-time prediction and confidence scores
- Visual interface with metrics

**Access:** http://localhost:8501

---

## 4. **REST API** - Flask Server
Production-ready API for integration with other systems.

**Installation:**
```bash
pip install flask
```

**Usage:**
```bash
python apps/flask_api.py
```

**API Endpoints:**

### GET `/`
Get API information and available endpoints.

```bash
curl http://localhost:5000/
```

### GET `/health`
Health check.

```bash
curl http://localhost:5000/health
```

### POST `/predict`
Predict from JSON with script content.

```bash
curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"script": "your powershell code here"}'
```

**Response:**
```json
{
  "prediction": "MALICIOUS",
  "confidence": 0.9234,
  "benign_probability": 0.0766,
  "malicious_probability": 0.9234,
  "script_info": {
    "size_bytes": 1024,
    "lines": 25,
    "words": 150
  }
}
```

### POST `/predict/file`
Predict from uploaded file.

```bash
curl -X POST http://localhost:5000/predict/file \
  -F "file=@script.ps1"
```

### POST `/predict/batch`
Batch predict multiple scripts.

```bash
curl -X POST http://localhost:5000/predict/batch \
  -H "Content-Type: application/json" \
  -d '{"scripts": ["script1_content", "script2_content"]}'
```

---

## Model Performance

- **Accuracy:** 93.44%
- **Precision:** 94.90%
- **Recall:** 95.18%
- **F1-Score:** 0.9504
- **AUC-ROC:** 0.9855

---

## Quick Start

1. **CLI (Fastest):**
   ```bash
   python apps/cli.py malicious_pure/1.ps1
   ```

2. **Batch Scan (Full Directory):**
   ```bash
   python apps/batch_scanner.py malicious_pure
   ```

3. **Web UI (User-Friendly):**
   ```bash
   pip install streamlit
   streamlit run apps/web_app.py
   ```

4. **API (Integration):**
   ```bash
   pip install flask
   python apps/flask_api.py
   ```

---

## Requirements

**Core (Required):**
- joblib
- scikit-learn
- numpy
- pandas

**CLI & Batch Scanner:**
- tqdm

**Web App:**
- streamlit

**REST API:**
- flask

Install all:
```bash
pip install joblib scikit-learn numpy pandas tqdm streamlit flask
```

---

## File Structure

```
training/
├── feature_extractor.py  # Feature extraction
├── data_loader.py        # Data loading
└── train.py              # Training script

apps/
├── cli.py                # Command-line tool
├── batch_scanner.py      # Directory scanner
├── web_app.py            # Streamlit web interface
└── flask_api.py          # Flask REST API

models/
├── random_forest_model.pkl  # Trained model
└── scaler.pkl               # Feature scaler

output/
├── results.txt              # Training results
├── confusion_matrix.png     # Confusion matrix
├── roc_curve.png            # ROC curve
└── feature_importance.csv   # Feature importance
```

---

## Examples

### Example 1: Analyze a single malicious script
```bash
$ python apps/cli.py malicious_pure/1.ps1

================================================================================
PowerShell Malicious Script Detector
================================================================================

Script: malicious_pure/1.ps1
File size: 2048 bytes
Lines: 1

--------------------------------------------------------------------------------
Classification: 🚨 MALICIOUS
Confidence: 92.34%
--------------------------------------------------------------------------------
Benign probability:    0.0766 (7.66%)
Malicious probability: 0.9234 (92.34%)
================================================================================
```

### Example 2: Scan entire directory
```bash
$ python apps/batch_scanner.py malicious_pure

Found 4202 PowerShell scripts to scan
Scanning: 100%|████████| 4202/4202

================================================================================
SCAN SUMMARY
================================================================================
Total files scanned: 4202
Malicious detected:  4081 (97.1%)
Benign files:        121 (2.9%)
================================================================================

🚨 MALICIOUS FILES DETECTED:
  1. malicious_pure/1.ps1
     Confidence: 98.50%
  2. malicious_pure/2.ps1
     Confidence: 97.23%
  ...

✓ Report saved to: scan_report.csv
```

### Example 3: Use REST API
```bash
$ python apps/flask_api.py

# In another terminal:
$ curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"script": "Write-Host Hello"}'

{
  "prediction": "BENIGN",
  "confidence": 0.8934,
  "benign_probability": 0.8934,
  "malicious_probability": 0.1066,
  "script_info": {
    "size_bytes": 20,
    "lines": 1,
    "words": 2
  }
}
```

---

Choose the application that best fits your needs!
