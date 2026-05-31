# PowerShell Malicious Script Detector

Projekt wykrywania złośliwych skryptów PowerShell przy użyciu uczenia maszynowego. Model oparty na algorytmie Random Forest analizuje cechy tekstowe, składniowe i tokenowe skryptu, by sklasyfikować go jako **MALICIOUS** lub **BENIGN**.

---

## Struktura projektu

```
projekt/
├── training/
│   ├── feature_extractor.py  # Ekstrakcja cech ze skryptów
│   ├── data_loader.py        # Ładowanie i preprocessing danych
│   └── train.py              # Skrypt trenujący model
│
├── apps/
│   ├── cli.py                # Interfejs wiersza poleceń
│   ├── batch_scanner.py      # Skaner katalogów
│   ├── web_app.py            # Interfejs webowy (Streamlit)
│   └── flask_api.py          # REST API (Flask)
│
├── models/
│   ├── random_forest_model.pkl  # Wytrenowany model
│   └── scaler.pkl               # Skaler cech
│
├── output/
│   ├── results.txt              # Wyniki treningu
│   ├── confusion_matrix.png     # Macierz pomyłek
│   ├── roc_curve.png            # Krzywa ROC
│   └── feature_importance.csv   # Ważność cech
│
├── malicious_pure/              # Zbiór złośliwych skryptów (etykieta: 1)
├── mixed_malicious/             # Skrypty mieszane — złośliwe zachowanie w normalnym kodzie (etykieta: 1)
└── powershell_benign_dataset/   # Zbiór łagodnych skryptów (etykieta: 0)
```

---

## Instalacja

**Wymagania:** Python 3.8+

```bash
pip install -r requirements.txt
```

---

## Wyniki modelu

Model wytrenowany na zbiorze **12 720 skryptów** (8404 złośliwych, 4316 łagodnych).

| Metryka    | Wartość |
|------------|---------|
| Accuracy   | 93.44%  |
| Precision  | 94.90%  |
| Recall     | 95.18%  |
| F1-Score   | 0.9504  |
| AUC-ROC    | 0.9855  |

---

## Aplikacje

### 1. CLI — analiza pojedynczego skryptu

Najprostszy sposób na sprawdzenie jednego pliku `.ps1` z poziomu terminala.

```bash
python apps/cli.py /path/to/script.ps1
```

---

### 2. Batch Scanner — skanowanie katalogu

Skanuje cały katalog i zapisuje wyniki do pliku `scan_report.csv`.

```bash
# Katalog bez podkatalogów
python apps/batch_scanner.py ./skrypty

# Rekurencyjnie z podkatalogami
python apps/batch_scanner.py ./skrypty --recursive
```

---

### 3. Web App — interfejs graficzny (Streamlit)

Graficzny interfejs webowy — możliwość wklejenia skryptu lub przesłania pliku.

```bash
streamlit run apps/web_app.py
```

Dostępny pod: http://localhost:8501

---

### 4. REST API — Flask

API do integracji z innymi systemami. Obsługuje analizę pojedynczego skryptu, przesłanego pliku oraz wsadową analizę wielu skryptów.

```bash
python apps/flask_api.py
```

Dostępne endpointy:

| Metoda | Endpoint          | Opis                            |
|--------|-------------------|---------------------------------|
| GET    | `/health`         | Status serwera                  |
| POST   | `/predict`        | Analiza skryptu (JSON)          |
| POST   | `/predict/file`   | Analiza z przesłanego pliku     |
| POST   | `/predict/batch`  | Analiza wielu skryptów naraz    |

Przykład użycia:

```bash
curl -X POST http://localhost:5000/predict \
  -H "Content-Type: application/json" \
  -d '{"script": "Write-Host Hello"}'
```

```json
{
  "prediction": "BENIGN",
  "confidence": 0.8934,
  "benign_probability": 0.8934,
  "malicious_probability": 0.1066
}
```
