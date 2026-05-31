"""
Batch scanner for multiple PowerShell scripts
Scans directory and generates report
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / 'training'))

import joblib
import csv
from tqdm import tqdm
from feature_extractor import PowerShellFeatureExtractor


class BatchScanner:
    """Scan multiple PowerShell scripts"""
    
    def __init__(self):
        models_dir = Path('./models')
        self.model = joblib.load(models_dir / 'random_forest_model.pkl')
        self.scaler = joblib.load(models_dir / 'scaler.pkl')
    
    def predict_file(self, filepath):
        """Predict for single file"""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            features_dict = PowerShellFeatureExtractor.extract_all_features(content)
            features_array = PowerShellFeatureExtractor.features_to_array(features_dict)
            features_scaled = self.scaler.transform([features_array])
            
            prediction = self.model.predict(features_scaled)[0]
            probability = self.model.predict_proba(features_scaled)[0]
            
            return {
                'file': str(filepath),
                'prediction': 'MALICIOUS' if prediction == 1 else 'BENIGN',
                'confidence': max(probability),
                'benign_prob': probability[0],
                'malicious_prob': probability[1],
                'status': 'SUCCESS'
            }
        except Exception as e:
            return {
                'file': str(filepath),
                'prediction': 'ERROR',
                'confidence': 0.0,
                'benign_prob': 0.0,
                'malicious_prob': 0.0,
                'status': f'ERROR: {str(e)}'
            }
    
    def scan_directory(self, directory, recursive=True):
        """Scan all PS1 files in directory"""
        directory = Path(directory)
        
        if recursive:
            ps1_files = list(directory.rglob('*.ps1'))
        else:
            ps1_files = list(directory.glob('*.ps1'))
        
        print(f"\nFound {len(ps1_files)} PowerShell scripts to scan")
        print("=" * 80)
        
        results = []
        malicious_count = 0
        benign_count = 0
        
        for filepath in tqdm(ps1_files, desc="Scanning"):
            result = self.predict_file(filepath)
            results.append(result)
            
            if result['prediction'] == 'MALICIOUS':
                malicious_count += 1
            elif result['prediction'] == 'BENIGN':
                benign_count += 1
        
        return results, malicious_count, benign_count
    
    def save_report(self, results, output_file='scan_report.csv'):
        """Save results to CSV"""
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=['file', 'prediction', 'confidence', 
                                                   'benign_prob', 'malicious_prob', 'status'])
            writer.writeheader()
            writer.writerows(results)
        
        return output_file
    
    def print_summary(self, results, malicious_count, benign_count):
        """Print summary report"""
        total = len(results)
        
        print("\n" + "=" * 80)
        print("SCAN SUMMARY")
        print("=" * 80)
        print(f"Total files scanned: {total}")
        print(f"Malicious detected:  {malicious_count} ({malicious_count/total*100:.1f}%)")
        print(f"Benign files:        {benign_count} ({benign_count/total*100:.1f}%)")
        print("=" * 80)
        
        # Show top malicious files
        malicious_results = [r for r in results if r['prediction'] == 'MALICIOUS']
        if malicious_results:
            print("\nMALICIOUS FILES DETECTED:")
            malicious_sorted = sorted(malicious_results, key=lambda x: x['confidence'], reverse=True)
            for i, result in enumerate(malicious_sorted[:10], 1):
                print(f"  {i}. {result['file']}")
                print(f"     Confidence: {result['confidence']*100:.2f}%")


def main():
    if len(sys.argv) < 2:
        print("=" * 80)
        print("PowerShell Batch Scanner")
        print("=" * 80)
        print("\nUsage: python batch_scanner.py <directory> [--recursive]")
        print("\nExamples:")
        print("  python batch_scanner.py ./scripts")
        print("  python batch_scanner.py ./scripts --recursive")
        print("  python batch_scanner.py malicious_pure")
        print("=" * 80)
        sys.exit(1)
    
    directory = sys.argv[1]
    recursive = '--recursive' in sys.argv or len(sys.argv) > 2
    
    if not Path(directory).exists():
        print(f" Error: Directory not found: {directory}")
        sys.exit(1)
    
    print("\n" + "=" * 80)
    print("PowerShell Malicious Script Batch Scanner")
    print("=" * 80)
    
    scanner = BatchScanner()
    results, malicious_count, benign_count = scanner.scan_directory(directory, recursive=recursive)
    
    # Print summary
    scanner.print_summary(results, malicious_count, benign_count)
    
    # Save report
    output_file = 'scan_report.csv'
    scanner.save_report(results, output_file)
    print(f"\nReport saved to: {output_file}")


if __name__ == '__main__':
    main()
