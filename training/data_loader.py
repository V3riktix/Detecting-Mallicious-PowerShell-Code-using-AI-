"""
Data loading and preprocessing for PowerShell scripts
"""

import os
from pathlib import Path
import numpy as np
import pandas as pd
from tqdm import tqdm
from feature_extractor import PowerShellFeatureExtractor


class PowerShellDataLoader:
    """Load and prepare PowerShell scripts for training"""
    
    def __init__(self, data_dir):
        self.data_dir = Path(data_dir)
        self.malicious_pure_dir = self.data_dir / 'malicious_pure'
        self.benign_dir = self.data_dir / 'powershell_benign_dataset'
        self.mixed_malicious_dir = self.data_dir / 'mixed_malicious'
        
    def load_scripts(self, directory, label):
        """Load all scripts from a directory"""
        scripts = []
        labels = []
        
        if not directory.exists():
            print(f"Warning: {directory} does not exist")
            return scripts, labels
        
        ps1_files = list(directory.glob('*.ps1'))
        print(f"Loading {len(ps1_files)} scripts from {directory.name} (label={label})")
        
        for filepath in tqdm(ps1_files, desc=f"Loading {directory.name}"):
            try:
                with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    scripts.append(content)
                    labels.append(label)
            except Exception as e:
                print(f"Error reading {filepath}: {e}")
        
        return scripts, labels
    
    def load_all_data(self, include_mixed=True):
        """
        Load all data from directories
        
        Args:
            include_mixed: If True, include mixed_malicious in training (as malicious)
            
        Returns:
            X: List of script contents
            y: List of labels (0=benign, 1=malicious)
            file_info: DataFrame with metadata
        """
        X = []
        y = []
        file_info = []
        
        # Load malicious pure scripts
        mal_scripts, mal_labels = self.load_scripts(self.malicious_pure_dir, label=1)
        X.extend(mal_scripts)
        y.extend(mal_labels)
        
        # Load benign scripts
        ben_scripts, ben_labels = self.load_scripts(self.benign_dir, label=0)
        X.extend(ben_scripts)
        y.extend(ben_labels)
        
        # Load mixed malicious (optional)
        if include_mixed:
            mixed_scripts, mixed_labels = self.load_scripts(self.mixed_malicious_dir, label=1)
            X.extend(mixed_scripts)
            y.extend(mixed_labels)
        
        return X, np.array(y)
    
    def extract_features(self, X):
        """
        Extract features from all scripts
        
        Args:
            X: List of script contents
            
        Returns:
            features_array: Numpy array of shape (n_samples, n_features)
            feature_names: List of feature names
        """
        print(f"\nExtracting features from {len(X)} scripts...")
        
        feature_list = []
        for script in tqdm(X, desc="Extracting features"):
            features = PowerShellFeatureExtractor.extract_all_features(script)
            feature_array = PowerShellFeatureExtractor.features_to_array(features)
            feature_list.append(feature_array)
        
        features_array = np.array(feature_list)
        feature_names = PowerShellFeatureExtractor.get_feature_names()
        
        print(f"Features shape: {features_array.shape}")
        
        return features_array, feature_names
    
    def get_statistics(self, X, y):
        """Print dataset statistics"""
        print("\n" + "="*50)
        print("DATASET STATISTICS")
        print("="*50)
        print(f"Total scripts: {len(X)}")
        print(f"Malicious scripts: {sum(y == 1)} ({sum(y == 1) / len(y) * 100:.1f}%)")
        print(f"Benign scripts: {sum(y == 0)} ({sum(y == 0) / len(y) * 100:.1f}%)")
        print(f"Script sizes - Min: {min(len(s) for s in X)} bytes, Max: {max(len(s) for s in X)} bytes")
        print(f"Average script size: {np.mean([len(s) for s in X]):.0f} bytes")
        print("="*50)
