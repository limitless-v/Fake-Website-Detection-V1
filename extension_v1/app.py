from flask import Flask, request, jsonify
import pickle
import pandas as pd
import os
import sys

# Add the parent directory to sys.path to import from model.py
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from model import extract_features  # Import the function to extract features

app = Flask(__name__)

# Define paths with proper directory handling
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
MODEL_PATH = os.path.join(parent_dir, "models", "phishing_model.pkl")
FEATURES_PATH = os.path.join(parent_dir, "models", "feature_names.pkl")

try:
    with open(MODEL_PATH, "rb") as f:
        model = pickle.load(f)
    
    with open(FEATURES_PATH, "rb") as f:
        feature_names = pickle.load(f)
    
    print(f"Successfully loaded model from {MODEL_PATH}")
except Exception as e:
    print(f"Error loading model: {e}")
    raise

@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Parse request data
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({"error": "Invalid request"}), 400
        
        url = data['url']
        
        # Extract features from URL
        features_dict = extract_features(url)
        
        # Ensure features are in the correct order
        features_df = pd.DataFrame([{name: features_dict.get(name, 0) for name in feature_names}])
        
        # Make prediction
        prediction = model.predict(features_df)[0]
        proba = model.predict_proba(features_df)[0]  # Get probability

        # Determine message
        result = "Phishing" if prediction == 1 else "Safe"
        confidence = round(proba[prediction] * 100, 2)
        security_message = "This site is secure" if result == "Safe" else "This site is a phishing attempt!"

        return jsonify({
            "prediction": result,
            "confidence": f"{confidence}%",
            "message": security_message
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Add a GET endpoint for easier testing in browsers
@app.route('/check', methods=['GET'])
def check():
    try:
        url = request.args.get('url')
        if not url:
            return jsonify({"error": "No URL provided"}), 400
            
        # Extract features from URL
        features_dict = extract_features(url)
        
        # Ensure features are in the correct order
        features_df = pd.DataFrame([{name: features_dict.get(name, 0) for name in feature_names}])
        
        # Make prediction
        prediction = model.predict(features_df)[0]
        proba = model.predict_proba(features_df)[0]  # Get probability

        # Determine message
        result = "Phishing" if prediction == 1 else "Safe"
        confidence = round(proba[prediction] * 100, 2)
        security_message = "This site is secure" if result == "Safe" else "This site is a phishing attempt!"

        return jsonify({
            "url": url,
            "prediction": result,
            "confidence": f"{confidence}%",
            "message": security_message
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
