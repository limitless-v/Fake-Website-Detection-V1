import re
import requests
import pandas as pd
import numpy as np
from bs4 import BeautifulSoup
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import pickle
import os

# Function to extract features from a URL (kept for testing new URLs)
def extract_features(url):
    features = {}
    
    # Basic URL features
    features['length_url'] = len(url)
    features['length_hostname'] = len(url.split('/')[2]) if len(url.split('/')) > 2 else 0
    
    # Check if URL contains IP address
    if len(url.split('/')) > 2:
        hostname = url.split('/')[2]
        features['ip'] = 1 if re.match(r'\d+\.\d+\.\d+\.\d+', hostname) else 0
    else:
        features['ip'] = 0
        
    features['nb_dots'] = url.count('.')
    features['nb_hyphens'] = url.count('-')
    features['nb_at'] = url.count('@')
    features['nb_qm'] = url.count('?')
    features['nb_and'] = url.count('&')
    features['nb_or'] = url.count('|')
    features['nb_eq'] = url.count('=')
    features['nb_underscore'] = url.count('_')
    features['nb_tilde'] = url.count('~')
    features['nb_percent'] = url.count('%')
    features['nb_slash'] = url.count('/')
    features['nb_star'] = url.count('*')
    features['nb_colon'] = url.count(':')
    features['nb_comma'] = url.count(',')
    features['nb_semicolumn'] = url.count(';')
    features['nb_dollar'] = url.count('$')
    features['nb_space'] = url.count(' ')
    features['nb_www'] = 1 if 'www' in url else 0
    features['nb_com'] = 1 if '.com' in url else 0
    features['nb_dslash'] = url.count('//')
    features['http_in_path'] = 1 if 'http' in url.split('?')[0] else 0
    features['https_token'] = 1 if 'https' in url else 0
    
    # Ratio features
    features['ratio_digits_url'] = len(re.findall(r'\d', url)) / len(url) if len(url) > 0 else 0
    
    # Set default values for other features
    # This is a simplified approach - in a real implementation, you would extract all 87 features
    for col in ['ratio_digits_host', 'punycode', 'port', 'tld_in_path', 'tld_in_subdomain', 
                'abnormal_subdomain', 'nb_subdomains', 'prefix_suffix', 'random_domain', 
                'shortening_service', 'path_extension', 'nb_redirection', 'nb_external_redirection',
                'length_words_raw', 'char_repeat', 'shortest_words_raw', 'shortest_word_host',
                'shortest_word_path', 'longest_words_raw', 'longest_word_host', 'longest_word_path',
                'avg_words_raw', 'avg_word_host', 'avg_word_path', 'phish_hints', 'domain_in_brand',
                'brand_in_subdomain', 'brand_in_path', 'suspecious_tld', 'statistical_report',
                'nb_hyperlinks', 'ratio_intHyperlinks', 'ratio_extHyperlinks', 'ratio_nullHyperlinks',
                'nb_extCSS', 'ratio_intRedirection', 'ratio_extRedirection', 'ratio_intErrors',
                'ratio_extErrors', 'login_form', 'external_favicon', 'links_in_tags', 'submit_email',
                'ratio_intMedia', 'ratio_extMedia', 'sfh', 'iframe', 'popup_window', 'safe_anchor',
                'onmouseover', 'right_clic', 'empty_title', 'domain_in_title', 'domain_with_copyright',
                'whois_registered_domain', 'domain_registration_length', 'domain_age', 'web_traffic',
                'dns_record', 'google_index', 'page_rank']:
        features[col] = 0
    
    # Try to get more features from the website content
    try:
        response = requests.get(url, timeout=3)
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Extract some additional features from the page content
        features['nb_hyperlinks'] = len(soup.find_all('a'))
        features['iframe'] = 1 if soup.find('iframe') else 0
        features['popup_window'] = 1 if 'window.open' in response.text else 0
        features['empty_title'] = 1 if not soup.title or not soup.title.text.strip() else 0
    except:
        # If request fails, keep default values
        pass
    
    return features

# Load the dataset
df = pd.read_csv('dataset_phishing.csv')

# Selecting relevant features (excluding 'url' and keeping numerical features)
feature_columns = [col for col in df.columns if col not in ['url', 'status']]
X = df[feature_columns]

# Convert 'status' to numerical labels (phishing = 1, legitimate = 0)
y = np.where(df['status'] == 'phishing', 1, 0)

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train a Random Forest model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Test model accuracy
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Model Accuracy: {accuracy * 100:.2f}%")
print("\nClassification Report:")
print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))

# Save the model and feature names for future use
if not os.path.exists('models'):
    os.makedirs('models')
    
with open('models/phishing_model.pkl', 'wb') as f:
    pickle.dump(model, f)
    
with open('models/feature_names.pkl', 'wb') as f:
    pickle.dump(X.columns.tolist(), f)

# Function to predict if a new URL is phishing or legitimate
def predict_url(url):
    try:
        # Extract features from the URL
        features_dict = extract_features(url)
        
        # Get the feature names in the correct order
        with open('models/feature_names.pkl', 'rb') as f:
            feature_names = pickle.load(f)
        
        # Create a DataFrame with the features in the correct order
        features_df = pd.DataFrame([{name: features_dict.get(name, 0) for name in feature_names}])
        
        # Load the model
        with open('models/phishing_model.pkl', 'rb') as f:
            loaded_model = pickle.load(f)
        
        # Make prediction
        prediction = loaded_model.predict(features_df)
        
        # Output the prediction result
        print(f"URL: {url} -> Prediction: {'Phishing' if prediction[0] == 1 else 'Legitimate'}")
        
        # Get prediction probability
        proba = loaded_model.predict_proba(features_df)[0]
        print(f"Confidence: Legitimate {proba[0]:.2f}, Phishing {proba[1]:.2f}")
        
        return prediction[0]
    except Exception as e:
        print(f"Error during prediction: {e}")
        return None

# Example usage
print("\nTesting prediction on example URLs:")
try:
    predict_url("https://www.w3schools.com/")
    predict_url("http://google.com")
    # Add a known phishing URL for testing
    predict_url("https://coupons.wyscale.com/")
except Exception as e:
    print(f"Error: {e}")
