import joblib
import streamlit as st

# Load the saved model
gbc_model = joblib.load('Phishing-URL-Detection-master/main_model.pkl')

from urllib.parse import urlparse

def extract_features(url):
    parsed_url = urlparse(url)

    features = []

    # UsingIP
    features.append(1 if parsed_url.netloc.replace('.', '').isdigit() else 0)

    # LongURL
    features.append(len(url))

    # ShortURL (assuming a threshold of 54 characters)
    features.append(1 if len(url) < 54 else 0)

    # Symbol@
    features.append(1 if '@' in url else 0)

    # Redirecting//
    features.append(1 if '//' in url else 0)

    # PrefixSuffix-
    features.append(1 if '-' in parsed_url.netloc else 0)

    # SubDomains
    features.append(parsed_url.netloc.count('.'))

    # HTTPS
    features.append(1 if parsed_url.scheme == 'https' else 0)

    # Additional features (placeholder functions)
    features.append(get_domain_registration_length(parsed_url.netloc))
    features.append(check_for_favicon(url))
    features.append(check_non_standard_port(parsed_url.port))
    features.append(check_https_domain_url(url, parsed_url.netloc))
    features.append(check_request_url(parsed_url.query))
    features.append(check_anchor_url(parsed_url.fragment))
    features.append(check_links_in_script_tags(url))
    features.append(check_server_form_handler(url))
    features.append(check_info_email(url))
    features.append(check_abnormal_url(url))
    features.append(check_website_forwarding(url))
    features.append(check_custom_status_bar(url))
    features.append(check_disable_right_click(url))
    features.append(check_using_popup_window(url))
    features.append(check_iframe_redirection(url))
    features.append(get_age_of_domain(parsed_url.netloc))
    features.append(check_dns_recording(parsed_url.netloc))
    features.append(get_website_traffic(url))
    features.append(get_page_rank(url))
    features.append(check_google_index(url))
    features.append(count_links_pointing_to_page(url))
    features.append(check_stats_report(url))

    return features

# Placeholder functions for feature extraction
def get_domain_registration_length(domain):
    # Placeholder function to retrieve domain registration length
    return 0

def check_for_favicon(url):
    # Placeholder function to check for the presence of favicon
    return 0

# Example usage:


# Function to preprocess the URL and extract features
def preprocess_url(url):
    # Parse the URL to extract relevant information
    parsed_url = urlparse(url)

    # Example feature extraction: URL length
    url_length = len(url)

    # Example feature extraction: Number of dots in the URL
    num_dots = url.count('.')

    # Example feature extraction: Length of the hostname
    hostname_length = len(parsed_url.hostname) if parsed_url.hostname else 0

    # Return the extracted features as a list
    return [url_length, num_dots, hostname_length]


# Function to predict using the loaded model
def predict(url):
    # Preprocess the URL and extract features
    # Your preprocessing code here (not implemented in this example)
    x=extract_features(url)
    st.write(x)
    # Make prediction using the model
    features = preprocess_url(url)
    st.write(features)
    prediction = gbc_model.predict([features])[0]
    return prediction

# Streamlit UI
def main():
    st.title("Website Safety Prediction")
    url = st.text_input("Enter the URL:", "")
    if st.button("Predict"):
        prediction = predict(url)
        if prediction == 0:
            st.write("The website is predicted to be unsafe.")
        else:
            st.write("The website is predicted to be safe.")

if __name__ == "__main__":
    main()
