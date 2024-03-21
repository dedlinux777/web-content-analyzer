# Import Required Libraries
import requests
from bs4 import BeautifulSoup
from collections import Counter
import spacy
import re
from msticpy.sectools import TILookup

# Load spaCy Model
nlp = spacy.load('en_core_web_sm')

# Define Function to Extract and Analyze
def extract_and_analyze(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    input_text = ' '.join(soup.getText().split())

    # Perform NER using spaCy
    doc = nlp(input_text)
    entities = [(ent.text, ent.label_) for ent in doc.ents]

    # Define regular expressions for sensitive information detection
    sensitive_patterns = {
        # Define patterns for detecting sensitive information
        'Credit Card Numbers': r'\b(?:\d[ -]*?){13,16}\b',
        'Email Addresses': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'Phone Numbers': r'\b(?:\+?(\d{1,3}))?[-. (]?\d{3}[-. )]?\d{3}[-. ]?\d{4}\b'
    }

    detected_sensitive_info = {}
    for category, pattern in sensitive_patterns.items():
        matches = re.findall(pattern, input_text)
        if matches:
            detected_sensitive_info[category] = matches

    # Count most common words
    words = input_text.split()
    common_words = Counter(words).most_common(5)

    return entities, detected_sensitive_info, common_words

# Define Function to Analyze Website
def analyze_website(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')
    for link in soup.find_all('a', href=True):
        href = link.get('href')
        if href.startswith('http'):
            print(f"Analyzing webpage: {href}")
            entities, detected_sensitive_info, common_words = extract_and_analyze(href)
            print("Named Entities:", entities)
            print("Detected Sensitive Info:", detected_sensitive_info)
            print("Most common words:", common_words)

            # Perform IOC lookup using TILookup
            ti_lookup = TILookup()
            ioc = {'URL': href}  # IOC format for URL
            ioc_result = ti_lookup.lookup_ioc(data=ioc)

            print("Threat Intelligence Lookup Result:")
            print(ioc_result)
            print("-" * 50)

# Main Execution
if __name__ == "__main__":
    url = 'http://testphp.vulnweb.com/login.php'  # Change URL to target website
    print(f"Fetching hyperlinks from: {url}")
    print("-" * 50)
    analyze_website(url)
