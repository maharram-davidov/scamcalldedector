"""
Configuration and constants for the Scam Detection System
"""

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Azure Configuration
AZURE_SPEECH_KEY = os.getenv("AZURE_SPEECH_KEY")
AZURE_SPEECH_REGION = os.getenv("AZURE_SPEECH_REGION")
AZURE_LANGUAGE_KEY = os.getenv("AZURE_LANGUAGE_KEY")
AZURE_LANGUAGE_ENDPOINT = os.getenv("AZURE_LANGUAGE_ENDPOINT")

# Google Gemini Configuration
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")
GEMINI_MODEL_NAME = os.getenv("GEMINI_MODEL_NAME", 'gemini-2.0-flash')

# Scam detection patterns (Azerbaijani)
SCAM_PATTERNS = {
    'urgency': [
        r'təcili', r'dərhal', r'indi', r'bu gün', 
        r'bu saat', r'tez', r'cəld', r'dərhal', r'məhdud zaman', r'son şans'
    ],
    'money': [
        r'pul', r'ödəniş', r'kart', r'bank', 
        r'kredit', r'borc', r'qaytarmaq', r'transfer', r'hesab', r'maliyyə', r'investisiya', r'uduş'
    ],
    'threat': [
        r'həbs', r'cəza', r'qanun', r'polis', 
        r'məhkəmə', r'şikayət', r'problem', r'təhlükə', r'bloklanacaq', r'bağlanacaq', r'itirəcəksiniz'
    ],
    'personal': [
        r'şəxsi məlumat', r'şifrə', r'pin', r'gizli kod',
        r'kart nömrəsi', r'hesab nömrəsi', r'şəxsiyyət', r'pasport', r'fin kod',
        r'kod', r'sms', r'verifikasiya', r'təsdiq', r'cvv', r'son istifadə tarixi'
    ],
    'verification': [
        r'telefonunuza gələn', r'sms kodu', r'verifikasiya kodu',
        r'təsdiq kodu', r'göndərilən kod', r'gələn kod',
        r'telefon kod', r'mobil kod', r'bir dəfəlik şifrə'
    ],
    'card_security': [
        r'kart şifrə', r'kart pin', r'kart kodu', r'kart məlumat',
        r'kart təhlükəsizlik', r'kart blok', r'kart aktivləşdirmə',
        r'kart yeniləmə', r'kart təsdiq', r'kart doğrulama',
        r'kart məlumatlarınızı', r'kart şifrənizi', r'kart pin kodunuzu',
        r'kartınızı təsdiqləyin', r'kartınızı yeniləyin', r'kartınızı aktivləşdirin'
    ]
}

# Risk factor weights
RISK_WEIGHTS = {
    'urgency_level': 0.15,
    'threat_level': 0.20,
    'personal_info_request': 0.25,
    'financial_request': 0.25,
    'emotional_manipulation': 0.10,
    'pii_exposure': 0.25,
    'card_security_risk': 0.30
}

# Model paths
MODEL_PATHS = {
    'ml_model': "scam_detector_model.joblib",
    'vectorizer': "scam_detector_vectorizer.joblib"
}

# Critical PII categories for Azerbaijan
CRITICAL_PII_CATEGORIES = [
    "CreditCardNumber", "AZBankAccountNumber", 
    "AZIdentityCardNumber", "AZPIN", "AZPassportNumber",
    "PhoneNumber", "Email"
] 