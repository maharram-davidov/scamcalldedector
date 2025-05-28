"""
Hybrid Scam Detection System with Real-Time Voice Input and Gemini AI Analysis
This system analyzes voice input in real-time to detect potential scam attempts using
Azure Cognitive Services for speech recognition and text analysis, combined with
Google's Gemini AI for advanced analysis.
"""

import os
import threading
import re
from datetime import datetime
from typing import Dict, List, Optional, Set, Any
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib

import azure.cognitiveservices.speech as speechsdk
from azure.ai.textanalytics import (
    AnalyzeSentimentAction,
    RecognizeEntitiesAction,
    ExtractKeyPhrasesAction,
    TextAnalyticsClient
)
from azure.core.credentials import AzureKeyCredential
from dotenv import load_dotenv
import google.generativeai as genai

# Load environment variables
load_dotenv()

# Configure Gemini AI
genai.configure(api_key=os.getenv("GOOGLE_API_KEY"))
GEMINI_MODEL = genai.GenerativeModel('gemini-2.0-flash')

# Scam detection patterns
SCAM_PATTERNS = {
    'urgency': [
        r'təcili', r'dərhal', r'indi', r'bu gün', 
        r'bu saat', r'tez', r'cəld', r'dərhal'
    ],
    'money': [
        r'pul', r'ödəniş', r'kart', r'bank', 
        r'kredit', r'borc', r'qaytarmaq', r'transfer', r'hesab'
    ],
    'threat': [
        r'həbs', r'cəza', r'qanun', r'polis', 
        r'məhkəmə', r'şikayət', r'problem', r'təhlükə'
    ],
    'personal': [
        r'şəxsi məlumat', r'şifrə', r'pin', 
        r'kart nömrəsi', r'hesab nömrəsi', r'şəxsiyyət',
        r'kod', r'sms', r'verifikasiya', r'təsdiq'
    ],
    'verification': [
        r'telefonunuza gələn', r'sms kodu', r'verifikasiya kodu',
        r'təsdiq kodu', r'göndərilən kod', r'gələn kod',
        r'telefon kod', r'mobil kod'
    ]
}

class MLScamDetector:
    """Machine Learning based scam detection model."""
    
    def __init__(self):
        """Initialize the ML model and vectorizer."""
        self.model = None
        self.vectorizer = None
        self.model_path = "scam_detector_model.joblib"
        self.vectorizer_path = "scam_detector_vectorizer.joblib"
        self._load_or_create_model()
    
    def _load_or_create_model(self):
        """Load existing model or create a new one if not exists."""
        try:
            self.model = joblib.load(self.model_path)
            self.vectorizer = joblib.load(self.vectorizer_path)
            print("✅ ML model yükləndi")
        except:
            print("ℹ️ Yeni ML model yaradılır...")
            self.model = RandomForestClassifier(n_estimators=100, random_state=42)
            self.vectorizer = TfidfVectorizer(max_features=1000)
            # İlkin məlumatlarla modeli öyrədirik
            self._train_initial_model()
    
    def _train_initial_model(self):
        """Train the model with initial data."""
        # İlkin məlumatlar
        texts = [
            # Kod tələbi olan nümunələr
            "Telefonunuza gələn kodu deyil.",
            "SMS ilə gələn kodu təsdiqləyin.",
            "Telefonunuza göndərilən verifikasiya kodunu deyil.",
            "Mobil nömrənizə gələn kodu bildirin.",
            "Təsdiq kodunu deyil.",
            
            # Bank və kart nümunələri
            "Salam, Kapital Bankdan zəng edirik. Kart məlumatlarınızı təsdiqləyin.",
            "Təcili olaraq bank hesabınızı yeniləyin.",
            "Sizin bank hesabınızda problem var.",
            "Kartınızı bloklamaq üçün şifrənizi göndərin.",
            
            # Normal zənglər
            "Salam, necəsiz?",
            "Gününüz xeyrə qalsın.",
            "Sizə kömək edə bilərəm?",
            "Bankdan zəng edirik, kartınızı yeniləyin.",
            "Şəxsi məlumatlarınızı təsdiqləyin.",
            "Hesabınızda problem var, dərhal həll edin.",
            
            # Əlavə scam nümunələri
            "Telefonunuza gələn kodu deyil, hesabınız bloklanacaq.",
            "SMS kodu təsdiqləyin, kartınız bloklanacaq.",
            "Verifikasiya kodunu deyil, hesabınız təhlükədədir.",
            "Telefonunuza gələn kodu bildirin, şifrənizi yeniləyək.",
            "Mobil nömrənizə gələn kodu deyil, hesabınızı qoruyaq."
        ]
        labels = [1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1]  # 1: scam, 0: normal
        
        # Mətnləri vektorlaşdırırıq
        X = self.vectorizer.fit_transform(texts)
        # Modeli öyrədirik
        self.model.fit(X, labels)
        
        # Modeli saxlayırıq
        joblib.dump(self.model, self.model_path)
        joblib.dump(self.vectorizer, self.vectorizer_path)
        print("✅ ML model yaradıldı və saxlanıldı")
    
    def predict(self, text: str) -> float:
        """
        Predict scam probability for given text.
        
        Args:
            text: Input text to analyze
            
        Returns:
            float: Probability of being a scam (0-1)
        """
        # Mətni vektorlaşdırırıq
        X = self.vectorizer.transform([text])
        # Ehtimalı hesablayırıq
        proba = self.model.predict_proba(X)[0]
        return proba[1]  # Scam ehtimalını qaytarırıq
    
    def update_model(self, text: str, is_scam: bool):
        """
        Update model with new data.
        
        Args:
            text: New text sample
            is_scam: Whether the text is a scam
        """
        # Mövcud vektorlaşdırıcı ilə yeni mətni vektorlaşdırırıq
        X = self.vectorizer.transform([text])
        # Modeli yeniləyirik
        self.model.partial_fit(X, [1 if is_scam else 0], classes=[0, 1])
        # Yenilənmiş modeli saxlayırıq
        joblib.dump(self.model, self.model_path)

class ScamAnalyzer:
    """Analyzes text for potential scam attempts using multiple detection methods."""
    
    def __init__(self):
        """Initialize the ScamAnalyzer with required clients and state."""
        self.text_analytics_client = TextAnalyticsClient(
            endpoint=os.getenv("AZURE_LANGUAGE_ENDPOINT"),
            credential=AzureKeyCredential(os.getenv("AZURE_LANGUAGE_KEY"))
        )
        self.conversation_history: List[Dict[str, Any]] = []
        self.scam_score: float = 0
        self.conversation_start_time: datetime = datetime.now()
        self.suspicious_entities: Set[str] = set()
        self.risk_factors: Dict[str, float] = {
            'urgency_level': 0,
            'threat_level': 0,
            'personal_info_request': 0,
            'financial_request': 0,
            'emotional_manipulation': 0
        }
        # ML modelini əlavə edirik
        self.ml_detector = MLScamDetector()

    def analyze_text(self, text: str, force_gemini: bool = False) -> Optional[Dict[str, Any]]:
        """
        Analyze text for potential scam indicators.
        
        Args:
            text: The text to analyze
            force_gemini: Whether to force Gemini AI analysis regardless of score
            
        Returns:
            Dict containing analysis results or None if analysis fails
        """
        try:
            self.conversation_history.append({
                'text': text, 
                'timestamp': datetime.now()
            })
            
            # Basic pattern matching
            pattern_matches = self._check_patterns(text)
            
            # Azure Language Service analysis
            documents = [text]
            lang = self.text_analytics_client.detect_language(documents=documents)[0]
            
            poller = self.text_analytics_client.begin_analyze_actions(
                documents=documents,
                actions=[
                    AnalyzeSentimentAction(),
                    RecognizeEntitiesAction(),
                    ExtractKeyPhrasesAction()
                ],
                show_stats=False
            )

            # Process Azure analysis results
            sentiment_result = None
            entities_result = None
            key_phrases_result = None
            
            for action in poller.result():
                for result in action:
                    if result.is_error:
                        continue
                    if result.kind == "SentimentAnalysis":
                        sentiment_result = result
                    elif result.kind == "EntityRecognition":
                        entities_result = result
                    elif result.kind == "KeyPhraseExtraction":
                        key_phrases_result = result

            if not all([sentiment_result, entities_result, key_phrases_result]):
                print("❌ Missing Azure analysis results")
                return None

            # Analyze context and calculate risk factors
            context = self._analyze_context(text, entities_result, key_phrases_result)
            self._calculate_risk_factors(
                sentiment_result, 
                pattern_matches, 
                context, 
                None, 
                key_phrases_result, 
                text
            )
            
            # Calculate final scam score
            rule_based_score = self._calculate_scam_score()
            
            # ML modelindən skor alırıq
            ml_score = self.ml_detector.predict(text)
            
            # İki skoru birləşdiririk (70% rule-based, 30% ML)
            self.scam_score = (rule_based_score * 0.7) + (ml_score * 0.3)

            # Trigger Gemini AI analysis if needed
            if force_gemini or self.scam_score >= 0.5:
                def run_gemini():
                    analysis = self._get_gemini_analysis(text, context)
                    print("\n🤖 Gemini AI Analysis:")
                    print(analysis)
                threading.Thread(target=run_gemini).start()

            return {
                'text': text,
                'scam_score': self.scam_score,
                'rule_based_score': rule_based_score,
                'ml_score': ml_score,
                'risk_factors': self.risk_factors,
                'context': context
            }

        except Exception as e:
            print(f"❌ Error in analyze_text: {str(e)}")
            return None

    def _check_patterns(self, text: str) -> Dict[str, List[str]]:
        """Check text against known scam patterns."""
        matches = {}
        for cat, patterns in SCAM_PATTERNS.items():
            matches[cat] = [p for p in patterns if re.search(p, text.lower())]
        return matches

    def _analyze_context(
        self, 
        text: str, 
        entities: Any, 
        key_phrases: Any
    ) -> Dict[str, Any]:
        """Analyze the context of the conversation."""
        context = {
            'suspicious_entities': [],
            'time_pressure': False,
            'authority_claim': False
        }
        
        for ent in entities.entities:
            if ent.category in ['Person', 'Organization', 'PhoneNumber']:
                self.suspicious_entities.add(ent.text)
                context['suspicious_entities'].append(ent.text)
                
        for phrase in key_phrases.key_phrases:
            if any(w in phrase.lower() for w in ['təcili', 'dərhal', 'tez']):
                context['time_pressure'] = True
            if any(w in phrase.lower() for w in ['polis', 'bank', 'məhkəmə']):
                context['authority_claim'] = True
                
        return context

    def _calculate_risk_factors(
        self,
        sentiment: Any,
        patterns: Dict[str, List[str]],
        context: Dict[str, Any],
        gemini: Optional[Any],
        key_phrases: Any,
        text: str
    ) -> None:
        """Calculate risk factors based on various indicators."""
        self.risk_factors = {k: 0 for k in self.risk_factors}
        text_lower = text.lower()

        # Base risk factors
        if context['time_pressure']:
            self.risk_factors['urgency_level'] = 0.8
        if patterns['threat']:
            self.risk_factors['threat_level'] = 0.9
        if patterns['personal']:
            self.risk_factors['personal_info_request'] = 0.9
        if patterns['money']:
            self.risk_factors['financial_request'] = 0.9
        if sentiment.sentiment == 'negative':
            self.risk_factors['emotional_manipulation'] = 0.7
            if sentiment.confidence_scores.negative > 0.8:
                self.risk_factors['emotional_manipulation'] = 0.9

        # Enhanced verification code detection
        if patterns['verification']:
            self.risk_factors['personal_info_request'] = max(
                self.risk_factors['personal_info_request'], 
                0.9
            )
            self.risk_factors['financial_request'] = max(
                self.risk_factors['financial_request'], 
                0.8
            )

        # Enhanced bank impersonation detection
        bank_keywords = ['kapital bank', 'paşa bank', 'bank respublika', 'leobank', 'bank']
        if any(bank in text_lower for bank in bank_keywords):
            self.risk_factors['financial_request'] = max(
                self.risk_factors['financial_request'], 
                0.9
            )
            if any(word in text_lower for word in ['göndər', 'ver', 'təqdim', 'məlumat']):
                self.risk_factors['personal_info_request'] = max(
                    self.risk_factors['personal_info_request'], 
                    0.9
                )

        # Enhanced card information request detection
        card_keywords = [
            'kart', 'şifrə', 'pin', 'cvv', 
            'son istifadə tarixi', 'kart nömrəsi'
        ]
        if any(keyword in text_lower for keyword in card_keywords):
            self.risk_factors['personal_info_request'] = max(
                self.risk_factors['personal_info_request'], 
                0.9
            )
            self.risk_factors['financial_request'] = max(
                self.risk_factors['financial_request'], 
                0.9
            )

        # Minimum base risk for any financial or personal info request
        if self.risk_factors['personal_info_request'] > 0 or self.risk_factors['financial_request'] > 0:
            self.risk_factors['personal_info_request'] = max(
                self.risk_factors['personal_info_request'], 
                0.7
            )
            self.risk_factors['financial_request'] = max(
                self.risk_factors['financial_request'], 
                0.7
            )

        # Additional boost for combined financial and personal requests
        if (self.risk_factors['personal_info_request'] > 0.5 and 
            self.risk_factors['financial_request'] > 0.5):
            self.risk_factors['personal_info_request'] = 1.0
            self.risk_factors['financial_request'] = 1.0

    def _calculate_scam_score(self) -> float:
        """Calculate the final scam score based on risk factors."""
        weights = {
            'urgency_level': 0.25,
            'threat_level': 0.25,
            'personal_info_request': 0.2,
            'financial_request': 0.2,
            'emotional_manipulation': 0.1
        }

        # Calculate base score with squared risk values
        base_score = sum(
            (v ** 2) * weights[k] 
            for k, v in self.risk_factors.items()
        )

        # Time-based risk adjustment
        duration = (datetime.now() - self.conversation_start_time).total_seconds()
        time_factor = 1.2 if duration < 30 else 1.1 if duration < 60 else 1.0

        # Entity-based risk adjustment
        entity_factor = 1.0 + (len(self.suspicious_entities) * 0.1)

        # Combined risk boost
        risk_combined = (
            self.risk_factors['personal_info_request'] + 
            self.risk_factors['financial_request']
        )
        combined_boost = 1.5 if risk_combined >= 1.5 else 1.2 if risk_combined >= 1.0 else 1.0

        final_score = base_score * time_factor * entity_factor * combined_boost
        return min(final_score, 1.0)

    def _get_gemini_analysis(self, text: str, context: Dict[str, Any]) -> str:
        """Get advanced analysis from Gemini AI."""
        convo = "\n".join(
            f"{e['timestamp'].strftime('%H:%M:%S')}: {e['text']}" 
            for e in self.conversation_history[-5:]
        )
        
        prompt = f"""
        Zəng konversasiyasını analiz et:
        {convo}
        Son mesaj: {text}
        - Şübhəli varlıqlar: {', '.join(context['suspicious_entities'])}
        - Təciliyyət: {context['time_pressure']}
        - Səlahiyyət iddiası: {context['authority_claim']}
        Cavabı qısa və başa düşülən et.
        """
        
        return GEMINI_MODEL.generate_content(prompt).text

def main() -> None:
    """Main function to run the scam detection system."""
    # Check required environment variables
    required = [
        "AZURE_SPEECH_KEY",
        "AZURE_SPEECH_REGION",
        "AZURE_LANGUAGE_KEY",
        "AZURE_LANGUAGE_ENDPOINT",
        "GOOGLE_API_KEY"
    ]
    
    if not all(os.getenv(k) for k in required):
        print("⚠️ Ətraf mühit dəyişənləri tapılmadı!")
        return

    # Initialize speech recognition
    speech_config = speechsdk.SpeechConfig(
        subscription=os.getenv("AZURE_SPEECH_KEY"),
        region=os.getenv("AZURE_SPEECH_REGION")
    )
    speech_config.speech_recognition_language = "az-AZ"
    audio_config = speechsdk.audio.AudioConfig(use_default_microphone=True)
    recognizer = speechsdk.SpeechRecognizer(
        speech_config=speech_config,
        audio_config=audio_config
    )

    # Initialize analyzer
    analyzer = ScamAnalyzer()
    print("🎤 Dinləyirəm... (Dayandırmaq üçün Ctrl+C və ya Enter)")

    def handle_result(evt: Any) -> None:
        """Handle speech recognition results."""
        text = evt.result.text.strip()
        if len(text.split()) < 3:
            return
        print(f"\n📝 Tanınan mətn: {text}")
        result = analyzer.analyze_text(text)
        if result:
            print("Scam Score:", result['scam_score'])

    def handle_canceled(evt: Any) -> None:
        """Handle speech recognition cancellation."""
        print(f"❌ Tanıma ləğv edildi: {evt.result.reason}")

    # Set up event handlers
    recognizer.recognized.connect(handle_result)
    recognizer.canceled.connect(handle_canceled)
    recognizer.start_continuous_recognition()

    try:
        input("\nEnter basın proqramı dayandırmaq üçün...\n")
    except KeyboardInterrupt:
        pass
    finally:
        recognizer.stop_continuous_recognition()
        print("🔚 Proqram dayandırıldı")

if __name__ == "__main__":
    main()