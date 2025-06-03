"""
Main scam analyzer class that coordinates all analysis components
"""

import os
import re
from datetime import datetime
from typing import Dict, List, Optional, Set, Any
import threading
import numpy as np

from azure.ai.textanalytics import (
    AnalyzeSentimentAction,
    RecognizeEntitiesAction,
    ExtractKeyPhrasesAction,
    RecognizePiiEntitiesAction,
    TextAnalyticsClient
)
from azure.core.credentials import AzureKeyCredential

from ..utils.config import (
    AZURE_LANGUAGE_KEY, AZURE_LANGUAGE_ENDPOINT,
    SCAM_PATTERNS, RISK_WEIGHTS, CRITICAL_PII_CATEGORIES
)
from ..models.ml_detector import MLScamDetector
from .gemini_analyzer import GeminiAnalyzer

class ScamAnalyzer:
    """Analyzes text for potential scam attempts using multiple detection methods."""
    
    def __init__(self):
        """Initialize the ScamAnalyzer with required clients and state."""
        try:
            self.text_analytics_client = TextAnalyticsClient(
                endpoint=AZURE_LANGUAGE_ENDPOINT,
                credential=AzureKeyCredential(AZURE_LANGUAGE_KEY)
            )
            print("✅ Azure Text Analytics Client initialized.")
        except Exception as e:
            print(f"❌ Error initializing Azure Text Analytics Client: {e}")
            self.text_analytics_client = None

        self.conversation_history: List[Dict[str, Any]] = []
        self.scam_score: float = 0.0
        self.conversation_start_time: datetime = datetime.now()
        self.suspicious_entities: Set[str] = set()
        self.risk_factors: Dict[str, float] = {
            'urgency_level': 0.0,
            'threat_level': 0.0,
            'personal_info_request': 0.0,
            'financial_request': 0.0,
            'emotional_manipulation': 0.0,
            'pii_exposure': 0.0,
            'card_security_risk': 0.0
        }
        self.ml_detector = MLScamDetector()
        self.gemini_analyzer = GeminiAnalyzer()

    def analyze_text(self, text: str, force_gemini: bool = False) -> Optional[Dict[str, Any]]:
        """Analyze text for potential scam indicators."""
        if not self.text_analytics_client:
            print("❌ Azure Text Analytics Client not available.")
            return None
        try:
            self.conversation_history.append({
                'text': text, 
                'timestamp': datetime.now()
            })
            
            pattern_matches = self._check_patterns(text)
            
            documents = [{"id": "1", "language": "az", "text": text}]
            
            actions_to_perform = [
                AnalyzeSentimentAction(include_sentence_sentiment=True),
                RecognizeEntitiesAction(),
                ExtractKeyPhrasesAction(),
                RecognizePiiEntitiesAction()
            ]

            poller = self.text_analytics_client.begin_analyze_actions(
                documents=documents,
                actions=actions_to_perform,
            )

            action_results = poller.result()
            document_level_results = next(iter(action_results))

            sentiment_result_item = document_level_results[0]
            entities_result_item = document_level_results[1]
            key_phrases_result_item = document_level_results[2]
            pii_entities_result_item = document_level_results[3]

            sentiment_result, entities_result, key_phrases_result, pii_entities_result = None, None, None, None
            sentence_sentiments = []

            if not sentiment_result_item.is_error:
                sentiment_result = sentiment_result_item
                for sentence in sentiment_result.sentences:
                    sentence_sentiments.append({
                        'text': sentence.text,
                        'sentiment': sentence.sentiment,
                        'scores': sentence.confidence_scores
                    })
            else: print(f"⚠️ Sentiment analysis error: {sentiment_result_item.error.message}")
            
            if not entities_result_item.is_error: entities_result = entities_result_item
            else: print(f"⚠️ Entity recognition error: {entities_result_item.error.message}")
            
            if not key_phrases_result_item.is_error: key_phrases_result = key_phrases_result_item
            else: print(f"⚠️ Key phrase extraction error: {key_phrases_result_item.error.message}")

            if not pii_entities_result_item.is_error: pii_entities_result = pii_entities_result_item
            else: print(f"⚠️ PII entity recognition error: {pii_entities_result_item.error.message}")

            context = self._analyze_context(text, entities_result, key_phrases_result, pii_entities_result)
            self._calculate_risk_factors(
                sentiment_result, 
                sentence_sentiments,
                pattern_matches, 
                context,
                key_phrases_result,
                text
            )
            
            rule_based_score = self._calculate_intermediate_scam_score(text)
            ml_score = self.ml_detector.predict(text)
            
            self.scam_score = (rule_based_score * 0.7) + (ml_score * 0.3)
            self.scam_score = min(max(self.scam_score, 0.0), 1.0)

            if self.gemini_analyzer.model and (force_gemini or self.scam_score >= 0.6):
                def run_gemini():
                    try:
                        analysis = self.gemini_analyzer.analyze(
                            text, context, self.conversation_history,
                            self.risk_factors, self.scam_score
                        )
                        print("\n🤖 Gemini AI Analizi:")
                        print(analysis)
                    except Exception as gemini_e:
                        print(f"❌ Gemini AI analizi zamanı xəta: {gemini_e}")
                threading.Thread(target=run_gemini).start()

            return {
                'text': text,
                'scam_score': self.scam_score,
                'rule_based_score': rule_based_score,
                'ml_score': ml_score,
                'risk_factors': self.risk_factors,
                'context': context,
                'sentence_sentiments': sentence_sentiments,
                'pii_entities': [entity.text for entity in pii_entities_result.entities] if pii_entities_result else [],
                'azure_analysis_failed': False
            }

        except Exception as e:
            print(f"❌ analyze_text xətası: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

    def _check_patterns(self, text: str) -> Dict[str, List[str]]:
        """Check text against known scam patterns."""
        matches = {}
        text_lower = text.lower()
        for cat, patterns in SCAM_PATTERNS.items():
            matches[cat] = [p for p in patterns if re.search(p, text_lower)]
        return matches

    def _analyze_context(
        self, 
        text: str, 
        entities_result: Optional[Any], 
        key_phrases_result: Optional[Any],
        pii_entities_result: Optional[Any]
    ) -> Dict[str, Any]:
        """Analyze the context of the conversation using Azure TA results."""
        context = {
            'suspicious_named_entities': [], 
            'time_pressure': False,
            'authority_claim': False,
            'detected_pii_categories': set(),
            'critical_pii_count': 0,
            'contains_card_pii': False
        }
        
        if entities_result:
            for ent in entities_result.entities:
                if ent.category in ['Person', 'Organization', 'PhoneNumber', 'Location']:
                    self.suspicious_entities.add(ent.text) 
                    context['suspicious_named_entities'].append({"text": ent.text, "category": ent.category})
        
        if key_phrases_result:
            for phrase in key_phrases_result.key_phrases:
                phrase_lower = phrase.lower()
                if any(w in phrase_lower for w in ['təcili', 'dərhal', 'tez', 'indi', 'məhdud zaman']):
                    context['time_pressure'] = True
                if any(w in phrase_lower for w in ['polis', 'bank', 'məhkəmə', 'dövlət', 'nazirlik']):
                    context['authority_claim'] = True
        
        if pii_entities_result:
            for pii_entity in pii_entities_result.entities:
                context['detected_pii_categories'].add(pii_entity.category)
                if pii_entity.category in CRITICAL_PII_CATEGORIES:
                    context['critical_pii_count'] += 1
                if pii_entity.category == "CreditCardNumber" or "Card" in pii_entity.category:
                    context['contains_card_pii'] = True

        return context

    def _calculate_risk_factors(
        self,
        sentiment_result: Optional[Any],
        sentence_sentiments: List[Dict[str, Any]],
        pattern_matches: Dict[str, List[str]],
        context: Dict[str, Any],
        key_phrases_result: Optional[Any],
        text: str
    ) -> None:
        """Calculate risk factors based on various indicators."""
        self.risk_factors = {k: 0.0 for k in self.risk_factors}
        text_lower = text.lower()

        # Kart güvenliği risk faktörü
        self.risk_factors['card_security_risk'] = 0.0
        if any(re.search(p, text_lower) for p in SCAM_PATTERNS['card_security']):
            self.risk_factors['card_security_risk'] = 1.0
            self.risk_factors['personal_info_request'] = 1.0
            self.risk_factors['financial_request'] = 1.0

        # 1. Urgency
        if context.get('time_pressure') or pattern_matches.get('urgency'):
            self.risk_factors['urgency_level'] = 0.85
            if "indi dərhal" in text_lower or "cəmi bir neçə dəqiqə" in text_lower:
                self.risk_factors['urgency_level'] = 1.0

        # 2. Threat
        if pattern_matches.get('threat') or context.get('authority_claim'):
            self.risk_factors['threat_level'] = 0.9
            if "həbs" in text_lower or "məhkəmə" in text_lower or "bloklanacaq" in pattern_matches.get('threat', []):
                self.risk_factors['threat_level'] = 1.0
        
        # 3. Personal Info & Financial Request
        base_personal_score = 0.0
        base_financial_score = 0.0

        if pattern_matches.get('personal') or pattern_matches.get('verification'):
            base_personal_score = 0.85
        if pattern_matches.get('money'):
            base_financial_score = 0.8

        # PII influence
        self.risk_factors['pii_exposure'] = min(context.get('critical_pii_count', 0) * 0.25, 1.0)
        if context.get('contains_card_pii', False):
            self.risk_factors['pii_exposure'] = 1.0
            base_personal_score = 1.0
            base_financial_score = 1.0

        if self.risk_factors['pii_exposure'] > 0.7:
            base_personal_score = max(base_personal_score, self.risk_factors['pii_exposure'])
            if any(cat in context.get('detected_pii_categories', set()) for cat in ["CreditCardNumber", "AZBankAccountNumber"]):
                base_financial_score = max(base_financial_score, self.risk_factors['pii_exposure'])
        
        self.risk_factors['personal_info_request'] = base_personal_score
        self.risk_factors['financial_request'] = base_financial_score

        # Bank impersonation
        bank_keywords = ['kapital bank', 'paşa bank', 'bank respublika', 'leobank', 'beynəlxalq bank', 'abbank', 'bank of baku', 'bank']
        if any(bank in text_lower for bank in bank_keywords):
            self.risk_factors['financial_request'] = max(self.risk_factors['financial_request'], 0.9)
            if any(word in text_lower for word in ['göndər', 'ver', 'təqdim et', 'məlumatları deyin', 'kodunuzu deyin']):
                 self.risk_factors['personal_info_request'] = max(self.risk_factors['personal_info_request'], 0.95)

        # Card keywords
        card_keywords = ['kart', 'şifrə', 'pin', 'cvv', 'üç rəqəmli kod', 'son istifadə tarixi', 'kart nömrəsi', 'balans']
        if any(keyword in text_lower for keyword in card_keywords):
            self.risk_factors['personal_info_request'] = max(self.risk_factors['personal_info_request'], 0.95)
            self.risk_factors['financial_request'] = max(self.risk_factors['financial_request'], 0.95)

        # 4. Emotional Manipulation
        if sentiment_result and sentiment_result.sentiment == 'negative':
            self.risk_factors['emotional_manipulation'] = sentiment_result.confidence_scores.negative * 0.8 
        elif sentiment_result and sentiment_result.sentiment == 'positive':
             self.risk_factors['emotional_manipulation'] = max(self.risk_factors['emotional_manipulation'], sentiment_result.confidence_scores.positive * 0.3)

        # Strong negative sentiment in key sentences
        for ss in sentence_sentiments:
            if ss['sentiment'] == 'negative' and ss['scores'].negative > 0.80:
                combined_patterns_for_neg_sentence = SCAM_PATTERNS.get('urgency',[]) + SCAM_PATTERNS.get('threat',[]) + SCAM_PATTERNS.get('money',[])
                if any(re.search(p, ss['text'].lower()) for p in combined_patterns_for_neg_sentence):
                    self.risk_factors['emotional_manipulation'] = max(self.risk_factors['emotional_manipulation'], 0.95)
                    self.risk_factors['threat_level'] = max(self.risk_factors['threat_level'], 0.9) 
                    break 

        # Ensure all factors are between 0 and 1
        for k in self.risk_factors:
            self.risk_factors[k] = min(max(self.risk_factors[k], 0.0), 1.0)

    def _calculate_intermediate_scam_score(self, text: str) -> float:
        """Calculate the rule-based scam score based on risk factors."""
        # Normalize weights
        total_weight = sum(RISK_WEIGHTS.values())
        normalized_weights = {k: v / total_weight for k, v in RISK_WEIGHTS.items()}

        base_score = sum(
            (self.risk_factors[k] ** 1.5) * normalized_weights[k]
            for k in self.risk_factors if k in normalized_weights
        )

        # Kart güvenliği ile ilgili özel durumlar için ek risk puanı
        if any(re.search(p, text.lower()) for p in SCAM_PATTERNS['card_security']):
            base_score = max(base_score, 0.75)  # Minimum %75 risk

        duration = (datetime.now() - self.conversation_start_time).total_seconds()
        time_factor = 1.15 if duration < 30 else 1.07 if duration < 60 else 1.0

        entity_factor = 1.0 + min(len(self.suspicious_entities) * 0.05, 0.15)

        # Combined critical risk boost
        combined_boost = 1.0
        if self.risk_factors['pii_exposure'] > 0.8 and \
           self.risk_factors['urgency_level'] > 0.8 and \
           self.risk_factors['threat_level'] > 0.5:
            combined_boost = 1.4
        elif self.risk_factors['personal_info_request'] > 0.8 and self.risk_factors['financial_request'] > 0.8:
            combined_boost = 1.3
        elif any(re.search(p, text.lower()) for p in SCAM_PATTERNS['card_security']):
            combined_boost = 1.5  # Kart güvenliği istekleri için yüksek boost
        
        final_score = base_score * time_factor * entity_factor * combined_boost
        return min(max(final_score, 0.0), 1.0) 