"""
Gemini AI analyzer for scam detection
"""

import google.generativeai as genai
from ..utils.config import GOOGLE_API_KEY, GEMINI_MODEL_NAME
from typing import Dict, Any, List
from datetime import datetime

class GeminiAnalyzer:
    """Gemini AI analyzer for advanced scam detection."""
    
    def __init__(self):
        """Initialize Gemini AI model."""
        try:
            genai.configure(api_key=GOOGLE_API_KEY)
            self.model = genai.GenerativeModel(GEMINI_MODEL_NAME)
            print(f"✅ Gemini AI Model '{GEMINI_MODEL_NAME}' configured.")
        except Exception as e:
            print(f"❌ Error configuring Gemini AI: {e}")
            self.model = None

    def analyze(self, text: str, context: Dict[str, Any], conversation_history: List[Dict[str, Any]], risk_factors: Dict[str, float], scam_score: float) -> str:
        """Get advanced analysis from Gemini AI with enriched context."""
        if not self.model:
            return "Gemini AI modeli konfiqurasiya edilməyib."

        convo_history_text = "\n".join(
            f"- {e['timestamp'].strftime('%H:%M:%S')}: \"{e['text']}\""
            for e in conversation_history[-5:] 
        )
        
        detected_pii_str = ', '.join(context.get('detected_pii_categories', [])) or "Yoxdur"
        critical_pii_count = context.get('critical_pii_count', 0)
        
        suspicious_named_entities_str = ', '.join([f"{e['text']} ({e['category']})" for e in context.get('suspicious_named_entities', [])]) or "Yoxdur"

        prompt = f"""
        Context: Sən Azərbaycan dilində telefon danışıqlarında dələduzluq hallarını təyin edən bir AI asistansan.
        Aşağıdakı telefon danışığı fraqmentini və əlavə məlumatları analiz et.

        Danışıq Keçmişi (son 5 mesaj):
        {convo_history_text}
        
        Cari Mesaj: "{text}"
        
        Avtomatik Analiz Nəticələri:
        - Ümumi Şübhəli Adlandırılmış Varlıqlar (NER): {suspicious_named_entities_str}
        - Təciliyyət Əlaməti: {'Bəli' if context.get('time_pressure') else 'Xeyr'}
        - Səlahiyyət İddiası Əlaməti: {'Bəli' if context.get('authority_claim') else 'Xeyr'}
        - Aşkarlanan PII Kateqoriyaları: {detected_pii_str}
        - Kritik PII Sayı: {critical_pii_count}
        
        Risk Faktorları (0.0 - 1.0 arası):
          Təciliyyət: {risk_factors.get('urgency_level', 0.0):.2f}
          Təhdid: {risk_factors.get('threat_level', 0.0):.2f}
          Şəxsi Məlumat Tələbi: {risk_factors.get('personal_info_request', 0.0):.2f}
          Maliyyə Tələbi: {risk_factors.get('financial_request', 0.0):.2f}
          Emosional Manipulyasiya: {risk_factors.get('emotional_manipulation', 0.0):.2f}
          PII Riski: {risk_factors.get('pii_exposure', 0.0):.2f}
        
        Ümumi Sistem Tərəfindən Hesablanmış Dələduzluq Ehtimalı: {scam_score:.2%}

        Tapşırıq:
        Bu məlumatlara əsaslanaraq, potensial dələduzluq riskini qiymətləndir. Konkret olaraq nəyin şübhəli olduğuna diqqət yetir.
        Cavabını Azərbaycan dilində, qısa (2-3 cümlə), aydın və konkret şəkildə təqdim et. Zəng edənin əsas taktikalarını və niyyətini göstər.
        """

        try:
            response = self.model.generate_content(prompt)
            return response.text
        except Exception as e:
            print(f"❌ Gemini AI content generation error: {e}")
            return "Gemini AI analizi zamanı xəta baş verdi." 