"""
Hybrid Scam Detection System with Real-Time Voice Input and Gemini AI Analysis
This system analyzes voice input in real-time to detect potential scam attempts using
Azure Cognitive Services for speech recognition and text analysis, combined with
Google's Gemini AI for advanced analysis.
"""

import os
import threading
from datetime import datetime
import azure.cognitiveservices.speech as speechsdk
from dotenv import load_dotenv

# Yeni modüler importlar
from .analyzers.scam_analyzer import ScamAnalyzer

# Ortam değişkenlerini yükle
load_dotenv()

def main() -> None:
    """Main function to run the scam detection system."""
    required_env_vars = [
        "AZURE_SPEECH_KEY", "AZURE_SPEECH_REGION",
        "AZURE_LANGUAGE_KEY", "AZURE_LANGUAGE_ENDPOINT",
        "GOOGLE_API_KEY" 
    ]
    
    if not all(os.getenv(k) for k in required_env_vars):
        print(f"⚠️ Ətraf mühit dəyişənləri tapılmadı! Tələb olunanlar: {', '.join(required_env_vars)}")
        missing_vars = [k for k in required_env_vars if not os.getenv(k)]
        print(f"⚠️ Eksik olanlar: {', '.join(missing_vars)}")
        return

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

    analyzer = ScamAnalyzer()
    print("🎤 Dinləyirəm... (Dayandırmaq üçün Ctrl+C)")

    def recognized_cb(evt: speechsdk.SpeechRecognitionEventArgs) -> None:
        text = evt.result.text.strip()
        if not text:
            return
        print(f"\n💬 Tanınan mətn ({datetime.now().strftime('%H:%M:%S')}): \"{text}\"")
        if len(text.split()) < 2 and not any(kw in text.lower() for kw in ['kod', 'pul', 'kart', 'bank', 'hə', 'yox', 'bəli']):
            print("ℹ️ Çox qısa ifadə, analiz edilmir.")
            return
        result = analyzer.analyze_text(text)
        if result:
            print(f"📊 Dələduzluq Ehtimalı: {result['scam_score']:.2%}")
            print(f"   (Qayda Əsaslı: {result['rule_based_score']:.2%}, ML Əsaslı: {result['ml_score']:.2%})")
            if result.get('azure_analysis_failed'):
                print("   ⚠️ Azure analizində problem olduğu üçün nəticə məhdud ola bilər.")

    def canceled_cb(evt: speechsdk.SpeechRecognitionCanceledEventArgs) -> None:
        print(f"❌ Tanıma ləğv edildi: Səbəb={evt.reason}")
        if evt.reason == speechsdk.CancellationReason.Error:
            print(f"❌ Xəta detalları: {evt.error_details}")
            print("ℹ️ Azure Speech Service ilə bağlı problem ola bilər. API açarınızı və regionu yoxlayın.")

    recognizer.recognized.connect(recognized_cb)
    recognizer.session_started.connect(lambda evt: print("🎙️ Səs tanıma sessiyası başladı."))
    recognizer.session_stopped.connect(lambda evt: print("🛑 Səs tanıma sessiyası dayandı."))
    recognizer.canceled.connect(canceled_cb)

    recognizer.start_continuous_recognition()
    try:
        while True:
            threading.Event().wait()
    except KeyboardInterrupt:
        print("\nℹ️ Proqram dayandırılır...")
    finally:
        recognizer.stop_continuous_recognition()
        print("🔚 Proqram dayandırıldı.")

if __name__ == "__main__":
    main()