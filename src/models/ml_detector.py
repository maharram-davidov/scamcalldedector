"""
Machine Learning based scam detection model
"""

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from ..utils.config import MODEL_PATHS


class MLScamDetector:
    """Machine Learning based scam detection model."""

    def __init__(self):
        """Initialize the ML model and vectorizer."""
        self.model = None
        self.vectorizer = None
        self.model_path = MODEL_PATHS['ml_model']
        self.vectorizer_path = MODEL_PATHS['vectorizer']
        self._load_or_create_model()

    def _load_or_create_model(self):
        """Load existing model or create a new one if not exists."""
        try:
            self.model = joblib.load(self.model_path)
            self.vectorizer = joblib.load(self.vectorizer_path)
            print("✅ ML model yükləndi")
        except (FileNotFoundError, EOFError, joblib.externals.loky.process_executor.TerminatedWorkerError):
            print("ℹ️ Yeni ML model yaradılır...")
            self.model = RandomForestClassifier(n_estimators=100, random_state=42, class_weight='balanced')
            self.vectorizer = TfidfVectorizer(max_features=1000)
            self._train_initial_model()

    def _train_initial_model(self):
        """Train the model with initial data."""
        texts = [
            # Scam examples
            "Kart şifrənizi təsdiqləyin.",
            "Kart pin kodunuzu deyin.",
            "Kart məlumatlarınızı yeniləyin.",
            "Kartınızı aktivləşdirmək üçün şifrəni göndərin.",
            "Kart təhlükəsizliyi üçün pin kodunuzu təsdiqləyin.",
            "Kartınızı bloklamaq üçün şifrənizi göndərin.",
            "Kart məlumatlarınızı yeniləmək üçün şifrəni deyin.",
            "Kartınızı təsdiqləmək üçün pin kodunuzu göndərin.",
            "Kart doğrulama üçün şifrənizi deyin.",
            "Kart məlumatlarınızı yeniləyin, linkə daxil olun.",
            "Telefonunuza gələn kodu deyin.",
            "SMS ilə gələn kodu təsdiqləyin.",
            "Telefonunuza göndərilən verifikasiya kodunu deyin.",
            "Mobil nömrənizə gələn kodu bildirin.",
            "Təsdiq kodunu deyin.",
            "Salam, Kapital Bankdan zəng edirik. Kart məlumatlarınızı təsdiqləyin.",
            "Təcili olaraq bank hesabınızı yeniləyin, linkə daxil olun.",
            "Sizin bank hesabınızda şübhəli aktivlik var, təcili təsdiq edin.",
            "Kartınızı bloklamaq üçün şifrənizi göndərin.",
            "Hesabınız bloklanacaq, dərhal kodu deyin.",
            "Polis idarəsindən narahat edirik, yaxınınız qəzaya düşüb, təcili pul köçürün.",
            "Lotereyada böyük məbləğ udmusunuz! Vergi üçün bu hesaba pul köçürün.",
            # Normal examples
            "Salam, necəsiz?",
            "Gününüz xeyrə qalsın.",
            "Sizə kömək edə bilərəm?",
            "Hava haqqında məlumat almaq istəyirəm.",
            "Restoranda yer sifariş etmək istəyirəm.",
            "Sabah görüşə bilərik?",
            "Bu məhsul haqqında məlumat verin.",
            "Tezliklə sizə geri dönüş edəcəyik.",
            "Bank kartım işləmir, nə edim?",
            "Kartımı itirdim, nə etməliyəm?",
            "Kart şifrəmi unutdum, yeniləmək istəyirəm.",
            "Bankın müştəri xidmətləri ilə əlaqə saxlamaq istəyirəm.",
            "Kartımın balansını yoxlamaq istəyirəm.",
            "Kartımın limitini artırmaq istəyirəm.",
            "Kartımın təhlükəsizlik parametrlərini dəyişmək istəyirəm."
        ]

        labels = [1] * 21 + [0] * 14  # 21 scam, 14 normal

        if len(texts) != len(labels):
            print(f"❌ XƏTA: Mətnlərin sayı ({len(texts)}) ilə etiketlərin ({len(labels)}) sayı uyğun deyil!")
            return

        X = self.vectorizer.fit_transform(texts)
        self.model.fit(X, labels)

        joblib.dump(self.model, self.model_path)
        joblib.dump(self.vectorizer, self.vectorizer_path)
        print("✅ ML model yaradıldı və saxlanıldı")

    def predict(self, text: str) -> float:
        """Predict scam probability for given text."""
        if not text.strip():
            print("❌ Boş mətn verildi.")
            return 0.0

        if not self.vectorizer or not self.model:
            print("❌ ML model və ya vektorlaşdırıcı yüklənməyib.")
            return 0.0

        X = self.vectorizer.transform([text])
        if hasattr(self.model, "predict_proba"):
            proba = self.model.predict_proba(X)[0]
            return proba[1]  # Scam ehtimalı
        else:
            return float(self.model.predict(X)[0])
