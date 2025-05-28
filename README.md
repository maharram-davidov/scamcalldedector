# Scam Call Detector 🚨

Real-time zəng analizi və scam aşkarlama sistemi. Bu proqram sizin zənglərinizi dinləyir və potensial scam cəhdlərini aşkarlayır.

## Xüsusiyyətlər ✨

- Real-time səs tanıma
- Çoxqatlı scam aşkarlama:
  - Pattern matching
  - Machine Learning analizi
  - Sentiment analizi
  - Entity recognition
  - Gemini AI inteqrasiyası
- Avtomatik risk skorlaması
- Adaptiv öyrənmə sistemi

## Tələblər 📋

- Python 3.8+
- Azure Cognitive Services hesabı
- Google Gemini API açarı
- Mikrofon

## Quraşdırma 🛠️

1. Repositoriyanı klonlayın:
```bash
git clone https://github.com/yourusername/scam-call-detector.git
cd scam-call-detector
```

2. Virtual mühit yaradın və aktivləşdirin:
```bash
python -m venv venv
# Windows
venv\Scripts\activate
# Linux/Mac
source venv/bin/activate
```

3. Lazımi paketləri quraşdırın:
```bash
pip install -r requirements.txt
```

4. `.env` faylını yaradın və API açarlarını əlavə edin:
```env
AZURE_SPEECH_KEY=your_azure_speech_key
AZURE_SPEECH_REGION=your_azure_region
AZURE_LANGUAGE_KEY=your_azure_language_key
AZURE_LANGUAGE_ENDPOINT=your_azure_language_endpoint
GOOGLE_API_KEY=your_gemini_api_key
```

## İstifadə 🚀

Proqramı başlatmaq üçün:
```bash
python speech_to_text.py
```

Proqram başladıqdan sonra:
1. Mikrofonunuzu aktivləşdirin
2. Zəngləri dinləməyə başlayın
3. Proqram hər zəngi analiz edəcək və risk skorunu göstərəcək
4. Yüksək risk skoru olan zənglər üçün Gemini AI təhlili avtomatik başlayacaq

## Machine Learning Modeli 🤖

Sistem ikiqat aşkarlama mexanizmi istifadə edir:
1. Rule-based analiz (70%)
2. Machine Learning analizi (30%)

ML modeli:
- RandomForestClassifier istifadə edir
- TfidfVectorizer ilə mətnləri vektorlaşdırır
- Avtomatik öyrənir və təkmilləşir
- Model faylları avtomatik saxlanılır və yüklənir

## Modeli Təkmilləşdirmək 📈

ML modelini təkmilləşdirmək üçün:
1. Daha çox məlumat əlavə edin
2. Model parametrlərini tənzimləyin
3. Fərqli ML alqoritmləri sınayın
4. Vektorlaşdırma parametrlərini optimallaşdırın

## Təhlükəsizlik 🔒

- Bütün API açarları `.env` faylında saxlanılır
- Səs məlumatları lokal olaraq işlənir
- Şəxsi məlumatlar saxlanılmır
- Təhlükəsiz HTTPS əlaqələri

## Lisenziya 📄

MIT Lisenziyası - daha ətraflı məlumat üçün [LICENSE](LICENSE) faylına baxın.

## Kömək 🤝

Problemlər və təkliflər üçün:
1. Issue yaradın
2. Pull request göndərin
3. Email: your.email@example.com

## Təşəkkür 🙏

- Azure Cognitive Services
- Google Gemini AI
- Scikit-learn
- Bütün kontributorlar 