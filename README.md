# 🛡️ CyberGhost-Ultra-Scanner v1.0
**World's #1 Secret Scanner - Thermal-Aware & Ultra-Fast**

CyberGhost-Ultra-Scanner एक शक्तिशाली सुरक्षा उपकरण (Security Tool) है जिसे GitHub रिपॉजिटरीज़ से 'Secrets' और 'API Keys' ढूंढने के लिए बनाया गया है। यह टूल विशेष रूप से **Intel i3 3rd Gen** जैसे कम संसाधनों वाले लैपटॉप पर बिना रुके और बिना गर्म हुए चलने के लिए डिज़ाइन किया गया है।

## 🚀 मुख्य विशेषताएं (Key Features)
* **Thermal-Aware Scanning:** यह आपके CPU के तापमान पर नज़र रखता है और 85°C से ऊपर जाने पर स्कैन को अपने आप रोक देता है।
* **Critical Discovery:** यह AWS, GitHub PAT, और Google API जैसी क्रिटिकल कीज़ को सेकंडों में पहचान लेता है।
* **Professional Dashboard:** इसमें एक लाइव प्रोग्रेस बार और रीयल-टाइम सिस्टम हेल्थ मॉनिटर मिलता है।
* **Smart Verification:** `verifier.py` के माध्यम से यह मिले हुए सीक्रेट्स की सत्यता की जांच करता है।

## 🛠️ इंस्टालेशन (Installation)
सबसे पहले ज़रूरी लाइब्रेरीज़ इंस्टॉल करें:
```bash
pip install psutil aiohttp rich pyahocorasick

python3 main.py --repo [https://github.com/user/repo](https://github.com/user/repo) --token YOUR_TOKEN .
