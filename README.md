# 🛰 Sentinel OSINT Hub

![Version](https://img.shields.io/badge/version-2.0-blue)
![Python](https://img.shields.io/badge/python-3.10%2B-green)
![Flask](https://img.shields.io/badge/flask-2.3-red)
![License](https://img.shields.io/badge/license-MIT-yellow)

**Advanced Open Source Intelligence Platform** - Uno strumento OSINT all-in-one con analisi AI integrata e export PDF.

## ✨ Features

- 👤 **SOCMINT** - Ricerca username su 25+ piattaforme social
- 📧 **Email Analysis** - Verifica leak database + MX records
- 🌐 **IP/Network** - Geolocalizzazione + porte aperte (Shodan)
- 📱 **Phone Analysis** - Operatore, paese, verifica WhatsApp/Telegram
- 🌍 **Domain Analysis** - WHOIS + DNS records completi
- 🔐 **File Hash** - VirusTotal integration
- 📋 **Pastebin Search** - Cerca leak e paste
- 📈 **Finance** - Dati azionari real-time
- ₿ **Bitcoin Lookup** - Saldo e transazioni
- 🪙 **Multi-Crypto** - Supporto ETH, BSC, SOL, TRON
- 📰 **News Search** - Ultime notizie da Google News
- 🤖 **AI Analysis** - Analisi automatica con OpenRouter (Llama 3.1, GPT-4o-mini, Gemini)
- 📄 **Export PDF** - Report professionali in PDF

## 🚀 Installazione

```bash
# Clona il repository
git clone https://github.com/terminalupdate/sentinel-osint-hub
cd sentinel-osint-hub

# Installa dipendenze
pip install -r requirements.txt

# (Opzionale) Configura API keys
cp .env.example .env
# Modifica .env con le tue chiavi