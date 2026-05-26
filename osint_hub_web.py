#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Sentinel OSINT Hub - Versione Avanzata con Moduli Aggiuntivi
"""

import logging
import sqlite3
import re
import os
import requests
import json
import hashlib
import whois
import dns.resolver
from datetime import datetime
from flask import Flask, render_template_string, request, jsonify
import secrets
import urllib.parse

# Tentativo import moduli opzionali
try:
    import yfinance as yf
    YFINANCE_AVAILABLE = True
except ImportError:
    YFINANCE_AVAILABLE = False

try:
    import phonenumbers
    from phonenumbers import carrier, geocoder, timezone as phone_timezone
    PHONE_AVAILABLE = True
except ImportError:
    PHONE_AVAILABLE = False

try:
    import shodan
    SHODAN_AVAILABLE = True
except ImportError:
    SHODAN_AVAILABLE = False

# ===== CONFIGURAZIONE =====
OPENROUTER_API_KEY = os.getenv('OPENROUTER_API_KEY', "")
SHODAN_API_KEY = os.getenv('SHODAN_API_KEY', "")
VT_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', "")
SECRET_KEY = os.getenv('FLASK_SECRET_KEY', secrets.token_hex(32))

logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = SECRET_KEY

# ===== DATABASE (con migrazione) =====
def init_db():
    if not os.path.exists('database'):
        os.makedirs('database')
    
    db_path = "database/osint_hub.db"
    db_exists = os.path.exists(db_path)
    
    with sqlite3.connect(db_path) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS history 
                     (id INTEGER PRIMARY KEY AUTOINCREMENT,
                      session_id TEXT,
                      mode TEXT,
                      target TEXT,
                      timestamp TEXT,
                      result TEXT)''')
        
        if db_exists:
            c.execute("PRAGMA table_info(history)")
            columns = [col[1] for col in c.fetchall()]
            if 'session_id' not in columns:
                c.execute("ALTER TABLE history ADD COLUMN session_id TEXT")
        
        conn.commit()
    print("✅ Database inizializzato")

def save_search(session_id, mode, target, result):
    try:
        with sqlite3.connect("database/osint_hub.db") as conn:
            c = conn.cursor()
            timestamp = datetime.now().isoformat()
            c.execute('INSERT INTO history (session_id, mode, target, timestamp, result) VALUES (?, ?, ?, ?, ?)',
                      (session_id, mode, target, timestamp, result[:500]))
            conn.commit()
    except Exception as e:
        logger.error(f"Errore salvataggio: {e}")

def get_user_history(session_id, limit=20):
    try:
        with sqlite3.connect("database/osint_hub.db") as conn:
            c = conn.cursor()
            c.execute('SELECT mode, target, timestamp FROM history WHERE session_id = ? ORDER BY timestamp DESC LIMIT ?',
                      (session_id, limit))
            return c.fetchall()
    except Exception as e:
        logger.error(f"Errore history: {e}")
        return []

# ===== MODULO 1: SOCMINT =====
def socmint_search(username: str) -> str:
    username = username.replace('@', '').strip().lower()
    
    platforms = {
        'GitHub': f'https://github.com/{username}',
        'Twitter': f'https://twitter.com/{username}',
        'Instagram': f'https://instagram.com/{username}',
        'Reddit': f'https://reddit.com/user/{username}',
        'TikTok': f'https://tiktok.com/@{username}',
        'YouTube': f'https://youtube.com/@{username}',
        'Twitch': f'https://twitch.tv/{username}',
        'Medium': f'https://medium.com/@{username}',
        'Pinterest': f'https://pinterest.com/{username}',
        'Tumblr': f'https://{username}.tumblr.com',
        'SoundCloud': f'https://soundcloud.com/{username}',
        'Steam': f'https://steamcommunity.com/id/{username}',
        'Telegram': f'https://t.me/{username}',
        'Facebook': f'https://facebook.com/{username}',
        'LinkedIn': f'https://linkedin.com/in/{username}',
        'Dev.to': f'https://dev.to/{username}',
        'Behance': f'https://behance.net/{username}',
        'Dribbble': f'https://dribbble.com/{username}',
        'Vimeo': f'https://vimeo.com/{username}',
        'Flickr': f'https://flickr.com/people/{username}',
        'Spotify': f'https://open.spotify.com/user/{username}',
        'Keybase': f'https://keybase.io/{username}',
        'Bitbucket': f'https://bitbucket.org/{username}',
        'GitLab': f'https://gitlab.com/{username}',
    }
    
    results = []
    found_count = 0
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
    
    for platform, url in platforms.items():
        try:
            resp = requests.head(url, headers=headers, timeout=5, allow_redirects=True)
            if resp.status_code == 200:
                results.append(f"✅ **{platform}**: [profilo]({url})")
                found_count += 1
        except:
            pass
    
    output = f"👤 **Username: {username}**\n\n"
    output += f"✅ **Profili trovati:** {found_count}/{len(platforms)}\n\n"
    output += "\n".join(results[:25])
    
    output += f"\n\n🔗 **Ricerca avanzata:**\n"
    output += f"• [Google](https://www.google.com/search?q={username})\n"
    output += f"• [DuckDuckGo](https://duckduckgo.com/?q={username})\n"
    output += f"• [Google Images](https://www.google.com/search?tbm=isch&q={username})"
    
    return output

# ===== MODULO 2: EMAIL =====
def email_lookup(email: str) -> str:
    email = email.strip().lower()
    
    email_pattern = re.compile(r'^[\w\.\+\-]+@[\w\-]+\.[\w\.\-]+$')
    if not email_pattern.match(email):
        return f"❌ Formato email non valido: `{email}`"
    
    domain = email.split('@')[1]
    
    output = f"📧 **Email Analysis: {email}**\n\n"
    output += f"**📋 DETTAGLI DOMINIO:**\n• Dominio: `{domain}`\n"
    
    providers = {
        'gmail.com': 'Google (Gmail)', 'proton.me': 'ProtonMail',
        'protonmail.com': 'ProtonMail', 'tutanota.com': 'Tutanota',
        'outlook.com': 'Microsoft Outlook', 'hotmail.com': 'Microsoft Hotmail',
        'yahoo.com': 'Yahoo!', 'icloud.com': 'Apple iCloud'
    }
    output += f"• Provider: {providers.get(domain, 'Privato/Aziendale')}\n\n"
    
    # Verifica MX
    try:
        mx = dns.resolver.resolve(domain, 'MX')
        output += f"**📧 SERVER MAIL (MX):**\n"
        for record in sorted(mx, key=lambda x: x.preference)[:5]:
            output += f"• {record.preference} - {record.exchange}\n"
        output += "\n"
    except:
        pass
    
    output += f"**🔐 DATABASE LEAK:**\n"
    output += f"• [Have I Been Pwned](https://haveibeenpwned.com/account/{email})\n"
    output += f"• [Firefox Monitor](https://monitor.firefox.com/?q={email})\n"
    output += f"• [IntelX](https://intelx.io/?s={email})\n"
    output += f"• [DeHashed](https://dehashed.com/search?query={email})\n\n"
    
    email_hash = hashlib.md5(email.lower().encode()).hexdigest()
    output += f"**🖼️ GRAVATAR:**\n• [Profilo](https://www.gravatar.com/{email_hash})\n"
    
    output += f"\n**🌐 INFORMAZIONI DOMINIO:**\n"
    output += f"• [SecurityTrails](https://securitytrails.com/domain/{domain})\n"
    output += f"• [Crt.sh](https://crt.sh/?q={domain})\n"
    output += f"• [Whois](https://www.whois.com/whois/{domain})\n"
    
    return output

# ===== MODULO 3: IP =====
def ip_lookup(ip: str) -> str:
    ip = ip.strip()
    
    ip_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    if not ip_pattern.match(ip):
        return f"❌ IP non valido: `{ip}`\nEsempio: `8.8.8.8`"
    
    output = f"🌐 **IP Analysis: {ip}**\n\n"
    
    # ipinfo.io
    try:
        resp = requests.get(f"https://ipinfo.io/{ip}/json", timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            output += f"**📋 GEOLOCALIZZAZIONE:**\n"
            output += f"• IP: `{data.get('ip', ip)}`\n"
            output += f"• Hostname: `{data.get('hostname', 'N/D')}`\n"
            output += f"• Organizzazione: `{data.get('org', 'N/D')}`\n"
            output += f"• Paese: {data.get('country', 'N/D')}\n"
            output += f"• Città: {data.get('city', 'N/D')}\n"
            output += f"• Coordinate: {data.get('loc', 'N/D')}\n\n"
    except Exception as e:
        output += f"⚠️ Errore geoloc: {str(e)}\n\n"
    
    # Shodan (se disponibile)
    if SHODAN_AVAILABLE and SHODAN_API_KEY:
        try:
            api = shodan.Shodan(SHODAN_API_KEY)
            host = api.host(ip)
            output += f"**🔌 PORTA APERTE:**\n"
            ports = host.get('ports', [])[:15]
            if ports:
                output += f"• {', '.join(map(str, ports))}\n\n"
            if host.get('vulns'):
                output += f"**⚠️ VULNERABILITÀ:** {len(host.get('vulns'))}\n\n"
        except:
            pass
    
    output += f"**🔗 SERVIZI:**\n"
    output += f"• [VirusTotal](https://www.virustotal.com/gui/ip-address/{ip})\n"
    output += f"• [AbuseIPDB](https://www.abuseipdb.com/check/{ip})\n"
    output += f"• [Censys](https://search.censys.io/hosts/{ip})\n"
    output += f"• [Shodan](https://www.shodan.io/host/{ip})\n"
    
    return output

# ===== MODULO 4: FINANCE =====
def finance_analysis(ticker: str) -> tuple:
    if not YFINANCE_AVAILABLE:
        return "❌ yfinance non installato. pip install yfinance", "N/D"
    
    ticker = ticker.upper().strip()
    
    try:
        stock = yf.Ticker(ticker)
        hist = stock.history(period="1d")
        info = stock.info
        
        if hist.empty:
            return f"❌ Nessun dato per {ticker}", "N/D"
        
        current = hist['Close'].iloc[-1]
        open_p = hist['Open'].iloc[0]
        high = hist['High'].iloc[0]
        low = hist['Low'].iloc[0]
        change = current - open_p
        change_pct = (change / open_p) * 100 if open_p != 0 else 0
        
        company = info.get('shortName', ticker)
        market_cap = info.get('marketCap', 0)
        
        output = f"📈 **{ticker} - {company}**\n\n"
        output += f"💰 **PREZZO:**\n"
        output += f"• Corrente: ${current:.2f}\n"
        output += f"• Apertura: ${open_p:.2f}\n"
        output += f"• Massimo: ${high:.2f}\n"
        output += f"• Minimo: ${low:.2f}\n"
        output += f"• Variazione: {change:+.2f} ({change_pct:+.2f}%)\n"
        
        if market_cap:
            output += f"\n💼 **AZIENDA:**\n• Market Cap: ${market_cap/1e9:.2f}B\n"
        
        fin_result = f"**{ticker}** | ${current:.2f} | {change_pct:+.2f}%"
        return output, fin_result
        
    except Exception as e:
        return f"❌ Errore: {str(e)}", "N/D"

# ===== MODULO 5: BITCOIN =====
def btc_lookup(address: str) -> str:
    address = address.strip()
    
    btc_pattern = re.compile(r'^(1|3|bc1)[a-km-zA-HJ-NP-Z1-9]{25,59}$')
    if not btc_pattern.match(address):
        return f"❌ Indirizzo Bitcoin non valido: `{address}`"
    
    output = f"₿ **Bitcoin Lookup**\n\n📍 `{address}`\n\n"
    
    try:
        resp = requests.get(f"https://blockchain.info/rawaddr/{address}?limit=3", 
                           timeout=15, headers={'User-Agent': 'Mozilla/5.0'})
        
        if resp.status_code == 404:
            return output + "ℹ️ Indirizzo mai usato"
        if resp.status_code != 200:
            return output + f"❌ Errore API (HTTP {resp.status_code})"
        
        data = resp.json()
        balance = data.get('final_balance', 0) / 1e8
        received = data.get('total_received', 0) / 1e8
        tx_count = data.get('n_tx', 0)
        
        output += f"💰 **SALDO:**\n• Attuale: `{balance:.8f} BTC`\n"
        output += f"• Ricevuto: `{received:.8f} BTC`\n"
        output += f"• Transazioni: `{tx_count}`\n\n"
        
        output += f"🔗 **ESPLORA:**\n"
        output += f"• [Blockchain.com](https://www.blockchain.com/btc/address/{address})\n"
        output += f"• [Mempool.space](https://mempool.space/address/{address})\n"
        
    except Exception as e:
        output += f"❌ Errore: {str(e)}"
    
    return output

# ===== MODULO 6: NEWS =====
def news_search(query: str, max_results: int = 8) -> str:
    try:
        import xml.etree.ElementTree as ET
        encoded = urllib.parse.quote(query)
        url = f"https://news.google.com/rss/search?q={encoded}&hl=it&gl=IT&ceid=IT:it"
        
        resp = requests.get(url, timeout=10)
        if resp.status_code != 200:
            return f"❌ Errore fetch news: HTTP {resp.status_code}"
        
        root = ET.fromstring(resp.content)
        items = root.findall('.//item')[:max_results]
        
        if not items:
            return f"📰 Nessuna notizia per: **{query}**"
        
        output = f"📰 **NEWS: {query.upper()}**\n📊 {len(items)} notizie\n\n"
        
        for i, item in enumerate(items, 1):
            title = item.find('title')
            link = item.find('link')
            pub_date = item.find('pubDate')
            
            title_text = title.text if title is not None else 'Senza titolo'
            link_text = link.text if link is not None else ''
            date_text = pub_date.text[:16] if pub_date is not None else 'N/D'
            
            output += f"**{i}. {title_text}**\n📅 {date_text}\n🔗 {link_text}\n\n"
        
        return output
        
    except Exception as e:
        return f"❌ Errore: {str(e)}\n\n🔗 [Cerca su Google News](https://news.google.com/search?q={query})"

# ===== NUOVO MODULO 7: TELEFONO =====
def phone_lookup(phone: str) -> str:
    """Analisi numero di telefono"""
    phone = phone.strip()
    
    output = f"📱 **Phone Analysis: {phone}**\n\n"
    
    if PHONE_AVAILABLE:
        try:
            pn = phonenumbers.parse(phone, None)
            if phonenumbers.is_valid_number(pn):
                output += f"**✅ Numero valido**\n"
                output += f"• Paese: {geocoder.description_for_number(pn, 'it')}\n"
                output += f"• Operatore: {carrier.name_for_number(pn, 'it')}\n"
                tz = phone_timezone.time_zones_for_number(pn)
                if tz:
                    output += f"• Timezone: {', '.join(tz)}\n"
            else:
                output += f"❌ Numero non valido\n"
        except:
            output += f"⚠️ Impossibile analizzare il numero\n"
    else:
        output += f"ℹ️ Installare phonenumbers per analisi avanzata:\n`pip install phonenumbers`\n"
    
    digits = re.sub(r'\D', '', phone)
    output += f"\n**🔗 VERIFICA ONLINE:**\n"
    output += f"• [WhatsApp](https://wa.me/{digits})\n"
    output += f"• [Telegram](https://t.me/{digits})\n"
    output += f"• [TrueCaller](https://www.truecaller.com/search/{digits})\n"
    
    return output

# ===== NUOVO MODULO 8: DOMINIO =====
def domain_lookup(domain: str) -> str:
    """Analisi dominio con WHOIS e DNS"""
    domain = domain.strip().lower()
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.split('/')[0]
    
    output = f"🌐 **Domain Analysis: {domain}**\n\n"
    
    # WHOIS
    try:
        w = whois.whois(domain)
        output += f"**📋 WHOIS:**\n"
        output += f"• Registrar: {w.registrar}\n" if w.registrar else ""
        output += f"• Creato: {w.creation_date}\n" if w.creation_date else ""
        output += f"• Scade: {w.expiration_date}\n" if w.expiration_date else ""
        output += f"• Nameserver: {w.name_servers}\n" if w.name_servers else ""
        output += "\n"
    except:
        output += f"⚠️ WHOIS non disponibile\n\n"
    
    # DNS
    output += f"**🔍 RECORD DNS:**\n"
    for record in ['A', 'MX', 'NS', 'TXT']:
        try:
            answers = dns.resolver.resolve(domain, record)
            output += f"• {record}: "
            output += ", ".join([str(r) for r in answers[:3]])
            output += "\n"
        except:
            pass
    
    output += f"\n**🔗 SERVIZI:**\n"
    output += f"• [SecurityTrails](https://securitytrails.com/domain/{domain})\n"
    output += f"• [Crt.sh](https://crt.sh/?q={domain})\n"
    output += f"• [VirusTotal](https://www.virustotal.com/gui/domain/{domain})\n"
    
    return output

# ===== NUOVO MODULO 9: FILE HASH =====
def hash_lookup(file_hash: str) -> str:
    """Analisi hash file su VirusTotal"""
    file_hash = file_hash.strip().upper()
    
    if not re.match(r'^[A-F0-9]{32,64}$', file_hash):
        return f"❌ Hash non valido (usa MD5, SHA1 o SHA256)"
    
    output = f"🔐 **Hash Analysis: {file_hash}**\n\n"
    
    if VT_API_KEY:
        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {"x-apikey": VT_API_KEY}
            resp = requests.get(url, headers=headers, timeout=15)
            
            if resp.status_code == 200:
                data = resp.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                output += f"**📊 VIRUSTOTAL STATS:**\n"
                output += f"• Malicious: {stats.get('malicious', 0)}\n"
                output += f"• Suspicious: {stats.get('suspicious', 0)}\n"
                output += f"• Undetected: {stats.get('undetected', 0)}\n\n"
            else:
                output += f"⚠️ Hash non trovato su VirusTotal\n\n"
        except Exception as e:
            output += f"⚠️ Errore VirusTotal: {str(e)}\n\n"
    else:
        output += f"ℹ️ Configura VIRUSTOTAL_API_KEY per analisi avanzata\n\n"
    
    output += f"**🔗 VERIFICA ONLINE:**\n"
    output += f"• [VirusTotal](https://www.virustotal.com/gui/search/{file_hash})\n"
    output += f"• [Hybrid Analysis](https://www.hybrid-analysis.com/search?query={file_hash})\n"
    output += f"• [PolySwarm](https://polyswarm.network/search?hash={file_hash})\n"
    
    return output

# ===== NUOVO MODULO 10: PASTEBIN =====
def pastebin_search(query: str) -> str:
    """Cerca su Pastebin e siti simili"""
    query = urllib.parse.quote(query)
    
    output = f"📋 **Paste Search: {query}**\n\n"
    
    output += f"**🔗 RICERCA SU PASTEBIN:**\n"
    output += f"• [Pastebin](https://pastebin.com/search?q={query})\n"
    output += f"• [PSBDMP](https://psbdmp.ws/search/{query})\n"
    output += f"• [Pastebin Scraper](https://pastebin.com/archive)\n\n"
    
    output += f"**🔗 DATABASE LEAK:**\n"
    output += f"• [LeakCheck](https://leakcheck.net/search?query={query})\n"
    output += f"• [Snusbase](https://snusbase.com/search?type=email&q={query})\n"
    output += f"• [ScatteredSecrets](https://scatteredsecrets.com/)\n"
    
    return output

# ===== NUOVO MODULO 11: CRYPTO MULTI-CHAIN =====
def crypto_multi_lookup(address: str) -> str:
    """Supporto multi-chain crypto"""
    address = address.strip()
    
    output = f"🪙 **Crypto Multi-Chain Lookup**\n\n📍 `{address}`\n\n"
    
    # Rileva tipo indirizzo
    if address.startswith('0x'):
        output += f"**🔗 ETHEREUM / BSC / POLYGON:**\n"
        output += f"• [Etherscan](https://etherscan.io/address/{address})\n"
        output += f"• [BscScan](https://bscscan.com/address/{address})\n"
        output += f"• [PolygonScan](https://polygonscan.com/address/{address})\n"
        output += f"• [Arbiscan](https://arbiscan.io/address/{address})\n\n"
    elif address.startswith('T') and len(address) == 34:
        output += f"**🔗 TRON (TRC20):**\n"
        output += f"• [Tronscan](https://tronscan.org/#/address/{address})\n\n"
    elif address.startswith('sol'):
        output += f"**🔗 SOLANA:**\n"
        output += f"• [Solscan](https://solscan.io/account/{address})\n\n"
    else:
        output += f"🔗 **ESPLORATORI GENERALI:**\n"
        output += f"• [Blockchair](https://blockchair.com/search?q={address})\n"
        output += f"• [OKLink](https://www.oklink.com/search/{address})\n"
    
    return output

# ===== FUNZIONE PRINCIPALE =====
def run_search(mode: str, target: str) -> dict:
    print(f"[*] Ricerca: {mode} - {target}")
    
    mode_functions = {
        "socmint": (socmint_search, "N/D"),
        "email": (email_lookup, "N/D"),
        "ip": (ip_lookup, "N/D"),
        "finance": (finance_analysis, None),
        "btc": (btc_lookup, "N/D"),
        "news": (news_search, "N/D"),
        "phone": (phone_lookup, "N/D"),
        "domain": (domain_lookup, "N/D"),
        "hash": (hash_lookup, "N/D"),
        "pastebin": (pastebin_search, "N/D"),
        "crypto_multi": (crypto_multi_lookup, "N/D"),
    }
    
    if mode not in mode_functions:
        return {"success": False, "error": f"Modalità {mode} non supportata"}
    
    func, fin_default = mode_functions[mode]
    
    try:
        if mode == "finance":
            result, fin_data = func(target)
        else:
            result = func(target)
            fin_data = fin_default
        
        return {
            "success": True,
            "osint_data": result,
            "finance_data": fin_data if fin_data else "N/D",
            "ai_analysis": "Analisi AI disponibile con OpenRouter",
            "mode": mode,
            "target": target
        }
    except Exception as e:
        return {"success": False, "error": str(e)}

# ===== TEMPLATE HTML (con nuovi moduli) =====
HTML_TEMPLATE = '''
<!DOCTYPE html>
<html lang="it">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sentinel OSINT Hub - Advanced</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #0a0e27 0%, #1a1f3a 100%);
            min-height: 100vh;
            color: #e0e0e0;
        }
        .header {
            background: rgba(10, 14, 39, 0.95);
            padding: 20px;
            text-align: center;
            border-bottom: 1px solid rgba(0, 229, 255, 0.3);
        }
        .header h1 { font-size: 2rem; background: linear-gradient(135deg, #00e5ff, #00c853); -webkit-background-clip: text; background-clip: text; color: transparent; }
        .header p { color: #888; margin-top: 5px; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        
        .modules-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 12px;
            margin-bottom: 30px;
        }
        .module-card {
            background: linear-gradient(135deg, rgba(30, 35, 70, 0.9), rgba(20, 25, 55, 0.9));
            border-radius: 12px;
            padding: 15px;
            text-align: center;
            cursor: pointer;
            transition: all 0.3s ease;
            border: 1px solid rgba(0, 229, 255, 0.2);
        }
        .module-card:hover { transform: translateY(-3px); border-color: #00e5ff; }
        .module-card.active { border-color: #00e5ff; background: rgba(0, 229, 255, 0.15); }
        .module-emoji { font-size: 2rem; margin-bottom: 8px; }
        .module-title { font-weight: bold; font-size: 0.9rem; }
        
        .search-area {
            background: rgba(20, 25, 55, 0.8);
            border-radius: 16px;
            padding: 25px;
            margin-bottom: 30px;
            border: 1px solid rgba(0, 229, 255, 0.2);
        }
        .search-label { font-size: 0.9rem; color: #00e5ff; margin-bottom: 10px; display: block; }
        .search-input-group { display: flex; gap: 15px; flex-wrap: wrap; }
        .search-input {
            flex: 1;
            padding: 15px 20px;
            background: rgba(10, 14, 39, 0.9);
            border: 1px solid #333;
            border-radius: 10px;
            color: #fff;
            font-size: 1rem;
        }
        .search-input:focus { outline: none; border-color: #00e5ff; }
        .search-btn {
            padding: 15px 30px;
            background: linear-gradient(135deg, #00e5ff, #00c853);
            border: none;
            border-radius: 10px;
            color: #0a0e27;
            font-weight: bold;
            cursor: pointer;
        }
        .search-btn:hover { transform: scale(1.02); }
        .search-btn:disabled { opacity: 0.6; cursor: not-allowed; }
        
        .results-area {
            background: rgba(20, 25, 55, 0.6);
            border-radius: 16px;
            padding: 25px;
            border: 1px solid rgba(0, 229, 255, 0.2);
            display: none;
        }
        .results-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid #333;
        }
        .results-title { font-size: 1.2rem; color: #00e5ff; }
        .results-content {
            font-family: 'Courier New', monospace;
            font-size: 0.85rem;
            line-height: 1.6;
            white-space: pre-wrap;
            max-height: 550px;
            overflow-y: auto;
            padding: 15px;
            background: rgba(10, 14, 39, 0.5);
            border-radius: 10px;
        }
        .results-content a { color: #00e5ff; text-decoration: none; }
        
        .loading { display: none; text-align: center; padding: 40px; }
        .spinner {
            width: 50px;
            height: 50px;
            border: 3px solid #333;
            border-top-color: #00e5ff;
            border-radius: 50%;
            animation: spin 1s linear infinite;
            margin: 0 auto 15px;
        }
        @keyframes spin { to { transform: rotate(360deg); } }
        
        .history-sidebar {
            position: fixed;
            right: -350px;
            top: 0;
            width: 350px;
            height: 100vh;
            background: rgba(10, 14, 39, 0.98);
            border-left: 1px solid rgba(0, 229, 255, 0.3);
            transition: right 0.3s ease;
            z-index: 200;
            padding: 20px;
            overflow-y: auto;
        }
        .history-sidebar.open { right: 0; }
        .history-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid #333;
        }
        .history-close { background: none; border: none; color: #fff; font-size: 1.5rem; cursor: pointer; }
        .history-item {
            background: rgba(30, 35, 70, 0.6);
            border-radius: 8px;
            padding: 10px;
            margin-bottom: 10px;
            cursor: pointer;
        }
        .history-item:hover { background: rgba(0, 229, 255, 0.2); }
        .history-mode { font-size: 0.8rem; color: #00e5ff; }
        .history-target { font-family: monospace; font-size: 0.9rem; margin-top: 5px; }
        .history-time { font-size: 0.7rem; color: #888; margin-top: 5px; }
        
        .history-toggle {
            position: fixed;
            right: 20px;
            bottom: 20px;
            background: linear-gradient(135deg, #00e5ff, #00c853);
            border: none;
            border-radius: 50%;
            width: 60px;
            height: 60px;
            font-size: 1.5rem;
            cursor: pointer;
            z-index: 150;
        }
        
        .error-message { background: rgba(255, 68, 68, 0.2); border: 1px solid #ff4444; border-radius: 10px; padding: 15px; color: #ff8888; }
        
        @media (max-width: 768px) {
            .modules-grid { grid-template-columns: repeat(2, 1fr); }
            .search-input-group { flex-direction: column; }
            .history-sidebar { width: 100%; right: -100%; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🛰 Sentinel OSINT Hub</h1>
        <p>Advanced Open Source Intelligence Platform</p>
    </div>

    <div class="container">
        <div class="modules-grid">
            <div class="module-card" data-mode="socmint"><div class="module-emoji">👤</div><div class="module-title">SOCMINT</div></div>
            <div class="module-card" data-mode="email"><div class="module-emoji">📧</div><div class="module-title">Email</div></div>
            <div class="module-card" data-mode="ip"><div class="module-emoji">🌐</div><div class="module-title">IP/Network</div></div>
            <div class="module-card" data-mode="phone"><div class="module-emoji">📱</div><div class="module-title">Phone</div></div>
            <div class="module-card" data-mode="domain"><div class="module-emoji">🌍</div><div class="module-title">Domain</div></div>
            <div class="module-card" data-mode="hash"><div class="module-emoji">🔐</div><div class="module-title">File Hash</div></div>
            <div class="module-card" data-mode="pastebin"><div class="module-emoji">📋</div><div class="module-title">Pastebin</div></div>
            <div class="module-card" data-mode="finance"><div class="module-emoji">📈</div><div class="module-title">Finance</div></div>
            <div class="module-card" data-mode="btc"><div class="module-emoji">₿</div><div class="module-title">Bitcoin</div></div>
            <div class="module-card" data-mode="crypto_multi"><div class="module-emoji">🪙</div><div class="module-title">Multi-Crypto</div></div>
            <div class="module-card" data-mode="news"><div class="module-emoji">📰</div><div class="module-title">News</div></div>
        </div>

        <div class="search-area">
            <label class="search-label" id="search-label">Seleziona un modulo per iniziare</label>
            <div class="search-input-group">
                <input type="text" id="search-input" class="search-input" placeholder="Inserisci target..." disabled>
                <button id="search-btn" class="search-btn" disabled>Cerca</button>
            </div>
        </div>

        <div id="loading" class="loading"><div class="spinner"></div><p>🔍 Ricerca in corso...</p></div>

        <div id="results-area" class="results-area">
            <div class="results-header"><span class="results-title">Risultati</span><button id="copy-results" class="search-btn" style="padding: 8px 15px;">📋 Copia</button></div>
            <div id="results-content" class="results-content"></div>
        </div>
    </div>

    <button class="history-toggle" onclick="toggleHistory()">📜</button>

    <div id="history-sidebar" class="history-sidebar">
        <div class="history-header"><span>📊 Cronologia</span><button class="history-close" onclick="toggleHistory()">×</button></div>
        <div id="history-list">Nessuna ricerca</div>
    </div>

    <script>
        let currentMode = null;
        let sessionId = 'session_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
        
        const labels = {
            'socmint': '👤 Username (es. elonmusk)',
            'email': '📧 Email (es. user@example.com)',
            'ip': '🌐 IP (es. 8.8.8.8)',
            'phone': '📱 Telefono (es. +393391234567)',
            'domain': '🌍 Dominio (es. google.com)',
            'hash': '🔐 Hash MD5/SHA1/SHA256',
            'pastebin': '📋 Parole chiave per leak',
            'finance': '📈 Ticker (es. AAPL, TSLA)',
            'btc': '₿ Indirizzo Bitcoin',
            'crypto_multi': '🪙 Indirizzo Crypto (ETH, BSC, ecc.)',
            'news': '📰 Parole chiave news'
        };
        
        document.querySelectorAll('.module-card').forEach(card => {
            card.addEventListener('click', () => {
                document.querySelectorAll('.module-card').forEach(c => c.classList.remove('active'));
                card.classList.add('active');
                currentMode = card.dataset.mode;
                document.getElementById('search-label').textContent = labels[currentMode] || 'Inserisci target:';
                document.getElementById('search-input').disabled = false;
                document.getElementById('search-btn').disabled = false;
                document.getElementById('search-input').focus();
            });
        });
        
        async function performSearch() {
            const target = document.getElementById('search-input').value.trim();
            if (!target) { alert('Inserisci un target'); return; }
            if (!currentMode) { alert('Seleziona un modulo'); return; }
            
            document.getElementById('loading').style.display = 'block';
            document.getElementById('results-area').style.display = 'none';
            document.getElementById('search-btn').disabled = true;
            
            try {
                const response = await fetch('/api/search', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ mode: currentMode, target: target, session_id: sessionId })
                });
                const data = await response.json();
                
                if (data.success) {
                    displayResults(data);
                    loadHistory();
                } else {
                    displayError(data.error || 'Errore');
                }
            } catch (error) {
                displayError('Errore: ' + error.message);
            } finally {
                document.getElementById('loading').style.display = 'none';
                document.getElementById('search-btn').disabled = false;
            }
        }
        
        function displayResults(data) {
            const formatText = (text) => {
                if (!text) return '';
                return text
                    .replace(/\\*\\*(.+?)\\*\\*/g, '<strong>$1</strong>')
                    .replace(/\\[(.+?)\\]\\((.+?)\\)/g, '<a href="$2" target="_blank">$1</a>')
                    .replace(/`(.+?)`/g, '<code>$1</code>')
                    .replace(/\\n/g, '<br>')
                    .replace(/•/g, '&bull;');
            };
            
            let html = `<strong>🎯 Target:</strong> ${escapeHtml(data.target)}<br>`;
            html += `<strong>📋 Modalità:</strong> ${data.mode.toUpperCase()}<br><br>`;
            html += `<div style="background:rgba(0,0,0,0.3);padding:15px;border-radius:8px;">${formatText(data.osint_data)}</div>`;
            
            document.getElementById('results-content').innerHTML = html;
            document.getElementById('results-area').style.display = 'block';
            document.getElementById('results-area').scrollIntoView({ behavior: 'smooth' });
        }
        
        function escapeHtml(text) { const div = document.createElement('div'); div.textContent = text; return div.innerHTML; }
        function displayError(error) { document.getElementById('results-content').innerHTML = `<div class="error-message">❌ ${escapeHtml(error)}</div>`; document.getElementById('results-area').style.display = 'block'; }
        
        async function loadHistory() {
            try {
                const response = await fetch(`/api/history?session_id=${sessionId}`);
                const data = await response.json();
                const historyDiv = document.getElementById('history-list');
                if (!data.history || data.history.length === 0) { historyDiv.innerHTML = 'Nessuna ricerca'; return; }
                let html = '';
                data.history.forEach(item => {
                    const date = new Date(item.timestamp);
                    html += `<div class="history-item" onclick="rerunSearch('${item.mode}', '${item.target.replace(/'/g, "\\'")}')">
                        <div class="history-mode">${item.mode.toUpperCase()}</div>
                        <div class="history-target">${escapeHtml(item.target)}</div>
                        <div class="history-time">${date.toLocaleString()}</div>
                    </div>`;
                });
                historyDiv.innerHTML = html;
            } catch(e) { console.error(e); }
        }
        
        function rerunSearch(mode, target) {
            const card = Array.from(document.querySelectorAll('.module-card')).find(c => c.dataset.mode === mode);
            if (card) card.click();
            setTimeout(() => { document.getElementById('search-input').value = target; performSearch(); }, 100);
        }
        
        function toggleHistory() { document.getElementById('history-sidebar').classList.toggle('open'); }
        document.getElementById('copy-results').addEventListener('click', () => { navigator.clipboard.writeText(document.getElementById('results-content').innerText).then(() => alert('Copiato!')); });
        document.getElementById('search-input').addEventListener('keypress', (e) => { if (e.key === 'Enter') performSearch(); });
        
        loadHistory();
        setInterval(loadHistory, 30000);
    </script>
</body>
</html>
'''

# ===== ROTTE FLASK =====

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/api/search', methods=['POST'])
def api_search():
    data = request.json
    mode = data.get('mode')
    target = data.get('target', '').strip()
    session_id = data.get('session_id', 'unknown')
    
    if not mode or not target:
        return jsonify({'success': False, 'error': 'Mode e target richiesti'})
    
    result = run_search(mode, target)
    
    if result.get('success'):
        save_search(session_id, mode, target, result.get('osint_data', '')[:500])
    
    return jsonify(result)

@app.route('/api/history', methods=['GET'])
def api_history():
    session_id = request.args.get('session_id', 'unknown')
    history = get_user_history(session_id, limit=20)
    return jsonify({'history': [{'mode': m, 'target': t, 'timestamp': ts} for m, t, ts in history]})

# ===== MAIN =====

if __name__ == '__main__':
    init_db()
    
    print("\n" + "=" * 60)
    print("🛰 SENTINEL OSINT HUB - ADVANCED")
    print("=" * 60)
    print("✅ Moduli disponibili: 11")
    print("   👤 SOCMINT | 📧 Email | 🌐 IP | 📱 Phone | 🌍 Domain")
    print("   🔐 File Hash | 📋 Pastebin | 📈 Finance | ₿ Bitcoin")
    print("   🪙 Multi-Crypto | 📰 News")
    print("=" * 60)
    print("\n🌐 Browser: http://127.0.0.1:5000")
    print("🛑 Ctrl+C per fermare\n")
    
    import warnings
warnings.filterwarnings("ignore")
app.run(host='127.0.0.1', port=5000, debug=False, threaded=True, use_reloader=False)
