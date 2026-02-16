#!/usr/bin/env python3
"""
Steganografi Analiz Aracı
PNG ve BMP dosyalarında gizlenmiş verileri tespit eder
"""

import sys
import os
import struct
import zlib
from collections import Counter
import numpy as np
from PIL import Image
import argparse
import base64
from datetime import datetime
import json

class SteganalysisToolError(Exception):
    """Steganaliz araç hatası"""
    pass

class SteganalysisTool:
    def __init__(self, filepath):
        self.filepath = filepath
        self.filename = os.path.basename(filepath)
        self.results = {
            'filename': self.filename,
            'file_type': None,
            'file_size': os.path.getsize(filepath),
            'suspicious_findings': [],
            'extracted_data': [],
            'lsb_analysis': {},
            'metadata': {},
            'chi_square_test': None
        }
        
    def analyze(self):
        """Ana analiz fonksiyonu"""
        print(f"\n{'='*70}")
        print(f"Steganografi Analizi: {self.filename}")
        print(f"{'='*70}\n")
        
        # Dosya türünü belirle
        self._detect_file_type()
        
        # Görüntüyü yükle
        try:
            self.image = Image.open(self.filepath)
            self.image_array = np.array(self.image)
        except Exception as e:
            raise SteganalysisToolError(f"Görüntü yüklenemedi: {e}")
        
        # Analizler
        self._analyze_lsb()
        self._analyze_metadata()
        self._chi_square_test()
        self._extract_lsb_data()
        self._check_unusual_patterns()
        self._analyze_file_structure()
        
        # Sonuçları göster
        self._display_results()
        
        return self.results
    
    def _detect_file_type(self):
        """Dosya türünü belirle"""
        with open(self.filepath, 'rb') as f:
            header = f.read(8)
        
        # PNG imzası
        if header[:8] == b'\x89PNG\r\n\x1a\n':
            self.results['file_type'] = 'PNG'
        # BMP imzası
        elif header[:2] == b'BM':
            self.results['file_type'] = 'BMP'
        else:
            self.results['file_type'] = 'UNKNOWN'
            self.results['suspicious_findings'].append(
                "⚠️  Dosya başlığı beklenen formatta değil"
            )
    
    def _analyze_lsb(self):
        """LSB (Least Significant Bit) analizi"""
        print("📊 LSB Analizi yapılıyor...")
        
        # Her kanal için LSB dağılımını analiz et
        if len(self.image_array.shape) == 3:  # Renkli görüntü
            channels = ['Red', 'Green', 'Blue']
            if self.image_array.shape[2] == 4:
                channels.append('Alpha')
            
            for idx, channel_name in enumerate(channels[:self.image_array.shape[2]]):
                channel = self.image_array[:, :, idx]
                lsb_bits = channel & 1
                
                # LSB dağılımı
                ones = np.sum(lsb_bits)
                zeros = lsb_bits.size - ones
                ratio = ones / lsb_bits.size if lsb_bits.size > 0 else 0
                
                self.results['lsb_analysis'][channel_name] = {
                    'ones': int(ones),
                    'zeros': int(zeros),
                    'ratio': float(ratio),
                    'total_bits': int(lsb_bits.size)
                }
                
                # Normal bir görüntüde LSB oranı ~0.5 olmalı
                if abs(ratio - 0.5) > 0.05:
                    self.results['suspicious_findings'].append(
                        f"⚠️  {channel_name} kanalında anormal LSB dağılımı (Oran: {ratio:.3f})"
                    )
        else:  # Gri tonlamalı
            lsb_bits = self.image_array & 1
            ones = np.sum(lsb_bits)
            zeros = lsb_bits.size - ones
            ratio = ones / lsb_bits.size if lsb_bits.size > 0 else 0
            
            self.results['lsb_analysis']['Grayscale'] = {
                'ones': int(ones),
                'zeros': int(zeros),
                'ratio': float(ratio),
                'total_bits': int(lsb_bits.size)
            }
            
            if abs(ratio - 0.5) > 0.05:
                self.results['suspicious_findings'].append(
                    f"⚠️  Gri tonlamada anormal LSB dağılımı (Oran: {ratio:.3f})"
                )
    
    def _chi_square_test(self):
        """Chi-Square testi ile steganografi tespiti"""
        print("📈 Chi-Square testi yapılıyor...")
        
        # İlk kanalı kullan
        if len(self.image_array.shape) == 3:
            data = self.image_array[:, :, 0].flatten()
        else:
            data = self.image_array.flatten()
        
        # Çift ve tek değerlerin frekansını say
        pairs = {}
        for i in range(0, 256, 2):
            pairs[i] = np.sum(data == i)
            pairs[i+1] = np.sum(data == i+1)
        
        # Chi-square değerini hesapla
        chi_square = 0
        for i in range(0, 256, 2):
            expected = (pairs[i] + pairs[i+1]) / 2
            if expected > 0:
                chi_square += ((pairs[i] - expected) ** 2) / expected
                chi_square += ((pairs[i+1] - expected) ** 2) / expected
        
        self.results['chi_square_test'] = float(chi_square)
        
        # Yüksek chi-square değeri steganografi göstergesi
        if chi_square > 200:
            self.results['suspicious_findings'].append(
                f"⚠️  Yüksek Chi-Square değeri tespit edildi: {chi_square:.2f} (Muhtemel steganografi)"
            )
    
    def _extract_lsb_data(self):
        """LSB'lerden veri çıkarmayı dene"""
        print("🔍 LSB verisi çıkarılıyor...")
        
        # Tüm LSB bitlerini topla
        if len(self.image_array.shape) == 3:
            # RGB kanallarını sırayla kullan
            flat_image = self.image_array[:, :, :3].flatten()
        else:
            flat_image = self.image_array.flatten()
        
        # LSB'leri al
        lsb_bits = (flat_image & 1).astype(np.uint8)
        
        # Bitleri byte'lara dönüştür
        bytes_data = []
        for i in range(0, len(lsb_bits) - 8, 8):
            byte = 0
            for j in range(8):
                byte |= (lsb_bits[i + j] << j)
            bytes_data.append(byte)
        
        # ASCII metnini kontrol et
        text_attempt = self._try_extract_text(bytes_data)
        if text_attempt:
            self.results['extracted_data'].append({
                'type': 'ASCII Text (LSB)',
                'data': text_attempt,
                'length': len(text_attempt)
            })
            self.results['suspicious_findings'].append(
                f"✅ LSB'lerde ASCII metin bulundu! ({len(text_attempt)} karakter)"
            )
        
        # Dosya imzalarını kontrol et
        file_signatures = self._check_file_signatures(bytes_data)
        if file_signatures:
            self.results['extracted_data'].extend(file_signatures)
    
    def _try_extract_text(self, bytes_data, min_length=10):
        """Byte dizisinden ASCII metin çıkarmayı dene"""
        text = ""
        consecutive_printable = 0
        
        for byte in bytes_data[:10000]:  # İlk 10KB'ı kontrol et
            if 32 <= byte <= 126 or byte in [9, 10, 13]:  # Yazdırılabilir ASCII
                text += chr(byte)
                consecutive_printable += 1
            else:
                if consecutive_printable >= min_length:
                    return text
                text = ""
                consecutive_printable = 0
        
        if len(text) >= min_length:
            return text
        return None
    
    def _check_file_signatures(self, bytes_data):
        """Bilinen dosya imzalarını kontrol et"""
        signatures = {
            'PNG': [b'\x89PNG\r\n\x1a\n'],
            'JPEG': [b'\xFF\xD8\xFF'],
            'ZIP': [b'PK\x03\x04', b'PK\x05\x06'],
            'PDF': [b'%PDF'],
            'GIF': [b'GIF87a', b'GIF89a'],
            'RAR': [b'Rar!\x1a\x07'],
            'EXE': [b'MZ'],
            'MP3': [b'ID3', b'\xFF\xFB'],
        }
        
        found_files = []
        bytes_array = bytes(bytes_data[:1000])  # İlk 1KB'ı kontrol et
        
        for file_type, sigs in signatures.items():
            for sig in sigs:
                if sig in bytes_array:
                    found_files.append({
                        'type': f'File Signature: {file_type}',
                        'data': f'Offset: {bytes_array.find(sig)}',
                        'length': len(sig)
                    })
                    self.results['suspicious_findings'].append(
                        f"⚠️  {file_type} dosya imzası tespit edildi!"
                    )
        
        return found_files
    
    def _check_unusual_patterns(self):
        """Olağandışı paternleri kontrol et"""
        print("🔎 Olağandışı paternler aranıyor...")
        
        # Piksel değerlerinin standart sapmasını kontrol et
        std_dev = np.std(self.image_array)
        if std_dev < 10:
            self.results['suspicious_findings'].append(
                f"⚠️  Çok düşük standart sapma: {std_dev:.2f} (Düz renkli alanlar)"
            )
        
        # Sıralı değerleri kontrol et (sequential patterns)
        flat = self.image_array.flatten()
        sequential_count = 0
        for i in range(len(flat) - 1):
            if abs(int(flat[i]) - int(flat[i+1])) <= 1:
                sequential_count += 1
        
        sequential_ratio = sequential_count / len(flat)
        if sequential_ratio > 0.8:
            self.results['suspicious_findings'].append(
                f"⚠️  Yüksek sıralı değer oranı: {sequential_ratio:.2%}"
            )
    
    def _analyze_metadata(self):
        """Görüntü metadata'sını analiz et"""
        print("📝 Metadata analizi yapılıyor...")
        
        # EXIF verisi
        try:
            from PIL.ExifTags import TAGS
            exif = self.image._getexif()
            if exif:
                for tag_id, value in exif.items():
                    tag = TAGS.get(tag_id, tag_id)
                    self.results['metadata'][tag] = str(value)
        except:
            pass
        
        # Temel bilgiler
        self.results['metadata']['Format'] = self.image.format
        self.results['metadata']['Mode'] = self.image.mode
        self.results['metadata']['Size'] = f"{self.image.size[0]}x{self.image.size[1]}"
        
        # PNG için özel kontroller
        if self.results['file_type'] == 'PNG':
            self._analyze_png_chunks()
    
    def _analyze_png_chunks(self):
        """PNG chunk'larını analiz et"""
        print("📦 PNG chunk'ları analiz ediliyor...")
        
        with open(self.filepath, 'rb') as f:
            f.read(8)  # PNG imzasını atla
            
            chunks = []
            while True:
                try:
                    # Chunk uzunluğunu oku
                    length_bytes = f.read(4)
                    if len(length_bytes) < 4:
                        break
                    
                    length = struct.unpack('>I', length_bytes)[0]
                    chunk_type = f.read(4).decode('ascii', errors='ignore')
                    chunk_data = f.read(length)
                    crc = f.read(4)
                    
                    chunks.append({
                        'type': chunk_type,
                        'length': length
                    })
                    
                    # Standart olmayan chunk'ları tespit et
                    standard_chunks = ['IHDR', 'PLTE', 'IDAT', 'IEND', 'tRNS', 
                                      'gAMA', 'cHRM', 'sRGB', 'iCCP', 'tEXt', 
                                      'zTXt', 'iTXt', 'bKGD', 'pHYs', 'tIME']
                    
                    if chunk_type not in standard_chunks:
                        self.results['suspicious_findings'].append(
                            f"⚠️  Standart olmayan PNG chunk bulundu: {chunk_type} ({length} byte)"
                        )
                        
                        # tEXt, zTXt, iTXt chunk'larından metin çıkar
                        if chunk_type in ['tEXt', 'zTXt', 'iTXt']:
                            try:
                                if chunk_type == 'tEXt':
                                    text = chunk_data.split(b'\x00', 1)
                                    if len(text) == 2:
                                        keyword, content = text
                                        self.results['extracted_data'].append({
                                            'type': f'PNG tEXt chunk: {keyword.decode()}',
                                            'data': content.decode('latin1'),
                                            'length': len(content)
                                        })
                            except:
                                pass
                    
                except Exception as e:
                    break
            
            self.results['metadata']['PNG_Chunks'] = chunks
    
    def _analyze_file_structure(self):
        """Dosya yapısını analiz et"""
        print("🏗️  Dosya yapısı analiz ediliyor...")
        
        with open(self.filepath, 'rb') as f:
            file_data = f.read()
        
        # Dosya sonunda ekstra veri var mı kontrol et
        if self.results['file_type'] == 'PNG':
            iend_pos = file_data.rfind(b'IEND')
            if iend_pos != -1:
                # IEND'den sonra CRC (4 byte) olmalı
                expected_end = iend_pos + 4 + 4
                if len(file_data) > expected_end:
                    extra_bytes = len(file_data) - expected_end
                    self.results['suspicious_findings'].append(
                        f"⚠️  PNG IEND chunk'ından sonra {extra_bytes} byte ekstra veri bulundu!"
                    )
                    
                    # Bu veriyi çıkarmayı dene
                    extra_data = file_data[expected_end:]
                    text = self._try_extract_text(list(extra_data))
                    if text:
                        self.results['extracted_data'].append({
                            'type': 'Text after IEND',
                            'data': text,
                            'length': len(text)
                        })
    
    def _display_results(self):
        """Sonuçları göster"""
        print(f"\n{'='*70}")
        print("📋 ANALİZ SONUÇLARI")
        print(f"{'='*70}\n")
        
        print(f"📄 Dosya: {self.results['filename']}")
        print(f"📊 Tip: {self.results['file_type']}")
        print(f"💾 Boyut: {self.results['file_size']:,} bytes")
        print(f"🖼️  Boyutlar: {self.results['metadata'].get('Size', 'N/A')}")
        
        # LSB Analizi
        print(f"\n{'─'*70}")
        print("📊 LSB Analiz Sonuçları:")
        print(f"{'─'*70}")
        for channel, stats in self.results['lsb_analysis'].items():
            print(f"\n  {channel} Kanalı:")
            print(f"    • 1'ler: {stats['ones']:,} ({stats['ratio']:.1%})")
            print(f"    • 0'lar: {stats['zeros']:,} ({1-stats['ratio']:.1%})")
            print(f"    • Toplam: {stats['total_bits']:,} bits")
        
        # Chi-Square
        if self.results['chi_square_test'] is not None:
            print(f"\n{'─'*70}")
            print(f"📈 Chi-Square Test: {self.results['chi_square_test']:.2f}")
            if self.results['chi_square_test'] > 200:
                print("    ⚠️  YÜKSEK - Steganografi olasılığı yüksek!")
            elif self.results['chi_square_test'] > 100:
                print("    ⚠️  ORTA - Steganografi olabilir")
            else:
                print("    ✅ DÜŞÜK - Normal görünüyor")
        
        # Şüpheli bulgular
        if self.results['suspicious_findings']:
            print(f"\n{'─'*70}")
            print(f"⚠️  ŞÜPHELİ BULGULAR ({len(self.results['suspicious_findings'])}):")
            print(f"{'─'*70}")
            for finding in self.results['suspicious_findings']:
                print(f"  {finding}")
        
        # Çıkarılan veriler
        if self.results['extracted_data']:
            print(f"\n{'─'*70}")
            print(f"✅ ÇIKARILAN VERİLER ({len(self.results['extracted_data'])}):")
            print(f"{'─'*70}")
            for idx, data in enumerate(self.results['extracted_data'], 1):
                print(f"\n  [{idx}] {data['type']}:")
                print(f"      Uzunluk: {data['length']} bytes")
                if isinstance(data['data'], str) and len(data['data']) <= 500:
                    print(f"      İçerik: {data['data'][:500]}")
                elif isinstance(data['data'], str):
                    print(f"      İçerik (ilk 500 karakter): {data['data'][:500]}...")
                else:
                    print(f"      İçerik: {data['data']}")
        
        # Özet
        print(f"\n{'='*70}")
        if self.results['suspicious_findings'] or self.results['extracted_data']:
            print("🚨 SONUÇ: Bu dosyada steganografi belirtileri tespit edildi!")
        else:
            print("✅ SONUÇ: Belirgin bir steganografi tespit edilemedi.")
        print(f"{'='*70}\n")
    
    def generate_html_report(self, output_path='report.html'):
        """Detaylı HTML raporu oluştur"""
        
        # Görüntüyü base64'e çevir
        with open(self.filepath, 'rb') as f:
            image_data = base64.b64encode(f.read()).decode('utf-8')
        
        # Analiz zamanı
        analysis_time = datetime.now().strftime('%d.%m.%Y %H:%M:%S')
        
        # Risk skoru hesapla (0-100)
        risk_score = 0
        if self.results['chi_square_test']:
            if self.results['chi_square_test'] > 200:
                risk_score += 40
            elif self.results['chi_square_test'] > 100:
                risk_score += 20
        
        risk_score += len(self.results['suspicious_findings']) * 10
        risk_score += len(self.results['extracted_data']) * 15
        risk_score = min(100, risk_score)
        
        # Risk seviyesi ve rengi
        if risk_score >= 70:
            risk_level = "YÜKSEK RİSK"
            risk_color = "#ef4444"
            risk_bg = "#fef2f2"
        elif risk_score >= 40:
            risk_level = "ORTA RİSK"
            risk_color = "#f59e0b"
            risk_bg = "#fffbeb"
        else:
            risk_level = "DÜŞÜK RİSK"
            risk_color = "#10b981"
            risk_bg = "#f0fdf4"
        
        # LSB grafiği için veri hazırla
        lsb_chart_data = []
        for channel, stats in self.results['lsb_analysis'].items():
            lsb_chart_data.append({
                'channel': channel,
                'ones': stats['ones'],
                'zeros': stats['zeros'],
                'ratio': stats['ratio']
            })
        
        html_content = f"""<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Steganografi Analiz Raporu - {self.results['filename']}</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Space+Grotesk:wght@300;400;600;700&display=swap');
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        :root {{
            --primary: #0f172a;
            --secondary: #1e293b;
            --accent: #3b82f6;
            --success: #10b981;
            --warning: #f59e0b;
            --danger: #ef4444;
            --text: #f8fafc;
            --text-secondary: #cbd5e1;
            --border: #334155;
            --card-bg: #1e293b;
            --gradient-start: #0f172a;
            --gradient-end: #1e293b;
        }}
        
        body {{
            font-family: 'Space Grotesk', sans-serif;
            background: linear-gradient(135deg, var(--gradient-start) 0%, var(--gradient-end) 100%);
            color: var(--text);
            line-height: 1.6;
            min-height: 100vh;
            position: relative;
        }}
        
        body::before {{
            content: '';
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: 
                radial-gradient(circle at 20% 50%, rgba(59, 130, 246, 0.1) 0%, transparent 50%),
                radial-gradient(circle at 80% 80%, rgba(168, 85, 247, 0.08) 0%, transparent 50%);
            pointer-events: none;
            z-index: 0;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 40px 20px;
            position: relative;
            z-index: 1;
        }}
        
        .header {{
            text-align: center;
            margin-bottom: 50px;
            padding: 40px;
            background: rgba(30, 41, 59, 0.6);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            border: 1px solid var(--border);
            position: relative;
            overflow: hidden;
        }}
        
        .header::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 4px;
            background: linear-gradient(90deg, var(--accent), #8b5cf6, var(--accent));
            background-size: 200% 100%;
            animation: shimmer 3s linear infinite;
        }}
        
        @keyframes shimmer {{
            0% {{ background-position: -200% 0; }}
            100% {{ background-position: 200% 0; }}
        }}
        
        .header h1 {{
            font-size: 3em;
            font-weight: 700;
            margin-bottom: 10px;
            background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }}
        
        .header .subtitle {{
            font-size: 1.2em;
            color: var(--text-secondary);
            font-family: 'JetBrains Mono', monospace;
        }}
        
        .risk-banner {{
            background: {risk_bg};
            border: 2px solid {risk_color};
            border-radius: 15px;
            padding: 30px;
            margin: 30px 0;
            text-align: center;
            position: relative;
            overflow: hidden;
        }}
        
        .risk-banner::before {{
            content: '';
            position: absolute;
            top: 0;
            left: -100%;
            width: 100%;
            height: 100%;
            background: linear-gradient(90deg, transparent, rgba(255,255,255,0.1), transparent);
            animation: scan 2s ease-in-out infinite;
        }}
        
        @keyframes scan {{
            0% {{ left: -100%; }}
            100% {{ left: 100%; }}
        }}
        
        .risk-score {{
            font-size: 4em;
            font-weight: 700;
            color: {risk_color};
            font-family: 'JetBrains Mono', monospace;
        }}
        
        .risk-level {{
            font-size: 1.5em;
            font-weight: 600;
            color: {risk_color};
            margin-top: 10px;
        }}
        
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 25px;
            margin: 30px 0;
        }}
        
        .card {{
            background: rgba(30, 41, 59, 0.8);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            padding: 30px;
            border: 1px solid var(--border);
            transition: all 0.3s ease;
        }}
        
        .card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.4);
            border-color: var(--accent);
        }}
        
        .card h2 {{
            font-size: 1.5em;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
            color: var(--text);
        }}
        
        .card h2 .icon {{
            font-size: 1.3em;
        }}
        
        .info-item {{
            display: flex;
            justify-content: space-between;
            padding: 12px 0;
            border-bottom: 1px solid var(--border);
        }}
        
        .info-item:last-child {{
            border-bottom: none;
        }}
        
        .info-label {{
            color: var(--text-secondary);
            font-weight: 500;
        }}
        
        .info-value {{
            font-family: 'JetBrains Mono', monospace;
            font-weight: 600;
        }}
        
        .image-preview {{
            width: 100%;
            border-radius: 10px;
            margin-top: 15px;
            border: 2px solid var(--border);
            transition: all 0.3s ease;
        }}
        
        .image-preview:hover {{
            transform: scale(1.02);
            border-color: var(--accent);
        }}
        
        .chart-container {{
            margin: 20px 0;
            padding: 20px;
            background: rgba(15, 23, 42, 0.5);
            border-radius: 10px;
        }}
        
        .bar {{
            display: flex;
            align-items: center;
            margin: 15px 0;
        }}
        
        .bar-label {{
            width: 100px;
            font-weight: 600;
            font-family: 'JetBrains Mono', monospace;
        }}
        
        .bar-container {{
            flex: 1;
            height: 30px;
            background: rgba(15, 23, 42, 0.8);
            border-radius: 5px;
            overflow: hidden;
            position: relative;
        }}
        
        .bar-fill {{
            height: 100%;
            background: linear-gradient(90deg, var(--accent), #8b5cf6);
            display: flex;
            align-items: center;
            justify-content: flex-end;
            padding: 0 10px;
            font-family: 'JetBrains Mono', monospace;
            font-weight: 700;
            font-size: 0.9em;
            transition: width 1s ease;
        }}
        
        .finding-item {{
            background: rgba(15, 23, 42, 0.5);
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
            border-left: 4px solid var(--warning);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.95em;
        }}
        
        .finding-item.critical {{
            border-left-color: var(--danger);
        }}
        
        .finding-item.success {{
            border-left-color: var(--success);
        }}
        
        .data-extract {{
            background: rgba(15, 23, 42, 0.8);
            padding: 20px;
            border-radius: 10px;
            margin: 15px 0;
            border: 1px solid var(--border);
        }}
        
        .data-extract h3 {{
            color: var(--accent);
            margin-bottom: 10px;
            font-size: 1.1em;
        }}
        
        .data-extract pre {{
            background: rgba(0, 0, 0, 0.5);
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9em;
            line-height: 1.5;
            color: #94a3b8;
        }}
        
        .metadata-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        
        .metadata-item {{
            background: rgba(15, 23, 42, 0.5);
            padding: 15px;
            border-radius: 8px;
            border: 1px solid var(--border);
        }}
        
        .metadata-item strong {{
            display: block;
            color: var(--text-secondary);
            margin-bottom: 5px;
            font-size: 0.9em;
        }}
        
        .metadata-item span {{
            font-family: 'JetBrains Mono', monospace;
            font-weight: 600;
        }}
        
        .footer {{
            text-align: center;
            margin-top: 50px;
            padding: 30px;
            background: rgba(30, 41, 59, 0.6);
            backdrop-filter: blur(10px);
            border-radius: 15px;
            border: 1px solid var(--border);
            color: var(--text-secondary);
            font-size: 0.9em;
        }}
        
        .badge {{
            display: inline-block;
            padding: 5px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            font-weight: 600;
            font-family: 'JetBrains Mono', monospace;
        }}
        
        .badge-success {{
            background: rgba(16, 185, 129, 0.2);
            color: var(--success);
            border: 1px solid var(--success);
        }}
        
        .badge-warning {{
            background: rgba(245, 158, 11, 0.2);
            color: var(--warning);
            border: 1px solid var(--warning);
        }}
        
        .badge-danger {{
            background: rgba(239, 68, 68, 0.2);
            color: var(--danger);
            border: 1px solid var(--danger);
        }}
        
        @media print {{
            body {{
                background: white;
                color: black;
            }}
            .card {{
                break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Steganografi Analiz Raporu</h1>
            <div class="subtitle">Gelişmiş Steganaliz ve Gizli Veri Tespiti</div>
        </div>
        
        <div class="risk-banner">
            <div class="risk-score">{risk_score}</div>
            <div class="risk-level">{risk_level}</div>
            <p style="margin-top: 15px; color: {risk_color}; font-weight: 600;">
                {'Bu dosyada steganografi belirtileri tespit edildi!' if risk_score >= 40 else 'Dosya temiz görünüyor.'}
            </p>
        </div>
        
        <div class="grid">
            <div class="card">
                <h2><span class="icon">📄</span> Dosya Bilgileri</h2>
                <div class="info-item">
                    <span class="info-label">Dosya Adı</span>
                    <span class="info-value">{self.results['filename']}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Dosya Türü</span>
                    <span class="info-value">{self.results['file_type']}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Boyut</span>
                    <span class="info-value">{self.results['file_size']:,} bytes</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Boyutlar</span>
                    <span class="info-value">{self.results['metadata'].get('Size', 'N/A')}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Format</span>
                    <span class="info-value">{self.results['metadata'].get('Format', 'N/A')}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Mod</span>
                    <span class="info-value">{self.results['metadata'].get('Mode', 'N/A')}</span>
                </div>
                <div class="info-item">
                    <span class="info-label">Analiz Zamanı</span>
                    <span class="info-value">{analysis_time}</span>
                </div>
            </div>
            
            <div class="card">
                <h2><span class="icon">🖼️</span> Görüntü Önizleme</h2>
                <img src="data:image/png;base64,{image_data}" alt="Analiz edilen görüntü" class="image-preview">
            </div>
        </div>
        
        <div class="card">
            <h2><span class="icon">📊</span> LSB (Least Significant Bit) Analizi</h2>
            <div class="chart-container">
"""
        
        # LSB grafikleri
        for channel_data in lsb_chart_data:
            ratio_percent = channel_data['ratio'] * 100
            html_content += f"""
                <div class="bar">
                    <div class="bar-label">{channel_data['channel']}</div>
                    <div class="bar-container">
                        <div class="bar-fill" style="width: {ratio_percent}%">{ratio_percent:.1f}%</div>
                    </div>
                </div>
"""
        
        html_content += """
            </div>
            <p style="color: var(--text-secondary); margin-top: 15px;">
                <strong>Not:</strong> Normal bir görüntüde 1'lerin oranı ~%50 olmalıdır. 
                %45-55 aralığının dışındaki değerler şüpheli olabilir.
            </p>
        </div>
        
"""
        
        # Chi-Square testi
        if self.results['chi_square_test'] is not None:
            chi_value = self.results['chi_square_test']
            if chi_value > 200:
                chi_badge = '<span class="badge badge-danger">YÜKSEK RİSK</span>'
                chi_desc = "Steganografi olasılığı çok yüksek!"
            elif chi_value > 100:
                chi_badge = '<span class="badge badge-warning">ORTA RİSK</span>'
                chi_desc = "Steganografi olabilir, detaylı inceleme önerilir."
            else:
                chi_badge = '<span class="badge badge-success">DÜŞÜK RİSK</span>'
                chi_desc = "Normal dağılım görünüyor."
            
            html_content += f"""
        <div class="card">
            <h2><span class="icon">📈</span> Chi-Square İstatistiksel Test</h2>
            <div style="text-align: center; padding: 20px;">
                <div style="font-size: 3em; font-weight: 700; font-family: 'JetBrains Mono', monospace; color: var(--accent);">
                    {chi_value:.2f}
                </div>
                <div style="margin: 15px 0;">
                    {chi_badge}
                </div>
                <p style="color: var(--text-secondary);">{chi_desc}</p>
            </div>
            <div style="background: rgba(15, 23, 42, 0.5); padding: 15px; border-radius: 8px; margin-top: 20px;">
                <strong>Chi-Square Değerlendirme Ölçeği:</strong>
                <ul style="margin-top: 10px; color: var(--text-secondary); line-height: 2;">
                    <li>&lt; 100: Düşük risk (Normal)</li>
                    <li>100-200: Orta risk (İncelenmeli)</li>
                    <li>&gt; 200: Yüksek risk (Muhtemelen steganografi)</li>
                </ul>
            </div>
        </div>
"""
        
        # Şüpheli bulgular
        if self.results['suspicious_findings']:
            html_content += f"""
        <div class="card">
            <h2><span class="icon">⚠️</span> Şüpheli Bulgular ({len(self.results['suspicious_findings'])})</h2>
"""
            for finding in self.results['suspicious_findings']:
                # Bulgu tipine göre class belirle
                if '✅' in finding:
                    finding_class = 'success'
                elif 'YÜKSEK' in finding or 'tespit edildi' in finding:
                    finding_class = 'critical'
                else:
                    finding_class = ''
                    
                html_content += f'            <div class="finding-item {finding_class}">{finding}</div>\n'
            
            html_content += """
        </div>
"""
        
        # Çıkarılan veriler
        if self.results['extracted_data']:
            html_content += f"""
        <div class="card">
            <h2><span class="icon">✅</span> Çıkarılan Veriler ({len(self.results['extracted_data'])})</h2>
"""
            for idx, data in enumerate(self.results['extracted_data'], 1):
                data_content = data['data']
                if isinstance(data_content, str):
                    # HTML escape
                    data_content = data_content.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                    if len(data_content) > 1000:
                        data_content = data_content[:1000] + '...\n\n[Kalan içerik kesiliyor...]'
                
                html_content += f"""
            <div class="data-extract">
                <h3>[{idx}] {data['type']}</h3>
                <p><strong>Uzunluk:</strong> {data['length']} bytes</p>
                <pre>{data_content}</pre>
            </div>
"""
            
            html_content += """
        </div>
"""
        
        # Metadata
        html_content += """
        <div class="card">
            <h2><span class="icon">📝</span> Metadata Bilgileri</h2>
            <div class="metadata-grid">
"""
        
        for key, value in self.results['metadata'].items():
            if key not in ['Size', 'Format', 'Mode', 'PNG_Chunks']:  # Zaten gösterildi
                html_content += f"""
                <div class="metadata-item">
                    <strong>{key}</strong>
                    <span>{str(value)[:100]}</span>
                </div>
"""
        
        html_content += """
            </div>
        </div>
        
        <div class="footer">
            <p><strong>Steganografi Analiz Aracı</strong></p>
            <p>Bu rapor otomatik olarak oluşturulmuştur • """ + analysis_time + """</p>
            <p style="margin-top: 10px; font-size: 0.85em;">
                ⚠️ Yasal Uyarı: Bu araç yalnızca eğitim ve güvenlik araştırması amaçlı kullanılmalıdır.
            </p>
        </div>
    </div>
    
    <script>
        // Sayfa yüklendiğinde animasyonları başlat
        window.addEventListener('load', function() {
            // Bar animasyonları
            const bars = document.querySelectorAll('.bar-fill');
            bars.forEach(bar => {
                const width = bar.style.width;
                bar.style.width = '0%';
                setTimeout(() => {
                    bar.style.width = width;
                }, 100);
            });
        });
        
        // Yazdırma fonksiyonu
        function printReport() {
            window.print();
        }
    </script>
</body>
</html>"""
        
        # HTML dosyasını kaydet
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"\n✅ HTML raporu oluşturuldu: {output_path}")
        return output_path


def main():
    parser = argparse.ArgumentParser(
        description='PNG ve BMP dosyalarında steganografi analizi',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnekler:
  %(prog)s image.png
  %(prog)s photo.bmp
  %(prog)s suspicious_image.png
  %(prog)s image.png --html report.html
        """
    )
    parser.add_argument('filepath', help='Analiz edilecek görüntü dosyası')
    parser.add_argument('--html', '--report', metavar='OUTPUT', 
                       help='HTML raporu oluştur (örn: --html report.html)')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.filepath):
        print(f"❌ Hata: '{args.filepath}' dosyası bulunamadı!")
        sys.exit(1)
    
    try:
        tool = SteganalysisTool(args.filepath)
        tool.analyze()
        
        # HTML raporu oluştur
        if args.html:
            html_path = args.html
            tool.generate_html_report(html_path)
            print(f"\n📊 HTML raporu görüntülemek için: {html_path}")
            
    except SteganalysisToolError as e:
        print(f"❌ Hata: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Beklenmeyen hata: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
