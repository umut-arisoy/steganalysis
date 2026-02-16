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


def main():
    parser = argparse.ArgumentParser(
        description='PNG ve BMP dosyalarında steganografi analizi',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Örnekler:
  %(prog)s image.png
  %(prog)s photo.bmp
  %(prog)s suspicious_image.png
        """
    )
    parser.add_argument('filepath', help='Analiz edilecek görüntü dosyası')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.filepath):
        print(f"❌ Hata: '{args.filepath}' dosyası bulunamadı!")
        sys.exit(1)
    
    try:
        tool = SteganalysisTool(args.filepath)
        tool.analyze()
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
