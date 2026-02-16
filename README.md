pip install numpy pillow --break-system-packages

pip install -r requirements.txt --break-system-packages

python steganalysis.py image.png

#Rapor oluşturma

python steganalysis.py image.png --methods all --html report.html

#Kullanım modu

python steganalysis.py --interactive

#Tüm analizler

python steganalysis.py image.png

#Temel kullanım örneği

python steganalysis.py image.png --methods lsb --html report.html
