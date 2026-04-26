Rapport d'Audit de Sécurité : Reverse Engineering APK (UnCrackable Level 1)
Ce document détaille les étapes techniques de l'analyse statique et de la rétro-ingénierie effectuées sur l'application UnCrackable-Level1.apk.

1. Identification et Intégrité
La première étape a consisté à vérifier l'intégrité du fichier et à explorer sa structure binaire initiale via PowerShell.

Calcul de l'empreinte numérique :

PowerShell
Get-FileHash -Algorithm SHA256 .\UnCrackable-Level1.apk
SHA256 : 1DA8BF57D266109F9A07C01BF7111A1975CE01F190B9D914BCD3AE3DBEF96F21

Analyse de la structure de l'archive :

PowerShell
Add-Type -Assembly System.IO.Compression.FileSystem
$apk = Join-Path (Get-Location).Path "UnCrackable-Level1.apk"
[System.IO.Compression.ZipFile]::OpenRead($apk).Entries | Select-Object -ExpandProperty FullName
2. Analyse du Manifeste (AndroidManifest.xml)
L'analyse du fichier de configuration a permis d'identifier une vulnérabilité de configuration critique.

Package : owasp.mstg.uncrackable1

Vulnérabilité identifiée : android:allowBackup="true"

Risque : Cette configuration autorise l'extraction des données de l'application via la commande adb backup, compromettant la confidentialité des données utilisateur sur un appareil non rooté.

3. Rétro-ingénierie du Code Source
Le passage du bytecode Dalvik (DEX) vers un format lisible (Java) a été réalisé via la suite d'outils dex2jar et JD-GUI.

Conversion DEX vers JAR :

PowerShell
.\d2j-dex2jar.bat "C:\APK-Analysis\dex_out\classes.dex" -o "C:\APK-Analysis\classes.jar"
Analyse de la logique de chiffrement :
L'examen de la classe sg.vantagepoint.uncrackable1.a a révélé la présence d'éléments codés en dur :

Clé AES (Hex) : 8d127684cbc37c17616d806cf50473cc

Ciphertext (Base64) : 5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=

4. Déchiffrement et Extraction du Secret
Un script Python a été utilisé pour automatiser le déchiffrement du secret en utilisant les constantes identifiées. La méthode de chiffrement utilisée est l'AES en mode ECB.

Script de déchiffrement (dec.py) :

Python
from Crypto.Cipher import AES
import base64

key = bytes.fromhex("8d127684cbc37c17616d806cf50473cc")
ciphertext = base64.b64decode("5UJiFctbmgbDoLXmpL12mkno8HT4Lv8dlat8FxR2GOc=")
cipher = AES.new(key, AES.MODE_ECB)
decrypted = cipher.decrypt(ciphertext)
print(decrypted.decode('utf-8'))
Exécution et résultat :

PowerShell
python .\dec.py
Secret extrait : I want to believe

5. Conclusion de l'Audit
L'application présente des faiblesses structurelles majeures :

Absence de protection des secrets : La clé de chiffrement est stockée en clair dans le code.

Mode de chiffrement obsolète : L'utilisation de l'AES-ECB permet une analyse de motifs sur le ciphertext.

Configuration de sauvegarde non sécurisée : Le flag allowBackup expose les données locales.
