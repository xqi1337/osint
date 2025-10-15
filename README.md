# OSINT-Techniques

###
###
### 
#######################################################################################
## Inhaltsverzeichnis
#######################################################################################

- [Gap Analysis Methodology](#gap-analysis-methodology)
- [Password Reset](#password-reset)
- [Reverse Image Searching](#reverse-image-searching)
- [Recent Satellite Imagery](#recent-satellite-imagery)
- [Calculate Photo Time of Day](#calculate-photo-time-of-day)
- [Fictional Account Creation](#fictional-account-creation)
- [Antiviruses](#antiviruses)
- [File Sharing](#file-sharing)
- [OSINT Tools](#osint-tools)
- [OSINT Resources](#osint-resources)
- [Books](#books)
- [Search Engines](#search-engines)

---
#######################################################################################
## Gap Analysis Methodology
#######################################################################################

Bei der **Lückenanalyse** wird eine Bestandsaufnahme der vorhandenen Ausgangsinformationen vorgenommen und dann anhand von vier einfachen Fragen ermittelt, was als nächstes zu tun ist. Auf diese Weise können Sie Struktur und Ordnung in Ihre OSINT-Forschung bringen.

**Die vier Kernfragen:**

1. Was weiß ich?
2. Was bedeutet das?
3. (Also) Was muss ich wissen?
4. Wie kann ich es herausfinden?

**Erweiterte Methodik:**

5. Welche Quellen sind am zuverlässigsten?
6. Welche Informationen können verifiziert werden?
7. Gibt es widersprüchliche Informationen?
8. Welche rechtlichen und ethischen Grenzen muss ich beachten?

**Best Practices für strukturierte OSINT-Recherche:**

- Dokumentieren Sie jeden Rechercheschritt mit Zeitstempel
- Erstellen Sie Mind Maps zur Visualisierung von Verbindungen
- Nutzen Sie Pivot-Techniken: Von einer Information zur nächsten springen
- Bewahren Sie Nachweise (Screenshots, Archive) für spätere Verifizierung
- Setzen Sie auf multiple Quellen zur Triangulation von Informationen

---
#######################################################################################
## Password Reset
#######################################################################################

Mangelnde Standardisierung bei den Ansätzen für Funktionen zum Zurücksetzen von Passwörtern, die verwendet werden können, um die Telefonnummern und E-Mail-Adressen von Zielkonten zu erhalten.



**Plattform-Übersicht:**

- **FACEBOOK:** Zeigt einen Bildschirm mit alternativen Kontaktmethoden an, die zum Zurücksetzen des Passworts verwendet werden können. Die Anzahl der Sternchen entspricht der Länge der E-Mail-Adressen.

- **GOOGLE:** Sie werden aufgefordert, das letzte Passwort einzugeben, das Sie sich gemerkt haben und das Sie beliebig ändern können. Auf dem nächsten Bildschirm wird eine geschwärzte Wiederherstellungs-Telefonnummer mit den letzten beiden Ziffern angezeigt, sofern eine solche in der Datei vorhanden ist.

- **TWITTER (X):** Bei der Eingabe eines Twitter-Benutzernamens wird eine geschwärzte E-Mail-Adresse mit den ersten 2 Zeichen des E-Mail-Benutzernamens und dem ersten Buchstaben der E-Mail-Domäne gespeichert. Außerdem wird genau die Anzahl der Sternchen verwendet, die der Länge der E-Mail-Adresse entspricht.

- **YAHOO:** Zeigt eine geschwärzte alternative E-Mail-Adresse an, falls vorhanden. Zeigt die genaue Anzahl der Zeichen sowie das erste Zeichen und die letzten 2 Zeichen des E-Mail-Benutzernamens zusammen mit der vollständigen Domäne an.

- **MICROSOFT:** Anzeige einer zensierten Rufnummer mit den letzten 2 Ziffern.

- **INSTAGRAM:** Löst automatisch einen Reset aus und sendet dem Benutzer eine E-Mail. Nicht verwenden.

- **LINKEDIN:** Löst automatisch einen Reset aus und sendet dem Benutzer eine E-Mail. Nicht verwenden.

- **FOURSQUARE:** Löst automatisch einen Reset aus und sendet dem Benutzer eine E-Mail. Nicht verwenden.

- **DISCORD:** Zeigt teilweise geschwärzte E-Mail-Adresse mit den ersten 2 Buchstaben und der Domain. Vorsicht: Löst E-Mail-Benachrichtigung aus.

- **SNAPCHAT:** Zeigt letzten 2 Ziffern der Telefonnummer oder ersten 2 Zeichen der E-Mail.

- **REDDIT:** Zeigt nur ob eine E-Mail mit dem Account verknüpft ist, aber keine Details.

- **GITHUB:** Primäre E-Mail-Adresse wird teilweise angezeigt (erste 2 Zeichen + Domain).

**Zusätzliche Informationsquellen bei Password-Reset-Flows:**

- Account-Erstellungsdatum (manchmal sichtbar)
- Verknüpfte Telefonnummern-Vorwahl (gibt geografische Hinweise)
- Alternative E-Mail-Domains (können auf Unternehmens- oder Bildungszugehörigkeit hinweisen)
- Zwei-Faktor-Authentifizierung-Status (gibt Hinweis auf Sicherheitsbewusstsein)

---
#######################################################################################
## Reverse Image Searching
#######################################################################################

**Tools für die Rückwärts-Bildersuche:**

- [Yandex Images](https://images.yandex.com) - Besonders effektiv für Gesichtserkennung
- [Bing Visual Search](https://bing.com/visualsearch) - Gut für Produkte und Objekte
- [Google Images](https://images.google.com) - Breite Abdeckung, Schwerpunkt auf indizierten Websites
- [TinEye](https://tineye.com) - Spezialisiert auf exakte Übereinstimmungen und Bildmanipulationen
- [Baidu Images](https://image.baidu.com/) - Unerlässlich für chinesischsprachige Quellen
- [PimEyes](https://pimeyes.com/en) - Gesichtserkennungs-Suchmaschine (kostenpflichtig für volle Features)
- [Duplichecker](https://www.duplichecker.com/reverse-image-search.php) - Aggregiert mehrere Suchmaschinen
- [Labnol Reverse Image Search](https://www.labnol.org/reverse/) - Multi-Engine-Suche

**Erweiterte Techniken:**

- **Bildvorverarbeitung:** Passen Sie Helligkeit, Kontrast oder beschneiden Sie Bilder, um bessere Ergebnisse zu erzielen
- **Reverse Search von Screenshots:** Verwenden Sie Tools wie TinEye für genaue Pixelübereinstimmungen
- **Exif-Daten prüfen:** Vor der Suche Metadaten extrahieren (Kamera, GPS, Datum)
- **Mehrfach-Engine-Ansatz:** Verschiedene Suchmaschinen liefern unterschiedliche Ergebnisse
- **Google Lens Mobile:** Oft bessere Ergebnisse als Desktop-Suche
- **Suche nach ähnlichen Bildern:** Nach erstem Treffer nach "ähnlichen Bildern" suchen für erweiterten Kontext

**Spezialisierte Anwendungsfälle:**

- **Logo-Identifikation:** Bing Visual Search ist hier besonders stark
- **Kunstwerke:** Google Arts & Culture integriert
- **Natur/Tiere:** Google Lens erkennt Pflanzen und Tierarten
- **Orte:** Kombinieren Sie Bildsuche mit Geolocation-Tools

---
#######################################################################################
## Recent Satellite Imagery
#######################################################################################

**Satellitenbilddienste:**

- [Google Earth - New Satellite Imagery Tool](https://earth.google.com/web/@30.12736717,35.69560812,-1530.56420215a,14967606.11368418d,35y,0h,0t,0r/data=CjkaNxIxCiUweDE0MzY4OTc2YzM1YzM2ZTk6MHgyYzQ1YTAwOTI1YzRjNDQ0KgjDhGd5cHRlbhgCIAE)
- [Mapbox Live](https://www.mapbox.com/)
- [Sentinel Hub](https://www.sentinel-hub.com/) - ESA Sentinel-Satellitendaten (2-5 Tage Aktualisierung)
- [Planet Labs](https://www.planet.com/) - Tägliche Satellitenbilder (kommerziell)
- [Zoom Earth](https://zoom.earth/) - Aktuelle Satellitenbilder mit Wetterlagen
- [NASA Worldview](https://worldview.earthdata.nasa.gov/) - NASA-Satellitenbilder in Echtzeit
- [Soar Earth](https://soar.earth/) - Crowdsourced hochauflösende Drohnen- und Satellitenbilder
- [EOS Land Viewer](https://eos.com/landviewer/) - Multispektrale Satellitenbildanalyse

**Historische Satellitenbildarchive:**

- [Google Earth Pro](https://www.google.com/earth/versions/) - Zeitreise-Funktion für historische Bilder
- [USGS Earth Explorer](https://earthexplorer.usgs.gov/) - Landsat-Archiv seit 1972
- [Copernicus Open Access Hub](https://scihub.copernicus.eu/) - ESA Sentinel-Datenarchiv

**Spezialisierte Anwendungen:**

- **Änderungserkennung:** Vergleichen Sie Bilder aus verschiedenen Zeiträumen
- **Infrastrukturanalyse:** Identifizieren Sie Gebäude, Straßen, militärische Anlagen
- **Umweltüberwachung:** Abholzung, Dürren, Überschwemmungen
- **Ereignisverifizierung:** Überprüfen Sie Behauptungen über Ereignisse anhand von Satellitenbildern

---
#######################################################################################
## Calculate Photo Time of Day
#######################################################################################

**Tools zur Berechnung der ungefähren Tageszeit von Fotos:**

- [SunCalc.net](https://suncalc.net) - Sonnenstand und Schattenlänge
- [SunCalc.org](https://suncalc.org) - Alternative mit zusätzlichen Funktionen
- [TimeAndDate Sun Calculator](https://www.timeanddate.com/sun/) - Sonnenaufgang/Untergang für beliebige Orte
- [PhotoPills](https://www.photopills.com/calculators/sun) - Erweiterte Sonnenpositionsberechnungen

**Methodik zur Zeitbestimmung:**

1. **Schattenanalyse:**
   - Messen Sie Schattenlänge und -richtung
   - Vergleichen Sie mit Sonnenpositionen für bekannte Koordinaten
   - Berücksichtigen Sie Jahreszeit und geografische Breite

2. **Sonnenwinkel:**
   - Identifizieren Sie die Sonneneinstrahlung auf Objekten
   - Nutzen Sie Tools zur Berechnung des Sonnenwinkels
   - Abgleich mit möglichen Tageszeiten

3. **Zusätzliche Hinweise:**
   - Beleuchtung von Straßenlaternen (Dämmerung/Nacht)
   - Geschäftsöffnungszeiten im Hintergrund
   - Verkehrsdichte (Rushhour-Zeiten)
   - Kleidung von Personen (Sommer/Winter)

4. **EXIF-Daten verifizieren:**
   - Prüfen Sie Bild-Metadaten auf Zeitstempel
   - Achtung: EXIF-Daten können manipuliert sein
   - Gleichen Sie EXIF mit visuellen Hinweisen ab

**Fortgeschrittene Chronolocation:**

- Kombinieren Sie Schatten mit Wetterdaten
- Nutzen Sie astronomische Berechnungen für präzise Zeitfenster
- Berücksichtigen Sie Zeitzone und Sommerzeit
- Verwenden Sie 3D-Modellierungssoftware für komplexe Szenarien

---
#######################################################################################
## Fictional Account Creation
#######################################################################################

Autogenerieren Sie fiktive Personas mit den folgenden Online-Tools:

- [This Person Does Not Exist](https://thispersondoesnotexist.com/) - KI-generierte Gesichter
- [This Resume Does Not Exist](https://thisresumedoesnotexist.com/) - Fiktive Lebensläufe
- [This Rental Does Not Exist](https://thisrentaldoesnotexist.com) - Nicht existierende Immobilien
- [Fake Name Bio Generator](https://www.fakenamegenerator.com/) - Vollständige Identitäten mit Adressen
- [Random User Generator](https://randomuser.me/) - API für Fake-Benutzerprofile
- [Fake User Generator](https://uinames.com) - Name-Generator mit kulturellem Kontext
- [Dating Profile Generator](https://www.dating-profile-generator.org.uk/) - Fiktive Dating-Profile
- [Fake Persona Generator](https://businer.com/fakeid.php) - Geschäftsorientierte Personas
- [International Random Name Generator](https://www.behindthename.com/random/) - Namen aus verschiedenen Kulturen
- [AI Human Generator](https://generated.photos/) - Photorealistische KI-Personen (kostenpflichtig)
- [Fake Address Generator](https://www.fakeaddressgenerator.com/) - Internationale Adressen
- [Privacy.com](https://privacy.com/) - Virtuelle Zahlungskarten (USA)

**Wichtige Sicherheitshinweise:**

**Best Practices für OSINT-Personas:**

- **Glaubwürdigkeit:** Mischen Sie generierte Daten mit realistischen Details
- **Konsistenz:** Bewahren Sie alle Details der Persona in verschlüsselten Notizen
- **Trennung:** Nutzen Sie separate Browser/VMs für jede Persona
- **Alterung:** Lassen Sie Accounts reifen bevor Sie sie aktiv nutzen
- **Verhalten:** Agieren Sie wie ein echter Benutzer (langsam, mit Pausen)
- **Vernichtung:** Löschen Sie Personas nach Abschluss der Recherche

**Technische Absicherung:**

- Verwenden Sie VPN/Tor für Registrierung
- Nutzen Sie separate E-Mail-Adressen (Burner-Emails)
- Deaktivieren Sie WebRTC und Browser-Fingerprinting
- Verwenden Sie temporäre Telefonnummern
- Clearen Sie Cookies und Cache nach jeder Session

---
#######################################################################################
## Antiviruses
#######################################################################################

**Online-Virenscanner:**

- http://fuckingscan.me/
- http://v2.scan.majyx.net/
- http://nodistribute.com/
- http://www.file2scan.net/
- http://anubis.iseclab.org/
- https://anonscanner.com/
- http://virusscan.jotti.org/it
- https://www.virustotal.com/nl/
- [Hybrid Analysis](https://www.hybrid-analysis.com/) - Verhaltensanalyse von Malware
- [Any.Run](https://app.any.run/) - Interaktive Malware-Sandbox
- [Joe Sandbox](https://www.joesandbox.com/) - Tiefgehende Malware-Analyse
- [Intezer Analyze](https://analyze.intezer.com/) - Gen-basierte Malware-Erkennung
- [Metadefender](https://metadefender.opswat.com/) - Multi-Scanning mit 30+ Engines

**Erweiterte Malware-Analyse:**

- **Statische Analyse:** Untersuchen Sie Datei ohne Ausführung
- **Dynamische Analyse:** Führen Sie in isolierter Sandbox aus
- **Netzwerk-Verhalten:** Überwachen Sie ausgehende Verbindungen
- **Registry-Änderungen:** Dokumentieren Sie Systemmodifikationen
- **Process-Tree:** Analysieren Sie spawning von Prozessen

**Tools für tiefgehende Analyse:**

- [IDA Pro](https://hex-rays.com/ida-pro/) - Disassembler für Reverse Engineering
- [Ghidra](https://ghidra-sre.org/) - NSA's Open-Source Reverse Engineering Tool
- [Cuckoo Sandbox](https://cuckoosandbox.org/) - Lokale Malware-Sandbox
- [YARA Rules](https://github.com/InQuest/awesome-yara) - Pattern-Matching für Malware
- [PEStudio](https://pestudio.it/) - Windows PE-Datei Analyse

---
#######################################################################################
## File Sharing
#######################################################################################

**Anonymes Filesharing mit OnionShare:**

1. Laden Sie [OnionShare](https://onionshare.org) herunter und installieren Sie es.
2. Klicken Sie auf die Schaltfläche „Mit TOR verbinden".
3. Ziehen Sie alle Dateien, die Sie hochladen möchten, per Drag & Drop in das Feld.
4. Warten Sie einen Moment.
5. Sie erhalten eine .onion-URL sowie einen privaten Schlüssel.
6. Geben Sie den Benutzern den Link und den privaten Schlüssel sowie den Download-Link für den Tor-Browser.

**Hinweis:** Nach dem Teilen können Sie das File Sharing jederzeit innerhalb der OnionShare-Anwendung stoppen. Dies ist nützlich, wenn Sie möchten, dass nur eine Person die Datei herunterlädt oder wenn Ihr Link und privater Schlüssel an Benutzer weitergegeben wurden, die keinen Zugriff haben sollten.

**Alternative anonyme Filesharing-Methoden:**

- [Send](https://send.vis.ee/) - Firefox Send Fork, verschlüsselt, selbstzerstörend
- [Wormhole](https://wormhole.app/) - Ende-zu-Ende verschlüsselter Dateitransfer
- [Croc](https://github.com/schollz/croc) - Command-line tool für sichere Dateiübertragung
- [Magic Wormhole](https://magic-wormhole.readthedocs.io/) - Sichere Dateien zwischen Geräten senden
- [Tresorit Send](https://send.tresorit.com/) - Verschlüsselte Cloud-basierte Lösung
- [Internxt Send](https://send.internxt.com/) - Zero-Knowledge Dateitransfer

**Dezentrale Filesharing-Optionen:**

- [IPFS](https://ipfs.io/) - InterPlanetary File System (dezentralisiert)
- [Storj](https://www.storj.io/) - Dezentraler Cloud-Storage
- [Sia](https://sia.tech/) - Blockchain-basierter Datenspeicher

**Sicherheitsempfehlungen:**

- Verschlüsseln Sie sensible Dateien vor dem Upload (GPG/7-Zip)
- Verwenden Sie Einmal-Links mit Zeitbegrenzung
- Nutzen Sie Ende-zu-Ende-Verschlüsselung
- Teilen Sie Links nur über sichere Kanäle (Signal, Threema)
- Verifizieren Sie Dateien mit Hash-Werten (SHA-256)
- Vermeiden Sie WeTransfer/Dropbox für vertrauliche Daten
- Teilen Sie niemals sensible Dateien über unverschlüsselte E-Mail

---
#######################################################################################
## OSINT Tools
#######################################################################################

#######################################################################################
### Anonymous Search
#######################################################################################

- [DuckDuckGo](https://duckduckgo.com/) - Privacy-fokussierte Suchmaschine
- [Start Page](https://www.startpage.com/) - Anonymisierte Google-Suche
- [Qwant](https://www.qwant.com/) - Europäische Privacy-Suchmaschine
- [Yacy](https://yacy.net/) - Dezentrale Peer-to-Peer Suchmaschine
- [Brave Search](https://search.brave.com/) - Unabhängiger Index, keine Tracking
- [Mojeek](https://www.mojeek.com/) - Eigener Crawler, kein Tracking
- [Searx](https://searx.space/) - Open-Source Meta-Suchmaschine (selbst hostbar)
- [MetaGer](https://metager.org/) - Deutsche Non-Profit Suchmaschine

**Spezialisierte Suchmaschinen:**

- [Ahmia](https://ahmia.fi/) - Tor Hidden Service Suche
- [You.com](https://you.com/) - KI-gestützte private Suche
- [Gibiru](https://gibiru.com/) - "Uncensored" Suche ohne Filter

---
#######################################################################################
### Bot/Troll Detection
#######################################################################################

- [Bot Sentinel](https://botsentinel.com/) - Twitter/X Bot-Erkennung
- [Botometer](https://botometer.iuni.iu.edu/) - Machine-Learning Bot-Score
- [Emergent](https://emergent.info) - Rumor-Tracking
- [Faker Fact](https://www.fakerfact.org/about) - Fact-Checking Tool
- [Hoaxy](https://hoaxy.osome.iu.edu/) - Visualisierung von Desinformations-Verbreitung
- [Iffy Quotient](https://csmr.umich.edu/plaform-health-metrics) - Social Media Health Metrics
- [Information Operations Archive](https://io-archive.org) - Archiv von Desinformations-Kampagnen
- [Twitter Trails](http://twittertrails.com/) - Gerüchte-Tracking auf Twitter
- [TweetBeaver](https://tweetbeaver.com/) - Twitter Account-Analyse
- [AccountAnalysis](https://accountanalysis.app/) - Twitter Aktivitätsmuster
- [Social Blade](https://socialblade.com/) - Statistiken und Bot-Indikatoren

**Indikatoren für Bot-Aktivität:**

- Hohe Tweet-Frequenz (>50/Tag)
- Generische Profilbilder
- Zufällig generierte Nutzernamen
- Geringe Follower-Following-Ratio
- Repetitive Inhalte
- Erstellungsdatum des Accounts vs. Aktivitätslevel
- Fehlende persönliche Interaktionen

---
#######################################################################################
### Digital Forensics
#######################################################################################

- [Autopsy](https://www.autopsy.com) - Open source digital forensics platform
- [EnCase](https://www.opentext.com/products-and-solutions/products/software/encase-platform) - Commercial computer forensics software
- [AccessData (FTK)](https://accessdata.com/products-services/forensic-toolkit-ftk) - Forensic toolkit
- [X-Ways Forensics](http://www.x-ways.net/forensics/) - Integrated computer forensics software
- [Sleuth Kit](https://www.sleuthkit.org) - Open source digital forensics tools
- [Volatility](https://www.volatilityfoundation.org/) - Memory forensics framework
- [Wireshark](https://www.wireshark.org) - Network protocol analyzer
- [Cellebrite UFED](https://www.cellebrite.com/en/ufed-ultimate/) - Mobile forensic software
- [Magnet AXIOM](https://www.magnetforensics.com/products/magnet-axiom/) - Digital investigations platform
- [OSForensics](https://www.osforensics.com/) - Forensics tools for Microsoft systems
- [NetworkMiner](http://www.netresec.com/?page=NetworkMiner) - Network forensic analyzer
- [RegRipper](https://github.com/keydet89/RegRipper3.0) - Windows registry parser
- [Bulk Extractor](https://github.com/simsong/bulk_extractor) - Disk image data extractor
- [TestDisk](https://www.cgsecurity.org/wiki/TestDisk) - Data recovery tool
- [PhotoRec](https://www.cgsecurity.org/wiki/PhotoRec) - Photo recovery tool
- [CAINE](https://www.caine-live.net) - GNU/Linux live distribution with forensics tools
- [Kali Linux](https://www.kali.org) - Penetration testing distribution
- [SIFT (SANS)](https://digital-forensics.sans.org/community/downloads) - Ubuntu-based forensic distribution
- [Ghiro](http://www.getghiro.org/) - Website screenshots and analysis
- [Scalpel](http://www.digitalforensicssolutions.com/Scalpel/) - File carver
- [HxD](https://mh-nexus.de/en/hxd/) - Hex editor
- [Axiom Cyber](https://axiomcyber.com/axiom-cyber/) - Digital forensics platform
- [Belkasoft Evidence](https://belkasoft.com/evidence) - All-in-one forensics solution
- [Fibratus](https://www.jpcert.or.jp/english/pub/sr/ir_research.html) - Windows kernel activity tool
- [DEFT](http://www.deftlinux.net) - Linux distribution for forensics
- [Volatility Framework](https://www.volatilityfoundation.org/) - Advanced memory forensics
- [PyFlag](http://www.pyflag.net) - Forensic and log analysis platform
- [Plaso (log2timeline)](https://plaso.readthedocs.io/en/latest/sources/user/log2timeline.html) - Timeline aggregation
- [Redline](https://www.fireeye.com/services/freeware/redline.html) - Host investigations tool
- [Snort](https://www.snort.org) - Intrusion detection system
- [Tcpdump](https://www.tcpdump.org) - Network traffic capture
- [Ngrep](http://ngrep.sourceforge.net/) - Network grep
- [dcfldd](https://dcfldd.sourceforge.net/) - Disk cloning tool
- [Paladin](https://sumuri.com/software/paladin/) - USB forensic environment
- [CAINE Live](https://www.caine-live.net/page5/page5.html) - Bootable forensic environment
- [XRY (XAMN)](https://msab.com/xry/) - Mobile forensic software
- [BlackLight](https://www.blackbagtech.com/blacklight.html) - Windows forensics platform
- [WinHex](https://www.x-ways.net/winhex/) - Hex editor
- [Access FTK Imager](https://accessdata.com/product-download) - Disk imaging software
- [DC3DD](https://github.com/Defense-Cyber-Center/DC3-DD) - Improved dd for forensics
- [EnCase Imager](https://www.guidancesoftware.com/encase-imager) - Disk imaging tool
- [Guymager](https://guymager.sourceforge.io) - Disk cloning tool
- [Extundelete](http://extundelete.sourceforge.net/) - Recover deleted files
- [Xplico](http://www.xplico.org/) - Network forensics tool
- [Foremost](http://foremost.sourceforge.net) - File carving utility
- [Live View](http://liveview.sourceforge.net/) - Volatile memory analysis
- [Yara](https://github.com/VirusTotal/yara) - Pattern matching tool
- [Checkm8](https://checkm8.info/) - iOS jailbreaking tool
- [Olefile](https://github.com/decalage2/olefile) - Parse OLE documents
- [Pyew](https://github.com/joxeankoret/pyew) - Malware analysis tool
- [USBDeview](https://www.nirsoft.net/utils/usb_devices_view.html) - USB devices history
- [DC3-MWCP](https://www.dc3.mil/software-catalog/) - Forensic analysis tools
- [Memoryze](https://www.fireeye.com/services/freeware/memoryze.html) - Memory acquisition tool
- [EVTExtract](https://evtxtract.readthedocs.io/en/latest/) - Windows event log parser
- [Nmap](https://nmap.org/) - Network scanning tool
- [OSINT Framework](https://osintframework.com/) - OSINT data gathering
- [Recon-ng](https://github.com/lanmaster53/recon-ng) - Reconnaissance framework
- [SpiderFoot](https://www.spiderfoot.net/) - OSINT automation tool
- [Metagoofil](https://github.com/laramies/metagoofil) - Extract metadata
- [TheHarvester](https://github.com/laramies/theHarvester) - Gather emails and names
- [Creepy](https://www.geocreepy.com/) - Geolocation OSINT tool
- [Rekall](https://github.com/google/rekall) - Memory forensics framework
- [ALEAPP](https://github.com/abrignoni/ALEAPP) - Android Logs Events And Protobuf Parser
- [iLEAPP](https://github.com/abrignoni/iLEAPP) - iOS Logs, Events, And Plists Parser

**Forensik-Workflow Best Practices:**

1. **Dokumentation:** Jeder Schritt muss lückenlos dokumentiert werden
2. **Chain of Custody:** Nachvollziehbare Beweiskette aufrechterhalten
3. **Write-Blocker:** Verwenden Sie Hardware-Write-Blocker für Originalmedien
4. **Hashing:** Erstellen Sie kryptografische Hashes (MD5, SHA-256) für Integrität
5. **Duplicate Analysis:** Arbeiten Sie immer auf Kopien, nie auf Originalen
6. **Legal Compliance:** Beachten Sie rechtliche Anforderungen Ihrer Jurisdiktion

#######################################################################################
### Domain Intelligence
#######################################################################################

- [Analyze ID](https://analyzeid.com)
- [DNS Trails](https://dnstrails.com)
- [Domain Big Data](https://domainbigdata.com)
- [DomainIQ](https://domainiq.com/snapshot/history)
- [Spyse](https://spyse.com)
- [ViewDNS Whois](https://viewdns.info)
- [Whoismind](https://whoismind.com)
- [Whoisology](https://whoisology.com)
- [Whoxy](https://whoxy.com/reverse-whois)
- [ICANN Lookup](https://lookup.icann.org/) - Offizielle WHOIS-Datenbank
- [DomainTools](https://whois.domaintools.com/) - Umfassende Domain-Intelligence
- [SecurityTrails](https://securitytrails.com/) - DNS History und Domain-Recherche
- [DNSdumpster](https://dnsdumpster.com/) - DNS Reconnaissance & Research
- [Netcraft](https://www.netcraft.com/) - Website-Infrastruktur-Analyse
- [BuiltWith](https://builtwith.com/) - Website-Technologie-Profiler

**Domain-Recherche-Techniken:**

- **Reverse WHOIS:** Finden Sie alle Domains eines Besitzers
- **DNS History:** Historische DNS-Records für Infrastrukturveränderungen
- **Subdomain Enumeration:** Entdecken Sie versteckte Subdomains
- **Certificate Transparency:** Durchsuchen Sie CT-Logs für Domains
- **Registrar-Analyse:** Identifizieren Sie Muster in Domain-Registrierungen
- **Nameserver-Clustering:** Gruppieren Sie Domains nach gemeinsamen Nameservern

#######################################################################################
### Email Investigation
#######################################################################################

- [Holehe](https://github.com/megadose/holehe)
- [GitHub Email Scraper](https://github.com/andyjsmith/GitHub-Email-Scraper)
- [Mosint](https://github.com/alpkeskin/mosint)
- [Cynic](https://ashley.cynic.al)
- [Dehashed](https://dehashed.com)
- [Email Format](https://email-format.com)
- [Email Hippo](https://tools.verifyemailadress.io)
- [Ghost Project](https://ghostproject.fr)
- [HaveIBeenPwned](https://haveibeenpwned.com)
- [Hunter](https://hunter.io)
- [IntelligenceX](https://intelx.io)
- [Leak Phone](https://leakprobe.net)
- [Leaked Source](https://leakedsource.ru)
- [Many Contacts](https://mancontacts.com/en/mail-check)
- [PasteBinDump](https://psbdmp.ws)
- [Public Mail Records](https://publicmailrecords.com)
- [Simple Email Reputation](https://emailrep.io)
- [Spycloud](https://spycloud.com)
- [Spytox](https://spytox.com)
- [TruMail](https://trumail.io)
- [Verify Email](https://verify-email.org)
- [Snov.io](https://snov.io/) - Email Finder & Verifier
- [VoilaNorbert](https://www.voilanorbert.com/) - Email-Adressen finden
- [RocketReach](https://rocketreach.co/) - Professionelle Kontakte
- [Clearbit Connect](https://connect.clearbit.com/) - Email-Lookup für Chrome
- [Email Sherlock](https://www.emailsherlock.com/) - Email OSINT Tool

**Email-Header-Analyse:**

- [MXToolbox Header Analyzer](https://mxtoolbox.com/EmailHeaders.aspx)
- [Google Admin Toolbox](https://toolbox.googleapps.com/apps/messageheader/)
- [WhatIsMyIPAddress](https://whatismyipaddress.com/email-header-analyzer)

**Erweiterte Email-OSINT-Techniken:**

- **Email Permutations:** Generieren Sie mögliche Email-Varianten
- **Domain Employee Enumeration:** Finden Sie Mitarbeiter-Emails eines Unternehmens
- **Gravatar Lookup:** Profilbilder über Email-Hash finden
- **Social Media Cross-Reference:** Verknüpfen Sie Emails mit Social-Media-Profilen
- **Breach Aggregation:** Kombinieren Sie Daten aus mehreren Breach-Datenbanken
- **SMTP Verification:** Überprüfen Sie Email-Existenz via SMTP-Handshake

#######################################################################################
### Forensics & Metadata
#######################################################################################

- [ExifData](https://exifdata.com)
- [Extract Metadata](https://extractmetadata.com)
- [Foto Forensics](https://fotoforensics.com)
- [Forensically](https://291.ch/photo-forensics)
- [MetaPicz](https://metapicz.com)
- [Image Verification](https://reveal-mklab.iti.gr/reveal/index.html)
- [WayBack Machine](https://archive.org)
- [ExifTool](https://exiftool.org/) - Command-line Metadata-Extraktion
- [Jeffrey's Image Metadata Viewer](http://exif.regex.info/exif.cgi)
- [InVID Verification Plugin](https://www.invid-project.eu/tools-and-services/invid-verification-plugin/) - Video/Bild-Verifizierung

**Metadata-Analyse für verschiedene Dateitypen:**

- **Bilder (JPEG, PNG, TIFF):** GPS, Kamera-Modell, Software, Erstellungsdatum
- **Videos (MP4, MOV, AVI):** Aufnahmeort, Gerät, Bearbeitungssoftware
- **Dokumente (PDF, DOCX, XLSX):** Autor, Organisation, Bearbeitungshistorie
- **Audio (MP3, WAV):** Aufnahmegerät, Datum, Bitrate-Informationen

**Bildforensik-Techniken:**

- **ELA (Error Level Analysis):** Erkennt bearbeitete Bildbereiche
- **Clone Detection:** Findet duplizierte/gestempelte Bereiche
- **Noise Analysis:** Inkonsistenzen im Bildrauschen aufdecken
- **JPEG Ghosts:** Mehrfache Kompressions-Artefakte identifizieren
- **Luminance Gradients:** Beleuchtungsinkonsistenzen finden
- **Principal Component Analysis:** Statistische Anomalien erkennen

**Dokumenten-Metadata-Extraktion:**

```
# ExifTool Beispiel-Kommando
exiftool -all document.pdf
exiftool -r -ext jpg -ext png /pfad/zu/ordner/
```

#######################################################################################
### Infrastructure Analysis
#######################################################################################

- [Analyze ID](https://analyzeid.com)
- [Backlink Checker](https://smallseotools.com/backlink-checker)
- [Built With](https://builtwith.com)
- [Carbon Dating](https://carbondate.cs.odu.edu)
- [Censys](https://censys.io)
- [Certificate Transparency Logs](https://crt.sh)
- [DNS Dumpster](https://dnsdumpster.com)
- [Pagodo](https://github.com/opsdisk/pagodo)
- [DomainIQ](https://domainiq.com/revers_analytics)
- [FOFA](https://fofa.info/)
- [Find Sub Domains](https://findsubdomains.com)
- [Follow That Page](https://followthatpage.com)
- [IntelX Google ID](https://intelx.io/tools?tab=analytics)
- [MX Toolbox](https://mxtoolbox.com)
- [Nerdy Data](https://search.nerdydata.com)
- [Pentest Tools](https://pentest-tools.com/reconnaissance/find-subdomains-of-domain)
- [PubDB](https://pub-db.com)
- [PublicWWW Source Code](https://publicwww.com)
- [Records Finder](https://recordsfinder.com/email)
- [Shared Count](https://sharedcount.com)
- [Shodan](https://shodan.io)
- [Similar Web](https://similarweb.com)
- [Spy On Web](https://spyonweb.com)
- [Spyse](https://spyse.com)
- [Thingful (IoT)](https://thingful.net)
- [Threat Crowd](https://threatcrowd.org)
- [Threat Intelligence Platform](https://threatintelligenceplatform.com)
- [URLscan](https://urlscan.io)
- [Virus Total](https://virustotal.com)
- [Visual Site Mapper](http://visualsitemapper.com)
- [Wigle](http://wigle.net)
- [Zoom Eye](http://zoomeye.org)
- [BGP Toolkit](https://bgp.he.net/) - BGP und ASN Informationen
- [IPInfo](https://ipinfo.io/) - IP-Adress-Datenbank
- [GreyNoise](https://www.greynoise.io/) - Internet-Scanner-Aktivität
- [BinaryEdge](https://www.binaryedge.io/) - Cybersecurity Data Platform

**Infrastruktur-Pivoting-Techniken:**

1. **IP zu Domain:** Finden Sie alle Domains auf einer IP
2. **ASN Enumeration:** Entdecken Sie alle IPs einer Organisation
3. **Reverse IP Lookup:** Shared Hosting Nachbarn identifizieren
4. **SSL Certificate Chains:** Verknüpfen Sie Infrastruktur über Zertifikate
5. **Nameserver Analysis:** Domains mit gleichen Nameservern finden
6. **CDN Fingerprinting:** Identifizieren Sie Original-Server hinter CDNs
7. **Google Analytics ID:** Verknüpfen Sie Websites über gemeinsame IDs

**Shodan Dork Beispiele:**

```
port:22 country:DE
product:Apache city:"Berlin"
http.favicon.hash:116323821
ssl.cert.subject.cn:"*.example.com"
```

#######################################################################################
### IP Address Investigation
#######################################################################################

- [Censys](http://censys.io/ipv4)
- [Exonerator](http://exonerator.torproject.org)
- [IPLocation](http://iplocation.net)
- [Shodan](http://shodan.io)
- [Spyse](http://spyse.com)
- [Threat Crowd](http://threatcrowd.org)
- [Threat Intelligence Platform](http://threatintelligenceplatform.com)
- [ViewDNS](http://viewdns.info/reverseip)
- [ViewDNS Port Scan](http://viewdns.info/portscan)
- [ViewDNS Whois](http://viewdns.info/whois)
- [ViewDNS IP Location](http://viewdns.info/iplocation)
- [Virus Total](http://virustotal.com)
- [AbuseIPDB](https://www.abuseipdb.com/) - IP Reputation Database
- [IPVoid](https://www.ipvoid.com/) - IP Reputation Check
- [Talos Intelligence](https://talosintelligence.com/) - IP & Domain Reputation
- [AlienVault OTX](https://otx.alienvault.com/) - Open Threat Exchange
- [Robtex](https://www.robtex.com/) - Netzwerk-Recherche

**IP-Analyse-Methoden:**

- **Geolocation:** Physischer Standort der IP
- **ASN Lookup:** Zugehöriges Autonomous System
- **Reverse DNS:** Hostnamen für IP-Adresse
- **Port Scanning:** Offene Ports und Dienste
- **Banner Grabbing:** Service-Versionen identifizieren
- **Historical Data:** Frühere DNS-Records und Verwendung
- **Reputation Scoring:** Malicious Activity Assessment

**Nützliche IP-Range-Tools:**

- [IPCalc](http://jodies.de/ipcalc) - IP Subnet Calculator
- [ARIN WHOIS](https://whois.arin.net/) - Nordamerikanische IP-Registrierung
- [RIPE Database](https://apps.db.ripe.net/db-web-ui/query) - Europäische IP-Registrierung

#######################################################################################
### IP Logger/URL Shortener
#######################################################################################

- [Bit.do](http://bit.do)
- [Bitly](http://bitly.com)
- [Canary Tokens](http://canarytokens.org)
- [Check Short URL](http://checkshorturl.com)
- [Get Notify](http://getnotify.com)
- [Google URL Shortener](http://goo.gl)
- [IP Logger](http://iplogger.org)
- [Tiny](http://tiny.cc)
- [URL Biggy](http://urlbiggy.com)
- [TinyURL](https://tinyurl.com/)
- [Rebrandly](https://www.rebrandly.com/)
- [Grabify](https://grabify.link/) - IP Logger und URL Shortener

**URL-Expansion-Tools:**

- [Unshorten.It](https://unshorten.it/)
- [CheckShortURL](https://checkshorturl.com/)
- [ExpandURL](https://www.expandurl.net/)
- [URL X-ray](https://urlxray.com/)

**Sicherheitshinweis:** IP-Logger werden oft für Phishing und Social Engineering verwendet. Nutzen Sie diese Tools nur für legitime OSINT-Zwecke und mit Einwilligung.

#######################################################################################
### Live Cameras
#######################################################################################

- [Airport Webcams](http://airportwebcams.net)
- [EarthCam](http://earthcam.com)
- [Opentopia](http://opentopia.com/hiddencam.php)
- [Open Webcam Network](http://the-webcam-network.com)
- [Webcam Galore](http://webcamgalore.com)
- [WorldCam](http://worldcam.eu)
- [Insecam](http://insecam.org/) - Ungesicherte IP-Kameras weltweit
- [Deckchair](https://www.deckchair.com/) - Webcam-Aggregator
- [SkylineWebcams](https://www.skylinewebcams.com/) - Live-Streams aus aller Welt

**Webcam-OSINT-Techniken:**

- **Shodan Queries:** `has_screenshot:true port:8080`
- **Google Dorks:** `inurl:/view/index.shtml`
- **Geolocation:** Verknüpfen Sie Kameraansichten mit Standorten
- **Zeitstempel-Verifizierung:** Nutzen Sie Live-Cams zur Zeitbestätigung
- **Weather Correlation:** Abgleich mit Wetterdaten

**Ethische Überlegungen:**

#######################################################################################
### Metadata Extraction
#######################################################################################

- [Exif Info](http://exifinfo.org)
- [Extract Metadata](http://extractmetadata.com)
- [Forensically](http://29a.ch/photo-forensics)
- [Get Metadata](http://get-metadata.com)
- [Jeffrey's Exif Viewer](http://exif.regex.info/exif.cgi)
- [Online Barcode Reader](http://online-barcode-reader.inliteresearch.com)
- [ExifTool](https://exiftool.org/) - Professionelles CLI-Tool
- [Mat2](https://0xacab.org/jvoisin/mat2) - Metadata Anonymisation Toolkit
- [ExifCleaner](https://exifcleaner.com/) - Desktop App zum Entfernen von Metadaten

**Metadata-Entfernung für Privacy:**

Entfernen Sie Metadaten vor dem Teilen von Dateien:

```bash
# ExifTool - Alle Metadaten entfernen
exiftool -all= bild.jpg

# Mat2 - Metadaten bereinigen
mat2 --inplace dokument.pdf
```

**Interessante Metadata-Felder:**

- **GPS Coordinates:** Exakte Aufnahmeposition
- **Device Make/Model:** Kamera- oder Smartphone-Typ
- **Software:** Bearbeitungsprogramme
- **Creation/Modification Date:** Zeitstempel
- **Author/Creator:** Urheberinformationen
- **Comments:** Versteckte Notizen

#######################################################################################
### Image Tools
#######################################################################################

- [Imgops](https://imgops.com/) - Alle wichtigen Bild-Tools an einem Ort
- [Depix](https://github.com/spipm/Depixelization_poc) - Verpixelte Texte wiederherstellen
- [Forensically](https://29a.ch/photo-forensics/#forensic-magnifier) - Bildforensik-Suite
- [FotoForensics](http://fotoforensics.com/) - ELA und andere Analysen
- [Image Edited?](https://imageedited.com/) - Prüft auf Bildmanipulation
- [Ghiro](http://www.getghiro.org/) - Automatisierte Bildforensik
- [InVID](https://www.invid-project.eu/verify/) - Video- und Bildverifizierung

**Spezialisierte Bildanalyse:**

- **Stereogramm-Extraktion:** Versteckte 3D-Bilder finden
- **Steganographie-Erkennung:** Versteckte Daten in Bildern aufdecken
- **Color Analysis:** Farbmanipulationen identifizieren
- **Noise Pattern Analysis:** Kamera-Fingerprints erkennen
- **Shadow Consistency:** Beleuchtungswinkel überprüfen

**Tools für Steganographie:**

- [StegOnline](https://stegonline.georgeom.net/upload) - Online Stego-Tool
- [Zsteg](https://github.com/zed-0xff/zsteg) - PNG/BMP Steganographie
- [Steghide](http://steghide.sourceforge.net/) - Versteckt Daten in Bildern
- [OpenStego](https://www.openstego.com/) - Open-Source Steganographie

#######################################################################################
### Open Directory Search
#######################################################################################

- [Filer](http://rsch.neocities.org/gen2filer.html)
- [File Chef](http://filechef.com)
- [File Pursuit](http://filepursuit.com)
- [Mamont](http://mmnt.net)
- [Open Directory Search Tool](http://opendirsearch.abifog.com)
- [Open Directory Search Portal](http://eyeofjustice.com/od/)
- [Musgle](http://musgle.com)
- [Lendex](http://lendex.org)
- [FONETASK](https://www.fonetask.com/) - Open Directory Finder
- [Palined](https://palined.com/search/) - Open Directory Suche

**Google Dorks für Open Directories:**

```
intitle:"index of" inurl:backup
intitle:"index of" "parent directory" confidential
intitle:"index of" /admin
intitle:"index of" passwords.txt
site:edu intitle:"index of" filetype:pdf
```

**Spezialisierte Open Directory Suchen:**

- Dokumente: `intitle:"index of" (pdf|doc|docx)`
- Datenbanken: `intitle:"index of" (sql|db|mdb)`
- Backup-Dateien: `intitle:"index of" (backup|bak|old)`
- Logs: `intitle:"index of" (log|logs)`
- Konfigurationsdateien: `intitle:"index of" (config|conf|cfg)`

#######################################################################################
### Satellite Imagery
#######################################################################################

- [Bing Maps](http://bing.com/maps)
- [Descartes Labs](http://map.descarteslabs.com)
- [Dual Maps](http://data.mashedworld.com/dualmaps/map.htm)
- [Google Maps](http://maps.google.com)
- [Wikimapia](http://wikimapia.com)
- [World Imagery WayBack](http://livingatlas.arcgis.com/wayback)
- [Yandex Maps](http://yandex.com/maps)
- [Zoom Earth](http://zoom.earth/)
- [HERE WeGo](https://wego.here.com/)
- [Mapillary](https://www.mapillary.com/) - Crowdsourced Straßenfotos
- [OpenStreetMap](https://www.openstreetmap.org/)

**Historische Kartenvergleiche:**

- Nutzen Sie Zeitreise-Funktionen zur Änderungserkennung
- Vergleichen Sie verschiedene Plattformen für beste Abdeckung
- Achten Sie auf Aktualisierungsintervalle (Google: 1-3 Jahre, Sentinel: Tage)

#######################################################################################
### Telephone Investigation
#######################################################################################

- [Carrier Lookup](http://carrierlookup.com)
- [Dehashed](http://dehashed.com)
- [Everyone API](http://everyoneapi.com)
- [Free Carriers Lookup](http://freecarrierlookup.com)
- [Nuwber](http://nuwber.com)
- [Old Phone Book](http://oldphonebook.com)
- [Open CNAM](http://opencnam.com)
- [People Search Now](http://peoplesearchnow.com)
- [Sly Dial](http://slydial.com)
- [Spy Dialer](https://spydialer.com)
- [Spytox](https://spytox.com)
- [That's Them](https://thatsthem.com)
- [True Caller](https://truecaller.com)
- [Twilio](https://twilio.com/lookup)
- [PhoneInfoga](https://sundowndev.github.io/phoneinfoga/) - Advanced Phone Number Scanner
- [NumLookup](https://www.numlookup.com/) - Reverse Phone Lookup
- [Sync.me](https://sync.me/) - Caller ID und Spam-Schutz

**Telefonnummer-OSINT-Techniken:**

- **International Format:** Nutzen Sie E.164 Format (+49...)
- **Carrier Identification:** Mobilfunk- oder Festnetz
- **Location Extraction:** Vorwahl gibt Region an
- **Social Media Linking:** Verknüpfung mit Social-Media-Profilen
- **VOIP Detection:** Unterscheiden Sie echte vs. virtuelle Nummern
- **WhatsApp/Telegram:** Prüfen Sie ob Nummer registriert ist

**HLR (Home Location Register) Lookup:**

Gibt Auskunft über:
- Netzwerkstatus
- Roaming-Status
- IMSI-Informationen
- Portierungs-Historie

#######################################################################################
### Tor Network
#######################################################################################

- [Ahmia](https://ahmia.fi)
- [Dark Search](https://darksearch.io)
- [Tor2Web](https://tor2web.org)
- [Not Evil (Inside Tor)](https://hss3uro2hsxfogfq.onion)
- [Torch](http://xmh57jrknzkhv6y3ls3ubitzfqnkrwxhopf5aygthi7d6rplyvk3noyd.onion/) - Tor Search Engine
- [OnionLand](https://onionlandsearchengine.com/) - Onion Search Engine
- [Excavator](http://2fd6cemt4gmccflhm6imvdfvli3nf7zn6rfrwpsy7uhxrgbypvwf5fad.onion/) - Tor Link Directory

**Tor-Browser-Sicherheit:**

 **Wichtige Sicherheitshinweise:**
- Nutzen Sie immer das offizielle Tor Browser Bundle
- Deaktivieren Sie JavaScript für maximale Anonymität
- Nutzen Sie keine Plugins oder Extensions
- Vergrößern Sie das Browser-Fenster nicht (Fingerprinting)
- Verwenden Sie keine persönlichen Accounts über Tor
- Kombinieren Sie mit VPN nur mit Vorsicht (Timing-Angriffe möglich)

**Darknet-Recherche Best Practices:**

- Dokumentieren Sie .onion-URLs in verschlüsselten Notizen
- Verwenden Sie separate virtuelle Maschinen
- Vertrauen Sie keinen Downloads aus dem Darknet
- Scannen Sie alles mit mehreren Antivirenprogrammen
- Niemals illegale Inhalte zugreifen oder herunterladen

**Alternative anonyme Netzwerke:**

- [I2P](https://geti2p.net/) - Invisible Internet Project
- [Freenet](https://freenetproject.org/) - Dezentrales anonymes Netzwerk
- [ZeroNet](https://zeronet.io/) - Dezentrales Web auf Bitcoin-Kryptographie

#######################################################################################
### Vehicle Investigation
#######################################################################################

- [Nomerogram - RU Plates](https://nomerogram.ru)
- [Vin-Info](https://vin-info.com)
- [World License Plates](https://worldlicenseplates.com)
- [VINCheck](https://www.nhtsa.gov/vin-decoder) - NHTSA VIN Decoder (USA)
- [VIN Decoder](https://vindecoder.eu/) - Europäischer VIN Decoder
- [AutoCheck](https://www.autocheck.com/) - Fahrzeughistorie (kommerziell)
- [Carfax](https://www.carfax.com/) - Fahrzeughistorie (kommerziell)

**Kennzeichen-OSINT:**

- **Format-Analyse:** Identifizieren Sie Land und Region
- **Registrierungsdatum:** Viele Länder kodieren Jahr im Kennzeichen
- **Diplomatenkennzeichen:** Besondere Codes für diplomatic Fahrzeuge
- **Historische Kennzeichen:** Oldtimer-Registrierungen
- **Temporäre Kennzeichen:** Händler- oder Überführungskennzeichen

**VIN (Vehicle Identification Number) Dekodierung:**

Eine VIN enthält:
- Position 1-3: World Manufacturer Identifier (WMI)
- Position 4-8: Fahrzeugbeschreibung
- Position 9: Prüfziffer
- Position 10: Modelljahr
- Position 11: Herstellungswerk
- Position 12-17: Seriennummer

**Fahrzeug-Tracking-Techniken:**

- Kennzeichenerkennung aus Fotos/Videos
- Cross-Reference mit Parkticket-Datenbanken
- Verkehrskamera-Aufnahmen (wo legal zugänglich)
- Toll-Road-Databases
- Maut-Systeme-Recherche

#######################################################################################
### GitHub Investigation
#######################################################################################

- [Shhgit](https://github.com/eth0izzle/shhgit) - Finde Secrets in Code
- [GitRob](https://github.com/michenriksen/gitrob) - Reconnaissance für GitHub
- [TruffleHog](https://github.com/trufflesecurity/trufflehog) - Secrets Scanner
- [GitLeaks](https://github.com/gitleaks/gitleaks) - SAST für Secrets
- [Git-Secrets](https://github.com/awslabs/git-secrets) - Verhindert Secret-Commits
- [GitGot](https://github.com/BishopFox/GitGot) - Semi-automated Tradecraft
- [GitHub Dorks](https://github.com/techgaun/github-dorks) - Sammlung nützlicher Dorks

**GitHub OSINT-Techniken:**

- **Commit History Mining:** Gelöschte Secrets in alten Commits
- **Contributor Analysis:** Identifizieren Sie Entwickler
- **Email Extraction:** Emails aus Commit-Historie
- **Fork Analysis:** Finden Sie private Informationen in Forks
- **Issue/PR Mining:** Sensible Informationen in Diskussionen
- **Gist Search:** Oft vergessene Code-Snippets mit Secrets

**Nützliche GitHub-Suchoperatoren:**

```
filename:.env DATABASE_PASSWORD
extension:pem private
filename:id_rsa
filename:credentials aws_access_key_id
org:company password
```

**GitHub Advanced Search:**

- [GitHub Code Search](https://github.com/search?type=code)
- Nutzen Sie Regex-Patterns für Secret-Formate
- Suchen Sie in Issues, Pull Requests, Wikis
- Filtern Sie nach Sprache, Datum, Repository-Größe

#######################################################################################
### Username Investigation
#######################################################################################

- [Sherlock](https://github.com/sherlock-project/sherlock) - Hunt down social media accounts by username
- [Nexfil](https://github.com/thewhiteh4t/nexfil) - Username Search Engine
- [Know Em](https://knowem.com) - Check username availability across 500+ social networks
- [Name Checkr](https://namecheckr.com) - Domain and username availability
- [Name Vine](https://namevine.com) - Brand name and social media handle search
- [User Search](https://usersearch.org) - Search by username or email
- [Discord Info](https://discord.id/) - Discord user lookup by ID
- [socid_extractor](https://github.com/soxoj/socid-extractor) - Extract IDs from social media
- [Webmii](https://webmii.com/) - People search engine
- [PimEyes](https://pimeyes.com/en) - Face recognition search
- [Agcom](https://www.agcom.it/node/42043) - Italian telecommunications authority lookup
- [Facecheck](https://facecheck.id/de) - Reverse image search for faces
- [Google GHunt](https://github.com/mxrch/GHunt) - Investigate Google accounts
- [WhatsMyName](https://whatsmyname.app/) - Username enumeration across platforms
- [Namechk](https://namechk.com/) - Username and domain availability checker
- [UserSearch.org](https://usersearch.org/) - Find people by username or email

**Username-OSINT-Strategien:**

1. **Pivot-Technik:** Von einem Username zu anderen Plattformen
2. **Variation Testing:** Testen Sie gängige Varianten (username123, user.name, etc.)
3. **Historical Search:** Nutzen Sie Wayback Machine für gelöschte Profile
4. **Cross-Platform Correlation:** Verknüpfen Sie Accounts über gemeinsame Details
5. **Email Pattern Recognition:** Leiten Sie mögliche Email-Adressen ab
6. **Profile Picture Reverse Search:** Finden Sie gleiche Bilder auf anderen Plattformen

**Nützliche Username-Variationen zu testen:**

- Originaler Username
- Username + Zahlen (birth year, lucky numbers)
- Username mit Punkten/Unterstrichen
- Verkürzte Versionen
- Plattform-spezifische Varianten
- Legacy Usernames (alte Accounts)

#######################################################################################
### Comprehensive OSINT Tools
#######################################################################################

- [Amass](https://github.com/owasp-amass/amass) - In-depth attack surface mapping and asset discovery
- [Atscan](https://github.com/AlisamTechnology/ATSCAN) - Advanced dork Search & Mass Exploit Scanner
- [Bdfr](https://github.com/aliparlakci/bulk-downloader-for-reddit) - Downloads and archives content from reddit
- [Blackbird](https://github.com/p1ngul1n0/blackbird) - Search for accounts by username in social networks
- [Binwalk](https://github.com/ReFirmLabs/binwalk) - Firmware Analysis Tool
- [Carbon14](https://github.com/Lazza/Carbon14) - OSINT dating tool for web pages
- [Cardpwn](https://github.com/itsmehacker/CardPwn) - Find Breached Credit Cards Information
- [Chatgpt-shell-cli](https://github.com/0xacx/chatGPT-shell-cli) - Simple shell script to use OpenAI's ChatGPT
- [Cloud_enum](https://github.com/initstring/cloud_enum) - Multi-cloud OSINT tool
- [Cloud_sherlock](https://github.com/Group-IB/cloud_sherlock) - Enum S3 buckets and SaaS
- [Crosslinked](https://github.com/m8sec/CrossLinked) - LinkedIn enumeration tool
- [DumpsterDiver](https://github.com/securing/DumpsterDiver) - Tool to search secrets in various filetypes
- [Elasticsearch](https://github.com/elastic/elasticsearch) - Distributed RESTful Search Engine
- [Email2phonenumber](https://github.com/martinvigo/email2phonenumber) - Obtain phone number from email
- [Emdofi](https://github.com/novitae/emdofi) - Uncovers a censored email's domain
- [ExchangeFinder](https://github.com/mhaskar/ExchangeFinder) - Find Microsoft Exchange instance
- [Exiflooter](https://github.com/aydinnyunus/exifLooter) - Finds geolocation on image urls
- [Exiv2](https://github.com/Exiv2/exiv2) - Image metadata library and tools
- [FacebookOsint](https://github.com/tomoneill19/FacebookOSINT) - Facebook graph search tool
- [Fake-sms](https://github.com/Narasimha1997/fake-sms) - Skip SMS verification with temporary phone number
- [Fbi](https://github.com/xHak9x/fbi) - Facebook Information tool
- [Ffmpeg](https://archlinux.org/packages/extra/x86_64/ffmpeg/) - Record, convert and stream audio and video
- [Fierce](https://github.com/mschwager/fierce) - DNS reconnaissance tool
- [FinalRecon](https://github.com/thewhiteh4t/FinalRecon) - Complete web reconnaissance tool
- [Foremost](https://github.com/korczis/foremost) - File recovery based on headers/footers
- [Gallery-dl](https://github.com/mikf/gallery-dl) - Download image galleries
- [GhostTrack](https://github.com/HunxByts/GhostTrack) - Track location or mobile number
- [Ghunt](https://github.com/mxrch/GHunt) - Offensive Google framework
- [Gitfive](https://github.com/mxrch/GitFive) - Track down GitHub users
- [Githound](https://github.com/tillson/git-hound) - GitHub code search reconnaissance
- [Gitleaks](https://github.com/gitleaks/gitleaks) - Protect and discover secrets
- [Gobuster](https://github.com/OJ/gobuster) - Directory/File, DNS and VHost busting tool
- [GooFuzz](https://github.com/m3n0sd0n4ld/GooFuzz) - Fuzzing with OSINT approach
- [Google Earth Pro](https://www.google.com/earth/about/) - World's most detailed globe
- [Gophish](https://github.com/gophish/gophish) - Open-Source Phishing Toolkit
- [H8mail](https://github.com/khast3x/h8mail) - Email OSINT & Password breach hunting
- [Harpoon](https://github.com/Te-k/harpoon) - CLI tool for open source intelligence
- [Holehe](https://github.com/megadose/holehe) - Check if email is used on different sites
- [Ignorant](https://github.com/megadose/ignorant) - Check if phone number is used on sites
- [ILS](https://github.com/bellingcat/instagram-location-search) - Instagram location ID finder
- [InstagramOsint](https://github.com/sc1341/InstagramOSINT) - Instagram OSINT Tool
- [Instaloader](https://github.com/instaloader/instaloader) - Download from Instagram
- [Ipinfo](https://github.com/ipinfo/cli) - IPinfo API CLI
- [Kamerka](https://github.com/woj-ciech/kamerka) - Build interactive map of cameras
- [Linkedin2username](https://github.com/initstring/linkedin2username) - Generate username lists
- [Mailcat](https://github.com/sharsil/mailcat) - Find existing email addresses
- [Maigret](https://github.com/soxoj/maigret) - Collect dossier by username
- [Maltego](https://www.maltego.com/) - Graphical link analyses tool
- [Masto](https://github.com/C3n7ral051nt4g3ncy/Masto) - Gather intelligence on Mastodon
- [Metagoofil](https://github.com/laramies/metagoofil) - Metadata harvester
- [Moriarty-Project](https://github.com/AzizKpln/Moriarty-Project) - Phone number information
- [Mpv](https://github.com/mpv-player/mpv) - Command line video player
- [Nqntnqnqmb](https://github.com/megadose/nqntnqnqmb) - LinkedIn profiles/companies info
- [Octosuite](https://github.com/bellingcat/octosuite) - GitHub OSINT framework
- [Onionsearch](https://github.com/megadose/OnionSearch) - Scrape .onion search engines
- [Osintgram](https://github.com/Datalux/Osintgram) - OSINT tool on Instagram
- [Osintmap](https://map.malfrats.industries/) - Map of OSINT tools
- [Phoneinfoga](https://github.com/sundowndev/phoneinfoga) - Phone number information gathering
- [Phonia](https://github.com/coredamage/phonia) - Phone number scanning toolkit
- [Photon](https://github.com/s0md3v/Photon) - Fast crawler for OSINT
- [PD](https://github.com/limkokhole/pinterest-downloader) - Pinterest downloader
- [Proton1ntelligence](https://github.com/C3n7ral051nt4g3ncy/Prot1ntelligence) - Protonmail intelligence
- [Protosint](https://github.com/pixelbubble/ProtOSINT) - Investigate Protonmail accounts
- [Pwndb](https://github.com/davidtavarez/pwndb) - Search for leaked credentials
- [PwnedOrNot](https://github.com/thewhiteh4t/pwnedOrNot) - Find Passwords of Compromised Emails
- [Recon-ng](https://github.com/lanmaster53/recon-ng) - OSINT gathering tool
- [Reavealin](https://github.com/mxrch/revealin) - Uncover full name on Linkedin
- [Ripme](https://github.com/RipMeApp/ripme) - Downloads albums in bulk
- [Sherlock](https://github.com/sherlock-project/sherlock) - Hunt down social media accounts
- [Shodan](https://github.com/achillean/shodan-python) - Official Python library for Shodan
- [Skiptracer](https://github.com/xillwillx/skiptracer) - OSINT webscaping framework
- [SlackPirate](https://github.com/emtunc/SlackPirate) - Slack Enumeration Tool
- [SleuthKit](https://github.com/sleuthkit/sleuthkit) - Digital forensics tools
- [SMWYG](https://github.com/Viralmaniar/SMWYG-Show-Me-What-You-Got) - OSINT and reconnaissance tool
- [SMS](https://github.com/nemec/snapchat-map-scraper) - Snapchat map scraper
- [Snoop](https://github.com/snooppr/snoop) - Search for nicknames
- [Snooper](https://github.com/NicholasDollick/Snooper) - Reddit user activity analyzer
- [Social-analyzer](https://github.com/qeeqbox/social-analyzer) - Find person's profile in 1000 sites
- [SonicVisualiser](https://www.sonicvisualiser.org/download.html) - Audio data exploration
- [Sqlitebrowser](https://github.com/sqlitebrowser/sqlitebrowser) - DB Browser for SQLite
- [Spiderfoot](https://github.com/smicallef/spiderfoot) - Automates OSINT
- [Stegoveritas](https://github.com/bannsec/stegoVeritas/) - Stego Tool
- [Sterra](https://github.com/novitae/sterraxcyl) - Instagram OSINT tool
- [Telepathy](https://github.com/proseltd/Telepathy-Community) - OSINT toolkit for Telegram
- [Telescan](https://github.com/pielco11/telescan) - Search users in Telegram groups
- [Theharvester](https://github.com/laramies/theHarvester) - E-mails, subdomains harvester
- [TD](https://github.com/krypton-byte/tiktok-downloader) - Tiktok Downloader
- [Tinfoleak](https://github.com/vaguileradiaz/tinfoleak) - Twitter intelligence analysis
- [TorBrowser](https://github.com/micahflee/torbrowser-launcher) - Tor Browser launcher
- [Torcrawl](https://github.com/MikeMeliz/TorCrawl.py) - Crawl through TOR network
- [Translate-shell](https://github.com/soimort/translate-shell) - Command-line translator
- [Trape](https://github.com/jofpin/trape) - People tracker on the Internet
- [Twint-zero](https://github.com/twintproject/twint-zero) - Old Twint style
- [Unredacted](https://github.com/BishopFox/unredacter) - Never use pixelation as redaction
- [Vt-cli](https://github.com/VirusTotal/vt-cli) - VirusTotal Command Line Interface
- [Waybackpy](https://github.com/akamhy/waybackpy) - Wayback Machine API interface
- [Wafw00f](https://github.com/EnableSecurity/wafw00f) - Identify and fingerprint WAF
- [WebOsint](https://github.com/C3n7ral051nt4g3ncy/WebOSINT) - Passive Domain Intelligence gathering
- [Whatbreach](https://github.com/Ekultek/WhatBreach) - Find breached emails and databases
- [Xeuledoc](https://github.com/Malfrats/xeuledoc) - Fetch info about public Google documents
- [Yara](https://github.com/VirusTotal/yara) - Pattern matching swiss knife
- [Yoga](https://github.com/WebBreacher/yoga) - Your OSINT Graphical Analyzer
- [Yt-dlp](https://github.com/yt-dlp/yt-dlp) - Youtube-dl fork with additional features
- [Zen](https://github.com/s0md3v/Zen) - Find emails of Github users

#######################################################################################
### Additional Tools & Resources
#######################################################################################

- [Leakpeek](https://leakpeek.com/) - Data breach search
- [Flare](https://try.flare.io/jh/) - Threat exposure monitoring
- [Rae Baker OSINT List](https://start.me/p/7kYgk2/rae-baker-deep-dive-osint) - Comprehensive resource list
- [DeDigger](https://www.dedigger.com/) - Deep web search
- [Awesome-OSINT-for-everything](https://github.com/Astrosp/Awesome-OSINT-For-Everything) - Curated OSINT list
- [OSINT framework](https://osintframework.com/) - Interactive framework
- [FBI OSINT tools](https://github.com/danieldurnea/FBI-tools) - FBI-curated tools
- [OSINT astrosp](https://github.com/Astrosp/osint-tools) - Tool collection
- [Phonebook.cz](https://phonebook.cz/) - Email and domain enumeration
- [Lampyre](https://lampyre.io/) - Data analysis & OSINT tool
- [Collection of 4000+ OSINT resources](https://metaosint.github.io/table) - Mega resource list
- [Wireless network osint](https://digitalinvestigator.blogspot.com/2022/12/wireless-network-osint.html) - WiFi OSINT techniques
- [Reconshell GitFive](https://reconshell.com/gitfive-osint-tool/) - GitHub reconnaissance
- [Anonpaste Username dataminer](https://anonpaste.io/share/0b00ed50a9) - Extract usernames from paste sites
- [DiscordChatExporter](https://github.com/Tyrrrz/DiscordChatExporter) - Export Discord chat logs
- [Anonymousplanet Guide](https://anonymousplanet.org/) - Privacy and anonymity guide
- [Shitexpress](https://www.shitexpress.com/) - Prank service (use responsibly!)
- [Confetti Mail Bomb](https://confettimailbomb.com/) - Prank mail service
- [Ruin Days](https://www.ruindays.com/) - Prank services
- [Whitepages](https://www.whitepages.com/person) - People search
- [Email Hippo Tools](https://tools.emailhippo.com/) - Email verification suite
- [Namecheckup](https://namecheckup.com/) - Username availability
- [Namechk](https://namechk.com/) - Brand name checker
- [Twitonomy](https://www.twitonomy.com/dashboard.php) - Twitter analytics
- [Social Bearing](https://socialbearing.com/) - Twitter analytics and sentiment
- [Fast People Search](https://www.fastpeoplesearch.com/) - Free people finder
- [OSINT ROCKS](https://osint.rocks/) - OSINT resource hub
- [Rengine](https://github.com/yogeshojha/rengine) - Reconnaissance automation
- [OSINT4ALL](https://start.me/p/L1rEYQ/osint4all) - Comprehensive OSINT collection

---
#######################################################################################
## OSINT Resources
#######################################################################################

#######################################################################################
### Framework & Collections
#######################################################################################

- [OSINT Framework](https://osintframework.com/) - Interactive OSINT tool directory
- [BELLINGCAT's Online Investigation Toolkit](https://docs.google.com/spreadsheets/d/18rtqh8EG2q1xBo2cLNyhIDuK9jrPGwYr9DI2UncoqJQ/) - Curated by investigative journalists
- [Aware Online OSINT Tools](https://www.aware-online.com/en/osint-tools/) - Dutch OSINT resource
- [OSINT Techniques Tools](https://www.osinttechniques.com/osint-tools.html) - Tool directory
- [OSINTCurious 10 Minute Tips](https://osintcurio.us/10-minute-tips/) - Quick OSINT tutorials
- [Investigative Dashboard](https://investigativedashboard.org) - Investigative journalism resources
- [Week in OSINT (Sector035)](https://medium.com/@sector035) - Weekly OSINT updates
- [I-Intelligence OSINT Resources Handbook](https://www.i-intelligence.eu/wp-content/uploads/2018/06/OSINT_Handbook_June-2018_Final.pdf) - Comprehensive PDF guide
- [Awesome OSINT Github](https://github.com/jivoi/awesome-osint) - Curated list of OSINT resources
- [Ph055a's OSINT Collection](https://github.com/Ph055a/OSINT_Collection) - Tool and resource collection
- [Collection of 4000+ OSINT resources](https://metaosint.github.io/table) - Massive resource database
- [IntelTechniques Tools](https://inteltechniques.com/tools/) - Michael Bazzell's tool collection
- [OSINT Combine](https://www.osintcombine.com/tools) - Tool aggregator
- [Nixintel](https://nixintel.info/) - OSINT blog and resources

---
#######################################################################################
## Books
#######################################################################################

#######################################################################################
### Official Resources & Publications
#######################################################################################

- [Wikipedia - List of Intelligence Gathering Disciplines](https://en.wikipedia.org/wiki/List_of_intelligence_gathering_disciplines)
  - [Wayback](https://web.archive.org/web/20211002002607/https://en.wikipedia.org/wiki/List_of_intelligence_gathering_disciplines)
  - [archive.today](https://archive.ph/rfzRf)
  - [WikiLess](https://wikiless.org/wiki/List_of_intelligence_gathering_disciplines?lang=en)

- [DIA - Defense and Intelligence Abbreviations and Acronyms - November 1997 [PDF]](https://www.dia.mil/FOIA/FOIA-Electronic-Reading-Room/FOIA-Reading-Room-Other-Available-Records/FileId/39954/)
  - [Wayback](https://web.archive.org/web/20210810222713/https://www.dia.mil/FOIA/FOIA-Electronic-Reading-Room/FOIA-Reading-Room-Other-Available-Records/FileId/39954/)
  - [Library Genesis](http://libgen.rs/book/index.php?md5=2ABBB54324D2F6403298914E7522D039)

- [Counter Intelligence Glossary - Terms and Definitions - June 2014 [PDF]](https://fas.org/irp/eprint/ci-glossary.pdf)
  - [Wayback](https://web.archive.org/web/20211002003503/https://irp.fas.org/eprint/ci-glossary.pdf)
  - [Library Genesis](http://libgen.rs/book/index.php?md5=8567E71ED1658AF9496B5CEB780CFB1B)

#######################################################################################
### Essential Reading Material
#######################################################################################

- [OSINT Techniques: Resources for Uncovering Online Information 10th Edition - Michael Bazzell - 2023](https://inteltechniques.com/book1.html)
  - **⭐ EMPFEHLUNG:** Dies ist das wichtigste Buch dieser Liste - praktische Anleitungen und regelmäßig aktualisiert
  - [archive.today](https://archive.ph/nU1Os)

- [US Army - Open-Source Intelligence ATP 2-22.9 - June 2017 - Redacted Copy [PDF]](https://irp.fas.org/doddir/army/atp2-22-9-2017.pdf)
  - [Wayback](https://web.archive.org/web/20210926093547/https://irp.fas.org/doddir/army/atp2-22-9-2017.pdf)
  - [Library Genesis](http://libgen.rs/book/index.php?md5=B294FA28A8F5E1C52CB7DFE3B391A83C)

- [US Army - Open-Source Intelligence - ATP 2-22.9 - July 2012 [PDF]](https://fas.org/irp/doddir/army/atp2-22-9.pdf)
  - [Wayback](https://web.archive.org/web/20210926093517/https://irp.fas.org/doddir/army/atp2-22-9.pdf)
  - [Library Genesis](https://libgen.rs/book/index.php?md5=090D419ADE50C0E268587291E5F35EC6)

- [Joint Military Intelligence Training Center - Open Source Intelligence Professional Handbook - October 1996 [PDF]](http://www.oss.net/dynamaster/file_archive/080807/a3127ddeaa9a083affdddce6766401fc/Open%20Source%20Intelligence_Professional%20Handbook.pdf)
  - [Wayback](https://web.archive.org/web/20211011044535/http://www.oss.net/dynamaster/file_archive/080807/a3127ddeaa9a083affdddce6766401fc/Open%20Source%20Intelligence_Professional%20Handbook.pdf)
  - [Library Genesis](https://libgen.rs/book/index.php?md5=0EFC24973A3CBE8ED28AE01327772AC5)

- [US Department of Justice - Legal Considerations when Gathering Online Cyber Threat Intelligence - 2020 [PDF]](https://www.justice.gov/criminal-ccips/page/file/1252341/download)
  - [Wayback](https://web.archive.org/web/20210808074010/https://www.justice.gov/criminal-ccips/page/file/1252341/download)
  - [Library Genesis](https://libgen.rs/book/index.php?md5=D9ED377FB72DFCA4E05403E6BE474D44)

- [The Psychology of Intelligence Analysis - Heuer, R. - 2006 [PDF]](https://www.ialeia.org/docs/Psychology_of_Intelligence_Analysis.pdf)
  - [Wayback](https://web.archive.org/web/20211011071927/https://www.ialeia.org/docs/Psychology_of_Intelligence_Analysis.pdf)
  - [Library Genesis](https://libgen.rs/book/index.php?md5=8597CA7B3A51B41702D419CBDC003BFA)

- [Romanian Intelligence Service - OSINT Handbook [PDF]](http://bib.opensourceintelligence.biz/STORAGE/OSINT%20Handbook.pdf)
  - [Wayback](https://web.archive.org/web/20210903190205/https://bib.opensourceintelligence.biz/STORAGE/OSINT%20Handbook.pdf)
  - [Library Genesis](https://libgen.rs/book/index.php?md5=9F546C7EECCA739702604A279E508F11)

- [UFMCS - Red Team Handbook - April 2012 [PDF]](http://bib.opensourceintelligence.biz/STORAGE/2012.%20Red%20Team%20Handbook.pdf)
  - [Wayback](https://web.archive.org/web/20210903190122/https://bib.opensourceintelligence.biz/STORAGE/2012.%20Red%20Team%20Handbook.pdf)
  - [Library Genesis](https://libgen.rs/book/index.php?md5=D504CAF150062A520CC836B3E9622671)

- [Open Source Intelligence Investigation: From Strategy to Implementation - Akhgar, B. - 2016 [PDF]](http://bib.opensourceintelligence.biz/STORAGE/2016.%20Open%20source%20intelligence%20investigation.pdf)
  - [Wayback](https://web.archive.org/web/20210903190138/https://bib.opensourceintelligence.biz/STORAGE/2016.%20Open%20source%20intelligence%20investigation.pdf)
  - [Library Genesis](https://libgen.rs/book/index.php?md5=3D8FFB51AA1DE1C7A5DB47F521EE3045)

- [Sailing the Sea of OSINT in the Information Age - Mercado, S.C. - 2004 [PDF]](http://bib.opensourceintelligence.biz/STORAGE/2004.%20Sailing%20the%20sea%20of%20OSINT.pdf)
  - [Wayback](https://web.archive.org/web/20210903190116/https://bib.opensourceintelligence.biz/STORAGE/2004.%20Sailing%20the%20sea%20of%20OSINT.pdf)
  - [Library Genesis](http://libgen.rs/book/index.php?md5=D6804C2B7EA96CF36D31B058AC3E06EB)

- [OSS - Special Operations Forces OSINT Handbook - 2004 [PDF]](http://bib.opensourceintelligence.biz/STORAGE/2004.%20Special%20operations%20forces%20open%20source%20intellingence%20\(OSINT\)%20handbook.pdf)
  - [Wayback](https://web.archive.org/web/20210903190144/https://bib.opensourceintelligence.biz/STORAGE/2004.%20Special%20operations%20forces%20open%20source%20intellingence%20\(OSINT\)%20handbook.pdf)
  - [Library Genesis](https://libgen.rs/book/index.php?md5=0784CE80298B415752AB8ED8E7ED6778)

- [NATO - Open Source Intelligence Handbook - November 2001 [PDF]](http://www.oss.net/dynamaster/file_archive/030201/ca5fb66734f540fbb4f8f6ef759b258c/NATO%20OSINT%20Handbook%20v1.2%20-%20Jan%202002.pdf)
  - [Wayback](https://web.archive.org/web/20210126020538/http://www.oss.net/dynamaster/file_archive/030201/ca5fb66734f540fbb4f8f6ef759b258c/NATO%20OSINT%20Handbook%20v1.2%20-%20Jan%202002.pdf)
  - [Internet Archive](https://archive.org/details/NATOOSINTHandbookV1.2/)

#######################################################################################
### Book Collections
#######################################################################################

- [The OSINT Treasure Trove](https://bib.opensourceintelligence.biz)
  - [Wayback](https://web.archive.org/web/20211010192751/http://bib.opensourceintelligence.biz/)
  - [archive.today](https://archive.is/0LNPm)

- [Blockint - The OSINT Library](https://www.blockint.nl/the-osint-library/)
  - [Wayback](https://web.archive.org/web/20211011075724/https://www.blockint.nl/the-osint-library/)
  - [archive.today](https://archive.is/tYj8M)

- [I-Intelligence OSINT Resources Handbook](https://i-intelligence.eu/uploads/public-documents/OSINT_Handbook_2020.pdf)

**Zusätzliche empfohlene Bücher:**

- **"Open Source Intelligence Techniques" - Michael Bazzell** - Der Goldstandard für praktisches OSINT
- **"We Are Bellingcat" - Eliot Higgins** - Einblicke in investigative OSINT-Journalismus
- **"Social Engineering: The Art of Human Hacking" - Christopher Hadnagy** - Verstehen Sie soziale Aspekte
- **"The Art of Invisibility" - Kevin Mitnick** - Privacy und OpSec
- **"Data and Goliath" - Bruce Schneier** - Datenschutz im digitalen Zeitalter

---

#######################################################################################
# SEARCH_ENGINES
#######################################################################################

# SearXNG
https://searx.space

# search.hbubli.cc
https://search.hbubli.cc/


- [Fagan Finder](https://www.faganfinder.com/)
- [Search All](https://www.searchall.net/), [WebSitesSearch](https://web-sites-search.web.app/), [CombinedSearch](https://combinedsearch.io/), [gnod Search](https://www.gnod.com/search/) or [AIO Search](https://www.aiosearch.com/) - Multi-Site Search
- [100 Search Engines](https://www.100searchengines.com/) - Search with 100 Search Engines
- [Jumps](https://jumps.io/) or [Yubnub](https://yubnub.org/) - Site Quick Search
- [Trovu.net](https://trovu.net/) - Command Search /
- [The Search Engine Map](https://www.searchenginemap.com/) - View Search Engine Connections
- [Marginalia Search](https://marginalia-search.com/) - Text-Based Search Engine /
- [TheOldNet](https://theoldnet.com/) or [OldVista](https://www.oldavista.com/) - Oldschool / Retro Site Search Engines
- [OceanHero](https://oceanhero.today/) or [ekoru](https://ekoru.org/) - Ocean Protection Search Engines
- [Ecosia](https://www.ecosia.org/) - Plant Trees via Search / [Firefox](https://addons.mozilla.org/en-US/firefox/addon/ecosia-the-green-search/) / [Chrome](https://chromewebstore.google.com/detail/ecosia-the-search-engine/eedlgdlajadkbbjoobobefphmfkcchfk)
- [Mullvad Leta](https://leta.mullvad.net/)
- [Presearch](https://presearch.com/) /
- [Bing](https://www.bing.com/)
- [Google](https://google.com/) / [AI Mode](https://google.com/aimode), [2](https://www.google.com/search?udm=50)
- [Lycos](https://www.lycos.com/)
- [WebCrawler](https://www.webcrawler.com/)
- [Million Short](https://millionshort.com/)
- [Andi](https://andisearch.com/)
- [Vuhuv](https://vuhuv.com/)
- [Carrot2](https://search.carrot2.org/#/web)
- [Yahoo](https://www.yahoo.com/)
- [Stract](https://stract.com/) /
- [AOL](https://search.aol.com/)
- [All the Internet](https://www.alltheinternet.com/)
- [eTools.ch](https://www.etools.ch/)
- [BizNar](https://biznar.com/biznar/desktop/en/search.html)
- [WorldWideScience](https://worldwidescience.org/)
- [Whoogle Search](https://github.com/benbusby/whoogle-search) or [ZincSearch](https://zincsearch-docs.zinc.dev/) / - Self-Hosted Search Engines
- **[CSE Utopia](https://start.me/p/EL84Km/cse-utopia)**, [Awesome CSEs](https://github.com/davzoku/awesome-custom-search-engines) or [Boolean Strings](https://booleanstrings.com/all-the-40-forty-custom-search-engines/) - Custom Search Engine Indexes
- [TV Streaming CSE](https://cse.google.com/cse?cx=006516753008110874046:hrhinud6efg) - Search TV Streaming Sites
- [Streaming CSE](https://cse.google.com/cse?cx=006516753008110874046:cfdhwy9o57g##gsc.tab=0), [2](https://cse.google.com/cse?cx=006516753008110874046:o0mf6t-ugea##gsc.tab=0), [3](https://cse.google.com/cse?cx=98916addbaef8b4b6), [4](https://cse.google.com/cse?cx=0199ade0b25835f2e)
- [Download CSE](https://cse.google.com/cse?cx=006516753008110874046:1ugcdt3vo7z), [2](https://cse.google.com/cse?cx=006516753008110874046:reodoskmj7h) - Search Download Sites
- [Virgil Software Search](https://virgil.samidy.com/software-search/) / or [Software CSE](https://cse.google.com/cse?cx=ae17d0c72fa6cbcd4) - Search Software Sites
- [Torrent CSE](https://cse.google.com/cse?cx=006516753008110874046:0led5tukccj), [2](https://cse.google.com/cse?cx=006516753008110874046:kh3piqxus6n) - Search General Torrent Sites
- [Reading CSE](https://cse.google.com/cse?cx=006516753008110874046:s9ddesylrm8), [2](https://cse.google.com/cse?cx=006516753008110874046:rc855wetniu), [3](https://cse.google.com/cse?cx=e9657e69c76480cb8), [4](https://cse.google.com/cse?cx=c46414ccb6a943e39), [5](https://ravebooksearch.com/), [6](https://recherche-ebook.fr/en/) - Search Reading Sites
- [Audiobooks CSE](https://cse.google.com/cse?cx=006516753008110874046:cwbbza56vhd) - Search Audiobook Sites
- [Comics CSE](https://cse.google.com/cse?cx=006516753008110874046:p4hgytyrohg) - Search Comic Sites
- [Manga CSE](https://cse.google.com/cse?cx=006516753008110874046:4im0fkhej3z), [2](https://cse.google.com/cse?cx=006516753008110874046:a5mavctjnsc#gsc.tab=0) - Search Manga Sites
- [Android APK CSE](https://cse.google.com/cse?cx=e0d1769ccf74236e8), [2](https://cse.google.com/cse?cx=73948689c2c206528), [3](https://cse.google.com/cse?cx=a805854b6a196d6a6) - Search Android APK Sites
- [Extensions CSE](https://cse.google.com/cse?cx=86d64a73544824102) - Search Extension Sites
- [Fonts CSE](https://cse.google.com/cse?cx=82154ebab193e493d) - Search Font Sites
- [Video Streaming CSE](https://cse.google.com/cse?cx=006516753008110874046:6v9mqdaai6q) - Search YouTube-Like Video Sites
- [Video Download CSE](https://cse.google.com/cse?cx=006516753008110874046:wevn3lkn9rr), [2](https://cse.google.com/cse?cx=89f2dfcea452fc451), [3](https://cse.google.com/cse?cx=aab218d0aa53e3578) - Search Video Download Sites
- [Video Torrent CSE](https://cse.google.com/cse?cx=006516753008110874046:gaoebxgop7j) - Search Video Torrent Sites
- [Anime Streaming CSE](https://cse.google.com/cse?cx=006516753008110874046:vzcl7wcfhei) or [Kuroiru](https://kuroiru.co/) - Search Anime Streaming Sites
- [Anime Download CSE](https://cse.google.com/cse?cx=006516753008110874046:osnah6w0yw8) - Search Anime Download Sites
- [Anime Torrent CSE](https://cse.google.com/cse?cx=006516753008110874046:lamzt6ls4iz) - Search Anime Torrent Sites
- [Audio Download CSE](https://cse.google.com/cse?cx=006516753008110874046:ibmyuhh72io), [2](https://cse.google.com/cse?cx=006516753008110874046:ohobg3wvr_w), [3](https://cse.google.com/cse?cx=32d85b41e2feacd3f) - Search Audio Download Sites
- [Audio Torrent CSE](https://cse.google.com/cse?cx=006516753008110874046:v75cyb4ci55) - Search Audio Torrent Sites
- [Virgil Game Search](https://virgil.samidy.com/Game-search/) / , [Rezi Search](https://rezi.one/), [⁠Playseek](https://playseek.app/), [Game Download CSE](https://cse.google.com/cse?cx=006516753008110874046:cbjowp5sdqg) or [r/PiratedGames CSE](https://cse.google.com/cse?cx=20c2a3e5f702049aa) - Multi-Site Search Engines
- [Game Torrent CSE](https://cse.google.com/cse?cx=006516753008110874046:pobnsujblyx) - Search Game Torrent Sites
- [PastebinSearch](https://cipher387.github.io/pastebinsearchengines/) or [Paste Skimmer](https://sites.google.com/view/l33tech/tools/pasteskimmer) - Search Pastebins
- [File Host Search](https://cse.google.com/cse?cx=90a35b59cee2a42e1) - Search File Hosts
- [Linux Software CSE](https://cse.google.com/cse?cx=81bd91729fe2a412b) - Search Linux Software Sites
- [ROM CSE](https://cse.google.com/cse?cx=f47f68e49301a07ac), [2](https://cse.google.com/cse?cx=744926a50bd7eb010) - Search ROM Sites
- [TikTok CSE](https://cse.google.com/cse?cx=c42f6b58703f83683) - TikTok Search
- [Telegago](https://cse.google.com/cse?&cx=006368593537057042503:efxu7xprihg#gsc.tab=0) or [TG CSE](https://cse.google.com/cse?cx=006249643689853114236:a3iibfpwexa) - Telegram CSE
- **[SearchTweaks](https://searchtweaks.com/)** - Google Search Tools
- [Mastering Google Search Operators](https://moz.com/blog/mastering-google-search-operators-in-67-steps), [2](https://ahrefs.com/blog/google-advanced-search-operators/), [3](https://moz.com/learn/seo/search-operators), [4](https://seranking.com/ru/blog/operatory-poiska-google/) - Google Search Operator Resources
- [Custom Sidebar](https://greasyfork.org/en/scripts/535629) - Highly Customizable ⁠Google Search Sidebar
- [ISearchFrom](https://isearchfrom.com/) - Change Location / Device for Google Search
- [goosh](https://goosh.org/) - Simple Google Web Client
- [Google Trends](https://trends.google.com/trends/) - Google Search Trends
- [⁠Google Images Tools Enhanced](https://greasyfork.org/en/scripts/537524) - Extra Google Image Search Filters
- [View Image](https://github.com/bijij/ViewImage) - Adds Back "View Image" Button to Google Image Search
- [Show Image Dimensions](https://greasyfork.org/scripts/401432) - Add Image Dimensions to Google
- [Google DWIMages](https://greasyfork.org/en/scripts/29420) - Direct Links to Images & Pages on Google
- [Endless Google](https://openuserjs.org/scripts/tumpio/Endless_Google) - Google Search Endless Scrolling
- [Google Bangs](https://greasyfork.org/en/scripts/424160) - DDG!bangs in Google
- [DisableAMP](https://github.com/AdguardTeam/DisableAMP) - Disable Google AMP Links

---
