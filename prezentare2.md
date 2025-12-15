---
marp: true
theme: gaia
style: |
  :root {
    --color-background: #ffffff;
    --color-foreground: #1a1a1a;
    --color-highlight: #0066cc;
    --color-dimmed: #888;
    font-family: 'Segoe UI', Arial, sans-serif;
  }
  
  section {
    padding: 50px;
    font-size: 24px;
    background: linear-gradient(135deg, #f5f7fa 0%, #ffffff 100%);
  }
  
  section.title {
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    background: linear-gradient(135deg, #0066cc 0%, #004499 100%);
    color: white;
  }
  
  section.title h1 {
    font-size: 48px;
    margin: 0;
    font-weight: bold;
  }
  
  section.title h2 {
    font-size: 28px;
    margin: 20px 0 0 0;
    color: #ccddff;
    font-weight: 300;
  }
  
  h1 {
    color: #0066cc;
    font-size: 40px;
    margin: 0 0 20px 0;
    border-bottom: 3px solid #0066cc;
    padding-bottom: 10px;
  }
  
  h2 {
    color: #0066cc;
    font-size: 32px;
    margin: 15px 0 10px 0;
  }
  
  h3 {
    color: #004499;
    font-size: 24px;
    margin: 12px 0 8px 0;
  }
  
  ul, ol {
    margin: 8px 0;
  }
  
  li {
    margin: 5px 0;
    line-height: 1.3;
  }
  
  code {
    background: #f0f0f0;
    color: #d63384;
    padding: 2px 5px;
    border-radius: 3px;
    font-family: 'Courier New', monospace;
    font-size: 18px;
  }
  
  table {
    font-size: 18px;
    width: 100%;
    border-collapse: collapse;
    margin: 10px 0;
  }
  
  table th {
    background: #0066cc;
    color: white;
    padding: 8px;
    text-align: left;
    font-weight: bold;
  }
  
  table td {
    border-bottom: 1px solid #ddd;
    padding: 6px 8px;
  }
  
  .small {
    font-size: 18px;
  }
  
  .tiny {
    font-size: 16px;
  }
  
  .success { color: #28a745; font-weight: bold; }
  .warning { color: #ff6b35; font-weight: bold; }
  .error { color: #dc3545; font-weight: bold; }
  .info { color: #0066cc; font-weight: bold; }
  
  em {
    color: #0066cc;
    font-style: normal;
    font-weight: 600;
  }
  
  strong {
    color: #004499;
    font-weight: 700;
  }
  
  footer {
    position: absolute;
    bottom: 20px;
    left: 50px;
    right: 50px;
    font-size: 14px;
    color: #888;
  }
  
  .columns {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
    margin: 10px 0;
  }

paginate: true
footer: "Digital Signature Authentication | December 2025"
---

<!-- _class: lead -->

# Tehnici de Semnătură Digitală ca Metodă de Autentificare

### Semnare fișiere · Multi-semnătură · Detecție automată algoritmi

<br/>

**Memedula Edna**  
**Nicolaev Andrei**

---

## De la teorie la practică – evoluția proiectului

**Versiunea inițială**
- Semnare de mesaje
- Un singur algoritm (RSA)
- Fără metadate
- Fără audit trail

**Versiunea finală**
- Semnare fișiere (orice tip)
- Multi-semnătură
- RSA + ECDSA
- Hash-uri multiple
- Detecție automată
- Semnături PDF

---

## De ce este necesară semnarea fișierelor

- Documentele reale sunt fișiere, nu text
- Fișierele pot fi:
  - binare (PDF, imagini)
  - mari
  - stocate pe termen lung

**Soluție:**  
➡️ semnarea hash-ului fișierului

---

## Modelul Hash-Then-Sign

**Flux standard**
1. Calcul hash fișier
2. Semnare hash cu cheia privată
3. Salvare semnătură + metadate
4. Verificare prin recalculare hash

**Avantaje**
- Eficient
- Securizat
- Standard industrial (NIST)

---

## Algoritmi hash suportați

- **SHA-256** – standard
- **SHA-512** – securitate ridicată
- **SHA3-256** – standard modern

**Scop**
- Agilitate criptografică
- Validare pe termen lung
- Conformitate legală

---

## Algoritmi de semnătură suportați

- **RSA (2048 biți, PSS)**
- **ECDSA (SECP256R1)**

**ECDSA**
- Chei mai mici
- Semnare mai rapidă
- Standard modern

---

## Comparație algoritmi

| Caracteristică | RSA | ECDSA |
|---------------|-----|-------|
| Dimensiune cheie | Mare | Mică |
| Performanță | Medie | Rapidă |
| Mobile / IoT | ❌ | ✅ |

---

## Metadate și audit trail

Fiecare semnătură conține:
- Nume semnatar
- Organizație
- Email
- Motiv
- Locație
- Timestamp
- Algoritmi folosiți
- ID unic (UUID)

➡️ **valoare legală și non-repudiere**

---

## Timestamping și non-repudiere

- ISO-8601
- Unix timestamp
- Fus orar

**Previne**
- antedatarea
- replay attacks
- fraudarea timpului

---

## Procesul de verificare a fișierelor

1. Recalculare hash fișier
2. Citire metadate semnătură
3. Detecție automată algoritmi
4. Verificare cu cheia publică
5. Comparare hash-uri

**Rezultat**
- ✓ autentic
- ✗ modificat / fals

---

## Scenarii de eșec detectate

- Fișier modificat
- Cheie publică greșită
- Algoritm incompatibil
- Semnătură coruptă
- Metadate lipsă

➡️ fiecare caz este raportat explicit

---

## De ce multi-semnătură

Necesar pentru:
- Contracte
- Aprobări manageriale
- Tranzacții financiare

**Cerințe**
- Semnatari independenți
- Ordine clară
- Integritate totală

---

## Arhitectura multi-semnăturii

- Un singur hash imutabil
- Mai multe semnături
- Fiecare semnătură:
  - algoritm propriu
  - hash propriu
  - metadate
  - timestamp

Stocare: **JSON**

---

## Flux secvențial de multi-semnare

1. Document → hash
2. Semnatar A (ex: ECDSA + SHA512)
3. Semnatar B (ex: RSA + SHA256)
4. Hash identic
5. Verificare completă

➡️ toți semnează același document

---

## Detecția automată a algoritmilor

**Problemă**
- Nu știm ce algoritm a fost folosit

**Soluție**
- Citire din metadate
- Configurare automată
- Validare nivel securitate

**Beneficii**
- Fără erori umane
- Verificare simplă

---

## Matrice de validare a securității

Combinații validate:
- RSA + SHA256 / SHA512 / SHA3
- ECDSA + SHA256 / SHA512 / SHA3

Fiecare clasificată ca:
- Secure
- Foarte sigur

---

## Semnături digitale în PDF

**Important**
- Semnătura criptografică = dovadă legală
- Semnătura vizuală = lizibilitate

Afișează:
- Nume
- Dată
- Motiv
- Organizație

---

## Multi-semnătură în PDF

- Afișare secvențială
- Paginare automată
- Conținutul original nu este modificat

Biblioteci:
- PyPDF2
- ReportLab

---

## Moduri de operare

1. Semnare mesaje
2. Semnare fișiere
3. Multi-semnătură

➡️ fiecare mod impune reguli stricte

---

## Amenințări și mitigări

| Amenințare | Măsură |
|-----------|--------|
| Modificare fișier | Hash |
| Reutilizare semnătură | Legare de document |
| Downgrade algoritm | Validare |
| Compromitere cheie | HSM |
| Fraudă timp | TSA |

---

## Conformitate legală

- eIDAS (UE)
- ESIGN & UETA (SUA)
- PAdES / PDF-A
- RFC 3161, 6979, 5652

---

## Concluzie

- Criptografie aplicată practic
- Autentificare digitală sigură
- Fluxuri reale de documente
- Încredere multi-party

**De la teorie academică la sistem pregătit pentru producție**
