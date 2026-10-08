# 📑 Forensic Ring Anomaly Hunter: SHA-256, 60 Hz ENF, F0/F1/F2 Biometry & PDF Suite

A comprehensive **read-only, non-destructive digital audio forensic examination tool** for validating Ring doorbell video clips, detecting silence-broken anomalies, analyzing 60 Hz Electric Network Frequency (ENF) phase continuity, extracting vocal biometry (Fundamental Pitch F0 & vocal formants F1/F2), and generating court-ready multi-page PDF forensic examination reports.

## 🎯 Features

- **Cryptographic Chain-of-Custody**: Pre/Post SHA-256 & MD5 hash verification with bitwise integrity confirmation
- **MP4 Container Audit**: ISO MP4 atom parsing, metadata inspection, encoder tag detection, audio/video sync validation
- **60 Hz ENF Phase Continuity Analysis**: Narrowband Hilbert transform ENF phase tracking, splice detection via phase discontinuity thresholds
- **Fundamental Pitch (F0) Extraction**: Probabilistic YIN pitch detection (65–450 Hz range)
- **Vocal Formant Biometry (F1/F2)**: 18th-order LPC complex root solver for vocal tract resonance extraction
- **Vowel Articulation Classification**: Acoustic vowel space mapping based on F1/F2 coordinates
- **Silence-Broken Anomaly Detection**: Piggyback modulation scoring with harmonic/transient separation (HPSS)
- **Non-Destructive Unmasking & DSP**:
  - Broadband click/transient suppression (HPSS harmonic/percussive separation)
  - Soft-knee vocal gain boost
  - Time-stretch expansion (0.65–0.95x rates) for intelligibility recovery
- **Forced Unthrottled ASR**: OpenAI Whisper transcription at both normal and time-expanded playback rates
- **Multi-Page PDF Report Generation**:
  - Executive summary & chain-of-custody table
  - Per-clip 60 Hz ENF phase continuity exhibits
  - Per-burst spectrogram + LPC envelope + F0/F1/F2 tracks + transcripts
- **Batch Export**: ZIP bundle with PDF report, expanded/unmasked WAV files, chain-of-custody JSON, CSV summaries, and SHA-256 manifest
- **Interactive Burst Inspector**: Play raw, unmasked, and time-expanded anomaly slices with standalone PDF export per burst

---

## 📋 System Requirements

### Required Software
- **Python 3.11+** ([python.org](https://www.python.org))
- **FFmpeg** with ffprobe (for MP4 metadata extraction)
  - **Windows**: [ffmpeg.org/download.html](https://www.ffmpeg.org/download.html)
  - **Ubuntu/Debian**: `sudo apt install ffmpeg`
  - **macOS**: `brew install ffmpeg`
- **Microsoft Visual C++ Build Tools** (Windows only, for scientific packages)

### Optional Hardware
- **GPU** (NVIDIA CUDA 12.1+): For faster Whisper transcription
  - CPU-only mode is included in `requirements.txt` by default

---

## 🚀 Installation

### Option 1: Windows (Full Setup)

1. **Install Python 3.11**
   - Download from [python.org](https://www.python.org)
   - Check "Add Python to PATH" during install
   - Verify:
     ```bash
     python --version
     pip --version
     ```

2. **Install Visual C++ Build Tools**
   - Download Visual Studio Build Tools 2022
   - Select "Desktop development with C++"
   - Reopen terminal after install

3. **Install FFmpeg**
   - Download from [ffmpeg.org](https://www.ffmpeg.org/download.html)
   - Add `ffmpeg/bin` folder to system PATH
   - Verify:
     ```bash
     ffprobe -version
     ```

4. **Clone and setup repository**
   ```bash
   git clone https://github.com/Royrgrs/forensic-ring-anomaly-hunter.git
   cd forensic-ring-anomaly-hunter
   python -m venv venv
   venv\Scripts\activate
   python -m pip install --upgrade pip setuptools wheel
   pip install -r requirements.txt
   ```

5. **Verify installation**
   ```bash
   python -c "import streamlit, numpy, pandas, librosa, soundfile, scipy, matplotlib, torch, whisper; print('✅ All dependencies installed')"
   ```

6. **Run the app**
   ```bash
   streamlit run app.py
   ```
   The app opens at `http://localhost:8501`

### Option 2: Linux/macOS

1. **Clone repository**
   ```bash
   git clone https://github.com/Royrgrs/forensic-ring-anomaly-hunter.git
   cd forensic-ring-anomaly-hunter
   ```

2. **Install FFmpeg**
   ```bash
   # Ubuntu/Debian
   sudo apt update && sudo apt install ffmpeg

   # macOS
   brew install ffmpeg
   ```

3. **Create virtual environment**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

4. **Install dependencies**
   ```bash
   python -m pip install --upgrade pip setuptools wheel
   pip install -r requirements.txt
   ```

5. **Run the app**
   ```bash
   streamlit run app.py
   ```

### Option 3: CPU-Only PyTorch (Lightweight)

If you don't have CUDA or want a smaller footprint, create a custom `requirements-cpu.txt`:

```txt
streamlit>=1.31.0
numpy>=1.24.0
pandas>=2.0.0
librosa>=0.10.2
soundfile>=0.12.1
scipy>=1.11.0
matplotlib>=3.8.0
openai-whisper>=20240930
torch==2.2.2 --index-url https://download.pytorch.org/whl/cpu
```

Then install:
```bash
pip install -r requirements-cpu.txt
```

---

## 📖 Usage

### Local Folder Scanning (Read-Only)

1. Navigate to **"Option 1: Scan Local Folder"** tab
2. Click **"📂 Browse Folder"** to select a directory containing Ring MP4 clips
3. Optionally enable **"Include Subfolders Recursively"**
4. Configure sidebar settings:
   - Examiner ID
   - Regional power grid frequency (60 Hz / 50 Hz)
   - ENF phase jump threshold (degrees)
   - Anomaly detection sensitivity
   - DSP boost and time-stretch rates
5. Click **"📑 Validate Hashes, Run ENF + F0/F1/F2 Biometry & Compile PDF Report"**
6. Wait for processing (bar shows progress)
7. Download:
   - **Forensic Examination Report** (printable PDF with exhibits)
   - **Complete Evidence Package** (ZIP with all WAV files, CSVs, JSON manifest)
   - **Chain-of-Custody JSON** (structured forensic metadata)
   - **F0/F1/F2 Transcripts CSV** (tabular burst data)

### File Upload (Drag & Drop)

1. Navigate to **"Option 2: Drag & Drop"** tab
2. Drag media files directly or click to upload
3. Follow the same workflow as folder scanning

### Interactive Burst Inspector

1. After processing, scroll to **"Interactive F0 / F1 / F2 Burst Inspector"**
2. Select a burst from the dropdown (showing F0, F1, F2 frequencies and transcript)
3. Play three audio versions:
   - **Raw Evidence Control Slice** (masking click included)
   - **Unmasked Vocal Band** (1.0x speed, click suppressed)
   - **Boosted & Time-Expanded** (0.80x or your configured rate, gain boosted)
4. Click **"📄 Download Standalone PDF Exhibit"** to generate a single-burst PDF

---

## ⚙️ Configuration Parameters

### Sidebar Settings

#### 60 Hz ENF & PDF
- **Examiner / Operator ID**: Printed on all PDF reports
- **Regional Power Grid Frequency**: 60 Hz (North America) or 50 Hz (Europe/Asia)
- **ENF Harmonic Selection**: Auto-detect strongest or force a specific harmonic (60, 120, 180, 240, 300 Hz)
- **ENF Phase Jump Splice Threshold**: Degrees per 50 ms frame; spikes above this flag phase breaks (default 45°)

#### Anomaly Detection
- **Whisper Decoder Size**: `base`, `small`, or `turbo` (larger = slower but more accurate)
- **Dead-Silence Floor Threshold**: dB below which audio is considered silence (default -40 dB)
- **Min Sudden Noise Jump**: Minimum dB rise above silence to trigger anomaly detection (default +10 dB)
- **Min Piggyback Modulation Score**: Threshold for vocal/speech likelihood (0–100, default 18)

#### Non-Destructive DSP
- **Physical Click Removal**: HPSS transient suppression ratio (0–98%, default 85%)
- **Underlying Anomaly Gain Boost**: Soft-knee multiplier for unmasked vocal layer (1.0–5.0x, default 2.5x)
- **Time-Expansion Rate**: Playback rate for expanded version (0.65–0.95x, default 0.80x)

---

## 📊 Output Files

All outputs saved to `Extracted_Anomalies/` folder:

### PDF Reports
- **Forensic_Examination_Report_{timestamp}.pdf**
  - Executive summary with source file table
  - Per-clip 60 Hz ENF phase continuity exhibits (3 subplots per clip)
  - Per-burst F0/F1/F2 biometry exhibits with spectrograms, transcripts, and forensic metadata

### Audio WAV Files (one set per anomaly burst)
- `{clip_hash}_Burst{N}_RAW_EVIDENCE_SLICE.wav` – Original masked slice
- `{clip_hash}_Burst{N}_UNMASKED_1.0x_{transcript}.wav` – Click-suppressed vocal layer
- `{clip_hash}_Burst{N}_BOOSTED_EXPANDED_{rate}x_{transcript}.wav` – Time-expanded + boosted

### Metadata & Evidence
- **forensic_chain_of_custody_enf_{timestamp}.json** – Structured forensic manifest (ISO 8601 UTC timestamps, SHA-256 hashes, F0/F1/F2 biometry per burst)
- **checksums_{timestamp}.sha256** – SHA-256 and MD5 digests for all outputs (UNIX `sha256sum` format)
- **enf_authenticated_clips_{timestamp}.csv** – Per-file summary (hashes, ENF verdict, container status, anomaly counts)
- **enf_formant_burst_transcripts_{timestamp}.csv** – Per-burst detailed table (F0/F1/F2, ENF boundary status, timestamps, transcripts, file paths)

### Compressed Bundle
- **Forensic_Complete_Evidence_Package_{timestamp}.zip** – Single-file download containing all of the above

---

## 🔐 Forensic Integrity & Legal Use

### Chain-of-Custody
This tool operates in **read-only mode** throughout. All files are:
- Verified pre-scan and post-scan with SHA-256/MD5 hashes
- Analyzed without modification to the original
- Exported with full cryptographic manifest

### Standards Compliance
- Follows **SWGDE (Scientific Working Group on Digital Evidence)** audio authentication best practices
- ENF analysis conforms to ISO/IEC 27040 and ATIS forensic audio guidelines
- LPC formant extraction aligns with acoustic phonetics literature (Ladefoged, Kent & Read)

### PDF Report Contents
Each report includes:
- Examiner ID and UTC generation timestamp
- Source file pre/post SHA-256 hashes
- MP4 container atom structure and metadata tags
- ENF phase residual, phase derivative, and instantaneous frequency plots per clip
- Per-burst biometry: F0 pitch contour, F1/F2 formant tracks, LPC spectral envelope, vowel classification
- Forced transcriptions at both normal and expanded rates
- ENF splice flags at anomaly boundaries

---

## 🐛 Troubleshooting

### "ffprobe not found"
- **Windows**: Add FFmpeg `bin/` folder to system PATH, restart terminal
- **Linux/macOS**: Verify with `which ffprobe` or reinstall FFmpeg

### "No module named 'whisper'"
- Ensure `openai-whisper` is installed (not just `whisper`):
  ```bash
  pip install openai-whisper>=20240930
  ```

### "CUDA out of memory" or GPU issues
- Use CPU-only PyTorch via `requirements-cpu.txt`
- Or reduce Whisper model size to `base`

### PDF generation fails
- Ensure `matplotlib` is installed: `pip install matplotlib>=3.8.0`
- Check disk space in `Extracted_Anomalies/` folder

### Slow processing on first run
- Whisper model downloads ~140 MB on first use (cached afterward)
- Time-expansion and LPC formant tracking are computationally intensive; consider smaller file batches

---

## 📦 Deployment

### Streamlit Cloud

1. **Push to GitHub**
   ```bash
   git add .
   git commit -m "Initial deployment"
   git push origin main
   ```

2. **Create `.streamlit/config.toml`**
   ```toml
   [theme]
   primaryColor = "#0066cc"
   backgroundColor = "#ffffff"
   secondaryBackgroundColor = "#f0f2f6"
   textColor = "#262730"

   [client]
   showErrorDetails = true
   maxUploadSize = 500

   [server]
   maxUploadSize = 500
   enableXsrfProtection = true
   ```

3. **Deploy via Streamlit Cloud**
   - Go to [share.streamlit.io](https://share.streamlit.io)
   - Sign in with GitHub
   - Click "New app"
   - Select repo, branch, and main file (`app.py`)
   - Click "Deploy"

### Docker (Self-Hosted)

Create `Dockerfile`:
```dockerfile
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    ffmpeg \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 8501

CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
```

Build and run:
```bash
docker build -t forensic-ring-anomaly-hunter .
docker run -p 8501:8501 forensic-ring-anomaly-hunter
```

---

## 📝 License

This project is provided for forensic examination, research, and educational purposes. Ensure compliance with local laws and institutional review boards when handling sensitive audio evidence.

---

## 🤝 Contributing

Issue reports and pull requests welcome. For major changes, open an issue first.

---

## 📧 Support

For questions or issues:
- Check [GitHub Issues](https://github.com/Royrgrs/forensic-ring-anomaly-hunter/issues)
- Review the troubleshooting section above
- Consult the embedded docstrings in `app.py`

---

**Made with ❤️ for digital forensics professionals.**
