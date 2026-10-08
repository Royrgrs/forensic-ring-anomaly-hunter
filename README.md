# Forensic Ring Anomaly Hunter

**A forensic workflow for examining Ring doorbell recordings and identifying suspicious audio anomalies using ENF continuity, pitch and formant analysis, and structured reporting.**

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org/downloads/)
[![License: Educational](https://img.shields.io/badge/License-Educational-green.svg)](#license)
[![FFmpeg Required](https://img.shields.io/badge/requires-FFmpeg-orange)](https://ffmpeg.org/)

## Overview

This tool provides a read-only forensic examination workflow for Ring-style MP4 recordings. It detects and analyzes:

- **ENF discontinuities** — phase instability in the 50/60 Hz power-line frequency
- **Silence-broken anomalies** — sudden signal excursions after periods of quiet
- **Formant dynamics** — F0, F1, F2 pitch and resonance features for human review
- **Acoustic modulation patterns** — scoring of speech-like content
- **Audio integrity** — SHA-256/MD5 chain-of-custody validation

Outputs are produced in **read-only mode** with full cryptographic manifests, PDF forensic reports, and exportable evidence packages for investigative review and documentation.

## Key Features

| Feature | Description |
|---------|-------------|
| **Chain-of-Custody** | SHA-256 / MD5 pre/post validation with signed manifests |
| **MP4 Audit** | Container structure, metadata inspection, codec detection |
| **ENF Analysis** | 50/60 Hz phase continuity tracking and splice detection |
| **Pitch & Formant** | F0 extraction, F1/F2-based acoustic features |
| **Anomaly Detection** | Silence-broken event scoring with modulation analysis |
| **Enhancement** | Optional non-destructive HPSS-based click suppression and time-stretch |
| **Transcription** | Whisper ASR at normal and expanded playback rates |
| **PDF Reports** | Multi-page exhibits with spectrograms, phase plots, and metadata |
| **Batch Export** | ZIP packages with WAV files, CSVs, JSON manifests |
| **Interactive UI** | Streamlit app with burst inspector and standalone PDF export |

## What This Is (And Is Not)

✅ **This tool is for:**
- Forensic audio examination and anomaly review
- Evidence documentation and chain-of-custody support
- Research into audio signal integrity
- Educational study of digital forensics techniques

❌ **This tool is not:**
- A legal determination engine
- A proof of authenticity or guilt
- A replacement for qualified examiner judgment
- Suitable for use without human review and case context

## System Requirements

### Required

- **Python 3.11+** ([download](https://www.python.org/downloads/))
- **FFmpeg** with ffprobe installed on PATH
  - **Windows**: [ffmpeg.org/download.html](https://www.ffmpeg.org/download.html)
  - **Ubuntu/Debian**: `sudo apt install ffmpeg`
  - **macOS**: `brew install ffmpeg`

### Optional

- **NVIDIA GPU** (CUDA 12.1+) — accelerates Whisper transcription
- **Microsoft Visual C++ Build Tools** (Windows only) — required for some scientific packages

---

## Installation

### Quick Start (All Platforms)

```bash
# Clone the repository
git clone https://github.com/Royrgrs/forensic-ring-anomaly-hunter.git
cd forensic-ring-anomaly-hunter

# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate          # On Windows: .venv\Scripts\activate

# Install dependencies
python -m pip install --upgrade pip setuptools wheel
pip install -r requirements.txt

# Run the app
streamlit run app.py
```

The app will open at `http://localhost:8501`

### Platform-Specific Setup

<details>
<summary><strong>Windows</strong></summary>

1. **Install Python 3.11+**
   - Download from [python.org](https://www.python.org)
   - Check "Add Python to PATH" during installation

2. **Install Visual C++ Build Tools** (if needed)
   - Download Visual Studio Build Tools 2022
   - Select "Desktop development with C++"
   - Reboot after installation

3. **Install FFmpeg**
   - Download from [ffmpeg.org](https://www.ffmpeg.org/download.html)
   - Add the `bin` folder to system PATH
   - Verify: `ffmpeg -version`

4. **Follow quick start** above

</details>

<details>
<summary><strong>Linux / macOS</strong></summary>

```bash
# Install FFmpeg
sudo apt update && sudo apt install ffmpeg      # Ubuntu/Debian
# or
brew install ffmpeg                             # macOS

# Follow quick start above
```

</details>

### CPU-Only Deployment

If you don't have CUDA or prefer a lightweight CPU-only setup:

```bash
pip install -r requirements-cpu.txt
```

Or manually create `requirements-cpu.txt` with:

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

---

## Usage

### Workflow 1: Local Folder Scanning

1. Open the Streamlit app
2. Select **"Option 1: Scan Local Folder"**
3. Click **"Browse Folder"** and select a directory with Ring MP4 clips
4. Optionally enable recursive scanning for subfolders
5. Configure sidebar parameters (examiner ID, frequency, thresholds)
6. Click **"Validate Hashes, Run ENF + F0/F1/F2 & Compile Report"**
7. Download the forensic report, evidence package, and metadata

### Workflow 2: Drag & Drop Upload

1. Select **"Option 2: Drag & Drop"** tab
2. Upload one or more media files
3. Follow the same analysis workflow

### Interactive Burst Inspector

After processing:

1. Scroll to **"Interactive F0 / F1 / F2 Burst Inspector"**
2. Select a burst from the dropdown (shows F0, F1, F2, and transcription)
3. Play three versions:
   - **Raw slice** (original with masking event)
   - **Unmasked** (click-suppressed, 1.0x speed)
   - **Enhanced** (time-expanded and gain-boosted)
4. Export a standalone single-burst PDF exhibit

---

## Configuration

### Sidebar Parameters

#### ENF & Report Settings
| Parameter | Range | Default | Purpose |
|-----------|-------|---------|---------|
| Examiner ID | text | — | Printed on all reports |
| Power Grid Frequency | 50/60 Hz | 60 Hz | Regional electrical frequency |
| ENF Harmonic | auto/forced | auto | Which harmonic to analyze |
| Phase Jump Threshold | degrees | 45° | Sensitivity to splice detection |

#### Anomaly Detection
| Parameter | Range | Default | Purpose |
|-----------|-------|---------|---------|
| Whisper Model | base/small/turbo | base | ASR accuracy vs. speed tradeoff |
| Silence Floor | dB | -40 | Noise floor threshold |
| Min Noise Jump | dB | +10 | Event trigger sensitivity |
| Modulation Score | 0–100 | 18 | Speech likelihood threshold |

#### DSP & Enhancement
| Parameter | Range | Default | Purpose |
|-----------|-------|---------|---------|
| Click Removal | 0–98% | 85% | HPSS transient suppression |
| Gain Boost | 1.0–5.0x | 2.5x | Soft-knee vocal amplification |
| Time Expansion | 0.65–0.95x | 0.80x | Playback rate for clarity |

---

## Output Files

All outputs are written to `Extracted_Anomalies/` directory.

### PDF Report
- **`Forensic_Examination_Report_{timestamp}.pdf`**
  - Executive summary with source file inventory
  - Per-clip ENF continuity plots
  - Per-burst spectrograms, LPC envelopes, F0/F1/F2 tracks
  - Transcriptions and forensic metadata

### Audio Exports (per burst)
- `{clip_hash}_Burst{N}_RAW_EVIDENCE_SLICE.wav` — Original
- `{clip_hash}_Burst{N}_UNMASKED_1.0x_{transcript}.wav` — Click-suppressed
- `{clip_hash}_Burst{N}_BOOSTED_EXPANDED_{rate}x_{transcript}.wav` — Enhanced

### Metadata & Evidence
- `forensic_chain_of_custody_enf_{timestamp}.json` — Structured manifest
- `checksums_{timestamp}.sha256` — Cryptographic verification
- `enf_authenticated_clips_{timestamp}.csv` — Per-file summary
- `enf_formant_burst_transcripts_{timestamp}.csv` — Per-burst details
- `Forensic_Complete_Evidence_Package_{timestamp}.zip` — All-in-one export

---

## Analysis Pipeline

```
Input MP4
    ↓
[Hash & Validate]
    ↓
[Extract Metadata & Audio Stream]
    ↓
[Detect Silence & Anomalies]
    ↓
[ENF Continuity Analysis]
    ↓
[F0 / F1 / F2 Extraction]
    ↓
[Anomaly Scoring]
    ↓
[Optional DSP Enhancement]
    ↓
[Whisper Transcription]
    ↓
[PDF Report Generation]
    ↓
Export Package
```

---

## Forensic Standards & Integrity

### Chain-of-Custody
- All analysis is **read-only**
- Source files are not modified
- Pre/post SHA-256 and MD5 hashes are collected
- Full cryptographic manifests are exported

### Standards Alignment
- Follows **SWGDE** (Scientific Working Group on Digital Evidence) guidelines
- ENF analysis conforms to **ISO/IEC 27040** and **ATIS** forensic audio standards
- Formant extraction aligns with acoustic phonetics literature (Ladefoged, Kent & Read)

### Limitations & Disclaimers
This tool provides structured analysis support, not definitive proof of:
- Audio authenticity or tampering
- Identity of speakers
- Guilt or innocence in legal proceedings

Results depend on:
- Source recording quality and completeness
- Audio codec, bit rate, and compression artifacts
- Environmental and device-specific characteristics
- Proper examiner review and case context

---

## Troubleshooting

| Issue | Solution |
|-------|----------|
| `ffprobe not found` | Add FFmpeg `bin/` to PATH; restart terminal |
| `No module named 'whisper'` | `pip install openai-whisper>=20240930` |
| CUDA out of memory | Use `requirements-cpu.txt` or reduce Whisper model to `base` |
| PDF generation fails | Verify `matplotlib` installed; check disk space |
| Slow first run | Whisper downloads ~140 MB model on first use (cached after) |

---

## Deployment

### Streamlit Cloud

1. Push your repo to GitHub
2. Go to [share.streamlit.io](https://share.streamlit.io)
3. Click "New app" → select repo, branch, and `app.py`
4. Deploy

### Docker (Self-Hosted)

```dockerfile
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y ffmpeg && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .

EXPOSE 8501

CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
```

```bash
docker build -t forensic-ring-anomaly-hunter .
docker run -p 8501:8501 forensic-ring-anomaly-hunter
```

---

## Project Structure

```
forensic-ring-anomaly-hunter/
├── app.py                           # Streamlit UI
├── requirements.txt                 # Full dependencies (with CUDA)
├── requirements-cpu.txt             # CPU-only variant
├── README.md
├── LICENSE
├── Extracted_Anomalies/             # Output directory
├── utils/                           # Hashing, metadata, utilities
├── processing/                      # ENF, pitch, formant, anomaly detection
├── reports/                         # PDF generation
└── exports/                         # ZIP and manifest creation
```

---

## Contributing

Contributions are welcome. Please open an issue before submitting a pull request for major changes.

Areas for contribution:
- Analysis accuracy and parameter tuning
- Signal-processing robustness
- PDF/export improvements
- Cross-platform installation support
- UI enhancements

---

## License

This project is provided for **forensic examination, research, and educational purposes**.

Use in compliance with:
- Local and jurisdictional laws
- Institutional policies and review boards
- Evidence handling and chain-of-custody procedures
- Professional forensic standards and ethics

---

## Support & Documentation

- **GitHub Issues**: [Report bugs or request features](https://github.com/Royrgrs/forensic-ring-anomaly-hunter/issues)
- **Troubleshooting**: See section above
- **Code Documentation**: Review embedded docstrings in `app.py`

---

## Acknowledgments

This project builds on established techniques in:
- **ENF Analysis** — power-line frequency forensics
- **Pitch Detection** — probabilistic YIN algorithm
- **LPC Formant Estimation** — acoustic phonetics
- **Audio Enhancement** — HPSS harmonic/percussive separation
- **Transcription** — OpenAI Whisper ASR

---

**Made for digital forensics professionals, researchers, and investigators.**
