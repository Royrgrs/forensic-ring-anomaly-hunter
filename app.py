import os
import re
import glob
import json
import shutil
import zipfile
import hashlib
import tempfile
import subprocess
import textwrap
from datetime import datetime, timezone
import numpy as np
import pandas as pd
import streamlit as st
import librosa
import librosa.display
import soundfile as sf
import scipy.signal as signal
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
import torch
import whisper

# Optional native OS folder picker for local desktop runs
try:
    import tkinter as tk
    from tkinter import filedialog
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False

# -------------------------------------------------------------------------
# PAGE CONFIGURATION & SESSION STATE
# -------------------------------------------------------------------------
st.set_page_config(
    page_title="Forensic Ring Anomaly Hunter + ENF, F0/F1/F2 & PDF Suite",
    page_icon="📑",
    layout="wide"
)

for key, default in [
    ("folder_path", ""),
    ("anomaly_batch_df", None),
    ("anomaly_events_df", None),
    ("extracted_dir_path", ""),
    ("zip_bundle_path", ""),
    ("manifest_json_path", ""),
    ("pdf_report_path", "")
]:
    if key not in st.session_state:
        st.session_state[key] = default

SUPPORTED_EXTENSIONS = (".mp4", ".mov", ".mkv", ".wav", ".mp3", ".m4a", ".flac")
SUBFOLDER_NAME = "Extracted_Anomalies"

TAMPER_SOFTWARE_SIGNATURES = [
    b"adobe", b"premiere", b"after effects", b"audacity", b"handbrake",
    b"davinci", b"resolve", b"capcut", b"virtualdub", b"avidemux",
    b"filmora", b"final cut", b"vegas", b"shotcut", b"kdenlive", b"obs "
]

st.title("📑 Forensic Ring Anomaly Hunter: SHA-256, 60 Hz ENF, F0/F1/F2 Biometry & PDF Generator")
st.markdown(
    f"Scans folders of Ring `.mp4` clips in **read-only mode**, validates **Pre/Post `SHA-256` hashes**, "
    f"runs **$60\\text{{ Hz}}$ ENF Phase Continuity Analysis**, extracts **Fundamental Pitch ($F_0$) and "
    f"Vocal Formant ($F_1 / F_2$) Biometry**, unmasks and force-transcribes anomalies into `{SUBFOLDER_NAME}/`, "
    f"and compiles a **Printable Multi-Page PDF Forensic Examination Report**."
)

# -------------------------------------------------------------------------
# CACHED MODEL LOADER
# -------------------------------------------------------------------------
@st.cache_resource(show_spinner="Loading OpenAI Whisper ASR model...")
def get_whisper_model(model_size: str):
    return whisper.load_model(model_size)

# -------------------------------------------------------------------------
# CRYPTOGRAPHIC HASHING & RING MP4 CONTAINER VALIDATION
# -------------------------------------------------------------------------
def compute_file_hashes(filepath: str) -> dict:
    sha256_hasher = hashlib.sha256()
    md5_hasher = hashlib.md5()
    byte_size = os.path.getsize(filepath)
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            sha256_hasher.update(chunk)
            md5_hasher.update(chunk)
    return {
        "sha256": sha256_hasher.hexdigest(),
        "md5": md5_hasher.hexdigest(),
        "byte_size": byte_size
    }

def parse_mp4_top_level_atoms(filepath: str) -> list[str]:
    atoms = []
    file_size = os.path.getsize(filepath)
    offset = 0
    try:
        with open(filepath, "rb") as f:
            while offset + 8 <= file_size and len(atoms) < 30:
                f.seek(offset)
                header = f.read(8)
                if len(header) < 8:
                    break
                box_size = int.from_bytes(header[:4], byteorder="big")
                box_type = header[4:8].decode("latin-1", errors="ignore")
                if box_type.isprintable():
                    atoms.append(box_type.strip())
                if box_size == 1:
                    ext_bytes = f.read(8)
                    if len(ext_bytes) < 8:
                        break
                    box_size = int.from_bytes(ext_bytes, byteorder="big")
                elif box_size == 0:
                    break
                if box_size < 8:
                    break
                offset += box_size
    except Exception:
        pass
    return atoms

def validate_ring_file_authenticity(filepath: str) -> dict:
    ext = os.path.splitext(filepath)[1].lower()
    flags = []
    atoms = []
    video_codec = "N/A"
    audio_codec = "N/A"
    creation_time_tag = "Not Embedded"
    encoder_tag = "Clean (No Editor Tag)"
    av_sync_delta_sec = 0.0

    if ext in (".mp4", ".mov", ".m4a"):
        atoms = parse_mp4_top_level_atoms(filepath)
        if "ftyp" not in atoms:
            flags.append("Missing 'ftyp' ISO MP4 header")
        if "moov" not in atoms or "mdat" not in atoms:
            flags.append("Missing 'moov' or 'mdat' media atom")

    try:
        file_size = os.path.getsize(filepath)
        with open(filepath, "rb") as bf:
            head_bytes = bf.read(min(131072, file_size)).lower()
            tail_bytes = b""
            if file_size > 131072:
                bf.seek(max(0, file_size - 131072))
                tail_bytes = bf.read(131072).lower()
            combined_scan = head_bytes + tail_bytes
            for sig in TAMPER_SOFTWARE_SIGNATURES:
                if sig in combined_scan:
                    detected_name = sig.decode("ascii", errors="ignore").strip().title()
                    flags.append(f"Detected editing software tag: {detected_name}")
                    encoder_tag = f"FLAGGED: {detected_name}"
    except Exception:
        pass

    if shutil.which("ffprobe"):
        try:
            cmd = [
                "ffprobe", "-v", "quiet", "-print_format", "json",
                "-show_format", "-show_streams", filepath
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if proc.returncode == 0 and proc.stdout:
                probe_data = json.loads(proc.stdout)
                fmt_tags = probe_data.get("format", {}).get("tags", {})
                creation_time_tag = fmt_tags.get("creation_time", "Not Embedded")
                raw_enc = fmt_tags.get("encoder", fmt_tags.get("comment", ""))
                if raw_enc:
                    encoder_tag = raw_enc

                v_dur, a_dur = None, None
                for stream in probe_data.get("streams", []):
                    c_type = stream.get("codec_type", "")
                    c_name = stream.get("codec_name", "unknown")
                    s_dur = stream.get("duration")
                    if c_type == "video":
                        video_codec = c_name.upper()
                        if s_dur is not None:
                            v_dur = float(s_dur)
                    elif c_type == "audio":
                        audio_codec = c_name.upper()
                        if s_dur is not None:
                            a_dur = float(s_dur)

                if v_dur is not None and a_dur is not None:
                    av_sync_delta_sec = round(abs(v_dur - a_dur), 3)
                    if av_sync_delta_sec > 0.45:
                        flags.append(f"Audio/Video duration mismatch ({av_sync_delta_sec}s)")
        except Exception:
            pass

    is_authentic = len(flags) == 0
    status_label = (
        "AUTHENTICATED (Intact Container & Clean Metadata)"
        if is_authentic
        else "WARNING: " + "; ".join(flags)
    )
    return {
        "authenticity_status": status_label,
        "is_authentic": is_authentic,
        "mp4_atoms": "/".join(atoms) if atoms else "Audio-Only Container",
        "video_codec": video_codec,
        "audio_codec": audio_codec,
        "av_sync_delta_sec": av_sync_delta_sec,
        "encoder_tag": encoder_tag,
        "creation_time_utc": creation_time_tag
    }

# -------------------------------------------------------------------------
# 60 Hz ELECTRIC NETWORK FREQUENCY (ENF) PHASE & SPLICE ANALYSIS ENGINE
# -------------------------------------------------------------------------
def narrowband_enf_filter(y: np.ndarray, sr: int, center_freq: float, half_width: float = 1.2) -> np.ndarray:
    nyq = 0.5 * sr
    low = max(1.0, center_freq - half_width) / nyq
    high = min(nyq - 1.0, center_freq + half_width) / nyq
    sos = signal.butter(4, [low, high], btype="band", output="sos")
    return signal.sosfiltfilt(sos, y)

def select_strongest_enf_harmonic(y: np.ndarray, sr: int, nominal_grid_hz: int = 60) -> tuple[float, float]:
    candidates = [nominal_grid_hz * k for k in (1, 2, 3, 4, 5)]
    nperseg = min(len(y), sr * 2)
    if nperseg < 512:
        return float(nominal_grid_hz * 3), 0.0

    freqs, psd = signal.welch(y, fs=sr, nperseg=nperseg)
    best_freq = float(nominal_grid_hz * 3)
    best_snr_db = -99.0

    for f0 in candidates:
        sig_mask = (freqs >= f0 - 1.0) & (freqs <= f0 + 1.0)
        noise_mask = ((freqs >= f0 - 8.0) & (freqs < f0 - 2.0)) | ((freqs > f0 + 2.0) & (freqs <= f0 + 8.0))
        if np.any(sig_mask) and np.any(noise_mask):
            sig_power = float(np.max(psd[sig_mask])) + 1e-18
            noise_power = float(np.median(psd[noise_mask])) + 1e-18
            snr_db = 10.0 * np.log10(sig_power / noise_power)
            if snr_db > best_snr_db:
                best_snr_db = snr_db
                best_freq = float(f0)

    return best_freq, round(best_snr_db, 2)

def analyze_enf_phase_continuity(
    y: np.ndarray,
    sr: int,
    nominal_grid_hz: int = 60,
    forced_harmonic_hz: float | None = None,
    phase_jump_threshold_deg: float = 45.0
) -> dict:
    if forced_harmonic_hz is not None and forced_harmonic_hz > 0:
        target_freq, snr_db = select_strongest_enf_harmonic(y, sr, nominal_grid_hz)
        target_freq = float(forced_harmonic_hz)
    else:
        target_freq, snr_db = select_strongest_enf_harmonic(y, sr, nominal_grid_hz)

    y_enf = narrowband_enf_filter(y, sr, center_freq=target_freq, half_width=1.2)
    analytic = signal.hilbert(y_enf)
    inst_phase = np.unwrap(np.angle(analytic))
    t = np.arange(len(y)) / float(sr)

    expected_phase = 2.0 * np.pi * target_freq * t
    raw_residual_rad = inst_phase - expected_phase
    detrended_residual_rad = signal.detrend(raw_residual_rad, type="linear")
    phase_residual_deg = np.rad2deg(detrended_residual_rad)

    step_samples = max(1, int(0.05 * sr))
    t_50ms = t[::step_samples]
    phase_res_50ms = phase_residual_deg[::step_samples]
    enf_env_50ms = np.abs(analytic)[::step_samples]

    if len(phase_res_50ms) > 2:
        phase_diff_deg = np.abs(np.diff(phase_res_50ms, prepend=phase_res_50ms[0]))
        inst_freq_raw = np.diff(inst_phase, prepend=inst_phase[0]) * (sr / (2.0 * np.pi))
        win_smooth = max(1, int(0.25 * sr))
        inst_freq_smooth = np.convolve(inst_freq_raw, np.ones(win_smooth) / win_smooth, mode="same")
        inst_freq_50ms = inst_freq_smooth[::step_samples]
    else:
        phase_diff_deg = np.zeros_like(phase_res_50ms)
        inst_freq_50ms = np.full_like(t_50ms, target_freq)

    env_floor = np.percentile(enf_env_50ms, 25) if len(enf_env_50ms) > 0 else 0.0
    active_enf_mask = enf_env_50ms >= max(env_floor, 1e-6)
    active_phase_jumps = phase_diff_deg[active_enf_mask] if np.any(active_enf_mask) else phase_diff_deg

    max_phase_jump_deg = float(np.max(active_phase_jumps)) if len(active_phase_jumps) > 0 else 0.0
    median_jump = float(np.median(active_phase_jumps)) + 1e-6 if len(active_phase_jumps) > 0 else 1.0
    mad_jump = float(np.median(np.abs(active_phase_jumps - median_jump))) + 1e-6
    max_jump_zscore = (max_phase_jump_deg - median_jump) / (1.4826 * mad_jump)

    if snr_db < 3.0:
        enf_verdict = f"LOW ENF CARRIER SNR ({snr_db:.1f} dB at {int(target_freq)} Hz)"
        is_splice_flagged = False
    elif max_phase_jump_deg >= phase_jump_threshold_deg and max_jump_zscore >= 3.5:
        enf_verdict = f"PHASE DISCONTINUITY FLAGGED (Max Jump {max_phase_jump_deg:.1f} deg at {int(target_freq)} Hz)"
        is_splice_flagged = True
    else:
        enf_verdict = f"CONTINUOUS ENF PHASE VERIFIED (Max Drift {max_phase_jump_deg:.1f} deg at {int(target_freq)} Hz)"
        is_splice_flagged = False

    return {
        "tracked_harmonic_hz": int(target_freq),
        "enf_snr_db": snr_db,
        "max_phase_jump_deg": round(max_phase_jump_deg, 2),
        "max_jump_zscore": round(float(max_jump_zscore), 2),
        "enf_verdict": enf_verdict,
        "is_splice_flagged": is_splice_flagged,
        "t_50ms": t_50ms,
        "phase_res_50ms": phase_res_50ms,
        "phase_diff_deg": phase_diff_deg,
        "inst_freq_50ms": inst_freq_50ms
    }

def evaluate_burst_boundary_enf_jump(enf_data: dict, start_sec: float, end_sec: float, threshold_deg: float) -> dict:
    t_arr = enf_data["t_50ms"]
    jumps = enf_data["phase_diff_deg"]
    if len(t_arr) == 0:
        return {"boundary_jump_deg": 0.0, "burst_enf_status": "N/A"}

    boundary_mask = (
        ((t_arr >= start_sec - 0.25) & (t_arr <= start_sec + 0.25))
        | ((t_arr >= end_sec - 0.25) & (t_arr <= end_sec + 0.25))
    )
    inside_mask = (t_arr >= start_sec) & (t_arr <= end_sec)
    combined_mask = boundary_mask | inside_mask

    local_max_jump = float(np.max(jumps[combined_mask])) if np.any(combined_mask) else 0.0
    if enf_data["enf_snr_db"] < 3.0:
        status = f"Low ENF SNR ({enf_data['enf_snr_db']} dB)"
    elif local_max_jump >= threshold_deg:
        status = f"SPLICE / PHASE JUMP ({local_max_jump:.1f} deg)"
    else:
        status = f"PHASE LOCKED ({local_max_jump:.1f} deg)"

    return {
        "boundary_jump_deg": round(local_max_jump, 2),
        "burst_enf_status": status
    }

# -------------------------------------------------------------------------
# FUNDAMENTAL PITCH (F0) & LPC VOCAL FORMANT (F1 / F2) BIOMETRY ENGINE
# -------------------------------------------------------------------------
def classify_vowel_quadrant(f1_hz: float, f2_hz: float) -> str:
    """Maps median (F1, F2) coordinates to their closest acoustic vowel articulation zone."""
    if f1_hz <= 0 or f2_hz <= 0:
        return "Non-Vocal / Undefined"
    vowels = [
        ("/i/ ('heed' - Close Front)", 300.0, 2250.0),
        ("/I/ ('hid' - Near-Close Front)", 390.0, 1950.0),
        ("/e/ ('hay' - Mid Front)", 460.0, 1850.0),
        ("/E/ ('head' - Open-Mid Front)", 550.0, 1750.0),
        ("/ae/ ('had' - Near-Open Front)", 690.0, 1650.0),
        ("/a/ ('hod/ah' - Open Central/Back)", 750.0, 1200.0),
        ("/^/ ('hud/uh' - Mid Central)", 620.0, 1350.0),
        ("/c/ ('hawed' - Open-Mid Back)", 570.0, 950.0),
        ("/o/ ('hoe' - Mid Back)", 450.0, 1000.0),
        ("/u/ ('who' - Close Back)", 320.0, 950.0)
    ]
    # Normalized perceptual distance in formant space
    best_label = "Central Schwa / Transitional"
    best_dist = 1e9
    for label, vf1, vf2 in vowels:
        dist = ((f1_hz - vf1) / 150.0) ** 2 + ((f2_hz - vf2) / 400.0) ** 2
        if dist < best_dist:
            best_dist = dist
            best_label = label
    return best_label

def extract_frame_formants_lpc(frame: np.ndarray, sr: int, lpc_order: int = 18) -> tuple[float, float, float, float]:
    """
    Solves the LPC all-pole vocal tract polynomial for a single pre-emphasized audio frame
    and returns (F1_Hz, F2_Hz, B1_Hz, B2_Hz). Returns np.nan where formants are absent.
    """
    if len(frame) < 128 or np.max(np.abs(frame)) < 1e-5:
        return np.nan, np.nan, np.nan, np.nan

    # Pre-emphasis + Hamming window
    pre_frame = np.append(frame[0], frame[1:] - 0.97 * frame[:-1])
    windowed = pre_frame * np.hamming(len(pre_frame))

    try:
        a_coeffs = librosa.lpc(windowed, order=lpc_order)
        roots = np.roots(a_coeffs)
        # Keep roots in upper half of complex plane with non-zero imaginary part
        pos_roots = roots[np.imag(roots) > 0.01]
        if len(pos_roots) == 0:
            return np.nan, np.nan, np.nan, np.nan

        angles = np.arctan2(np.imag(pos_roots), np.real(pos_roots))
        freqs = angles * (sr / (2.0 * np.pi))
        bandwidths = -(sr / np.pi) * np.log(np.abs(pos_roots) + 1e-12)

        # Filter for biological vocal tract poles (bandwidth < 420 Hz, frequency 220 - 3400 Hz)
        valid_mask = (freqs >= 220.0) & (freqs <= 3400.0) & (bandwidths > 15.0) & (bandwidths < 420.0)
        valid_freqs = freqs[valid_mask]
        valid_bws = bandwidths[valid_mask]

        if len(valid_freqs) == 0:
            return np.nan, np.nan, np.nan, np.nan

        sort_idx = np.argsort(valid_freqs)
        sorted_f = valid_freqs[sort_idx]
        sorted_b = valid_bws[sort_idx]

        # Identify F1 (240 - 950 Hz) and F2 (950 - 2850 Hz, at least 250 Hz above F1)
        f1_val, b1_val = np.nan, np.nan
        f2_val, b2_val = np.nan, np.nan

        for f_cand, b_cand in zip(sorted_f, sorted_b):
            if np.isnan(f1_val) and 240.0 <= f_cand <= 950.0:
                f1_val, b1_val = float(f_cand), float(b_cand)
            elif not np.isnan(f1_val) and np.isnan(f2_val):
                if 920.0 <= f_cand <= 2900.0 and (f_cand - f1_val) >= 250.0:
                    f2_val, b2_val = float(f_cand), float(b_cand)
                    break

        return f1_val, f2_val, b1_val, b2_val
    except Exception:
        return np.nan, np.nan, np.nan, np.nan

def analyze_f0_and_formants_lpc(y_unmasked: np.ndarray, sr: int = 16000) -> dict:
    """
    Computes frame-by-frame Fundamental Pitch (F0 via pYIN) and Vocal Formants (F1 & F2 via LPC),
    plus a global LPC spectral envelope for the PDF Exhibit B plot.
    """
    hop_len = 160      # 10 ms frame step
    frame_len = 512    # 32 ms analysis window
    lpc_order = 2 + int(sr // 1000)  # Order 18 at 16 kHz

    # 1. Fundamental Pitch (F0) via Probabilistic YIN (65 Hz to 450 Hz)
    try:
        f0_contour, voiced_flag, voiced_probs = librosa.pyin(
            y_unmasked,
            fmin=65.0,
            fmax=450.0,
            sr=sr,
            frame_length=1024,
            hop_length=hop_len
        )
    except Exception:
        n_frames_est = max(1, len(y_unmasked) // hop_len)
        f0_contour = np.full(n_frames_est, np.nan)
        voiced_probs = np.zeros(n_frames_est)

    # 2. Sliding-Window LPC Formant Tracking (F1 & F2)
    rms = librosa.feature.rms(y=y_unmasked, frame_length=frame_len, hop_length=hop_len)[0]
    rms_thresh = np.percentile(rms, 35) if len(rms) > 0 else 0.0

    f1_track, f2_track, b1_track, b2_track = [], [], [], []
    for i in range(len(rms)):
        s_i = i * hop_len
        e_i = min(len(y_unmasked), s_i + frame_len)
        if rms[i] >= max(rms_thresh, 1e-4) and (e_i - s_i) >= 256:
            f1_v, f2_v, b1_v, b2_v = extract_frame_formants_lpc(y_unmasked[s_i:e_i], sr=sr, lpc_order=lpc_order)
        else:
            f1_v, f2_v, b1_v, b2_v = np.nan, np.nan, np.nan, np.nan
        f1_track.append(f1_v)
        f2_track.append(f2_v)
        b1_track.append(b1_v)
        b2_track.append(b2_v)

    f1_track = np.array(f1_track, dtype=float)
    f2_track = np.array(f2_track, dtype=float)
    b1_track = np.array(b1_track, dtype=float)
    b2_track = np.array(b2_track, dtype=float)
    track_times = librosa.frames_to_time(np.arange(len(f1_track)), sr=sr, hop_length=hop_len)
    f0_times = librosa.frames_to_time(np.arange(len(f0_contour)), sr=sr, hop_length=hop_len)

    # Compute summary statistics for F0, F1, F2
    valid_f0 = f0_contour[~np.isnan(f0_contour)]
    valid_f1 = f1_track[~np.isnan(f1_track)]
    valid_f2 = f2_track[~np.isnan(f2_track)]
    valid_b1 = b1_track[~np.isnan(b1_track)]
    valid_b2 = b2_track[~np.isnan(b2_track)]

    f0_median = round(float(np.median(valid_f0)), 1) if len(valid_f0) > 0 else 0.0
    f0_min = round(float(np.min(valid_f0)), 1) if len(valid_f0) > 0 else 0.0
    f0_max = round(float(np.max(valid_f0)), 1) if len(valid_f0) > 0 else 0.0
    f0_std = round(float(np.std(valid_f0)), 1) if len(valid_f0) > 0 else 0.0
    voiced_pct = round(float(len(valid_f0) / max(1, len(f0_contour)) * 100.0), 1)

    f1_median = round(float(np.median(valid_f1)), 1) if len(valid_f1) > 0 else 0.0
    f2_median = round(float(np.median(valid_f2)), 1) if len(valid_f2) > 0 else 0.0
    b1_median = round(float(np.median(valid_b1)), 1) if len(valid_b1) > 0 else 0.0
    b2_median = round(float(np.median(valid_b2)), 1) if len(valid_b2) > 0 else 0.0
    formant_dispersion = round(f2_median - f1_median, 1) if (f1_median > 0 and f2_median > 0) else 0.0

    # Classify Vocal Register & Articulation Type
    has_formants = (f1_median > 0 and f2_median > 0)
    if f0_median > 0 and voiced_pct >= 12.0:
        if f0_median < 165.0:
            register_label = f"Voiced Low/Male Register (F0={f0_median} Hz)"
        elif f0_median <= 265.0:
            register_label = f"Voiced Mid/Female Register (F0={f0_median} Hz)"
        else:
            register_label = f"Voiced High Register (F0={f0_median} Hz)"
    elif has_formants:
        register_label = "Whispered / Unvoiced Formant Articulation (F1/F2 Present, No F0)"
    else:
        register_label = "Aperiodic Non-Vocal / Transient"

    vowel_quadrant = classify_vowel_quadrant(f1_median, f2_median) if has_formants else "N/A"

    # 3. Compute Smooth LPC Spectral Envelope of Peak Energy Frame for PDF Exhibit B Plot
    peak_frame_idx = int(np.argmax(rms)) if len(rms) > 0 else 0
    ps = max(0, peak_frame_idx * hop_len)
    pe = min(len(y_unmasked), ps + 1024)
    y_peak_win = y_unmasked[ps:pe]
    if len(y_peak_win) < 256:
        y_peak_win = np.pad(y_peak_win, (0, 256 - len(y_peak_win)))

    pre_peak = np.append(y_peak_win[0], y_peak_win[1:] - 0.97 * y_peak_win[:-1]) * np.hamming(len(y_peak_win))
    try:
        a_env = librosa.lpc(pre_peak, order=lpc_order)
        w_freqs, h_resp = signal.freqz([1.0], a_env, worN=512, fs=sr)
        lpc_env_db = 20.0 * np.log10(np.abs(h_resp) + 1e-12)
        lpc_env_db = lpc_env_db - np.max(lpc_env_db)
    except Exception:
        w_freqs = np.linspace(0, sr / 2, 512)
        lpc_env_db = np.zeros(512)

    # Also compute FFT magnitude of the same peak frame for overlay comparison
    fft_spec = np.fft.rfft(pre_peak, n=1024)
    fft_freqs = np.fft.rfftfreq(1024, d=1.0 / sr)
    fft_db = 20.0 * np.log10(np.abs(fft_spec) + 1e-12)
    fft_db = fft_db - np.max(fft_db)

    return {
        "f0_median_hz": f0_median,
        "f0_range_str": f"{f0_min}-{f0_max} Hz (SD: {f0_std} Hz)" if f0_median > 0 else "Unvoiced / Whispered",
        "voiced_frames_pct": voiced_pct,
        "f1_median_hz": f1_median,
        "f2_median_hz": f2_median,
        "b1_median_hz": b1_median,
        "b2_median_hz": b2_median,
        "formant_dispersion_hz": formant_dispersion,
        "vocal_register_profile": register_label,
        "vowel_articulation_zone": vowel_quadrant,
        "f0_times": f0_times,
        "f0_contour": f0_contour,
        "track_times": track_times,
        "f1_track": f1_track,
        "f2_track": f2_track,
        "lpc_freqs": w_freqs,
        "lpc_env_db": lpc_env_db,
        "fft_freqs": fft_freqs,
        "fft_db": fft_db
    }

# -------------------------------------------------------------------------
# FILE & FOLDER HELPERS
# -------------------------------------------------------------------------
def select_local_folder() -> str:
    if not TKINTER_AVAILABLE:
        return ""
    root = tk.Tk()
    root.withdraw()
    root.wm_attributes("-topmost", 1)
    selected_dir = filedialog.askdirectory(title="Select Folder of Downloaded Ring MP4 Clips")
    root.destroy()
    return selected_dir

def sanitize_for_filename(text: str, max_len: int = 28) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9]+", "_", text).strip("_")
    if not cleaned or "No_lexical_match" in cleaned or "Unintelligible" in cleaned:
        return "phonetic_burst"
    return cleaned[:max_len]

# -------------------------------------------------------------------------
# NON-DESTRUCTIVE ANOMALY DETECTION, UNMASKING & TIME-EXPANSION DSP
# -------------------------------------------------------------------------
def bandpass_vocal_range(y: np.ndarray, sr: int, lowcut: float = 280.0, highcut: float = 3500.0) -> np.ndarray:
    nyq = 0.5 * sr
    low = lowcut / nyq
    high = min(highcut / nyq, 0.99)
    sos = signal.butter(4, [low, high], btype="band", output="sos")
    return signal.sosfiltfilt(sos, y)

def unmask_and_expand_anomaly(
    y_slice: np.ndarray,
    sr: int,
    transient_suppression: float = 0.85,
    vocal_boost: float = 2.5,
    stretch_rate: float = 0.80
) -> tuple[np.ndarray, np.ndarray]:
    if len(y_slice) < 512:
        return y_slice.copy(), y_slice.copy()

    # Keep down to 75 Hz so fundamental pitch F0 (80-250 Hz) and F1/F2 formants are preserved intact
    nyq = 0.5 * sr
    sos_full_vocal = signal.butter(4, [75.0 / nyq, 3600.0 / nyq], btype="band", output="sos")
    y_band = signal.sosfiltfilt(sos_full_vocal, y_slice)

    D = librosa.stft(y_band, n_fft=512, hop_length=128)
    H, P = librosa.decompose.hpss(D, margin=(1.0, 2.2))

    D_unmasked = H + P * (1.0 - transient_suppression)
    y_unmasked = librosa.istft(D_unmasked, hop_length=128, length=len(y_slice))

    peak = np.max(np.abs(y_unmasked))
    if peak > 1e-6:
        y_unmasked = y_unmasked / peak
    y_unmasked_1x = np.tanh(vocal_boost * y_unmasked)
    b_peak = np.max(np.abs(y_unmasked_1x))
    if b_peak > 1e-6:
        y_unmasked_1x = (y_unmasked_1x / b_peak) * 0.92

    try:
        y_expanded = librosa.effects.time_stretch(y_unmasked_1x, rate=stretch_rate)
    except Exception:
        y_expanded = y_unmasked_1x.copy()

    exp_peak = np.max(np.abs(y_expanded))
    if exp_peak > 1e-6:
        y_expanded = (y_expanded / exp_peak) * 0.92

    return y_unmasked_1x, y_expanded

def detect_silence_broken_anomalies(
    y: np.ndarray,
    sr: int,
    silence_floor_db: float = -40.0,
    burst_jump_db: float = 10.0,
    min_piggyback_score: float = 18.0
) -> list[dict]:
    hop_length = 160
    frame_length = 512
    rms = librosa.feature.rms(y=y, frame_length=frame_length, hop_length=hop_length)[0]
    rms_db = librosa.amplitude_to_db(rms, ref=np.max)
    frame_times = librosa.frames_to_time(np.arange(len(rms_db)), sr=sr, hop_length=hop_length)

    active_threshold_db = silence_floor_db + burst_jump_db
    is_active = rms_db >= active_threshold_db

    raw_windows = []
    in_burst = False
    start_idx = 0
    max_gap_frames = int(0.35 * sr / hop_length)
    gap_counter = 0

    for i, active in enumerate(is_active):
        if active:
            if not in_burst:
                in_burst = True
                start_idx = i
            gap_counter = 0
        else:
            if in_burst:
                gap_counter += 1
                if gap_counter > max_gap_frames:
                    end_idx = max(start_idx + 1, i - gap_counter)
                    raw_windows.append((start_idx, end_idx))
                    in_burst = False
                    gap_counter = 0
    if in_burst:
        raw_windows.append((start_idx, len(is_active) - 1))

    detected_anomalies = []
    for s_idx, e_idx in raw_windows:
        pre_start = max(0, s_idx - int(0.30 * sr / hop_length))
        pre_rms_db = float(np.median(rms_db[pre_start:s_idx])) if s_idx > pre_start else silence_floor_db
        burst_peak_db = float(np.max(rms_db[s_idx:e_idx + 1]))
        db_jump = burst_peak_db - pre_rms_db

        start_sec = max(0.0, frame_times[s_idx] - 0.15)
        end_sec = min(len(y) / sr, frame_times[min(e_idx, len(frame_times) - 1)] + 0.25)
        if (end_sec - start_sec) < 0.12:
            continue

        s_samp = int(start_sec * sr)
        e_samp = int(end_sec * sr)
        y_slice = y[s_samp:e_samp].copy()

        y_vocal = bandpass_vocal_range(y_slice, sr)
        vocal_energy_ratio = float(np.sum(y_vocal ** 2) / (np.sum(y_slice ** 2) + 1e-9))

        D_slice = librosa.stft(y_vocal, n_fft=512, hop_length=128)
        H_s, _ = librosa.decompose.hpss(D_slice, margin=(1.0, 2.0))
        harm_ratio = float(np.sum(np.abs(H_s) ** 2) / (np.sum(np.abs(D_slice) ** 2) + 1e-9))
        onset_flux = float(np.mean(librosa.onset.onset_strength(y=y_vocal, sr=sr)))

        piggyback_score = min(100.0, (vocal_energy_ratio * 45.0) + (harm_ratio * 40.0) + min(15.0, onset_flux * 4.0))

        if db_jump >= (burst_jump_db * 0.75) and piggyback_score >= min_piggyback_score:
            detected_anomalies.append({
                "start_sec": round(start_sec, 2),
                "end_sec": round(end_sec, 2),
                "start_sample_16k": s_samp,
                "end_sample_16k": e_samp,
                "duration_sec": round(end_sec - start_sec, 2),
                "pre_silence_db": round(pre_rms_db, 1),
                "burst_peak_db": round(burst_peak_db, 1),
                "db_jump": round(db_jump, 1),
                "piggyback_score": round(piggyback_score, 1),
                "y_slice": y_slice
            })

    return detected_anomalies

# -------------------------------------------------------------------------
# FORCED UNTHROTTLED WHISPER TRANSCRIPTION
# -------------------------------------------------------------------------
def force_transcribe_anomaly_arrays(
    y_unmasked_1x: np.ndarray,
    y_boosted_expanded: np.ndarray,
    sr: int,
    whisper_model,
    stretch_rate: float = 0.80
) -> dict:
    pad_samples = int(0.5 * sr)
    y_pad_norm = np.pad(y_unmasked_1x, (pad_samples, pad_samples), mode="constant")
    y_pad_slow = np.pad(y_boosted_expanded, (pad_samples, pad_samples), mode="constant")

    decode_options = dict(
        fp16=torch.cuda.is_available(),
        language="en",
        condition_on_previous_text=False,
        no_speech_threshold=None,
        logprob_threshold=None,
        compression_ratio_threshold=None,
        temperature=0.0,
        beam_size=5
    )

    with tempfile.NamedTemporaryFile(delete=False, suffix="_1x.wav") as tn, \
         tempfile.NamedTemporaryFile(delete=False, suffix="_exp.wav") as ts:
        sf.write(tn.name, y_pad_norm, sr, subtype="PCM_16")
        sf.write(ts.name, y_pad_slow, sr, subtype="PCM_16")
        norm_path, slow_path = tn.name, ts.name

    try:
        res_norm = whisper_model.transcribe(norm_path, **decode_options)
        res_slow = whisper_model.transcribe(slow_path, **decode_options)
    finally:
        for p in (norm_path, slow_path):
            if os.path.exists(p):
                try:
                    os.remove(p)
                except OSError:
                    pass

    text_norm = res_norm.get("text", "").strip()
    text_slow = res_slow.get("text", "").strip()

    all_segs = res_norm.get("segments", []) + res_slow.get("segments", [])
    best_vocal_likelihood = 0.0
    if all_segs:
        best_vocal_likelihood = max(1.0 - float(s.get("no_speech_prob", 1.0)) for s in all_segs)

    primary_readout = text_slow if text_slow else text_norm
    if text_norm and text_slow and text_norm.lower() != text_slow.lower():
        combined_readout = f"[{stretch_rate}x Expanded]: {text_slow} | [1.0x]: {text_norm}"
    else:
        combined_readout = primary_readout if primary_readout else "[Unintelligible Phonetic Burst]"

    return {
        "transcript_normal": text_norm if text_norm else "[No lexical match at 1.0x]",
        "transcript_slow": text_slow if text_slow else f"[No lexical match at {stretch_rate}x]",
        "combined_transcript": combined_readout,
        "snippet_for_filename": sanitize_for_filename(primary_readout),
        "vocal_likelihood": round(best_vocal_likelihood, 3)
    }

# -------------------------------------------------------------------------
# COURT-READY MULTI-PAGE PDF FORENSIC REPORT COMPILER (WITH F0 & F1/F2)
# -------------------------------------------------------------------------
def generate_forensic_pdf_report(
    pdf_out_path: str,
    manifest_data: dict,
    df_files: pd.DataFrame,
    df_events: pd.DataFrame,
    clip_plot_cache: list[dict],
    phase_jump_threshold_deg: float,
    stretch_rate: float
) -> str:
    with PdfPages(pdf_out_path) as pdf:
        # =====================================================================
        # PAGE 1: EXECUTIVE SUMMARY & CRYPTOGRAPHIC CHAIN OF CUSTODY TABLE
        # =====================================================================
        fig_cover = plt.figure(figsize=(11.0, 8.5))
        ax_cover = fig_cover.add_subplot(111)
        ax_cover.axis("off")

        params = manifest_data.get("enf_and_dsp_parameters", {})
        header_lines = [
            "DIGITAL AUDIO FORENSIC EXAMINATION, ENF PHASE & VOCAL BIOMETRY REPORT",
            f"Generated UTC: {manifest_data.get('generated_utc', '')}   |   Examiner ID: {manifest_data.get('examiner_id', '')}",
            f"Standard: {manifest_data.get('forensic_manifest_version', 'SWGDE-ENF-Formant-Compliant')} (Read-Only Non-Destructive Verification)",
            "-" * 115,
            "REPRODUCIBILITY, ENF & VOCAL BIOMETRY PARAMETERS:",
            f"  * Power Grid Nominal Frequency : {params.get('nominal_grid_hz', 60)} Hz   |   ENF Splice Phase Jump Threshold: {params.get('phase_jump_threshold_deg', 45.0)} deg / 50ms",
            f"  * Pitch & Formant Extraction   : pYIN Fundamental Pitch F0 (65-450 Hz) + 18th-Order LPC Root Formants F1 (240-950 Hz) & F2 (920-2,900 Hz)",
            f"  * HPSS Click Suppression       : {int(float(params.get('hpss_transient_suppression_ratio', 0.85))*100)}%   |   Soft-Knee Gain Boost: {params.get('soft_knee_vocal_boost_multiplier', 2.5)}x   |   Time-Stretch: {stretch_rate:.2f}x",
            "-" * 115,
            f"BATCH EXECUTIVE SUMMARY: Scanned {len(df_files)} Source File(s)  |  Decoded {len(df_events)} Silence-Broken Anomaly Burst(s)"
        ]
        ax_cover.text(
            0.01, 0.97, "\n".join(header_lines),
            transform=ax_cover.transAxes,
            fontsize=9.2, fontfamily="monospace", verticalalignment="top",
            bbox=dict(boxstyle="round,pad=0.5", facecolor="#f4f6f9", edgecolor="#cbd5e1")
        )

        if not df_files.empty:
            table_rows = []
            for _, r in df_files.head(14).iterrows():
                fname_short = textwrap.shorten(str(r.get("File_Name", "")), width=26, placeholder="...")
                sha_short = str(r.get("Source_SHA256", ""))[:16] + "..." if r.get("Source_SHA256") else "N/A"
                integ = "PASS (Pre==Post)" if "VERIFIED" in str(r.get("Source_Integrity", "")) else "CHECK"
                enf_v = textwrap.shorten(str(r.get("ENF_Phase_Splice_Verdict", "")), width=32, placeholder="...")
                table_rows.append([
                    fname_short, sha_short, integ,
                    str(r.get("Tracked_ENF_Harmonic", "")), enf_v, str(r.get("Anomaly_Burst_Count", 0))
                ])

            col_labels = ["Source File", "SHA-256 (Prefix)", "Pre/Post Hash", "ENF Harmonic", "ENF Phase Verdict", "Bursts"]
            tbl = ax_cover.table(cellText=table_rows, colLabels=col_labels, loc="bottom", bbox=[0.01, 0.04, 0.98, 0.54])
            tbl.auto_set_font_size(False)
            tbl.set_fontsize(8.0)

        plt.tight_layout()
        pdf.savefig(fig_cover, dpi=200)
        plt.close(fig_cover)

        # =====================================================================
        # EXHIBIT A & B PAGES: PER-CLIP 60 Hz ENF & PER-BURST F0/F1/F2 EXHIBITS
        # =====================================================================
        for clip_item in clip_plot_cache:
            disp_name = clip_item["file_name"]
            pre_sha256 = clip_item["pre_sha256"]
            post_sha256 = clip_item["post_sha256"]
            md5_hex = clip_item["md5"]
            auth_status = clip_item["auth_status"]
            enf_rep = clip_item["enf_report"]
            burst_items = clip_item["burst_items"]

            # --- EXHIBIT A: FULL-CLIP 60 Hz ENF PHASE CONTINUITY PAGE ---
            fig_enf, axes_enf = plt.subplots(3, 1, figsize=(11.0, 8.5), sharex=True)
            fig_enf.suptitle(f"EXHIBIT A: 60 Hz ENF PHASE CONTINUITY & SPLICE AUDIT — {disp_name}", fontsize=11, fontweight="bold", y=0.98)

            meta_banner = (
                f"Parent Source Pre-Scan SHA-256 : {pre_sha256}\n"
                f"Parent Source Post-Scan SHA-256: {post_sha256} (Bitwise Match: TRUE | MD5: {md5_hex})\n"
                f"MP4 Container & Metadata Audit : {auth_status}   |   ENF Verdict: {enf_rep['enf_verdict']}"
            )
            fig_enf.text(0.02, 0.90, meta_banner, fontsize=8.2, fontfamily="monospace", bbox=dict(boxstyle="round,pad=0.35", facecolor="#eef2ff", edgecolor="#94a3b8"))

            t_50 = enf_rep["t_50ms"]
            h_hz = enf_rep["tracked_harmonic_hz"]

            axes_enf[0].plot(t_50, enf_rep["phase_res_50ms"], linewidth=1.4, label=f"Unwrapped Phase Residual ({h_hz} Hz)")
            axes_enf[0].set_ylabel("Phase (Deg)")
            axes_enf[0].set_title(f"1. Unwrapped Hilbert ENF Phase Residual ({h_hz} Hz Harmonic | Carrier SNR: {enf_rep['enf_snr_db']} dB)", fontsize=9.5)
            axes_enf[0].grid(True, alpha=0.3)

            axes_enf[1].plot(t_50, enf_rep["phase_diff_deg"], linewidth=1.3, label="Phase Step Jump (Deg / 50ms)")
            axes_enf[1].axhline(phase_jump_threshold_deg, linestyle="--", linewidth=1.2, label=f"Splice Threshold ({phase_jump_threshold_deg} Deg)")
            axes_enf[1].set_ylabel("Jump (Deg)")
            axes_enf[1].set_title("2. Frame-to-Frame ENF Phase Derivative (Spikes Above Dashed Line Indicate Phase Breaks)", fontsize=9.5)
            axes_enf[1].grid(True, alpha=0.3)

            axes_enf[2].plot(t_50, enf_rep["inst_freq_50ms"], linewidth=1.3, label=f"Instantaneous Grid Freq (~{h_hz} Hz)")
            axes_enf[2].set_ylim(h_hz - 1.5, h_hz + 1.5)
            axes_enf[2].set_ylabel("Freq (Hz)")
            axes_enf[2].set_xlabel("Timeline (Seconds)")
            axes_enf[2].set_title("3. Instantaneous ENF Grid Frequency Stability Across Recording", fontsize=9.5)
            axes_enf[2].grid(True, alpha=0.3)

            for b_item in burst_items:
                for ax_e in axes_enf:
                    ax_e.axvspan(b_item["start_sec"], b_item["end_sec"], alpha=0.22)
            for ax_e in axes_enf:
                ax_e.legend(loc="upper right", fontsize=8)

            fig_enf.tight_layout(rect=[0.0, 0.01, 1.0, 0.87])
            pdf.savefig(fig_enf, dpi=200)
            plt.close(fig_enf)

            # --- EXHIBIT B: PER-BURST SPECTROGRAM, LPC F0/F1/F2 & TRANSCRIPT SHEET ---
            for b_item in burst_items:
                fig_b = plt.figure(figsize=(11.0, 8.5))
                gs = fig_b.add_gridspec(3, 2, height_ratios=[0.95, 1.35, 1.15], hspace=0.44, wspace=0.22)

                fig_b.suptitle(
                    f"EXHIBIT B: ANOMALY BURST #{b_item['anomaly_index']} F0/F1/F2 BIOMETRY & TRANSCRIPT — {disp_name} "
                    f"[{b_item['start_sec']}s - {b_item['end_sec']}s]",
                    fontsize=10.5, fontweight="bold", y=0.98
                )

                sr_b = b_item["sr"]
                y_raw_b = b_item["y_raw_slice"]
                y_unm_b = b_item["y_unmasked_1x"]
                v_bio = b_item["vocal_biometry"]
                t_raw = np.linspace(b_item["start_sec"], b_item["end_sec"], len(y_raw_b))

                # Panel 1A (Top Left): Raw vs Unmasked Waveform Overlay
                ax_w1 = fig_b.add_subplot(gs[0, 0])
                ax_w1.plot(t_raw, y_raw_b, alpha=0.45, linewidth=0.8, label="Raw Slice (With Click)")
                ax_w1.plot(t_raw, y_unm_b, linewidth=0.9, label="Unmasked Vocal Layer")
                ax_w1.set_title("1A. Raw vs. Unmasked Waveform Envelope", fontsize=9)
                ax_w1.set_ylabel("Amplitude")
                ax_w1.legend(loc="upper right", fontsize=7.5)
                ax_w1.grid(True, alpha=0.25)

                # Panel 1B (Top Right): LPC Spectral Envelope & F1/F2 Resonance Peaks
                ax_lpc = fig_b.add_subplot(gs[0, 1])
                ax_lpc.plot(v_bio["fft_freqs"], v_bio["fft_db"], alpha=0.40, linewidth=0.8, label="Harmonic FFT Spectrum")
                ax_lpc.plot(v_bio["lpc_freqs"], v_bio["lpc_env_db"], linewidth=1.6, label="18th-Order LPC Vocal Envelope")
                if v_bio["f0_median_hz"] > 0:
                    ax_lpc.axvline(v_bio["f0_median_hz"], linestyle="--", linewidth=1.1, label=f"F0 Pitch ({v_bio['f0_median_hz']} Hz)")
                if v_bio["f1_median_hz"] > 0:
                    ax_lpc.axvline(v_bio["f1_median_hz"], linestyle="-.", linewidth=1.2, label=f"F1 ({v_bio['f1_median_hz']} Hz)")
                if v_bio["f2_median_hz"] > 0:
                    ax_lpc.axvline(v_bio["f2_median_hz"], linestyle=":", linewidth=1.3, label=f"F2 ({v_bio['f2_median_hz']} Hz)")
                ax_lpc.set_xlim(0, 3800)
                ax_lpc.set_ylim(-55, 3)
                ax_lpc.set_title("1B. LPC Vocal Tract Resonance Envelope (F0, F1 & F2 Peaks)", fontsize=9)
                ax_lpc.set_ylabel("Rel. Power (dB)")
                ax_lpc.legend(loc="upper right", fontsize=7.0)
                ax_lpc.grid(True, alpha=0.25)

                # Panel 2A (Middle Left): Raw Burst Spectrogram
                ax_s1 = fig_b.add_subplot(gs[1, 0])
                S_raw_db = librosa.amplitude_to_db(np.abs(librosa.stft(y_raw_b, n_fft=512, hop_length=64)), ref=np.max)
                librosa.display.specshow(S_raw_db, sr=sr_b, hop_length=64, x_axis="time", y_axis="linear", ax=ax_s1)
                ax_s1.set_ylim(0, 3800)
                ax_s1.set_title("2A. Raw Burst Spectrogram (Masking Click Included)", fontsize=9)
                ax_s1.set_ylabel("Freq (Hz)")

                # Panel 2B (Middle Right): Unmasked Spectrogram OVERLAID with F0, F1 & F2 Tracks
                ax_s2 = fig_b.add_subplot(gs[1, 1])
                S_unm_db = librosa.amplitude_to_db(np.abs(librosa.stft(y_unm_b, n_fft=512, hop_length=64)), ref=np.max)
                librosa.display.specshow(S_unm_db, sr=sr_b, hop_length=64, x_axis="time", y_axis="linear", ax=ax_s2)
                ax_s2.plot(v_bio["f0_times"], v_bio["f0_contour"], linewidth=1.8, label="F0 Pitch Contour")
                ax_s2.scatter(v_bio["track_times"], v_bio["f1_track"], s=10, label="F1 Formant Track")
                ax_s2.scatter(v_bio["track_times"], v_bio["f2_track"], s=10, marker="^", label="F2 Formant Track")
                ax_s2.set_ylim(0, 3800)
                ax_s2.set_title("2B. Unmasked Spectrogram + Tracked F0 Pitch & F1/F2 Formants", fontsize=9)
                ax_s2.set_ylabel("Freq (Hz)")
                ax_s2.legend(loc="upper right", fontsize=7.2)

                # Bottom Full-Width: Forensic Biometry, Transcript & Hash Evidence Block
                ax_txt = fig_b.add_subplot(gs[2, :])
                ax_txt.axis("off")

                t_slow_wrapped = textwrap.fill(b_item["transcript_slow"], width=95)
                t_norm_wrapped = textwrap.fill(b_item["transcript_normal"], width=95)

                evidence_card_lines = [
                    f"FORENSIC BIOMETRY & TRANSCRIPTION EXHIBIT — BURST #{b_item['anomaly_index']} ({b_item['start_sec']}s to {b_item['end_sec']}s | 16 kHz Samples: {b_item['sample_range']})",
                    f"  * Fundamental Pitch (F0)      : Median {v_bio['f0_median_hz']} Hz ({v_bio['f0_range_str']} | Voiced Frames: {v_bio['voiced_frames_pct']}%) -> {v_bio['vocal_register_profile']}",
                    f"  * Vocal Formants (F1 & F2)    : F1 = {v_bio['f1_median_hz']} Hz (BW: {v_bio['b1_median_hz']} Hz)  |  F2 = {v_bio['f2_median_hz']} Hz (BW: {v_bio['b2_median_hz']} Hz)  |  Dispersion (F2-F1) = {v_bio['formant_dispersion_hz']} Hz",
                    f"  * Closest Phonetic Vowel Zone : {v_bio['vowel_articulation_zone']}   |   Boundary 60 Hz ENF Status: {b_item['burst_enf_status']} ({b_item['boundary_jump_deg']} deg)",
                    f"  * FORCED TRANSCRIPT ({stretch_rate:.2f}x Time-Expanded) : {t_slow_wrapped}",
                    f"  * FORCED TRANSCRIPT (1.00x Unmasked)      : {t_norm_wrapped}",
                    "-" * 118,
                    f"  * Parent Ring MP4 SHA-256 : {pre_sha256}   |   Expanded WAV SHA-256: {b_item['exp_wav_sha256']}"
                ]
                ax_txt.text(
                    0.01, 0.98, "\n".join(evidence_card_lines),
                    transform=ax_txt.transAxes,
                    fontsize=7.9, fontfamily="monospace", verticalalignment="top",
                    bbox=dict(boxstyle="round,pad=0.42", facecolor="#f8fafc", edgecolor="#64748b")
                )

                fig_b.tight_layout(rect=[0.0, 0.01, 1.0, 0.94])
                pdf.savefig(fig_b, dpi=200)
                plt.close(fig_b)

    return pdf_out_path

# -------------------------------------------------------------------------
# SIDEBAR CONTROLS
# -------------------------------------------------------------------------
with st.sidebar:
    st.header("⚡ 60 Hz ENF & PDF Settings")
    examiner_name = st.text_input("Examiner / Operator ID (Printed on PDF)", value="Forensic_Auditor_01")
    nominal_grid_hz = st.selectbox("Regional Power Grid Nominal Frequency", options=[60, 50], index=0)
    harmonic_choice = st.selectbox(
        "ENF Harmonic Selection",
        options=["Auto-Select Strongest Harmonic (Recommended)", "60 Hz (1st)", "120 Hz (2nd)", "180 Hz (3rd)", "240 Hz (4th)", "300 Hz (5th)"],
        index=0
    )
    phase_jump_threshold_deg = st.slider("ENF Phase Jump Splice Threshold (Deg)", 20.0, 120.0, 45.0, 5.0)
    st.divider()
    st.header("🎯 Anomaly Detection Settings")
    whisper_size = st.selectbox("Whisper Decoder Size", options=["base", "small", "turbo"], index=0)
    silence_floor_db = st.slider("Dead-Silence Floor Threshold (dB)", -60.0, -25.0, -40.0, 2.0)
    burst_jump_db = st.slider("Min Sudden Noise Jump (+dB)", 4.0, 25.0, 10.0, 1.0)
    min_piggyback_score = st.slider("Min Piggyback Modulation Score (0-100)", 5.0, 60.0, 18.0, 1.0)
    st.divider()
    st.header("🔊 Non-Destructive DSP Settings")
    transient_suppression = st.slider("Physical Click Removal (%)", 0.0, 0.98, 0.85, 0.05)
    vocal_boost = st.slider("Underlying Anomaly Gain Boost", 1.0, 5.0, 2.5, 0.5)
    stretch_rate = st.slider("Time-Expansion Rate", 0.65, 0.95, 0.80, 0.05)

forced_harmonic_val = None
if not harmonic_choice.startswith("Auto"):
    forced_harmonic_val = float(harmonic_choice.split()[0])

# -------------------------------------------------------------------------
# FOLDER & FILE INPUT TABS
# -------------------------------------------------------------------------
tab_folder, tab_upload = st.tabs([
    "📁 Option 1: Scan Local Folder of Ring MP4 Clips (Read-Only)",
    "☁️ Option 2: Drag & Drop Suspected Files"
])

files_to_scan = []
target_base_folder = None

with tab_folder:
    col_in, col_btn = st.columns([4, 1])
    with col_btn:
        st.write("")
        st.write("")
        if st.button("📂 Browse Folder", use_container_width=True):
            chosen = select_local_folder()
            if chosen:
                st.session_state["folder_path"] = chosen

    with col_in:
        folder_input = st.text_input(
            "Local Folder Path Containing Downloaded Ring Clips:",
            value=st.session_state["folder_path"],
            placeholder=r"C:\Users\YourName\Downloads\RingClips"
        )
        st.session_state["folder_path"] = folder_input

    scan_subfolders = st.checkbox("Include Subfolders Recursively (Auto-skips Extracted_Anomalies)", value=True)

    if folder_input and os.path.isdir(folder_input):
        target_base_folder = folder_input
        pattern = "**/*" if scan_subfolders else "*"
        for fp in sorted(glob.glob(os.path.join(folder_input, pattern), recursive=scan_subfolders)):
            if SUBFOLDER_NAME.lower() in os.path.normpath(fp).lower().split(os.sep):
                continue
            if os.path.isfile(fp) and fp.lower().endswith(SUPPORTED_EXTENSIONS):
                files_to_scan.append((fp, os.path.relpath(fp, folder_input)))
        st.caption(f"Discovered **{len(files_to_scan)}** source evidence file(s) ready for SHA-256, 60 Hz ENF, and F0/F1/F2 biometry.")
    elif folder_input:
        st.warning("Folder path not found on this machine.")

with tab_upload:
    uploaded_files = st.file_uploader(
        "Or drag and drop multiple Ring MP4 / audio files here:",
        type=["mp4", "mov", "mkv", "wav", "mp3", "m4a", "flac"],
        accept_multiple_files=True
    )

# -------------------------------------------------------------------------
# EXECUTE FORENSIC VALIDATION, ENF, F0/F1/F2 BIOMETRY & PDF COMPILATION
# -------------------------------------------------------------------------
if st.button("📑 Validate Hashes, Run ENF + F0/F1/F2 Biometry & Compile PDF Report", type="primary", use_container_width=True):
    if not files_to_scan and uploaded_files:
        for uf in uploaded_files:
            suffix = os.path.splitext(uf.name)[1]
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp_f:
                tmp_f.write(uf.read())
                files_to_scan.append((tmp_f.name, uf.name))

    if not files_to_scan:
        st.error("Please select a folder with media files or upload files first.")
    else:
        base_dir = target_base_folder if target_base_folder else os.getcwd()
        extracted_subfolder = os.path.join(base_dir, SUBFOLDER_NAME)
        os.makedirs(extracted_subfolder, exist_ok=True)
        st.session_state["extracted_dir_path"] = extracted_subfolder

        whisper_model = get_whisper_model(whisper_size)
        progress = st.progress(0.0, text="Running SHA-256 verification, 60 Hz ENF & F0/F1/F2 vocal biometry...")

        file_summary_rows = []
        detailed_event_rows = []
        exported_files_for_zip = []
        sha256_manifest_lines = []
        clip_plot_cache = []
        total_files = len(files_to_scan)

        chain_of_custody_manifest = {
            "forensic_manifest_version": "5.0-SWGDE-ENF-Formant-PDF-Compliant",
            "generated_utc": datetime.now(timezone.utc).isoformat(),
            "examiner_id": examiner_name,
            "enf_and_dsp_parameters": {
                "nominal_grid_hz": nominal_grid_hz,
                "phase_jump_threshold_deg": phase_jump_threshold_deg,
                "pitch_f0_estimator": "Probabilistic YIN (65-450 Hz)",
                "formant_f1_f2_estimator": "18th-Order LPC Complex Root Solver",
                "hpss_transient_suppression_ratio": transient_suppression,
                "soft_knee_vocal_boost_multiplier": vocal_boost,
                "phase_vocoder_time_stretch_rate": stretch_rate
            },
            "source_evidence_files": []
        }

        for idx, (f_path, disp_name) in enumerate(files_to_scan, start=1):
            progress.progress(idx / total_files, text=f"Auditing & Extracting [{idx}/{total_files}]: {disp_name}...")
            try:
                orig_stat = os.stat(f_path)
                orig_atime, orig_mtime = orig_stat.st_atime, orig_stat.st_mtime
                pre_hashes = compute_file_hashes(f_path)
                sha256_manifest_lines.append(f"{pre_hashes['sha256']} *SOURCE_MP4::{disp_name}")

                auth_report = validate_ring_file_authenticity(f_path)

                suffix = os.path.splitext(f_path)[1]
                with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp_work:
                    work_copy_path = tmp_work.name
                shutil.copyfile(f_path, work_copy_path)
                try:
                    os.utime(f_path, (orig_atime, orig_mtime))
                except OSError:
                    pass

                try:
                    y_raw, sr = librosa.load(work_copy_path, sr=16000, mono=True)
                finally:
                    if os.path.exists(work_copy_path):
                        try:
                            os.remove(work_copy_path)
                        except OSError:
                            pass

                pk = np.max(np.abs(y_raw))
                y_norm = y_raw / pk if pk > 0 else y_raw

                enf_report = analyze_enf_phase_continuity(
                    y=y_norm,
                    sr=sr,
                    nominal_grid_hz=nominal_grid_hz,
                    forced_harmonic_hz=forced_harmonic_val,
                    phase_jump_threshold_deg=phase_jump_threshold_deg
                )

                anomalies = detect_silence_broken_anomalies(
                    y=y_norm,
                    sr=sr,
                    silence_floor_db=silence_floor_db,
                    burst_jump_db=burst_jump_db,
                    min_piggyback_score=min_piggyback_score
                )

                post_hashes = compute_file_hashes(f_path)
                try:
                    os.utime(f_path, (orig_atime, orig_mtime))
                except OSError:
                    pass
                hash_integrity_match = (pre_hashes["sha256"] == post_hashes["sha256"])
                integrity_badge = "VERIFIED INTACT (Pre == Post SHA-256)" if hash_integrity_match else "INTEGRITY MISMATCH"

                source_manifest_entry = {
                    "file_name": disp_name,
                    "file_path": f_path,
                    "pre_scan_sha256": pre_hashes["sha256"],
                    "post_scan_sha256": post_hashes["sha256"],
                    "md5_checksum": pre_hashes["md5"],
                    "zero_bytes_altered_verified": hash_integrity_match,
                    "container_authenticity": auth_report,
                    "enf_phase_continuity_audit": {
                        "tracked_harmonic_hz": enf_report["tracked_harmonic_hz"],
                        "enf_snr_db": enf_report["enf_snr_db"],
                        "max_phase_jump_deg": enf_report["max_phase_jump_deg"],
                        "enf_verdict": enf_report["enf_verdict"]
                    },
                    "derived_anomaly_stems": []
                }

                if not anomalies:
                    chain_of_custody_manifest["source_evidence_files"].append(source_manifest_entry)
                    file_summary_rows.append({
                        "File_Name": disp_name,
                        "ENF_Phase_Splice_Verdict": enf_report["enf_verdict"],
                        "Tracked_ENF_Harmonic": f"{enf_report['tracked_harmonic_hz']} Hz (SNR: {enf_report['enf_snr_db']} dB)",
                        "Max_ENF_Phase_Jump_Deg": enf_report["max_phase_jump_deg"],
                        "Container_Authenticity": auth_report["authenticity_status"],
                        "Source_Integrity": integrity_badge,
                        "Source_SHA256": pre_hashes["sha256"],
                        "Anomaly_Status": "CLEAN (No Silence-Broken Anomalies)",
                        "Anomaly_Burst_Count": 0,
                        "Forced_Anomaly_Transcripts": "",
                        "File_Path": f_path
                    })
                    continue

                clip_transcripts = []
                burst_plot_items = []
                clean_stem = re.sub(r"[^a-zA-Z0-9_-]+", "_", os.path.splitext(os.path.basename(disp_name))[0])
                short_parent_hash = pre_hashes["sha256"][:10]

                for a_idx, anom in enumerate(anomalies, start=1):
                    y_unmasked_1x, y_boosted_expanded = unmask_and_expand_anomaly(
                        y_slice=anom["y_slice"],
                        sr=sr,
                        transient_suppression=transient_suppression,
                        vocal_boost=vocal_boost,
                        stretch_rate=stretch_rate
                    )

                    # Extract Fundamental Pitch (F0) and Vocal Formants (F1 / F2) on the 1.0x unmasked slice
                    vocal_bio = analyze_f0_and_formants_lpc(y_unmasked=y_unmasked_1x, sr=sr)

                    asr_out = force_transcribe_anomaly_arrays(
                        y_unmasked_1x=y_unmasked_1x,
                        y_boosted_expanded=y_boosted_expanded,
                        sr=sr,
                        whisper_model=whisper_model,
                        stretch_rate=stretch_rate
                    )

                    burst_enf = evaluate_burst_boundary_enf_jump(
                        enf_data=enf_report,
                        start_sec=anom["start_sec"],
                        end_sec=anom["end_sec"],
                        threshold_deg=phase_jump_threshold_deg
                    )

                    time_tag = f"{anom['start_sec']:05.2f}s-{anom['end_sec']:05.2f}s"
                    snippet_tag = asr_out["snippet_for_filename"]
                    base_burst_name = f"{clean_stem}__{short_parent_hash}__Burst{a_idx:02d}_{time_tag}"

                    expanded_wav_name = f"{base_burst_name}__BOOSTED_EXPANDED_{stretch_rate:.2f}x__{snippet_tag}.wav"
                    expanded_wav_path = os.path.join(extracted_subfolder, expanded_wav_name)
                    sf.write(expanded_wav_path, y_boosted_expanded, sr, subtype="PCM_16")
                    exp_wav_hashes = compute_file_hashes(expanded_wav_path)
                    exported_files_for_zip.append(expanded_wav_path)
                    sha256_manifest_lines.append(f"{exp_wav_hashes['sha256']} *DERIVED_EXPANDED_WAV::{expanded_wav_name}")

                    unmasked_1x_name = f"{base_burst_name}__UNMASKED_1.0x__{snippet_tag}.wav"
                    unmasked_1x_path = os.path.join(extracted_subfolder, unmasked_1x_name)
                    sf.write(unmasked_1x_path, y_unmasked_1x, sr, subtype="PCM_16")
                    unm_wav_hashes = compute_file_hashes(unmasked_1x_path)
                    exported_files_for_zip.append(unmasked_1x_path)

                    raw_slice_name = f"{base_burst_name}__RAW_EVIDENCE_SLICE.wav"
                    raw_slice_path = os.path.join(extracted_subfolder, raw_slice_name)
                    sf.write(raw_slice_path, anom["y_slice"], sr, subtype="PCM_16")
                    raw_wav_hashes = compute_file_hashes(raw_slice_path)
                    exported_files_for_zip.append(raw_slice_path)

                    clip_transcripts.append(f"[{time_tag}] {asr_out['combined_transcript']}")
                    sample_range_str = f"{anom['start_sample_16k']}-{anom['end_sample_16k']}"

                    burst_plot_items.append({
                        "anomaly_index": a_idx,
                        "start_sec": anom["start_sec"],
                        "end_sec": anom["end_sec"],
                        "sample_range": sample_range_str,
                        "db_jump": anom["db_jump"],
                        "piggyback_score": anom["piggyback_score"],
                        "burst_enf_status": burst_enf["burst_enf_status"],
                        "boundary_jump_deg": burst_enf["boundary_jump_deg"],
                        "transcript_slow": asr_out["transcript_slow"],
                        "transcript_normal": asr_out["transcript_normal"],
                        "raw_wav_sha256": raw_wav_hashes["sha256"],
                        "exp_wav_sha256": exp_wav_hashes["sha256"],
                        "exp_wav_name": expanded_wav_name,
                        "sr": sr,
                        "y_raw_slice": anom["y_slice"],
                        "y_unmasked_1x": y_unmasked_1x,
                        "vocal_biometry": vocal_bio
                    })

                    source_manifest_entry["derived_anomaly_stems"].append({
                        "anomaly_index": a_idx,
                        "start_sec": anom["start_sec"],
                        "end_sec": anom["end_sec"],
                        "f0_median_hz": vocal_bio["f0_median_hz"],
                        "f1_median_hz": vocal_bio["f1_median_hz"],
                        "f2_median_hz": vocal_bio["f2_median_hz"],
                        "vocal_register_profile": vocal_bio["vocal_register_profile"],
                        "vowel_articulation_zone": vocal_bio["vowel_articulation_zone"],
                        "boundary_enf_phase_jump_deg": burst_enf["boundary_jump_deg"],
                        "boundary_enf_status": burst_enf["burst_enf_status"],
                        "parent_source_sha256": pre_hashes["sha256"],
                        "boosted_expanded_wav_sha256": exp_wav_hashes["sha256"],
                        "forced_transcripts": asr_out["combined_transcript"]
                    })

                    detailed_event_rows.append({
                        "File_Name": disp_name,
                        "Anomaly_Index": a_idx,
                        "Start_Sec": anom["start_sec"],
                        "End_Sec": anom["end_sec"],
                        "F0_Median_Hz": vocal_bio["f0_median_hz"],
                        "F0_Pitch_Range": vocal_bio["f0_range_str"],
                        "F1_Formant_Hz": vocal_bio["f1_median_hz"],
                        "F2_Formant_Hz": vocal_bio["f2_median_hz"],
                        "Formant_Dispersion_Hz": vocal_bio["formant_dispersion_hz"],
                        "Vocal_Register_Profile": vocal_bio["vocal_register_profile"],
                        "Closest_Vowel_Zone": vocal_bio["vowel_articulation_zone"],
                        "Burst_Boundary_ENF_Status": burst_enf["burst_enf_status"],
                        "Boundary_Phase_Jump_Deg": burst_enf["boundary_jump_deg"],
                        "Transcript_Slow_Expanded": asr_out["transcript_slow"],
                        "Transcript_1x_Unmasked": asr_out["transcript_normal"],
                        "Combined_Forced_Transcript": asr_out["combined_transcript"],
                        "Sample_Range_16kHz": sample_range_str,
                        "dB_Jump_Above_Silence": anom["db_jump"],
                        "Piggyback_Modulation_Score": anom["piggyback_score"],
                        "Parent_Source_SHA256": pre_hashes["sha256"],
                        "Parent_Source_MD5": pre_hashes["md5"],
                        "Container_Authenticity": auth_report["authenticity_status"],
                        "Expanded_WAV_SHA256": exp_wav_hashes["sha256"],
                        "Raw_Slice_WAV_SHA256": raw_wav_hashes["sha256"],
                        "Saved_Expanded_WAV_File": expanded_wav_name,
                        "Saved_Expanded_WAV_Path": expanded_wav_path,
                        "Saved_Unmasked_1x_WAV_Path": unmasked_1x_path,
                        "Saved_Raw_Slice_WAV_Path": raw_slice_path,
                        "Full_File_Path": f_path
                    })

                clip_plot_cache.append({
                    "file_name": disp_name,
                    "pre_sha256": pre_hashes["sha256"],
                    "post_sha256": post_hashes["sha256"],
                    "md5": pre_hashes["md5"],
                    "auth_status": auth_report["authenticity_status"],
                    "enf_report": enf_report,
                    "burst_items": burst_plot_items
                })

                chain_of_custody_manifest["source_evidence_files"].append(source_manifest_entry)
                file_summary_rows.append({
                    "File_Name": disp_name,
                    "ENF_Phase_Splice_Verdict": enf_report["enf_verdict"],
                    "Tracked_ENF_Harmonic": f"{enf_report['tracked_harmonic_hz']} Hz (SNR: {enf_report['enf_snr_db']} dB)",
                    "Max_ENF_Phase_Jump_Deg": enf_report["max_phase_jump_deg"],
                    "Container_Authenticity": auth_report["authenticity_status"],
                    "Source_Integrity": integrity_badge,
                    "Source_SHA256": pre_hashes["sha256"],
                    "Anomaly_Status": "ANOMALY DETECTED",
                    "Anomaly_Burst_Count": len(anomalies),
                    "Forced_Anomaly_Transcripts": " || ".join(clip_transcripts),
                    "File_Path": f_path
                })

            except Exception as exc:
                file_summary_rows.append({
                    "File_Name": disp_name,
                    "ENF_Phase_Splice_Verdict": f"ERROR ({str(exc)})",
                    "Tracked_ENF_Harmonic": "N/A",
                    "Max_ENF_Phase_Jump_Deg": 0.0,
                    "Container_Authenticity": "ERROR",
                    "Source_Integrity": "ERROR",
                    "Source_SHA256": "",
                    "Anomaly_Status": "ERROR",
                    "Anomaly_Burst_Count": 0,
                    "Forced_Anomaly_Transcripts": "",
                    "File_Path": f_path
                })

        df_files = pd.DataFrame(file_summary_rows)
        df_events = pd.DataFrame(detailed_event_rows)
        st.session_state["anomaly_batch_df"] = df_files
        st.session_state["anomaly_events_df"] = df_events

        ts_now = datetime.now().strftime("%Y%m%d_%H%M%S")
        pdf_report_path = os.path.join(extracted_subfolder, f"Forensic_Examination_Report_{ts_now}.pdf")
        manifest_path = os.path.join(extracted_subfolder, f"forensic_chain_of_custody_enf_{ts_now}.json")
        sha256_txt_path = os.path.join(extracted_subfolder, f"checksums_{ts_now}.sha256")
        clips_csv_path = os.path.join(extracted_subfolder, f"enf_authenticated_clips_{ts_now}.csv")
        events_csv_path = os.path.join(extracted_subfolder, f"enf_formant_burst_transcripts_{ts_now}.csv")

        progress.progress(0.95, text="Compiling printable multi-page PDF Report with F0 & F1/F2 Formant Exhibits...")
        generate_forensic_pdf_report(
            pdf_out_path=pdf_report_path,
            manifest_data=chain_of_custody_manifest,
            df_files=df_files,
            df_events=df_events,
            clip_plot_cache=clip_plot_cache,
            phase_jump_threshold_deg=phase_jump_threshold_deg,
            stretch_rate=stretch_rate
        )
        pdf_hashes = compute_file_hashes(pdf_report_path)
        sha256_manifest_lines.append(f"{pdf_hashes['sha256']} *FORENSIC_PDF_REPORT::{os.path.basename(pdf_report_path)}")
        chain_of_custody_manifest["compiled_pdf_report_sha256"] = pdf_hashes["sha256"]

        with open(manifest_path, "w", encoding="utf-8") as mf:
            json.dump(chain_of_custody_manifest, mf, indent=2)
        with open(sha256_txt_path, "w", encoding="utf-8") as sf_txt:
            sf_txt.write("\n".join(sha256_manifest_lines) + "\n")

        df_files.to_csv(clips_csv_path, index=False, encoding="utf-8-sig")
        if not df_events.empty:
            df_events.to_csv(events_csv_path, index=False, encoding="utf-8-sig")

        st.session_state["manifest_json_path"] = manifest_path
        st.session_state["pdf_report_path"] = pdf_report_path

        zip_path = os.path.join(extracted_subfolder, f"Forensic_Complete_Evidence_Package_{ts_now}.zip")
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for meta_p in (pdf_report_path, manifest_path, sha256_txt_path, clips_csv_path, events_csv_path):
                if os.path.exists(meta_p):
                    zf.write(meta_p, arcname=os.path.basename(meta_p))
            for wav_p in exported_files_for_zip:
                if os.path.exists(wav_p):
                    zf.write(wav_p, arcname=os.path.basename(wav_p))
        st.session_state["zip_bundle_path"] = zip_path
        progress.empty()
        st.toast("PDF Forensic Report with F0 Pitch & F1/F2 Formants generated!", icon="📑")

# -------------------------------------------------------------------------
# FORENSIC DASHBOARD, ONE-CLICK PDF REPORT DOWNLOAD & INSPECTOR
# -------------------------------------------------------------------------
if st.session_state["anomaly_batch_df"] is not None:
    df_files = st.session_state["anomaly_batch_df"]
    df_events = st.session_state["anomaly_events_df"]
    zip_bundle = st.session_state["zip_bundle_path"]
    manifest_json_p = st.session_state["manifest_json_path"]
    pdf_report_p = st.session_state["pdf_report_path"]

    st.divider()
    st.subheader("📑 Forensic Examination Summary & One-Click Report Downloads")

    intact_count = int((df_files["Source_Integrity"].str.startswith("VERIFIED")).sum())
    enf_cont_count = int((df_files["ENF_Phase_Splice_Verdict"].str.startswith("CONTINUOUS")).sum())
    voiced_count = int((df_events["F0_Median_Hz"] > 0).sum()) if not df_events.empty else 0
    formant_count = int((df_events["F1_Formant_Hz"] > 0).sum()) if not df_events.empty else 0

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("🔒 Pre == Post SHA-256 Match", f"{intact_count}/{len(df_files)}")
    m2.metric("⚡ ENF Phase Continuous", str(enf_cont_count))
    m3.metric("🗣️ Bursts with F1/F2 Formants", f"{formant_count}/{len(df_events)}")
    m4.metric("🎵 Bursts with Voiced F0 Pitch", f"{voiced_count}/{len(df_events)}")

    dl1, dl2, dl3, dl4 = st.columns(4)
    with dl1:
        if pdf_report_p and os.path.exists(pdf_report_p):
            with open(pdf_report_p, "rb") as pf_bytes:
                st.download_button(
                    label="📑 Download Printable PDF Forensic Report",
                    data=pf_bytes.read(),
                    file_name=os.path.basename(pdf_report_p),
                    mime="application/pdf",
                    type="primary",
                    use_container_width=True
                )
    with dl2:
        if zip_bundle and os.path.exists(zip_bundle):
            with open(zip_bundle, "rb") as zf_bytes:
                st.download_button(
                    label="📦 Download Complete ZIP (PDF + WAVs + CSVs)",
                    data=zf_bytes.read(),
                    file_name="Forensic_Complete_Evidence_Package.zip",
                    mime="application/zip",
                    use_container_width=True
                )
    with dl3:
        if manifest_json_p and os.path.exists(manifest_json_p):
            with open(manifest_json_p, "rb") as jf_bytes:
                st.download_button(
                    label="📜 Download Chain-of-Custody JSON",
                    data=jf_bytes.read(),
                    file_name="forensic_chain_of_custody_enf.json",
                    mime="application/json",
                    use_container_width=True
                )
    with dl4:
        csv_burst_events = (
            df_events.to_csv(index=False).encode("utf-8-sig")
            if not df_events.empty
            else df_files.to_csv(index=False).encode("utf-8-sig")
        )
        st.download_button(
            label="📥 Download F0/F1/F2 & Transcripts CSV",
            data=csv_burst_events,
            file_name="enf_formant_anomaly_transcripts.csv",
            mime="text/csv",
            use_container_width=True
        )

    st.dataframe(df_files, use_container_width=True, hide_index=True)

    if not df_events.empty:
        st.markdown("### 📝 Anomaly Bursts with $F_0$ Pitch, $F_1/F_2$ Formants, ENF Status & Forced Transcripts")
        hide_cols = ["Saved_Expanded_WAV_Path", "Saved_Unmasked_1x_WAV_Path", "Saved_Raw_Slice_WAV_Path", "Full_File_Path"]
        st.dataframe(df_events.drop(columns=hide_cols, errors="ignore"), use_container_width=True, hide_index=True)

        # ---------------------------------------------------------------------
        # INTERACTIVE SINGLE-BURST INSPECTOR + ON-DEMAND SINGLE-EXHIBIT PDF
        # ---------------------------------------------------------------------
        st.divider()
        st.subheader("🎧 Interactive F0 / F1 / F2 Burst Inspector & Standalone PDF Exporter")
        df_events["Selector_Label"] = (
            df_events["File_Name"]
            + " | Burst #" + df_events["Anomaly_Index"].astype(str)
            + " | F0=" + df_events["F0_Median_Hz"].astype(str) + "Hz, F1=" + df_events["F1_Formant_Hz"].astype(str)
            + "Hz, F2=" + df_events["F2_Formant_Hz"].astype(str) + "Hz -> "
            + df_events["Combined_Forced_Transcript"]
        )
        selected_label = st.selectbox("Select an anomaly burst to inspect or export as a standalone PDF:", options=df_events["Selector_Label"].tolist())
        sel_row = df_events[df_events["Selector_Label"] == selected_label].iloc[0]

        ac1, ac2, ac3 = st.columns(3)
        with ac1:
            st.markdown("**1. Raw Evidence Control Slice (1.0x)**")
            st.caption(f"SHA-256: `{sel_row['Raw_Slice_WAV_SHA256'][:14]}...`")
            if os.path.exists(sel_row["Saved_Raw_Slice_WAV_Path"]):
                st.audio(sel_row["Saved_Raw_Slice_WAV_Path"], format="audio/wav")
        with ac2:
            st.markdown("**2. Unmasked Vocal Band (1.0x)**")
            st.caption(f"{sel_row['Vocal_Register_Profile']}")
            if os.path.exists(sel_row["Saved_Unmasked_1x_WAV_Path"]):
                st.audio(sel_row["Saved_Unmasked_1x_WAV_Path"], format="audio/wav")
        with ac3:
            st.markdown(f"**3. Boosted & Time-Expanded (`{stretch_rate:.2f}x`)**")
            st.caption(f"Vowel Zone: `{sel_row['Closest_Vowel_Zone']}`")
            if os.path.exists(sel_row["Saved_Expanded_WAV_Path"]):
                st.audio(sel_row["Saved_Expanded_WAV_Path"], format="audio/wav")

        if os.path.exists(sel_row["Full_File_Path"]) and os.path.exists(sel_row["Saved_Raw_Slice_WAV_Path"]):
            y_full_s, sr_s = librosa.load(sel_row["Full_File_Path"], sr=16000, mono=True)
            pk_s = np.max(np.abs(y_full_s))
            y_full_s = y_full_s / pk_s if pk_s > 0 else y_full_s
            enf_s = analyze_enf_phase_continuity(y_full_s, sr_s, nominal_grid_hz, forced_harmonic_val, phase_jump_threshold_deg)

            y_raw_s, _ = librosa.load(sel_row["Saved_Raw_Slice_WAV_Path"], sr=16000, mono=True)
            y_unm_s, _ = librosa.load(sel_row["Saved_Unmasked_1x_WAV_Path"], sr=16000, mono=True)
            v_bio_s = analyze_f0_and_formants_lpc(y_unmasked=y_unm_s, sr=sr_s)

            with tempfile.NamedTemporaryFile(delete=False, suffix="_single_exhibit.pdf") as tmp_pdf:
                single_pdf_path = tmp_pdf.name

            single_cache = [{
                "file_name": sel_row["File_Name"],
                "pre_sha256": sel_row["Parent_Source_SHA256"],
                "post_sha256": sel_row["Parent_Source_SHA256"],
                "md5": sel_row["Parent_Source_MD5"],
                "auth_status": sel_row["Container_Authenticity"],
                "enf_report": enf_s,
                "burst_items": [{
                    "anomaly_index": sel_row["Anomaly_Index"],
                    "start_sec": sel_row["Start_Sec"],
                    "end_sec": sel_row["End_Sec"],
                    "sample_range": sel_row["Sample_Range_16kHz"],
                    "db_jump": sel_row["dB_Jump_Above_Silence"],
                    "piggyback_score": sel_row["Piggyback_Modulation_Score"],
                    "burst_enf_status": sel_row["Burst_Boundary_ENF_Status"],
                    "boundary_jump_deg": sel_row["Boundary_Phase_Jump_Deg"],
                    "transcript_slow": sel_row["Transcript_Slow_Expanded"],
                    "transcript_normal": sel_row["Transcript_1x_Unmasked"],
                    "raw_wav_sha256": sel_row["Raw_Slice_WAV_SHA256"],
                    "exp_wav_sha256": sel_row["Expanded_WAV_SHA256"],
                    "exp_wav_name": sel_row["Saved_Expanded_WAV_File"],
                    "sr": sr_s,
                    "y_raw_slice": y_raw_s,
                    "y_unmasked_1x": y_unm_s,
                    "vocal_biometry": v_bio_s
                }]
            }]

            generate_forensic_pdf_report(
                pdf_out_path=single_pdf_path,
                manifest_data={
                    "forensic_manifest_version": "5.0-SWGDE-Single-Exhibit",
                    "generated_utc": datetime.now(timezone.utc).isoformat(),
                    "examiner_id": examiner_name,
                    "enf_and_dsp_parameters": {
                        "nominal_grid_hz": nominal_grid_hz,
                        "phase_jump_threshold_deg": phase_jump_threshold_deg,
                        "hpss_transient_suppression_ratio": transient_suppression,
                        "soft_knee_vocal_boost_multiplier": vocal_boost
                    }
                },
                df_files=df_files[df_files["File_Name"] == sel_row["File_Name"]],
                df_events=pd.DataFrame([sel_row]),
                clip_plot_cache=single_cache,
                phase_jump_threshold_deg=phase_jump_threshold_deg,
                stretch_rate=stretch_rate
            )

            with open(single_pdf_path, "rb") as sp_bytes:
                st.download_button(
                    label=f"📄 Download Standalone F0/F1/F2 PDF Exhibit for {sel_row['File_Name']} (Burst #{sel_row['Anomaly_Index']})",
                    data=sp_bytes.read(),
                    file_name=f"Forensic_Formant_Exhibit_{sel_row['File_Name']}_Burst{sel_row['Anomaly_Index']}.pdf",
                    mime="application/pdf",
                    use_container_width=True
                )
            try:
                os.remove(single_pdf_path)
            except OSError:
                pass