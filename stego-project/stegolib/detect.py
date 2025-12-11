#Divya Patel ECE 56401- Computer Security - Final Project
#Detection Module
#Project Description:
#Implements chi-square, RS analysis, and histogram methods for LSB steganalysis
#Detects hidden data in images using statistical anomaly detection

import numpy as np
from PIL import Image
import math

def load_image(path):
    img = Image.open(path)
    if img.mode != "RGB":
        img = img.convert("RGB")
    return np.array(img)


def chi_square_lsb(img):
    flat = img.flatten()
    evens = np.sum(flat % 2 == 0)
    odds = np.sum(flat % 2 == 1)

    total = evens + odds
    if total == 0:
        return {"chi2": 0, "p": 1.0, "evens": 0, "odds": 0}

    expected = total / 2
    chi2 = ((evens - expected)**2 / expected) + ((odds - expected)**2 / expected)
    p = math.exp(-chi2 / 2)

    return {
        "chi2": chi2,
        "p": p,
        "evens": int(evens),
        "odds": int(odds)
    }


def group_factors(block):
    return np.sum(np.abs(np.diff(block)))

def flip_lsb(block):
    return block ^ 1


def rs_analysis(img):
    flat = img.flatten()
    n = len(flat)

    if n < 8:
        return {"R": 0, "S": 0, "F": 0, "difference": 0, "estimate": 0}

    blocks = flat[: n - (n % 4)].reshape(-1, 4)

    R = 0
    S = 0

    for b in blocks:
        f_b = group_factors(b)
        f_f = group_factors(flip_lsb(b))

        if f_f > f_b:
            R += 1
        elif f_f < f_b:
            S += 1

    F = S
    diff = F - R

    return {
        "R": int(R),
        "S": int(S),
        "F": int(F),
        "difference": int(diff),
        "estimate": float(abs(diff) / (R + S + 1e-9))
    }


def histogram_analysis(img):
    flat = img.flatten()
    hist, _ = np.histogram(flat, bins=256, range=(0, 255))

    even_counts = hist[0::2]
    odd_counts = hist[1::2]

    diffs = np.abs(even_counts - odd_counts)

    return {
        "avg_even_odd_diff": float(np.mean(diffs)),
        "max_even_odd_diff": int(np.max(diffs)),
    }


def detect_stego(img):
    chi = chi_square_lsb(img)
    rs  = rs_analysis(img)
    hist = histogram_analysis(img)

    susp = 0
    if chi["p"] < 0.05:
        susp += 1
    if abs(rs["difference"]) < 0.01 * (rs["R"] + rs["S"] + 1):
        susp += 1
    if hist["avg_even_odd_diff"] < 1000:
        susp += 1

    decision = "LIKELY LSB STEGO" if susp >= 2 else "NO CLEAR EVIDENCE"

    return {
        "chi_square": chi,
        "rs_analysis": rs,
        "histogram": hist,
        "decision": decision
    }
