#Divya Patel ECE 56401- Computer Security - Final Project
#Command Line Interface with automatic payload hashing
#Project Description: Performs the commands Embed, Extract, Detect, and Hash on a cover image

import argparse
import hashlib
from stegolib.lsb import lsb_embed, lsb_extract
from crypto_utils import aes_encrypt, aes_decrypt
from stegolib.detect import detect_stego, load_image

def compute_sha256(data: bytes):
    """Compute SHA-256 hash of data."""
    return hashlib.sha256(data).hexdigest()

def main():
    parser = argparse.ArgumentParser(description="Stego Project CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    # Embed
    p_embed = sub.add_parser("embed")
    p_embed.add_argument("cover")
    p_embed.add_argument("payload")
    p_embed.add_argument("output")
    p_embed.add_argument("-pw", help="Password for optional AES encryption")

    # Extract
    p_extract = sub.add_parser("extract")
    p_extract.add_argument("stego")
    p_extract.add_argument("output")
    p_extract.add_argument("-pw", help="Password if payload was encrypted")

    # Detect
    p_detect = sub.add_parser("detect")
    p_detect.add_argument("image")

    # Hash
    p_hash = sub.add_parser("hash")
    p_hash.add_argument("file", help="File to compute SHA-256 hash for")

    args = parser.parse_args()

    if args.command == "embed":
        try:
            with open(args.payload, "rb") as f:
                data = f.read()
            payload_hash = compute_sha256(data)
            print(f"[+] Original payload SHA-256: {payload_hash}")

            if args.pw:
                data = aes_encrypt(args.pw, data)

            lsb_embed(args.cover, data, args.output)
            print(f"[+] Embedded into {args.output}")

        except Exception as e:
            print("[ERROR]", e)

    elif args.command == "extract":
        try:
            data = lsb_extract(args.stego)
            if args.pw:
                data = aes_decrypt(args.pw, data)

            with open(args.output, "wb") as f:
                f.write(data)

            extracted_hash = compute_sha256(data)
            print(f"[+] Extracted to {args.output}")
            print(f"[+] Extracted payload SHA-256: {extracted_hash}")

        except Exception as e:
            print("[ERROR]", e)

    elif args.command == "detect":
        try:
            print(f"[+] Loading image: {args.image}")
            img = load_image(args.image)
            print("[+] Running detection suite...\n")
            results = detect_stego(img)

            chi = results["chi_square"]
            rs  = results["rs_analysis"]
            hist = results["histogram"]

            print("[Chi-Square]")
            print("χ² =", chi["chi2"])
            print("p =", chi["p"])
            print("evens =", chi["evens"], "odds =", chi["odds"])
            print()

            print("[RS]")
            print("R =", rs["R"])
            print("F =", rs["F"])
            print("F - R =", rs["difference"])
            print()

            print("[Histogram]")
            print("avg diff =", hist["avg_even_odd_diff"])
            print("max diff =", hist["max_even_odd_diff"])
            print()

            print("FINAL DECISION:", results["decision"])

        except Exception as e:
            print("[ERROR]", e)

    elif args.command == "hash":
        try:
            with open(args.file, "rb") as f:
                data = f.read()
            sha = compute_sha256(data)
            print(f"[+] SHA-256 hash of {args.file}: {sha}")
        except Exception as e:
            print("[ERROR]", e)


if __name__ == "__main__":
    main()