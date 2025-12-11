#Divya Patel ECE 56401- Computer Security - Final Project
#Graphical User Interface 
#Project Description: 
#Graphical interface for embedding, extracting, and detecting hidden data in images, also saves output in user device
#Combines LSB steganography with AES-256 encryption (optional) for secure data hiding

import tkinter as tk
from tkinter import filedialog, messagebox
import os

from stegolib.lsb import lsb_embed, lsb_extract
from stegolib.detect import detect_stego, load_image  # Make sure load_image is imported
from crypto_utils import aes_encrypt, aes_decrypt


class StegoGUI:
    def __init__(self, root):
        self.root = root
        root.title("Steganography Tool by Divya Patel")
        root.geometry("580x450")
        root.configure(bg="black")
        root.resizable(False, False)

        title = tk.Label(
            root,
            text="Welcome to Stego tool, select files to get started",
            font=("Calibri", 15, "bold"),
            bg="black",
            fg="white"
        )
        title.pack(pady=10)

        self.tab_frame = tk.Frame(root, bg="black")
        self.tab_frame.pack()

        self.embed_btn = tk.Button(self.tab_frame, text="Embed", width=10,
                                   command=self.embed_tab, bg="#333", fg="white")
        self.extract_btn = tk.Button(self.tab_frame, text="Extract", width=10,
                                     command=self.extract_tab, bg="#333", fg="white")
        self.detect_btn = tk.Button(self.tab_frame, text="Detect", width=10,
                                    command=self.detect_tab, bg="#333", fg="white")

        self.embed_btn.grid(row=0, column=0, padx=5)
        self.extract_btn.grid(row=0, column=1, padx=5)
        self.detect_btn.grid(row=0, column=2, padx=5)

        self.content = tk.Frame(root, bg="black")
        self.content.pack(pady=20)

        self.embed_tab()

    def file_picker(self, types):
        return filedialog.askopenfilename(filetypes=types)

    def save_picker(self, def_ext):
        return filedialog.asksaveasfilename(defaultextension=def_ext)

    def embed_tab(self):
        self.clear_content()

        self.add_label("Cover Image:", 0)
        self.cover_path = self.add_entry(0)
        self.add_browse_button(self.cover_path, 0, [("Images", "*.png;*.jpg")])

        self.add_label("Payload File:", 1)
        self.payload_path = self.add_entry(1)
        self.add_browse_button(self.payload_path, 1, [("All Files", "*")])

        self.add_label("Password (optional):", 2)
        self.embed_pw = self.add_entry(2, show="*")

        tk.Button(self.content, text="Embed", width=20, bg="#4CAF50", fg="white",
                  command=self.do_embed).grid(row=3, column=1, pady=20)

    def do_embed(self):
        try:
            cover = self.cover_path.get().strip()
            payload = self.payload_path.get().strip()

            # Fix: Use os.path.isfile and normalize path
            cover = os.path.normpath(cover)
            payload = os.path.normpath(payload)
            
            if not os.path.isfile(cover) or not os.path.isfile(payload):
                messagebox.showerror("Error", "Invalid file path(s)")
                return

            with open(payload, "rb") as f:
                data = f.read()

            pw = self.embed_pw.get()
            if pw:
                data = aes_encrypt(data, pw)

            out = self.save_picker(".png")
            if not out:
                return

            lsb_embed(cover, data, out)
            messagebox.showinfo("Success", f"Embedded successfully into:\n{out}")

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def extract_tab(self):
        self.clear_content()

        self.add_label("Stego Image:", 0)
        self.stego_path = self.add_entry(0)
        self.add_browse_button(self.stego_path, 0, [("Images", "*.png;*.jpg")])

        self.add_label("Password (optional):", 1)
        self.extract_pw = self.add_entry(1, show="*")

        tk.Button(self.content, text="Extract", width=20, bg="#2196F3", fg="white",
                  command=self.do_extract).grid(row=2, column=1, pady=20)

    def do_extract(self):
        try:
            stego = self.stego_path.get().strip()
            stego = os.path.normpath(stego)
            
            if not os.path.isfile(stego):
                messagebox.showerror("Error", "Invalid file path")
                return

            data = lsb_extract(stego)
            pw = self.extract_pw.get()
            if pw:
                data = aes_decrypt(data, pw)

            out = self.save_picker(".bin")
            if not out:
                return

            with open(out, "wb") as f:
                f.write(data)

            messagebox.showinfo("Success", f"Extracted file saved:\n{out}")

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def detect_tab(self):
        self.clear_content()

        self.add_label("Image to Analyze:", 0)
        self.detect_path = self.add_entry(0)
        self.add_browse_button(self.detect_path, 0, [("Images", "*.png;*.jpg")])

        tk.Button(self.content, text="Run Detection", width=20, bg="#9C27B0", fg="white",
                  command=self.do_detect).grid(row=1, column=1, pady=20)

        self.detect_output = tk.Text(
            self.content, width=70, height=12,
            bg="black", fg="lime", insertbackground="white"
        )
        self.detect_output.grid(row=2, column=0, columnspan=3)

    def do_detect(self):
        try:
            path = self.detect_path.get().strip()
            path = os.path.normpath(path)
            
            if not os.path.isfile(path):
                messagebox.showerror("Error", "Invalid file path")
                return

            # FIXED: Load the image first, then pass to detect_stego
            img = load_image(path)
            results = detect_stego(img)  # Pass image array, not path

            # Clear and display results
            self.detect_output.delete("1.0", tk.END)
            
            # Format the output based on your detect.py structure
            if "chi_square" in results:
                # New format from your detect.py
                chi = results["chi_square"]
                rs = results["rs_analysis"]
                hist = results["histogram"]
                
                self.detect_output.insert(tk.END, "=== CHI-SQUARE TEST ===\n")
                self.detect_output.insert(tk.END, f"Chi2: {chi['chi2']:.4f}\n")
                self.detect_output.insert(tk.END, f"p-value: {chi['p']:.6f}\n")
                self.detect_output.insert(tk.END, f"Evens: {chi['evens']}, Odds: {chi['odds']}\n\n")
                
                self.detect_output.insert(tk.END, "=== RS ANALYSIS ===\n")
                self.detect_output.insert(tk.END, f"Regular (R): {rs['R']}\n")
                self.detect_output.insert(tk.END, f"Flipped (F): {rs['F']}\n")
                self.detect_output.insert(tk.END, f"Difference (F-R): {rs['difference']}\n\n")
                
                self.detect_output.insert(tk.END, "=== HISTOGRAM ANALYSIS ===\n")
                self.detect_output.insert(tk.END, f"Avg even/odd diff: {hist['avg_even_odd_diff']:.2f}\n")
                self.detect_output.insert(tk.END, f"Max even/odd diff: {hist['max_even_odd_diff']}\n\n")
                
                # Make a decision based on results
                likely_stego = chi['p'] < 0.05 or abs(rs['difference']) > 1000
                decision = "LIKELY CONTAINS HIDDEN DATA" if likely_stego else "LIKELY CLEAN"
                self.detect_output.insert(tk.END, f"FINAL DECISION: {decision}")
                
            else:
                # Old format from previous version
                self.detect_output.insert(tk.END, f"Chi-Square: {results.get('chi2', 'N/A')}\n")
                self.detect_output.insert(tk.END, f"p-value: {results.get('p_value', 'N/A')}\n\n")
                self.detect_output.insert(tk.END, f"RS R={results.get('R', 'N/A')}  S={results.get('S', 'N/A')}\n")
                self.detect_output.insert(tk.END, f"Estimate: {results.get('embedding_rate_est', 0):.4f}\n\n")
                
                decision = "LIKELY STEGO" if results.get("likely_stego", False) else "LIKELY CLEAN"
                self.detect_output.insert(tk.END, f"FINAL DECISION: {decision}")

        except Exception as e:
            messagebox.showerror("Error", f"Detection failed: {str(e)}")

    def clear_content(self):
        for w in self.content.winfo_children():
            w.destroy()

    def add_label(self, text, row):
        tk.Label(self.content, text=text, fg="white", bg="black").grid(row=row, column=0, sticky="w")

    def add_entry(self, row, show=None):
        e = tk.Entry(self.content, width=45, bg="#222", fg="white", insertbackground="white", show=show)
        e.grid(row=row, column=1)
        return e

    def add_browse_button(self, entry, row, types):
        tk.Button(self.content, text="Browse", bg="#444", fg="white",
                  command=lambda: entry.insert(0, self.file_picker(types))).grid(row=row, column=2)


if __name__ == "__main__":
    root = tk.Tk()
    StegoGUI(root)
    root.mainloop()