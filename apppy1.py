import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import subprocess
import os
import time
import psutil

def run_command(command):
    start_time = time.time()
    process = psutil.Process(os.getpid())

    # Measure CPU and memory usage at the start
    cpu_start = psutil.cpu_times()
    mem_start = process.memory_info().rss

    # Execute the command
    result = subprocess.run(command, shell=True, text=True, capture_output=True)

    # Measure CPU and memory usage at the end
    cpu_end = psutil.cpu_times()
    mem_end = process.memory_info().rss
    end_time = time.time()

    # Calculate elapsed time
    elapsed_time = end_time - start_time

    # Calculate CPU usage difference in milliseconds
    cpu_usage = ((cpu_end.user - cpu_start.user) + (cpu_end.system - cpu_start.system)) * 1000

    # Calculate memory usage difference in bytes
    mem_usage = mem_end - mem_start

    if result.returncode != 0:
        log_process(f"Error running command: {command}\n{result.stderr}")
        return False, elapsed_time, cpu_usage, mem_usage
    else:
        log_process(f"Command executed successfully: {command}\n{result.stdout}")
        return True, elapsed_time, cpu_usage, mem_usage

def log_process(message):
    process_log.config(state=tk.NORMAL)
    process_log.insert(tk.END, f"{message}\n")
    process_log.config(state=tk.DISABLED)
    process_log.see(tk.END)

def generate_keys():
    success, elapsed_time, cpu_usage, mem_usage = run_command("python key_gen.py")
    if success:
        messagebox.showinfo("Success", f"Keys generated successfully in {elapsed_time:.2f} seconds.")
        update_metrics("Generate Keys", "N/A", elapsed_time, cpu_usage, mem_usage)

def encrypt_message(algorithm):
    secret_message = message_entry.get("1.0", tk.END).strip()
    if not secret_message:
        messagebox.showerror("Error", "Please enter a secret message.")
        return

    message_file = "secret_message.txt"
    with open(message_file, "w") as f:
        f.write(secret_message)

    if algorithm == "RSA":
        command = f"python rsa_encrypt.py {message_file} rsa_encrypted_message.bin"
    elif algorithm == "ECC":
        command = f"python ecc_encrypt.py {message_file} ecc_public_key.pem ecc_encrypted_message.bin"

    success, elapsed_time, cpu_usage, mem_usage = run_command(command)
    if success:
        encrypted_file = f"{algorithm.lower()}_encrypted_message.bin"
        with open(encrypted_file, "rb") as f:
            encrypted_message = f.read()
        messagebox.showinfo("Success", f"Message encrypted using {algorithm} in {elapsed_time:.2f} seconds.")
        update_metrics("Encrypt Message", algorithm, elapsed_time, cpu_usage, mem_usage)
        log_process(f"{algorithm} Encrypted Message: {encrypted_message}")

def embed_message(algorithm):
    output_file = filedialog.asksaveasfilename(title="Save Embedded File As", defaultextension=".wav", filetypes=[("WAV Files", "*.wav")])
    if not output_file:
        return

    log_process(f"Selected output file: {output_file}")

    audio_file = "secret_audio.wav"
    if not os.path.exists(audio_file):
        log_process(f"Audio file {audio_file} does not exist.")
        messagebox.showerror("Error", f"Audio file {audio_file} does not exist.")
        return

    if algorithm == "RSA":
        command = f"python embed.py rsa_encrypted_message.bin {audio_file} \"{output_file}\""
    elif algorithm == "ECC":
        command = f"python embed.py ecc_encrypted_message.bin {audio_file} \"{output_file}\""

    log_process(f"Running command: {command}")
    success, elapsed_time, cpu_usage, mem_usage = run_command(command)
    if success:
        if os.path.exists(output_file):
            log_process(f"{algorithm} encrypted message embedded in {elapsed_time:.2f} seconds.")
            messagebox.showinfo("Success", f"{algorithm} encrypted message embedded in {elapsed_time:.2f} seconds.")
            update_metrics("Embed Message", algorithm, elapsed_time, cpu_usage, mem_usage)
        else:
            log_process(f"Failed to save the output file: {output_file}")
            messagebox.showerror("Error", f"Failed to save the output file: {output_file}")

def extract_message(algorithm):
    input_file = filedialog.askopenfilename(title="Select Embedded File", filetypes=[("WAV Files", "*.wav")])
    if not input_file:
        return

    log_process(f"Selected input file: {input_file}")

    if algorithm == "RSA":
        command = f"python extract.py \"{input_file}\" rsa_extracted_message.bin"
    elif algorithm == "ECC":
        command = f"python extract.py \"{input_file}\" ecc_extracted_message.bin"

    log_process(f"Running command: {command}")
    success, elapsed_time, cpu_usage, mem_usage = run_command(command)
    if success:
        messagebox.showinfo("Success", f"{algorithm} encrypted message extracted in {elapsed_time:.2f} seconds.")
        update_metrics("Extract Message", algorithm, elapsed_time, cpu_usage, mem_usage)

def decrypt_message(algorithm):
    if algorithm == "RSA":
        command = "python rsa_decrypt.py rsa_extracted_message.bin rsa_private_key.pem rsa_decrypted_message.txt"
    elif algorithm == "ECC":
        command = "python ecc_decrypt.py ecc_extracted_message.bin ecc_private_key.pem ecc_decrypted_message.txt"

    success, elapsed_time, cpu_usage, mem_usage = run_command(command)
    if success:
        messagebox.showinfo("Success", f"{algorithm} message decrypted in {elapsed_time:.2f} seconds.")
        update_metrics("Decrypt Message", algorithm, elapsed_time, cpu_usage, mem_usage)
        with open(f"{algorithm.lower()}_decrypted_message.txt", "r") as f:
            decrypted_message = f.read()
        log_process(f"{algorithm} Decrypted Message: {decrypted_message}")

def update_metrics(operation, algorithm, elapsed_time, cpu_usage, mem_usage):
    if algorithm == "RSA":
        rsa_metrics[operation] = (elapsed_time, cpu_usage, mem_usage)
    elif algorithm == "ECC":
        ecc_metrics[operation] = (elapsed_time, cpu_usage, mem_usage)
    display_metrics()

def display_metrics():
    for widget in metrics_frame.winfo_children():
        widget.destroy()

    tk.Label(metrics_frame, text="Operation", borderwidth=2, relief="groove", font=("Arial", 10, "bold")).grid(row=0, column=0, sticky="nsew")
    tk.Label(metrics_frame, text="RSA Time (s)", borderwidth=2, relief="groove", font=("Arial", 10, "bold")).grid(row=0, column=1, sticky="nsew")
    tk.Label(metrics_frame, text="RSA CPU (ms)", borderwidth=2, relief="groove", font=("Arial", 10, "bold")).grid(row=0, column=2, sticky="nsew")
    tk.Label(metrics_frame, text="RSA Memory (bytes)", borderwidth=2, relief="groove", font=("Arial", 10, "bold")).grid(row=0, column=3, sticky="nsew")
    tk.Label(metrics_frame, text="ECC Time (s)", borderwidth=2, relief="groove", font=("Arial", 10, "bold")).grid(row=0, column=4, sticky="nsew")
    tk.Label(metrics_frame, text="ECC CPU (ms)", borderwidth=2, relief="groove", font=("Arial", 10, "bold")).grid(row=0, column=5, sticky="nsew")
    tk.Label(metrics_frame, text="ECC Memory (bytes)", borderwidth=2, relief="groove", font=("Arial", 10, "bold")).grid(row=0, column=6, sticky="nsew")

    row = 1
    for operation in set(rsa_metrics.keys()).union(ecc_metrics.keys()):
        tk.Label(metrics_frame, text=operation, borderwidth=2, relief="groove", font=("Arial", 10)).grid(row=row, column=0, sticky="nsew")
        rsa_data = rsa_metrics.get(operation, ('N/A', 'N/A', 'N/A'))
        ecc_data = ecc_metrics.get(operation, ('N/A', 'N/A', 'N/A'))
        tk.Label(metrics_frame, text=f"{rsa_data[0]:.2f}" if isinstance(rsa_data[0], float) else rsa_data[0], borderwidth=2, relief="groove", font=("Arial", 10)).grid(row=row, column=1, sticky="nsew")
        tk.Label(metrics_frame, text=f"{rsa_data[1]:.2f}" if isinstance(rsa_data[1], float) else rsa_data[1], borderwidth=2, relief="groove", font=("Arial", 10)).grid(row=row, column=2, sticky="nsew")
        tk.Label(metrics_frame, text=f"{rsa_data[2]:.0f}" if isinstance(rsa_data[2], float) else rsa_data[2], borderwidth=2, relief="groove", font=("Arial", 10)).grid(row=row, column=3, sticky="nsew")
        tk.Label(metrics_frame, text=f"{ecc_data[0]:.2f}" if isinstance(ecc_data[0], float) else ecc_data[0], borderwidth=2, relief="groove", font=("Arial", 10)).grid(row=row, column=4, sticky="nsew")
        tk.Label(metrics_frame, text=f"{ecc_data[1]:.2f}" if isinstance(ecc_data[1], float) else ecc_data[1], borderwidth=2, relief="groove", font=("Arial", 10)).grid(row=row, column=5, sticky="nsew")
        tk.Label(metrics_frame, text=f"{ecc_data[2]:.0f}" if isinstance(ecc_data[2], float) else ecc_data[2], borderwidth=2, relief="groove", font=("Arial", 10)).grid(row=row, column=6, sticky="nsew")
        row += 1

app = tk.Tk()
app.title("Encryption App with Performance Metrics")

style = ttk.Style()
style.configure("TButton", font=("Arial", 10, "bold"), padding=10)
style.configure("TLabel", font=("Arial", 10), padding=10)

frame = tk.Frame(app)
frame.grid(row=0, column=0, padx=20, pady=20, sticky="n")

message_frame = tk.Frame(app)
message_frame.grid(row=0, column=1, padx=20, pady=20, sticky="n")

metrics_frame = tk.Frame(app)
metrics_frame.grid(row=1, column=0, columnspan=3, padx=20, pady=20, sticky="nsew")

process_log_frame = tk.Frame(app)
process_log_frame.grid(row=0, column=2, padx=20, pady=20, sticky="n")

message_label = ttk.Label(message_frame, text="Enter Secret Message:", font=("Arial", 10, "bold"))
message_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")

message_entry = tk.Text(message_frame, height=5, width=40, font=("Arial", 10))
message_entry.grid(row=1, column=0, padx=10, pady=5)

generate_keys_btn = ttk.Button(frame, text="Generate Keys", command=generate_keys)
generate_keys_btn.grid(row=0, column=0, padx=10, pady=5)

rsa_encrypt_btn = ttk.Button(frame, text="Encrypt Message (RSA)", command=lambda: encrypt_message("RSA"))
rsa_encrypt_btn.grid(row=1, column=0, padx=10, pady=5)

ecc_encrypt_btn = ttk.Button(frame, text="Encrypt Message (ECC)", command=lambda: encrypt_message("ECC"))
ecc_encrypt_btn.grid(row=2, column=0, padx=10, pady=5)

rsa_embed_btn = ttk.Button(frame, text="Embed Message (RSA)", command=lambda: embed_message("RSA"))
rsa_embed_btn.grid(row=3, column=0, padx=10, pady=5)

ecc_embed_btn = ttk.Button(frame, text="Embed Message (ECC)", command=lambda: embed_message("ECC"))
ecc_embed_btn.grid(row=4, column=0, padx=10, pady=5)

rsa_extract_btn = ttk.Button(frame, text="Extract Message (RSA)", command=lambda: extract_message("RSA"))
rsa_extract_btn.grid(row=5, column=0, padx=10, pady=5)

ecc_extract_btn = ttk.Button(frame, text="Extract Message (ECC)", command=lambda: extract_message("ECC"))
ecc_extract_btn.grid(row=6, column=0, padx=10, pady=5)

rsa_decrypt_btn = ttk.Button(frame, text="Decrypt Message (RSA)", command=lambda: decrypt_message("RSA"))
rsa_decrypt_btn.grid(row=7, column=0, padx=10, pady=5)

ecc_decrypt_btn = ttk.Button(frame, text="Decrypt Message (ECC)", command=lambda: decrypt_message("ECC"))
ecc_decrypt_btn.grid(row=8, column=0, padx=10, pady=5)

process_log_label = ttk.Label(process_log_frame, text="Process Log:", font=("Arial", 10, "bold"))
process_log_label.pack(anchor="w")

process_log_scrollbar = tk.Scrollbar(process_log_frame)
process_log_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

process_log = tk.Text(process_log_frame, height=30, width=100, font=("Arial", 10), state=tk.DISABLED, yscrollcommand=process_log_scrollbar.set)
process_log.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

process_log_scrollbar.config(command=process_log.yview)

rsa_metrics = {}
ecc_metrics = {}

app.mainloop()

