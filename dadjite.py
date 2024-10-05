import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk
import subprocess
import threading
import os
import re

# Function to validate the IP address
def validate_ip(ip):
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return pattern.match(ip)

# Function to check if the userdb and passdb files exist
def validate_files(userdb, passdb):
    return os.path.isfile(userdb) and os.path.isfile(passdb)

# Function to save the results in a text file
def save_results_to_file(output):
    with open("brute_force_results.txt", "w") as f:
        f.write(output)

# Function to get the command based on the protocol and provided parameters
def get_command(protocol, userdb, passdb, ip_address, port):
    default_ports = {
        "FTP": "21", "SSH": "22", "TELNET": "23",
        "SMB": "445", "POSTGRESQL": "5432",
        "MYSQL": "3306", "MS-SQL": "1433",
    }
    port = port if port else default_ports.get(protocol)
    commands = {
        "FTP": f"nmap -p{port} --script ftp-brute.nse --script-args userdb={userdb},passdb={passdb} {ip_address}",
        "SSH": f"nmap -p{port} --script ssh-brute.nse --script-args userdb={userdb},passdb={passdb} {ip_address}",
        "TELNET": f"nmap -p{port} --script telnet-brute.nse --script-args userdb={userdb},passdb={passdb} {ip_address}",
        "SMB": f"nmap -p{port} --script smb-brute.nse --script-args userdb={userdb},passdb={passdb} {ip_address}",
        "POSTGRESQL": f"nmap -p{port} --script pgsql-brute --script-args userdb={userdb},passdb={passdb} {ip_address}",
        "MYSQL": f"nmap -p{port} --script mysql-brute --script-args userdb={userdb},passdb={passdb} {ip_address}",
        "MS-SQL": f"nmap -p{port} --script ms-sql-brute --script-args userdb={userdb},passdb={passdb} {ip_address}",
    }
    return commands.get(protocol)

# Main function to run the brute force attack
def run_brute_force():
    protocol = protocol_var.get()
    ip_address = ip_entry.get()
    userdb = userdb_entry.get()
    passdb = passdb_entry.get()
    port = port_entry.get()

    if not ip_address or not userdb or not passdb:
        messagebox.showerror("Input Error", "Please fill in all fields.")
        return

    if not validate_ip(ip_address):
        messagebox.showerror("IP Error", "Please enter a valid IP address.")
        return

    if not validate_files(userdb, passdb):
        messagebox.showerror("File Error", "UserDB or PassDB files not found.")
        return

    command = get_command(protocol, userdb, passdb, ip_address, port)
    
    if command:
        try:
            progress_bar.grid(row=3, column=0, columnspan=7, pady=10)
            root.update_idletasks()
            output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
            result_text.delete(1.0, tk.END)
            output_decoded = output.decode()
            filtered_output = "\n".join([line for line in output_decoded.splitlines() if "Valid credentials" in line])
            
            # Display the filtered result in the text box with new formatting
            result_text.tag_configure('style', foreground='green', font=("Helvetica", 12, "bold"))
            result_text.insert(tk.END, filtered_output if filtered_output else "No 'Valid credentials' found.", 'style')  
            
            save_results_to_file(filtered_output)  
        except subprocess.CalledProcessError as e:
            result_text.delete(1.0, tk.END)
            result_text.insert(tk.END, e.output.decode())
            save_results_to_file(e.output.decode())
        finally:
            progress_bar.grid_forget()
    else:
        messagebox.showerror("Selection Error", "Please select a valid protocol.")

# Function to run the command in a separate thread
def run_brute_force_threaded():
    threading.Thread(target=run_brute_force).start()

# Function to limit the port entry to 4 digits
def validate_port_entry(char):
    return len(char) <= 4 and char.isdigit()

# Function to clear all input fields and the result box
def clear_fields():
    ip_entry.delete(0, tk.END)
    userdb_entry.delete(0, tk.END)
    passdb_entry.delete(0, tk.END)
    port_entry.delete(0, tk.END)
    result_text.delete(1.0, tk.END)
    protocol_var.set("Select Protocol")

# GUI configuration
root = tk.Tk()
root.title("Brute Force Tool")
root.geometry("700x500")
root.configure(bg="black")

protocol_var = tk.StringVar(value="Select Protocol")
protocols = ["FTP", "SSH", "TELNET", "SMB", "POSTGRESQL", "MYSQL", "MS-SQL"]

# Protocol dropdown menu
protocol_menu = tk.OptionMenu(root, protocol_var, *protocols)
protocol_menu.grid(row=0, column=0, padx=5, pady=5)
protocol_menu.config(bg="#FF3F3F", fg="white", font=("Helvetica", 10, "bold"))

# IP Address input
ip_label = tk.Label(root, text="IP:", bg="black", fg="white", font=("Helvetica", 10, "bold"))  # Made bold
ip_label.grid(row=0, column=1, padx=5, pady=5)

ip_entry = tk.Entry(root, font=("Helvetica", 10, "bold"))  # Made bold
ip_entry.grid(row=0, column=2, padx=5, pady=5)

# UserDB input
userdb_label = tk.Label(root, text="UserDB:", bg="black", fg="white", font=("Helvetica", 10, "bold"))  # Made bold
userdb_label.grid(row=0, column=3, padx=5, pady=5)

userdb_entry = tk.Entry(root, font=("Helvetica", 10, "bold"))  # Made bold
userdb_entry.grid(row=0, column=4, padx=5, pady=5)

# PassDB input
passdb_label = tk.Label(root, text="PassDB:", bg="black", fg="white", font=("Helvetica", 10, "bold"))  # Made bold
passdb_label.grid(row=0, column=5, padx=5, pady=5)

passdb_entry = tk.Entry(root, font=("Helvetica", 10, "bold"))  # Made bold
passdb_entry.grid(row=0, column=6, padx=5, pady=5)

# Port input (with validation)
port_label = tk.Label(root, text="Port (optional):", bg="black", fg="white", font=("Helvetica", 10, "bold"))  # Made bold
port_label.grid(row=0, column=7, padx=5, pady=5)

validate_port_cmd = (root.register(validate_port_entry), '%P')
port_entry = tk.Entry(root, width=5, validate="key", validatecommand=validate_port_cmd, font=("Helvetica", 10, "bold"))  # Made bold
port_entry.grid(row=0, column=8, padx=5, pady=5)

# Run Brute Force button
run_button = tk.Button(root, text="Run Brute Force", command=run_brute_force_threaded, bg="#FF3F3F", fg="white", font=("Helvetica", 12, "bold"))
run_button.grid(row=1, column=0, columnspan=9, pady=20)

# Result display area
result_text = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=50, height=8, bg="black", fg="white", font=("Helvetica", 10))
result_text.grid(row=2, column=0, columnspan=9, pady=10)

# Clear button
clear_button = tk.Button(root, text="Clear", command=clear_fields, bg="#FF3F3F", fg="white", font=("Helvetica", 12, "bold"))
clear_button.grid(row=3, column=0, columnspan=9, pady=10)

# Progress bar
progress_bar = ttk.Progressbar(root, mode='indeterminate')

# Update the window layout
root.update_idletasks()
root.geometry("")

root.mainloop()

