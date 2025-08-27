# ----------------------------------------------------------------------
#  Copyright (c) 2024 Rayan Zayat
#  All Rights Reserved.
#
#  Author: Rayan Zayat (rayanzayat.com)
#  Description: This code is developed and maintained by Rayan Zayat.
#
#  License:
#  You are free to use, modify, and distribute this code for personal or
#  educational purposes, as long as you credit Rayan Zayat as the original author.
#
#  Recommended citation or credit in your project:
#     "Code adapted from Rayan Zayat (rayanzayat.com), 2024"
#
#  Contact: contact@rayanzayat.com
#           rayan.zayat4@gmail.com
# ----------------------------------------------------------------------

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
from scapy.layers.inet import IPOption_Timestamp as Timestamp, UDP, IP
import tkinter as tk
from tkinter import ttk
import ttkbootstrap as ttk
from colorama import Fore, init
import math
import time
import threading
import socket
import rsa


# Generating an RSA key pair
public_key, private_key = rsa.newkeys(512)
global public_key_partner

# Initializing colorama in Windows OS
init()

# Shared variables
l4protocol = UDP
port = 34152  # random allowed port

# Some variables for the receiver side
text = ""
packets_num = 0


# --------------------------------------Exchanging Public keys--------------------------------------


def initialize_connection():
    global public_key, private_key, public_key_partner

    # Disabling options and its associated button
    client_option.configure(state='disabled')
    server_option.configure(state='disabled')
    initialize_connection_button.configure(state='disabled')

    if my_choice.get() == "server":
        # Establishing server's socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server_socket.bind((source_string.get(), port))

        # Receiving the partner's Public key
        public_key_partner, _ = server_socket.recvfrom(1024)
        public_key_partner = rsa.PublicKey.load_pkcs1(public_key_partner)

        # Sending the server's Public key
        server_socket.sendto(public_key.save_pkcs1("PEM"), (destination_string.get(), port))

        print("Public keys exchange process - DONE")
        # Displaying "End-to-End Encrypted" label
        e2e_encrypted_label.grid(row=8, column=0, columnspan=5, pady=10)

        server_socket.close()

        # Activating check_length function to check if a message is too long
        threading.Thread(target=check_length).start()


    elif my_choice.get() == "client":
        # Establishing client's socket
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.bind((source_string.get(), port))

        # Sending client's Public key
        client.sendto(public_key.save_pkcs1("PEM"), (destination_string.get(), port))

        # Receiving the partner's Public key
        public_key_partner, _ = client.recvfrom(1024)
        public_key_partner = rsa.PublicKey.load_pkcs1(public_key_partner)

        print("Public keys exchange process - DONE")
        # Displaying "End-to-End Encrypted" label
        e2e_encrypted_label.grid(row=8, column=0, columnspan=5, pady=10)

        client.close()

        # Activating check_length function to check if a message is too long
        threading.Thread(target=check_length).start()


# --------------------------------------End of Public Key Exchange process--------------------------------------

def send_message():
    if chat_message.get():
        threading.Thread(target=sending_message).start()


def sending_message():
    # Deactivating the send button
    chat_send_button.configure(state='disabled')

    # Processing the message
    sending_message = chat_message.get()
    encrypted_message = rsa.encrypt(sending_message.encode(), public_key_partner)
    # Converting the RSA encrypted message to binary
    encoded_message = ''.join(format(char, '08b') for char in encrypted_message) #meaning
    string_list = [encoded_message[i:i + 4] for i in range(0, len(encoded_message), 4)] #meaning

    # Removing the text from the message entry
    chat_message.delete(0, tk.END)

    message_length = str(math.ceil(len(string_list) / 5))  # Converted to String to use encode method
    # Sending how many packets to receive
    encrypted_message_length = rsa.encrypt(message_length.encode(), public_key_partner)
    send(IP(src=source_string.get(), dst=destination_string.get())/l4protocol(sport=port, dport=port)/encrypted_message_length, verbose=False, iface=conf.iface)
    time.sleep(1)

    # Assigning overflow field values and sending packets
    for i in range(0, len(string_list), 5):
        # Making a list of 5 timestamps for each packet
        times = 0
        timestamp_list = []
        while times < 5:
            if i + times < len(string_list):
                timestamp_list.append(Timestamp(oflw=int(string_list[i + times], 2), flg=0))
                times += 1
            else:
                break

        # Crafting and sending packets
        packet = IP(src=source_string.get(), dst=destination_string.get(), options=timestamp_list)/l4protocol(sport=port, dport=port)
        send(packet, verbose=False, iface=conf.iface)
        # A break between packets
        time.sleep(0.2)  # 0.2s

    # Displaying the message on the sender side
    chat_box.configure(state='normal')
    chat_box.insert(tk.END, "You: " + sending_message)
    chat_box.insert(tk.END, f'\n{"-" * 106}\n')
    # Automatically scroll down
    chat_box.see(tk.END)
    chat_box.configure(state='disabled')
    # Activating the send button
    chat_send_button.configure(state='normal')


def receive():
    # Hiding some of the GUI elements when clicking "initialize connection" button
    source_label.grid_forget()
    source_entry.grid_forget()
    destination_label.grid_forget()
    destination_entry.grid_forget()
    client_option.grid_forget()
    server_option.grid_forget()
    initialize_connection_button.grid_forget()
    # Changing window size
    window.geometry("800x600")

    # Start receiving
    threading.Thread(target=receiving_message).start()


def receiving_message():
    print("Initializing connection..")
    initialize_connection()
    print("Start receiving...")
    # Displaying sending and receiving elements
    chat_box_frame.pack()
    send_frame.pack(pady=10)

    while True:
        global chat_box, text
        text = ""
        # Receiving the message length
        sniff(lfilter=filtering, prn=packet_callback_length, count=1, iface=conf.iface)
        # Deactivating "Send" button
        chat_send_button.configure(state='disabled')
        # A break between two sniffing process
        time.sleep(0.5)

        # Making output text green
        print(f"{Fore.GREEN}Message length is received: ", packets_num)

        # Receiving the message
        sniff(lfilter=filtering, prn=packet_callback, count=int(packets_num), iface=conf.iface, timeout=10)

        # Reassembling, converting to integers then bytes, decrypting, and printing then eventually displaying the message
        # Converting to integers
        encrypted_message = int(text, 2)
        # Converting to bytes
        encrypted_message = encrypted_message.to_bytes((encrypted_message.bit_length() + 7) // 8, 'big')
        # Decrypting the message
        decrypted_message = rsa.decrypt(encrypted_message, private_key).decode()
        print("Here's the message: ", decrypted_message)

        # Activating the send button
        chat_send_button.configure(state='normal')
        # Displaying the message
        chat_box.configure(state='normal')
        chat_box.insert(tk.END, "Partner: " + decrypted_message)
        chat_box.insert(tk.END, f'\n{"-" * 106}\n')
        # Automatically scroll down
        chat_box.see(tk.END)
        chat_box.configure(state='disabled')


def packet_callback_length(packet):
    global packets_num
    packets_num = rsa.decrypt(packet.lastlayer().load, private_key).decode()


def packet_callback(packet):
    global text
    for i in range(len(packet.getlayer(IP).options)):
        if i >= 5:
            break
        text += bin(packet.getlayer(IP).options[i].oflw).replace('0b', '').rjust(4, '0')


def filtering(packet):
    if packet.haslayer(IP):
        if packet.haslayer(l4protocol) and packet.getlayer(IP).src != source_string.get():
            return packet.getlayer(l4protocol).dport == port


def who_are_you():
    whoyouare_label.configure(text=f"You're the {my_choice.get()}")
    # Activating "initialize connection" button
    initialize_connection_button.configure(state='normal')


def check_length():
    global chat_message
    while True:
        time.sleep(0.5)
        if chat_message.get():
            # 53 is the limit with (512) RSA keys
            if len(chat_message.get()) > 53:
                warning_label.pack(side='left')
            else:
                warning_label.pack_forget()


# ----------------------------------------Graphical User Interface & Main----------------------------------------


if __name__ == "__main__":
    try:
        window = ttk.Window(themename='darkly')
        window.resizable(False, False)
        window.title("Network Steganography")
        window.geometry("800x400")

        # Heading
        chat_label = ttk.Label(master=window, text='Secret Chat', font='Calibri 20 bold')
        chat_label.pack(pady=(20,10))

        # Main frame
        main_frame = ttk.Frame()
        main_frame.pack(fill='x', pady=20, padx=70)

        # ----------------------------

        # Source IP address
        source_label = ttk.Label(master=main_frame, text='Source IP address', font='Calibri 11 bold', style='info')
        source_label.grid(row=0, column=0, columnspan=3, pady=5, padx=(0,70))

        source_string = ttk.StringVar(value=get_if_addr(conf.iface))
        source_entry = ttk.Entry(master=main_frame, text=source_string)
        source_entry.grid(row=0, column=3, columnspan=3, pady=5)

        # ----------------------------

        # Destination IP address
        destination_label = ttk.Label(master=main_frame, text='Destination IP address', font='Calibri 11 bold', style='info')
        destination_label.grid(row=1, column=0, columnspan=3, padx=(0,40))

        destination_string = ttk.StringVar(value="192.168.1.1")
        destination_entry = ttk.Entry(master=main_frame, text=destination_string)
        destination_entry.grid(row=1, column=3, columnspan=3)

        # ----------------------------

        # Choosing to be {client | server}
        whoyouare_label = ttk.Label(master=main_frame, text="Please select who you are!", font='montserrat 9 bold')
        whoyouare_label.grid(row=5, column=0, columnspan=3, pady=(15, 5), padx=(0, 5))

        my_choice = tk.StringVar()
        client_option = ttk.Radiobutton(master=main_frame, variable=my_choice, text="Client", value="client", bootstyle="info.Outline.Toolbutton", command=who_are_you)
        server_option = ttk.Radiobutton(master=main_frame, variable=my_choice, text="Server", value="server", bootstyle="info.Outline.Toolbutton", command=who_are_you)
        client_option.grid(row=6, column=0, pady=5, padx=(0,20))
        server_option.grid(row=6, column=1, pady=5, padx=(0,50))

        # ----------------------------

        initialize_connection_button = ttk.Button(master=main_frame, text="Initialize connection", width=45, command=receive)
        initialize_connection_button.grid(row=7, column=0, columnspan=6, pady=(20,0))
        initialize_connection_button.configure(state='disabled')

        e2e_encrypted_label = ttk.Label(master=main_frame, text="End-to-end encrypted", bootstyle='info', font='montserrat 10 bold')

        # ----------------------------

        # Chat box structure
        chat_box_frame = ttk.Frame()
        chat_box_frame.pack_forget()

        scrollbar = ttk.Scrollbar(chat_box_frame, orient='vertical', style='info')
        scrollbar.pack(side=ttk.RIGHT, fill='y')

        chat_box = ttk.Text(master=chat_box_frame, state='disabled', height=15, yscrollcommand=scrollbar.set)
        chat_box.pack()
        scrollbar.config(command=chat_box.yview)

        # ----------------------------

        # Sending messages section
        send_frame = ttk.Frame()
        send_frame.pack_forget()

        chat_message = ttk.Entry(master=send_frame, width=40)
        chat_message.pack(side='left', padx=75)

        chat_send_button = ttk.Button(master=send_frame, text='Send', command=send_message, width=40, style='info-outline')
        chat_send_button.pack(side='right', padx=75)

        # ----------------------------

        # Message length checker frame
        warning_frame = ttk.Frame()
        warning_frame.pack(fill='x', padx=75)

        warning_label = ttk.Label(master=warning_frame, text="The message is too long!!", foreground="red")

        # ----------------------------

        # Start the application & loop forever until the user exits the window
        window.mainloop()

    except Exception:
        exit()

