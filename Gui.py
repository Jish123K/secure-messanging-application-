import tkinter as tk

class SecureMessagingApp(tk.Tk):

    def __init__(self):

        super().__init__()

        # Create the main window

        self.main_window = tk.Frame(self)

        self.main_window.pack(side="top", fill="both", expand=True)

        # Create the username label

        self.username_label = tk.Label(self.main_window, text="Username:")

        self.username_label.pack(side="left")

        # Create the username entry box

        self.username_entry = tk.Entry(self.main_window)

        self.username_entry.pack(side="left")

        # Create the password label

        self.password_label = tk.Label(self.main_window, text="Password:")

        self.password_label.pack(side="left")

        # Create the password entry box

        self.password_entry = tk.Entry(self.main_window, show="*")

        self.password_entry.pack(side="left")

        # Create the connect button

        self.connect_button = tk.Button(self.main_window, text="Connect", command=self.connect)

        self.connect_button.pack(side="left")

        # Create the disconnect button

        self.disconnect_button = tk.Button(self.main_window, text="Disconnect", command=self.disconnect)

        self.disconnect_button.pack(side="left")

        # Create the message entry box

        self.message_entry = tk.Entry(self.main_window)

        self.message_entry.pack(side="left")

        # Create the send button

        self.send_button = tk.Button(self.main_window, text="Send", command=self.send_message)

        self.send_button.pack(side="left")
# Create the listbox for displaying messages

        self.messages_listbox = tk.Listbox(self.main_window)

        self.messages_listbox.pack(side="left", fill="both", expand=True)

        # Create the scrollbar for the listbox

        self.messages_scrollbar = tk.Scrollbar(self.main_window, orient="vertical", command=self.messages_listbox.yview)

        self.messages_scrollbar.pack(side="right", fill="y")

        self.messages_listbox.config(yscrollcommand=self.messages_scrollbar.set)

        # Create the status bar

        self.status_bar = tk.Label(self.main_window, text="Status:")

        self.status_bar.pack(side="bottom", fill="x")

        # Initialize the application

        self.initialize()

    def initialize(self):

        # Set the username and password

        self.username = ""

        self.password = ""

        # Connect to the server

        self.connect()

    def connect(self):

        # Connect to the server using the username and password

        try:

            self.client = SecureMessagingClient(self.username, self.password)

            self.status_bar.config(text="Connected")

        except Exception as e:

            self.status_bar.config(text="Error: {}".format(e))

    def disconnect(self):

        # Disconnect from the server

        try:

            self.client.close()

            self.status_bar.config(text="Disconnected")

        except Exception as e:

            self.status_bar.config(text="Error: {}".format(e))

    def send_message(self):

        # Send the message to the server

        try:
                 message = self.message_entry.get()

            self.client.send_message(message)

            self.messages_listbox.insert(tk.END, message)

            self.message_entry.delete(0, tk.END)

        except Exception as e:

            self.status_bar.config(text="Error: {}".format(e))
            class SecureMessagingClient:

    def __init__(self, username, password):

        self.username = username

        self.password = password

        # Generate a public and private key pair

        self.public_key, self.private_key = rsa.generate_keys(2048, default_backend())

        # Connect to the server

        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.server.connect(("localhost", 5000))

        # Authenticate with the server

        self.authenticate(self.username, self.password)

        # Start the message loop

        self.start_message_loop()

    def authenticate(self, username, password):

        # Encrypt the password using the server's public key

        encrypted_password = self.encrypt_message(password, self.server.public_key)

        # Send the encrypted password to the server

        self.server.sendall(encrypted_password)

        # Receive the server's response

        response = self.server.recv(1024)

        # If the server's response is "OK", then the authentication was successful

        if response == "OK":

            return True

        else:

            return False

    def start_message_loop(self):

        while True:

            # Receive a message from the server

            message = self.server.recv(1024)

            # If the message is empty, then the server has closed the connection

            if not message:

                break
                # Decrypt the message using the client's private key

            decrypted_message = self.decrypt_message(message, self.private_key)

            # Display the message

            self.messages_listbox.insert(tk.END, decrypted_message)

    def send_message(self, message):

        # Encrypt the message using the server's public key

        encrypted_message = self.encrypt_message(message, self.server.public_key)

        # Send the encrypted message to the server

        self.server.sendall(encrypted_message)

    def encrypt_message(self, message, public_key):

        # Encrypt the message using the public key

        cipher = Cipher(algorithms.AES(128), modes.CBC, default_backend())

        encryptor = cipher.encryptor()

        encrypted_message = encryptor.update(message) + encryptor.finalize()

        return encrypted_message

    def decrypt_message(self, encrypted_message, private_key):

        # Decrypt the message using the private key

        cipher = Cipher(algorithms.AES(128), modes.CBC, default_backend())

        decryptor = cipher.decryptor()

        decrypted_message = decryptor.update(encrypted_message) + decryptor.finalize()

        return decrypted_message

    def close(self):

        # Close the connection to the server

        self.server.close()

if __name__ == "__main__":

    # Create the application

    app = SecureMessagingApp()

    app.mainloop()
