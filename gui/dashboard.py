import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog

from filesystem.full_sefs import (
    create_file,
    encrypt_file,
    decrypt_file,
    read_from_file,
    write_to_file,
    file_size,
    delete_file,
    file_integrity_check,
    system_health_check
)



# =====================================================
# USER DASHBOARD
# =====================================================

class Dashboard:


    def __init__(
        self,
        root,
        username,
        password
    ):

        self.root = root

        self.username = username

        self.password = password


        self.root.title(
            "SEFS User Dashboard"
        )


        self.root.geometry(
            "500x650"
        )


        self.create_widgets()



    # =================================================
    # GUI
    # =================================================

    def create_widgets(self):


        title = tk.Label(
            self.root,
            text="Secure Encrypted File System",
            font=(
                "Arial",
                16,
                "bold"
            )
        )


        title.pack(
            pady=20
        )


        user = tk.Label(
            self.root,
            text=f"User: {self.username}"
        )


        user.pack()



        buttons = [

            (
                "Create SEFS File",
                self.create_file_gui
            ),

            (
                "Encrypt File",
                self.encrypt_gui
            ),

            (
                "Decrypt File",
                self.decrypt_gui
            ),

            (
                "Read File",
                self.read_gui
            ),

            (
                "Write File",
                self.write_gui
            ),

            (
                "File Size",
                self.size_gui
            ),

            (
                "Integrity Check",
                self.integrity_gui
            ),

            (
                "Delete File",
                self.delete_gui
            ),

            (
                "System Health",
                self.health_gui
            ),

            (
                "Logout",
                self.logout
            )

        ]



        for text, command in buttons:


            button = tk.Button(
                self.root,
                text=text,
                width=25,
                command=command
            )


            button.pack(
                pady=5
            )




    # =================================================
    # CREATE FILE
    # =================================================

    def create_file_gui(self):


        filename = simpledialog.askstring(
            "Create",
            "Filename:"
        )


        if filename:


            result = create_file(
                self.username,
                self.password,
                filename
            )


            messagebox.showinfo(
                "Result",
                str(result)
            )




    # =================================================
    # ENCRYPT
    # =================================================

    def encrypt_gui(self):


        filename = filedialog.askopenfilename()


        if filename:


            result = encrypt_file(
                self.username,
                self.password,
                filename
            )


            messagebox.showinfo(
                "Encryption",
                str(result)
            )




    # =================================================
    # DECRYPT
    # =================================================

    def decrypt_gui(self):


        filename = simpledialog.askstring(
            "Decrypt",
            "SEFS filename:"
        )


        output = filedialog.asksaveasfilename()


        if filename and output:


            result = decrypt_file(
                self.username,
                self.password,
                filename,
                output
            )


            messagebox.showinfo(
                "Decrypt",
                str(result)
            )




    # =================================================
    # READ
    # =================================================

    def read_gui(self):


        filename = simpledialog.askstring(
            "Read",
            "Filename:"
        )


        position = simpledialog.askinteger(
            "Position",
            "Start position:"
        )


        length = simpledialog.askinteger(
            "Length",
            "Number of bytes:"
        )



        data = read_from_file(
            self.username,
            self.password,
            filename,
            position,
            length
        )


        messagebox.showinfo(
            "Data",
            str(data)
        )




    # =================================================
    # WRITE
    # =================================================

    def write_gui(self):


        filename = simpledialog.askstring(
            "Write",
            "Filename:"
        )


        position = simpledialog.askinteger(
            "Position",
            "Position:"
        )


        content = simpledialog.askstring(
            "Content",
            "New content:"
        )



        if content:


            result = write_to_file(
                self.username,
                self.password,
                filename,
                position,
                content.encode()
            )


            messagebox.showinfo(
                "Write",
                str(result)
            )




    # =================================================
    # SIZE
    # =================================================

    def size_gui(self):


        filename = simpledialog.askstring(
            "Size",
            "Filename:"
        )


        result = file_size(
            self.username,
            self.password,
            filename
        )


        messagebox.showinfo(
            "Size",
            str(result)
        )




    # =================================================
    # INTEGRITY
    # =================================================

    def integrity_gui(self):


        filename = simpledialog.askstring(
            "Integrity",
            "Filename:"
        )


        result = file_integrity_check(
            self.username,
            self.password,
            filename
        )


        messagebox.showinfo(
            "Integrity",
            str(result)
        )




    # =================================================
    # DELETE
    # =================================================

    def delete_gui(self):


        filename = simpledialog.askstring(
            "Delete",
            "Filename:"
        )


        result = delete_file(
            self.username,
            self.password,
            filename
        )


        messagebox.showinfo(
            "Delete",
            str(result)
        )




    # =================================================
    # HEALTH
    # =================================================

    def health_gui(self):


        result = system_health_check()


        messagebox.showinfo(
            "Health",
            result
        )




    # =================================================
    # LOGOUT
    # =================================================

    def logout(self):


        self.root.destroy()


        from gui.login import start_login


        start_login()