import tkinter as tk
from tkinter import messagebox, simpledialog

from auth.admin import (
    admin_create_user,
    admin_delete_user,
    admin_change_password
)

from auth.auth import read_users



PASSWORD_FILE = "database/passwd"



# =====================================================
# ADMIN DASHBOARD
# =====================================================

class AdminDashboard:


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
            "SEFS Admin Dashboard"
        )


        self.root.geometry(
            "450x500"
        )


        self.create_widgets()



    # =================================================
    # GUI
    # =================================================

    def create_widgets(self):


        title = tk.Label(
            self.root,
            text="SEFS ADMIN PANEL",
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
            text=f"Admin: {self.username}"
        )


        user.pack()



        buttons = [

            (
                "Create User",
                self.create_user
            ),

            (
                "Delete User",
                self.delete_user
            ),

            (
                "Change User Password",
                self.change_password
            ),

            (
                "View Users",
                self.view_users
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
                pady=8
            )




    # =================================================
    # CREATE USER
    # =================================================

    def create_user(self):


        username = simpledialog.askstring(
            "Create User",
            "New username:"
        )


        password = simpledialog.askstring(
            "Create User",
            "Password:",
            show="*"
        )



        if username and password:


            result = admin_create_user(
                self.username,
                username,
                password
            )


            if result == 1:


                messagebox.showinfo(
                    "Success",
                    "User created"
                )


            else:


                messagebox.showerror(
                    "Error",
                    "Could not create user"
                )




    # =================================================
    # DELETE USER
    # =================================================

    def delete_user(self):


        username = simpledialog.askstring(
            "Delete User",
            "Username:"
        )


        password = simpledialog.askstring(
            "Delete User",
            "User password:",
            show="*"
        )



        if username and password:


            result = admin_delete_user(
                self.username,
                username,
                password
            )



            if result == 1:


                messagebox.showinfo(
                    "Success",
                    "User deleted"
                )


            else:


                messagebox.showerror(
                    "Error",
                    "Delete failed"
                )




    # =================================================
    # CHANGE PASSWORD
    # =================================================

    def change_password(self):


        username = simpledialog.askstring(
            "Change Password",
            "Username:"
        )


        old_password = simpledialog.askstring(
            "Old Password",
            "Old password:",
            show="*"
        )


        new_password = simpledialog.askstring(
            "New Password",
            "New password:",
            show="*"
        )



        if username and old_password and new_password:


            result = admin_change_password(
                self.username,
                username,
                old_password,
                new_password
            )



            if result == 1:


                messagebox.showinfo(
                    "Success",
                    "Password changed"
                )


            else:


                messagebox.showerror(
                    "Error",
                    "Password change failed"
                )




    # =================================================
    # VIEW USERS
    # =================================================

    def view_users(self):


        users = read_users(
            PASSWORD_FILE
        )


        names = []


        for user in users:

            names.append(
                user[0]
            )



        messagebox.showinfo(
            "Users",
            "\n".join(names)
        )




    # =================================================
    # LOGOUT
    # =================================================

    def logout(self):


        self.root.destroy()



        from gui.login import start_login


        start_login()