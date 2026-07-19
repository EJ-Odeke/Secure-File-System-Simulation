import tkinter as tk
from tkinter import messagebox

from auth.auth import (
    register_user,
    match_user
)

from auth.admin import (
    is_admin
)


PASSWORD_FILE = "database/passwd"



# =====================================================
# LOGIN WINDOW
# =====================================================

class LoginWindow:


    def __init__(
        self,
        root
    ):

        self.root = root

        self.root.title(
            "SEFS Login"
        )

        self.root.geometry(
            "400x350"
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



        tk.Label(
            self.root,
            text="Username"
        ).pack()


        self.username_entry = tk.Entry(
            self.root
        )


        self.username_entry.pack()



        tk.Label(
            self.root,
            text="Password"
        ).pack()



        self.password_entry = tk.Entry(
            self.root,
            show="*"
        )


        self.password_entry.pack()



        login_button = tk.Button(
            self.root,
            text="Login",
            width=20,
            command=self.login
        )


        login_button.pack(
            pady=10
        )



        register_button = tk.Button(
            self.root,
            text="Register User",
            width=20,
            command=self.register
        )


        register_button.pack()



    # =================================================
    # LOGIN
    # =================================================

    def login(self):


        username = self.username_entry.get()

        password = self.password_entry.get()



        result = match_user(
            username,
            password,
            PASSWORD_FILE
        )



        if result != 1:


            messagebox.showerror(
                "Login Failed",
                "Invalid username or password"
            )

            return



        messagebox.showinfo(
            "Success",
            "Login successful"
        )



        self.root.destroy()



        if is_admin(
            username
        ):


            from gui.admin_dashboard import AdminDashboard


            root = tk.Tk()


            AdminDashboard(
                root,
                username,
                password
            )


            root.mainloop()



        else:


            from gui.dashboard import Dashboard


            root = tk.Tk()


            Dashboard(
                root,
                username,
                password
            )


            root.mainloop()




    # =================================================
    # REGISTER
    # =================================================

    def register(self):


        username = self.username_entry.get()

        password = self.password_entry.get()



        if username == "" or password == "":


            messagebox.showerror(
                "Error",
                "Enter username and password"
            )


            return



        result = register_user(
            username,
            password,
            PASSWORD_FILE
        )



        if result == 1:


            messagebox.showinfo(
                "Success",
                "User created successfully"
            )


        else:


            messagebox.showerror(
                "Error",
                "User creation failed"
            )




# =====================================================
# START LOGIN
# =====================================================

def start_login():


    root = tk.Tk()


    LoginWindow(
        root
    )


    root.mainloop()



if __name__ == "__main__":

    start_login()