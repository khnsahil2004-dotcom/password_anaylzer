import tkinter as tk
from tkinter import ttk, messagebox
import math

class PasswordStrengthGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Strength Analyzer")
        self.root.geometry("500x650")
        self.root.resizable(False, False)
        
        # Updated 2024-2025 Most Common Passwords List
        self.common_passwords = [
            "123456", "123456789", "qwerty", "password", "12345",
            "qwerty123", "1q2w3e", "12345678", "111111", "1234567890",
            "1234567", "123123", "000000", "admin", "abc123",
            "password1", "iloveyou", "dragon", "monkey", "sunshine",
            "1234", "123321", "654321", "121212", "555555",
            "7777777", "666666", "222222", "888888", "999999",
            "112233", "123654", "123abc", "qwe123", "asdfgh",
            "zxcvbnm", "1q2w3e4r", "1qaz2wsx", "qazwsx", "asdf1234",
            "welcome", "login", "master", "superman", "letmein",
            "password123", "princess", "football", "baseball", "mustang"
        ]
        
        self.setup_gui()
    
    def setup_gui(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = ttk.Label(main_frame, text="🔒 Password Strength Analyzer", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Password entry
        ttk.Label(main_frame, text="Enter Password:", font=("Arial", 12)).grid(row=1, column=0, sticky=tk.W, pady=5)
        
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(main_frame, textvariable=self.password_var, 
                                       font=("Arial", 12), show="•", width=30)
        self.password_entry.grid(row=1, column=1, pady=5, padx=(10, 0))
        self.password_entry.bind("<KeyRelease>", self.real_time_check)
        
        # Show password checkbox
        self.show_var = tk.IntVar()
        show_check = ttk.Checkbutton(main_frame, text="Show Password", 
                                    variable=self.show_var, command=self.toggle_password_visibility)
        show_check.grid(row=2, column=1, sticky=tk.W, pady=5)
        
        # Buttons frame
        buttons_frame = ttk.Frame(main_frame)
        buttons_frame.grid(row=3, column=0, columnspan=2, pady=20)
        
        # Analyze button
        #analyze_btn = ttk.Button(buttons_frame, text="Analyze Password", command=self.analyze_password)
        #analyze_btn.grid(row=0, column=0, padx=5)
        
        # Approve button
        self.approve_btn = ttk.Button(buttons_frame, text="Approve", command=self.show_approval_result,
                                     state=tk.DISABLED)
        self.approve_btn.grid(row=0, column=1, padx=5)
        
        # Results frame
        results_frame = ttk.LabelFrame(main_frame, text="Analysis Results", padding="10")
        results_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)
        
        # Strength label
        self.strength_label = ttk.Label(results_frame, text="Strength: Not Analyzed", 
                                       font=("Arial", 14, "bold"), foreground="gray")
        self.strength_label.grid(row=0, column=0, sticky=tk.W, pady=5)
        
        # Feedback text
        self.feedback_text = tk.Text(results_frame, height=8, width=50, font=("Arial", 10),
                                    wrap=tk.WORD, state=tk.DISABLED)
        self.feedback_text.grid(row=1, column=0, pady=5)
        
        # Scrollbar for feedback
        scrollbar = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.feedback_text.yview)
        scrollbar.grid(row=1, column=1, sticky=(tk.N, tk.S))
        self.feedback_text.configure(yscrollcommand=scrollbar.set)
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, orient=tk.HORIZONTAL, length=400, mode='determinate')
        self.progress.grid(row=5, column=0, columnspan=2, pady=10)
        
        # Approval Result Frame
        self.approval_frame = ttk.LabelFrame(main_frame, text="Approval Result", padding="10")
        self.approval_frame.grid(row=6, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)
        
        self.approval_label = ttk.Label(self.approval_frame, text="Click 'Approve' to see final result", 
                                       font=("Arial", 12), foreground="gray")
        self.approval_label.grid(row=0, column=0, sticky=tk.W)
        
        # Test examples
        examples_frame = ttk.LabelFrame(main_frame, text="Test Examples", padding="10")
        examples_frame.grid(row=7, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)
        
        examples = [
            "123456 → Very Weak (common)",
            "Password123 → Medium", 
            "Password123! → Strong",
            "P@ssw0rd123!Secure → Very Strong"
        ]
        
        for i, example in enumerate(examples):
            ttk.Label(examples_frame, text=example, font=("Arial", 9)).grid(row=i, column=0, sticky=tk.W, pady=2)
    
    def toggle_password_visibility(self):
        if self.show_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="•")
    
    def real_time_check(self, event):
        password = self.password_var.get()
        if password:
            self.analyze_password(real_time=True)
    
    def analyze_password(self, real_time=False):
        password = self.password_var.get()
        
        if not password:
            if not real_time:
                messagebox.showwarning("Warning", "Please enter a password first!")
            return
        
        self.strength, self.feedback = self.check_password_strength(password)
        
        # Update strength label with color
        colors = {
            "Very Weak": "red",
            "Weak": "orange",
            "Medium": "blue", 
            "Strong": "green",
            "Very Strong": "dark green"
        }
        
        self.strength_label.config(text=f"Strength: {self.strength}", foreground=colors.get(self.strength, "black"))
        
        # Update progress bar
        progress_values = {
            "Very Weak": 20,
            "Weak": 40,
            "Medium": 60,
            "Strong": 80,
            "Very Strong": 100
        }
        self.progress['value'] = progress_values.get(self.strength, 0)
        
        # Update feedback text
        self.feedback_text.config(state=tk.NORMAL)
        self.feedback_text.delete(1.0, tk.END)
        
        if self.feedback:
            for suggestion in self.feedback:
                if "CRITICAL" in suggestion:
                    self.feedback_text.insert(tk.END, f"⚠️ {suggestion}\n", "critical")
                else:
                    self.feedback_text.insert(tk.END, f"• {suggestion}\n")
        else:
            self.feedback_text.insert(tk.END, "✅ Excellent! No improvements needed!\n")
        
        self.feedback_text.tag_configure("critical", foreground="red", font=("Arial", 10, "bold"))
        self.feedback_text.config(state=tk.DISABLED)
        
        # Enable Approve button only if password is analyzed
        self.approve_btn.config(state=tk.NORMAL)
        
        if not real_time and "CRITICAL" in str(self.feedback):
            messagebox.showwarning("Security Warning", 
                                 "This password is extremely common and easily hackable!\nPlease choose a stronger password.")
    
    def show_approval_result(self):
        if not hasattr(self, 'strength'):
            messagebox.showinfo("Info", "Please analyze a password first!")
            return
        
        # Determine approval status
        if self.strength in ["Strong", "Very Strong"]:
            result_text = "✅ APPROVED - Password meets security standards!"
            color = "green"
        elif self.strength == "Medium":
            result_text = "⚠️ CONDITIONAL APPROVAL - Consider improving password strength"
            color = "orange"
        else:
            result_text = "❌ REJECTED - Password is too weak for approval"
            color = "red"
        
        # Update approval label
        self.approval_label.config(text=result_text, foreground=color)
        
        # Show detailed message
        message = f"Final Approval Result:\n\nStrength: {self.strength}\nStatus: {result_text.split(' - ')[0]}"
        
        if self.strength in ["Strong", "Very Strong"]:
            messagebox.showinfo("Approval Granted", message)
        elif self.strength == "Medium":
            messagebox.showwarning("Conditional Approval", message)
        else:
            messagebox.showerror("Approval Denied", message)
    
    def check_password_strength(self, password):
        strength = 0
        feedback = []
        
        # Check if password is common
        if password.lower() in [p.lower() for p in self.common_passwords]:
            feedback.append("🚨 CRITICAL WARNING: This is among the most commonly hacked passwords worldwide!")
            return "Very Weak", feedback
        
        # Check length
        if len(password) >= 8:
            strength += 1
        else:
            feedback.append("Password should be at least 8 characters long")
        
        # Check for uppercase letters
        if any(char.isupper() for char in password):
            strength += 1
        else:
            feedback.append("Add uppercase letters (A-Z)")
        
        # Check for lowercase letters
        if any(char.islower() for char in password):
            strength += 1
        else:
            feedback.append("Add lowercase letters (a-z)")
        
        # Check for digits
        if any(char.isdigit() for char in password):
            strength += 1
        else:
            feedback.append("Add numbers (0-9)")
        
        # Check for special characters
        special_chars = "!@#$%^&*()_+-=[]{}|;:,.<>?/"
        if any(char in special_chars for char in password):
            strength += 1
        else:
            feedback.append("Add special characters (!@#$% etc.)")
        
        # Calculate entropy
        char_set = 0
        if any(char.islower() for char in password): char_set += 26
        if any(char.isupper() for char in password): char_set += 26  
        if any(char.isdigit() for char in password): char_set += 10
        if any(char in special_chars for char in password): char_set += len(special_chars)
        
        entropy = len(password) * math.log2(char_set) if char_set > 0 else 0
        
        # Determine strength level
        if strength == 5 and entropy > 50:
            return "Very Strong", feedback
        elif strength >= 3 and entropy > 30:
            return "Strong", feedback
        elif strength >= 2:
            return "Medium", feedback
        else:
            return "Weak", feedback

# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordStrengthGUI(root)
    root.mainloop()