import tkinter as tk
from tkinter import messagebox, Canvas
import random
import time
import math

class RoundedFrame(tk.Frame):
    def __init__(self, master, corner_radius=20, **kwargs):
        super().__init__(master, **kwargs)
        self.corner_radius = corner_radius
        self._canvas = tk.Canvas(self, highlightthickness=0, bg=self['bg'])
        self._canvas.place(relwidth=1, relheight=1)
        self.bind('<Configure>', self._on_configure)
        self.bind('<Map>', self._on_configure)
        
    def _on_configure(self, event=None):
        width = self.winfo_width()
        height = self.winfo_height()
        self._canvas.delete("rounded_frame")
        
        # Create rounded rectangle using arcs and lines
        r = self.corner_radius
        self._canvas.create_arc(r, r, r*2, r*2, start=90, extent=90, fill=self['bg'], outline=self['bg'], tags="rounded_frame")
        self._canvas.create_arc(width-r*2, r, width-r, r*2, start=0, extent=90, fill=self['bg'], outline=self['bg'], tags="rounded_frame")
        self._canvas.create_arc(width-r*2, height-r*2, width-r, height-r, start=270, extent=90, fill=self['bg'], outline=self['bg'], tags="rounded_frame")
        self._canvas.create_arc(r, height-r*2, r*2, height-r, start=180, extent=90, fill=self['bg'], outline=self['bg'], tags="rounded_frame")
        
        # Fill the center
        self._canvas.create_rectangle(r, 0, width-r, height, fill=self['bg'], outline=self['bg'], tags="rounded_frame")
        self._canvas.create_rectangle(0, r, width, height-r, fill=self['bg'], outline=self['bg'], tags="rounded_frame")
        
        self._canvas.lower("rounded_frame")

class MemoryGame:
    def __init__(self, root):
        self.root = root
        self.root.title("Mind Card Flip Game")
        self.root.resizable(False, False)
        
        # Set window size
        window_width = 800
        window_height = 600
        self.root.geometry(f"{window_width}x{window_height}")
        
        # Configure root window background
        self.root.configure(bg='#2B0B3A')
        
        # Game settings
        self.rows = 4
        self.cols = 4
        self.pairs = (self.rows * self.cols) // 2
        self.card_width = 8  # Increased card size
        self.card_height = 4
        self.symbols = ["🐶", "🐱", "🐭", "🐹", "🐰", "🦊", "🐻", "🐼"]
        
        # Animation settings
        self.animation_speed = 150
        self.flip_animation_frames = 8
        
        # Game state
        self.cards = []
        self.flipped = []
        self.matched_pairs = 0
        self.moves = 0
        self.game_active = False
        
        # Create UI
        self.create_game_frame()
        
    def create_background(self):
        # Create canvas for background
        self.bg_canvas = Canvas(self.root, highlightthickness=0)
        self.bg_canvas.place(relwidth=1, relheight=1)
        
        # Draw base background (deep purple)
        self.bg_canvas.create_rectangle(0, 0, 1000, 700, 
                                      fill='#2B0B3A', outline='#2B0B3A')
        
        # Draw hexagonal pattern
        hex_size = 45  # Larger hexagons for better visibility
        rows = 18
        cols = 25
        
        # Calculate center point for radial gradient
        center_x = 1000 / 2
        center_y = 700 / 2
        max_distance = math.sqrt(center_x**2 + center_y**2)
        
        # Create diagonal gradient corners
        corners = [(0, 0), (1000, 700)]  # Top-left and bottom-right are bright
        
        for row in range(-2, rows):
            for col in range(-2, cols):
                x = col * hex_size * 1.5
                y = row * hex_size * math.sqrt(3)
                if row % 2:
                    x += hex_size * 0.75
                
                # Calculate distance from center and corners
                dx = x - center_x
                dy = y - center_y
                distance = math.sqrt(dx**2 + dy**2)
                
                # Calculate corner brightness
                corner_brightness = 0
                for cx, cy in corners:
                    dist_to_corner = math.sqrt((x - cx)**2 + (y - cy)**2)
                    corner_brightness = max(corner_brightness, 
                                         1 - (dist_to_corner / max_distance))
                
                # Enhance corner brightness
                corner_brightness = math.pow(corner_brightness, 0.7)  # Make glow more pronounced
                
                # Create hexagon points
                points = []
                for i in range(6):
                    angle = i * math.pi / 3
                    px = x + hex_size * math.cos(angle)
                    py = y + hex_size * math.sin(angle)
                    points.extend([px, py])
                
                # Draw glowing intersection points
                for i in range(6):
                    angle = i * math.pi / 3
                    px = x + hex_size * math.cos(angle)
                    py = y + hex_size * math.sin(angle)
                    
                    # Calculate intersection glow intensity
                    glow_intensity = corner_brightness * 0.9
                    
                    # Draw multiple layers of glow for better effect
                    for size in [4, 3, 2]:
                        glow_color = self.calculate_glow_color(glow_intensity * (size/4))
                        self.bg_canvas.create_oval(
                            px - size, py - size,
                            px + size, py + size,
                            fill=glow_color,
                            outline=glow_color
                        )
                
                # Draw hexagon edges with bright pink glow
                edge_points = []
                edge_size = hex_size + 0.5
                for i in range(6):
                    angle = i * math.pi / 3
                    px = x + edge_size * math.cos(angle)
                    py = y + edge_size * math.sin(angle)
                    edge_points.extend([px, py])
                
                # Calculate edge glow based on corner position
                edge_intensity = corner_brightness * 0.8
                edge_color = self.calculate_edge_color(edge_intensity)
                
                # Draw edges with extra glow effect
                for width in [2, 1]:
                    glow_edge_size = edge_size + width * 0.5
                    glow_points = []
                    for i in range(6):
                        angle = i * math.pi / 3
                        px = x + glow_edge_size * math.cos(angle)
                        py = y + glow_edge_size * math.sin(angle)
                        glow_points.extend([px, py])
                    
                    self.bg_canvas.create_polygon(glow_points,
                                               fill='',
                                               outline=edge_color,
                                               width=width)
                
                # Draw slightly smaller filled hexagon
                fill_points = []
                fill_size = hex_size - 1
                for i in range(6):
                    angle = i * math.pi / 3
                    px = x + fill_size * math.cos(angle)
                    py = y + fill_size * math.sin(angle)
                    fill_points.extend([px, py])
                
                # Calculate fill color (purple gradient)
                gradient_factor = 1 - (corner_brightness * 0.6)  # Keep some color for contrast
                fill_color = self.calculate_fill_color(gradient_factor)
                
                self.bg_canvas.create_polygon(fill_points,
                                           fill=fill_color,
                                           outline='')
    
    def calculate_edge_color(self, intensity):
        # Create vibrant pink edge color
        intensity = max(0, min(1, intensity))
        r = int(255 * intensity)
        g = int(20 * intensity)  # Slight green for better pink
        b = int(220 * intensity)  # More blue for brighter pink
        return f'#{r:02x}{g:02x}{b:02x}'
    
    def calculate_glow_color(self, intensity):
        # Create bright white-pink glow color
        intensity = max(0, min(1, intensity))
        r = int(255 * intensity)
        g = int(200 * intensity)  # Higher green for whiter glow
        b = int(255 * intensity)
        return f'#{r:02x}{g:02x}{b:02x}'
    
    def calculate_fill_color(self, factor):
        # Create purple gradient fill color
        factor = max(0, min(1, factor))
        
        # Base purple color (brighter)
        base_r = 80
        base_g = 20
        base_b = 120
        
        # Gradient to bright purple
        bright_r = 140
        bright_g = 40
        bright_b = 180
        
        # Interpolate between base and bright colors
        r = int(base_r + (bright_r - base_r) * (1 - factor))
        g = int(base_g + (bright_g - base_g) * (1 - factor))
        b = int(base_b + (bright_b - base_b) * (1 - factor))
        
        return f'#{r:02x}{g:02x}{b:02x}'
    
    def create_game_frame(self):
        # Main container frame with rounded corners
        self.game_frame = RoundedFrame(self.root, bg='#2B0B3A', corner_radius=30)
        self.game_frame.place(relx=0.5, rely=0.5, anchor='center')
        
        # Add game stats frame with rounded corners
        self.stats_frame = RoundedFrame(self.game_frame, bg='#2B0B3A', corner_radius=20)
        self.stats_frame.grid(row=0, column=0, columnspan=self.cols, pady=(0, 15))
        
        # Add moves counter with modern styling
        self.moves_label = tk.Label(self.stats_frame,
                                  text="Moves: 0",
                                  font=("Helvetica", 14, "bold"),
                                  fg='#FF1493',
                                  bg='#2B0B3A')
        self.moves_label.pack(side=tk.LEFT, padx=15)
        
        # Add pairs counter
        self.pairs_label = tk.Label(self.stats_frame,
                                  text="Pairs: 0/8",
                                  font=("Helvetica", 14, "bold"),
                                  fg='#FF1493',
                                  bg='#2B0B3A')
        self.pairs_label.pack(side=tk.LEFT, padx=15)
        
        # Add restart button with hover effect
        self.restart_button = tk.Button(self.stats_frame,
                                      text="Restart Game",
                                      font=("Helvetica", 12),
                                      bg='#4B0082',
                                      fg='white',
                                      activebackground='#FF1493',
                                      activeforeground='white',
                                      relief="flat",
                                      cursor="hand2",
                                      command=self.restart_game)
        self.restart_button.pack(side=tk.RIGHT, padx=15)
        
        # Add hover effect to restart button
        self.restart_button.bind("<Enter>", lambda e: self.restart_button.configure(bg='#9370DB'))
        self.restart_button.bind("<Leave>", lambda e: self.restart_button.configure(bg='#4B0082'))
        
        # Create card grid
        self.card_buttons = []
        for row in range(self.rows):
            button_row = []
            for col in range(self.cols):
                # Container frame for each card with rounded corners
                card_frame = RoundedFrame(self.game_frame, 
                                        bg='#2B0B3A',
                                        corner_radius=25,  # Increased from 15 to 25 for more curve
                                        padx=4,
                                        pady=4)
                card_frame.grid(row=row+1, column=col, padx=4, pady=4)
                
                # Create card with modern styling
                btn = tk.Button(card_frame,
                              width=self.card_width,
                              height=self.card_height,
                              font=("Helvetica", 16),
                              command=lambda r=row, c=col: self.flip_card(r, c),
                              bg='#4B0082',
                              fg='white',
                              activebackground='#FF1493',
                              activeforeground='white',
                              relief="flat",
                              cursor="hand2")
                
                # Add hover effects
                btn.bind("<Enter>", lambda e, b=btn: self.add_glow(b))
                btn.bind("<Leave>", lambda e, b=btn: self.remove_glow(b))
                
                btn.pack()
                button_row.append(btn)
            self.card_buttons.append(button_row)
        
        self.setup_game()
    
    def click_animation(self, button):
        # Remove scaling animation to keep size consistent
        pass
    
    def add_glow(self, button):
        # Enhanced hover effect with gradient
        button.configure(bg='#9370DB')  # Medium purple
        # Add subtle shadow effect
        button.configure(relief="flat", borderwidth=0)
    
    def remove_glow(self, button):
        button.configure(bg='#4B0082')  # Dark purple
        button.configure(relief="flat", borderwidth=0)
    
    def update_stats(self):
        self.moves_label.configure(text=f"Moves: {self.moves}")
        self.pairs_label.configure(text=f"Pairs: {self.matched_pairs}/{self.pairs}")
    
    def restart_game(self):
        # Animate cards flipping back
        for row in range(self.rows):
            for col in range(self.cols):
                button = self.card_buttons[row][col]
                button.configure(
                    text="",
                    state="normal",
                    bg='#4B0082',
                    width=self.card_width,
                    height=self.card_height
                )
        
        # Reset game state
        self.setup_game()
        self.update_stats()
    
    def setup_game(self):
        # Reset game state
        self.cards = []
        self.flipped = []
        self.matched_pairs = 0
        self.moves = 0
        self.game_active = True
        
        # Create card deck
        symbols = self.symbols[:self.pairs] * 2
        random.shuffle(symbols)
        
        # Set up card grid
        self.cards = []
        index = 0
        for row in range(self.rows):
            card_row = []
            for col in range(self.cols):
                card_row.append(symbols[index])
                index += 1
            self.cards.append(card_row)
        
        # Reset all buttons
        for row in range(self.rows):
            for col in range(self.cols):
                self.card_buttons[row][col].configure(
                    text="",
                    state="normal",
                    width=self.card_width,
                    height=self.card_height,
                    bg='#4B0082'  # Dark purple
                )
    
    def flip_card(self, row, col):
        if not self.game_active or (row, col) in self.flipped:
            return
        
        button = self.card_buttons[row][col]
        
        # Add flip animation
        self.animate_flip(button, self.cards[row][col])
        
        self.flipped.append((row, col))
        
        if len(self.flipped) == 2:
            self.moves += 1
            self.update_stats()
            r1, c1 = self.flipped[0]
            r2, c2 = self.flipped[1]
            
            if self.cards[r1][c1] == self.cards[r2][c2]:
                self.matched_pairs += 1
                self.animate_match(r1, c1, r2, c2)
                self.flipped = []
                
                if self.matched_pairs == self.pairs:
                    self.game_active = False
                    self.show_win_animation()
            else:
                self.root.after(1000, self.flip_back)
    
    def animate_flip(self, button, symbol):
        # Flip animation frames
        frames = 8
        for i in range(frames):
            self.root.after(i * (self.animation_speed // frames),
                          lambda f=i: self.update_flip_frame(button, symbol, f))
    
    def update_flip_frame(self, button, symbol, frame):
        if frame < self.flip_animation_frames // 2:
            # First half: no scaling
            pass
        else:
            # Second half: show symbol without scaling
            button.configure(text=symbol, bg='#9370DB')
    
    def animate_match(self, r1, c1, r2, c2):
        # Match animation without size change
        for r, c in [(r1, c1), (r2, c2)]:
            button = self.card_buttons[r][c]
            # Change color with animation
            self.animate_color_change(button, '#FF1493')
            button.configure(state="disabled")
    
    def animate_color_change(self, button, target_color):
        # Smooth color transition animation
        frames = 10
        start_color = '#9370DB'
        r1, g1, b1 = int(start_color[1:3], 16), int(start_color[3:5], 16), int(start_color[5:7], 16)
        r2, g2, b2 = int(target_color[1:3], 16), int(target_color[3:5], 16), int(target_color[5:7], 16)
        
        for i in range(frames):
            r = int(r1 + (r2 - r1) * i / frames)
            g = int(g1 + (g2 - g1) * i / frames)
            b = int(b1 + (b2 - b1) * i / frames)
            color = f'#{r:02x}{g:02x}{b:02x}'
            self.root.after(i * 20, lambda c=color: button.configure(bg=c))
    
    def flip_back(self):
        for row, col in self.flipped:
            self.card_buttons[row][col].configure(
                text="",
                bg='#4B0082',  # Back to dark purple
                width=self.card_width,
                height=self.card_height
            )
        self.flipped = []
    
    def show_win_animation(self):
        def animate_win(frame):
            if frame <= 5:
                for row in range(self.rows):
                    for col in range(self.cols):
                        # Winning animation without size change
                        button = self.card_buttons[row][col]
                        if frame % 2 == 0:
                            button.configure(bg='#FF1493')
                        else:
                            button.configure(bg='#9370DB')
                self.root.after(200, lambda: animate_win(frame + 1))
            else:
                # Show win message
                messagebox.showinfo("Congratulations!", f"You won in {self.moves} moves!")

        animate_win(0)

if __name__ == "__main__":
    root = tk.Tk()
    game = MemoryGame(root)
    root.mainloop()