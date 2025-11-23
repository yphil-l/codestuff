"""Main game logic for the tower defense game."""

import turtle
import time
import math

from config import (
    SCREEN_WIDTH, SCREEN_HEIGHT, GRID_SIZE, MAP_WIDTH, MAP_HEIGHT,
    COLOR_BACKGROUND, COLOR_GRID, COLOR_PATH, COLOR_TOWER_RANGE,
    COLOR_UI_BG, COLOR_UI_TEXT, INITIAL_LIVES, INITIAL_CURRENCY,
    CURRENCY_PER_KILL, PATH_WAYPOINTS, TOWERS, FPS
)
from tower import Tower
from projectile import Projectile
from wave import WaveManager
from sound import SoundManager


class TowerDefenseGame:
    """Main game class."""
    
    def __init__(self):
        """Initialize the game."""
        self.screen = turtle.Screen()
        self.screen.setup(width=SCREEN_WIDTH, height=SCREEN_HEIGHT)
        self.screen.bgcolor(COLOR_BACKGROUND)
        self.screen.title("Tower Defense Game")
        self.screen.tracer(0)
        
        self.clock = turtle.time.time
        self.last_frame_time = time.time()
        
        self.lives = INITIAL_LIVES
        self.currency = INITIAL_CURRENCY
        self.towers = []
        self.enemies = []
        self.projectiles = []
        
        self.wave_manager = WaveManager()
        self.sound_manager = SoundManager()
        
        self.game_state = "start_menu"  # "start_menu", "playing", "paused", "game_over", "victory"
        self.selected_tower_type = None
        self.show_tower_range = None
        
        self.setup_graphics()
        self.setup_input()
    
    def setup_graphics(self):
        """Set up the drawing turtles."""
        self.map_drawer = turtle.Turtle()
        self.map_drawer.hideturtle()
        self.map_drawer.speed(0)
        
        self.ui_drawer = turtle.Turtle()
        self.ui_drawer.hideturtle()
        self.ui_drawer.speed(0)
        
        self.object_drawer = turtle.Turtle()
        self.object_drawer.hideturtle()
        self.object_drawer.speed(0)
    
    def setup_input(self):
        """Set up keyboard and mouse input."""
        self.screen.onkey(lambda: self.select_tower("basic"), "b")
        self.screen.onkey(lambda: self.select_tower("strong"), "s")
        self.screen.onkey(lambda: self.select_tower("laser"), "l")
        self.screen.onkey(self.toggle_pause, "p")
        self.screen.onkey(self.reset_game, "r")
        self.screen.onkey(self.start_wave, "space")
        self.screen.listen()
        
        self.screen.onclick(self.on_click)
    
    def select_tower(self, tower_type):
        """Select a tower type to place.
        
        Args:
            tower_type: Type of tower to select
        """
        if self.game_state != "playing":
            return
        
        self.selected_tower_type = tower_type if self.selected_tower_type != tower_type else None
    
    def on_click(self, x, y):
        """Handle mouse clicks for tower placement.
        
        Args:
            x: X coordinate of click
            y: Y coordinate of click
        """
        if self.game_state != "playing" or not self.selected_tower_type:
            return
        
        tower_config = TOWERS.get(self.selected_tower_type)
        if not tower_config:
            return
        
        cost = tower_config["cost"]
        if self.currency < cost:
            return
        
        if self.can_place_tower(x, y):
            tower = Tower(x, y, self.selected_tower_type)
            self.towers.append(tower)
            self.currency -= cost
            self.sound_manager.play("tower_place")
    
    def can_place_tower(self, x, y):
        """Check if a tower can be placed at the given position.
        
        Args:
            x: X coordinate
            y: Y coordinate
            
        Returns:
            bool: True if the position is valid
        """
        if abs(x) > MAP_WIDTH / 2 or abs(y) > MAP_HEIGHT / 2:
            return False
        
        if x > 0:
            return False
        
        return True
    
    def toggle_pause(self):
        """Toggle game pause state."""
        if self.game_state == "playing":
            self.game_state = "paused"
        elif self.game_state == "paused":
            self.game_state = "playing"
    
    def start_wave(self):
        """Start the next wave or start the game."""
        if self.game_state == "start_menu":
            self.game_state = "playing"
            if self.wave_manager.start_wave():
                self.sound_manager.play("wave_start")
        elif self.game_state == "playing" and not self.wave_manager.wave_active:
            if self.wave_manager.start_wave():
                self.sound_manager.play("wave_start")
    
    def reset_game(self):
        """Reset the game to the start state."""
        self.__init__()
    
    def update(self, dt):
        """Update game logic.
        
        Args:
            dt: Delta time since last update
        """
        if self.game_state == "start_menu":
            return
        
        if self.game_state == "paused":
            return
        
        if self.game_state == "game_over" or self.game_state == "victory":
            return
        
        # Spawn new enemies
        new_enemy = self.wave_manager.update(dt)
        if new_enemy:
            self.enemies.append(new_enemy)
        
        # Update enemies
        for enemy in self.enemies:
            if not enemy.reached_end:
                enemy.update()
        
        # Check for enemies that reached the end
        for enemy in self.enemies:
            if enemy.reached_end and enemy.is_alive():
                self.lives -= 1
                enemy.health = 0
        
        # Update towers
        current_time = time.time()
        for tower in self.towers:
            tower.target = tower.find_target(self.enemies)
            
            if tower.target and tower.can_shoot(current_time):
                projectile = Projectile(tower, tower.target)
                self.projectiles.append(projectile)
                tower.set_target(tower.target, current_time)
                self.sound_manager.play("shoot")
        
        # Update projectiles
        self.projectiles = [p for p in self.projectiles if not p.update()]
        
        # Check for killed enemies
        dead_enemies = [e for e in self.enemies if e.health <= 0]
        for enemy in dead_enemies:
            if enemy in self.enemies:
                self.enemies.remove(enemy)
                self.currency += CURRENCY_PER_KILL
                self.sound_manager.play("enemy_death")
        
        # Remove reached enemies
        self.enemies = [e for e in self.enemies if not e.reached_end]
        
        # Check loss condition
        if self.lives <= 0:
            self.game_state = "game_over"
            self.sound_manager.play("game_over")
        
        # Check win condition
        if self.wave_manager.is_all_waves_complete() and len(self.enemies) == 0:
            self.game_state = "victory"
            self.sound_manager.play("victory")
    
    def draw(self):
        """Draw the game state."""
        self.map_drawer.clear()
        self.ui_drawer.clear()
        self.object_drawer.clear()
        
        if self.game_state == "start_menu":
            self.draw_start_menu()
        else:
            self.draw_game()
        
        self.screen.update()
    
    def draw_start_menu(self):
        """Draw the start menu."""
        self.ui_drawer.penup()
        self.ui_drawer.goto(0, 100)
        self.ui_drawer.color(COLOR_UI_TEXT)
        self.ui_drawer.write("TOWER DEFENSE GAME", align="center", font=("Arial", 40, "bold"))
        
        self.ui_drawer.goto(0, 0)
        self.ui_drawer.write("Press SPACE to start", align="center", font=("Arial", 20, "normal"))
        
        self.ui_drawer.goto(0, -60)
        self.ui_drawer.write("Press B/S/L to select towers", align="center", font=("Arial", 14, "normal"))
        
        self.ui_drawer.goto(0, -100)
        self.ui_drawer.write("Click to place towers", align="center", font=("Arial", 14, "normal"))
        
        self.ui_drawer.goto(0, -140)
        self.ui_drawer.write("Press P to pause, R to reset", align="center", font=("Arial", 14, "normal"))
    
    def draw_game(self):
        """Draw the game state."""
        self.draw_map()
        self.draw_towers()
        self.draw_enemies()
        self.draw_projectiles()
        self.draw_ui()
    
    def draw_map(self):
        """Draw the game map."""
        self.map_drawer.penup()
        self.map_drawer.goto(-MAP_WIDTH / 2, -MAP_HEIGHT / 2)
        self.map_drawer.pendown()
        self.map_drawer.color(COLOR_GRID)
        self.map_drawer.pensize(2)
        
        for _ in range(2):
            self.map_drawer.forward(MAP_WIDTH)
            self.map_drawer.right(90)
            self.map_drawer.forward(MAP_HEIGHT)
            self.map_drawer.right(90)
        
        # Draw path
        self.map_drawer.penup()
        self.map_drawer.color(COLOR_PATH)
        self.map_drawer.pensize(10)
        
        for waypoint in PATH_WAYPOINTS:
            self.map_drawer.goto(waypoint[0], waypoint[1])
            self.map_drawer.pendown()
            self.map_drawer.dot(15)
            self.map_drawer.penup()
    
    def draw_towers(self):
        """Draw towers and their range indicators."""
        for tower in self.towers:
            self.object_drawer.penup()
            self.object_drawer.goto(tower.x, tower.y)
            self.object_drawer.color(tower.color)
            self.object_drawer.dot(20)
            
            if tower == self.show_tower_range:
                self.object_drawer.penup()
                self.object_drawer.goto(tower.x, tower.y - tower.range)
                self.object_drawer.color(COLOR_TOWER_RANGE)
                self.object_drawer.pensize(1)
                self.object_drawer.pendown()
                
                for _ in range(360):
                    self.object_drawer.forward(1)
                    self.object_drawer.right(1)
    
    def draw_enemies(self):
        """Draw enemies with health bars."""
        for enemy in self.enemies:
            self.object_drawer.penup()
            self.object_drawer.goto(enemy.x, enemy.y)
            self.object_drawer.color(enemy.color)
            self.object_drawer.dot(enemy.size * 2)
            
            health_pct = enemy.get_health_percentage()
            self.object_drawer.penup()
            self.object_drawer.goto(enemy.x, enemy.y + 20)
            
            self.object_drawer.pensize(2)
            self.object_drawer.color("#00ff00" if health_pct > 50 else "#ff9900" if health_pct > 25 else "#ff0000")
            self.object_drawer.pendown()
            self.object_drawer.forward((health_pct / 100) * 15)
    
    def draw_projectiles(self):
        """Draw projectiles."""
        for projectile in self.projectiles:
            self.object_drawer.penup()
            self.object_drawer.goto(projectile.x, projectile.y)
            self.object_drawer.color(projectile.color)
            self.object_drawer.dot(projectile.size)
    
    def draw_ui(self):
        """Draw UI elements."""
        self.ui_drawer.penup()
        
        ui_x = MAP_WIDTH / 2 - 50
        ui_y = MAP_HEIGHT / 2 - 30
        
        self.ui_drawer.goto(ui_x, ui_y)
        self.ui_drawer.color(COLOR_UI_TEXT)
        self.ui_drawer.write(f"Lives: {self.lives}", font=("Arial", 14, "bold"))
        
        self.ui_drawer.goto(ui_x, ui_y - 30)
        self.ui_drawer.write(f"Gold: {self.currency}", font=("Arial", 14, "bold"))
        
        self.ui_drawer.goto(ui_x, ui_y - 60)
        wave_num = self.wave_manager.get_current_wave_number()
        total_waves = self.wave_manager.get_total_waves()
        self.ui_drawer.write(f"Wave: {wave_num}/{total_waves}", font=("Arial", 14, "bold"))
        
        self.ui_drawer.goto(ui_x, ui_y - 90)
        self.ui_drawer.write(f"Towers: {len(self.towers)}", font=("Arial", 12, "normal"))
        
        self.ui_drawer.goto(ui_x, ui_y - 120)
        self.ui_drawer.write(f"Enemies: {len(self.enemies)}", font=("Arial", 12, "normal"))
        
        if self.selected_tower_type:
            tower_config = TOWERS.get(self.selected_tower_type)
            self.ui_drawer.goto(ui_x, ui_y - 150)
            self.ui_drawer.write(f"Selected: {tower_config['name']} ({tower_config['cost']}g)", font=("Arial", 10, "normal"))
        
        if self.game_state == "paused":
            self.ui_drawer.goto(0, 0)
            self.ui_drawer.color(COLOR_UI_TEXT)
            self.ui_drawer.write("PAUSED", align="center", font=("Arial", 30, "bold"))
        
        if self.game_state == "game_over":
            self.ui_drawer.goto(0, 0)
            self.ui_drawer.color("#ff0000")
            self.ui_drawer.write("GAME OVER", align="center", font=("Arial", 40, "bold"))
            self.ui_drawer.goto(0, -40)
            self.ui_drawer.color(COLOR_UI_TEXT)
            self.ui_drawer.write("Press R to restart", align="center", font=("Arial", 20, "normal"))
        
        if self.game_state == "victory":
            self.ui_drawer.goto(0, 0)
            self.ui_drawer.color("#00ff00")
            self.ui_drawer.write("VICTORY!", align="center", font=("Arial", 40, "bold"))
            self.ui_drawer.goto(0, -40)
            self.ui_drawer.color(COLOR_UI_TEXT)
            self.ui_drawer.write(f"Final Gold: {self.currency}", align="center", font=("Arial", 20, "normal"))
            self.ui_drawer.goto(0, -80)
            self.ui_drawer.write("Press R to restart", align="center", font=("Arial", 20, "normal"))
    
    def run(self):
        """Main game loop."""
        self.game_state = "playing"
        
        try:
            while True:
                current_time = time.time()
                dt = current_time - self.last_frame_time
                self.last_frame_time = current_time
                
                self.update(dt)
                self.draw()
                
                self.screen.update()
                time.sleep(1 / FPS)
        except KeyboardInterrupt:
            self.sound_manager.stop_all()
            self.screen.bye()
