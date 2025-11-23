"""Tower system for the tower defense game."""

import math
from config import TOWERS


class Tower:
    """Represents a tower in the game."""
    
    def __init__(self, x, y, tower_type="basic"):
        """Initialize a tower.
        
        Args:
            x: X coordinate
            y: Y coordinate
            tower_type: Type of tower (key from TOWERS config)
        """
        self.x = x
        self.y = y
        self.tower_type = tower_type
        self.config = TOWERS.get(tower_type, TOWERS["basic"])
        
        self.name = self.config["name"]
        self.cost = self.config["cost"]
        self.range = self.config["range"]
        self.damage = self.config["damage"]
        self.fire_rate = self.config["fire_rate"]
        self.color = self.config["color"]
        self.projectile_speed = self.config["projectile_speed"]
        
        self.last_shot_time = 0
        self.target = None
    
    def can_shoot(self, current_time):
        """Check if the tower can shoot.
        
        Args:
            current_time: Current game time
            
        Returns:
            bool: True if enough time has passed since last shot
        """
        return (current_time - self.last_shot_time) >= (1.0 / self.fire_rate)
    
    def set_target(self, target, current_time):
        """Set a target and mark that we've shot.
        
        Args:
            target: The target enemy
            current_time: Current game time
        """
        self.target = target
        self.last_shot_time = current_time
    
    def get_distance_to(self, x, y):
        """Calculate distance to a point.
        
        Args:
            x: X coordinate
            y: Y coordinate
            
        Returns:
            float: Distance to the point
        """
        dx = self.x - x
        dy = self.y - y
        return math.sqrt(dx * dx + dy * dy)
    
    def is_in_range(self, x, y):
        """Check if a point is in tower range.
        
        Args:
            x: X coordinate
            y: Y coordinate
            
        Returns:
            bool: True if within range
        """
        return self.get_distance_to(x, y) <= self.range
    
    def find_target(self, enemies):
        """Find the closest enemy in range.
        
        Args:
            enemies: List of enemies
            
        Returns:
            Enemy: The closest enemy in range, or None
        """
        closest = None
        min_distance = float('inf')
        
        for enemy in enemies:
            if enemy.health <= 0:
                continue
            
            distance = self.get_distance_to(enemy.x, enemy.y)
            if distance <= self.range and distance < min_distance:
                closest = enemy
                min_distance = distance
        
        return closest
    
    def __repr__(self):
        """String representation of the tower."""
        return f"Tower({self.name} at ({self.x}, {self.y}))"
