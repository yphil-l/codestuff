"""Enemy system for the tower defense game."""

import math
from config import PATH_WAYPOINTS, ENEMY_BASE_HEALTH, ENEMY_BASE_SPEED, ENEMY_BASE_SIZE


class Enemy:
    """Represents an enemy unit in the game."""
    
    def __init__(self, wave_number=0):
        """Initialize an enemy.
        
        Args:
            wave_number: The wave number (for difficulty scaling)
        """
        self.waypoints = PATH_WAYPOINTS
        self.current_waypoint = 0
        
        self.x = self.waypoints[0][0]
        self.y = self.waypoints[0][1]
        
        self.wave_number = wave_number
        health_multiplier = 1.0 + (wave_number * 0.2)
        speed_multiplier = 1.0 + (wave_number * 0.1)
        
        self.max_health = int(ENEMY_BASE_HEALTH * health_multiplier)
        self.health = self.max_health
        self.speed = ENEMY_BASE_SPEED * speed_multiplier
        self.size = ENEMY_BASE_SIZE
        self.color = "#ff0000"
        
        self.reached_end = False
    
    def update(self):
        """Update enemy position along the path."""
        if self.current_waypoint >= len(self.waypoints):
            self.reached_end = True
            return
        
        target_x, target_y = self.waypoints[self.current_waypoint]
        
        dx = target_x - self.x
        dy = target_y - self.y
        distance = math.sqrt(dx * dx + dy * dy)
        
        if distance < self.speed:
            self.current_waypoint += 1
            if self.current_waypoint >= len(self.waypoints):
                self.reached_end = True
                return
            target_x, target_y = self.waypoints[self.current_waypoint]
            dx = target_x - self.x
            dy = target_y - self.y
            distance = math.sqrt(dx * dx + dy * dy)
        
        if distance > 0:
            self.x += (dx / distance) * self.speed
            self.y += (dy / distance) * self.speed
    
    def take_damage(self, damage):
        """Apply damage to the enemy.
        
        Args:
            damage: Amount of damage to apply
        """
        self.health -= damage
    
    def is_alive(self):
        """Check if the enemy is still alive.
        
        Returns:
            bool: True if health > 0
        """
        return self.health > 0
    
    def get_health_percentage(self):
        """Get the health as a percentage.
        
        Returns:
            float: Health percentage (0-100)
        """
        return max(0, min(100, (self.health / self.max_health) * 100))
    
    def __repr__(self):
        """String representation of the enemy."""
        return f"Enemy(health={self.health}/{self.max_health} at ({self.x:.1f}, {self.y:.1f}))"
