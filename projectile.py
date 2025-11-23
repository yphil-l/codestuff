"""Projectile system for the tower defense game."""

import math


class Projectile:
    """Represents a projectile fired by a tower."""
    
    def __init__(self, tower, target):
        """Initialize a projectile.
        
        Args:
            tower: The tower that fired this projectile
            target: The target enemy
        """
        self.tower = tower
        self.target = target
        
        self.x = tower.x
        self.y = tower.y
        self.speed = tower.projectile_speed
        self.damage = tower.damage
        self.color = tower.color
        self.size = 5
        
        self.max_distance = tower.range * 1.5
        self.distance_traveled = 0
        self.hit = False
    
    def update(self):
        """Update projectile position towards target."""
        if self.hit or self.target.health <= 0:
            return True  # Mark for removal
        
        dx = self.target.x - self.x
        dy = self.target.y - self.y
        distance = math.sqrt(dx * dx + dy * dy)
        
        if distance < self.speed or distance == 0:
            self.target.take_damage(self.damage)
            self.hit = True
            return True  # Mark for removal
        
        # Move towards target
        self.x += (dx / distance) * self.speed
        self.y += (dy / distance) * self.speed
        self.distance_traveled += self.speed
        
        # Remove if traveled too far
        if self.distance_traveled > self.max_distance:
            return True  # Mark for removal
        
        return False  # Keep alive
    
    def __repr__(self):
        """String representation of the projectile."""
        return f"Projectile(from {self.tower} to {self.target})"
