"""Wave system for the tower defense game."""

from config import WAVES
from enemy import Enemy


class WaveManager:
    """Manages enemy waves."""
    
    def __init__(self):
        """Initialize the wave manager."""
        self.current_wave = 0
        self.enemies_spawned = 0
        self.enemies_to_spawn = 0
        self.wave_active = False
        self.wave_timer = 0
        self.spawn_interval = 0.5  # Seconds between spawns
        self.spawn_timer = 0
    
    def start_wave(self):
        """Start the next wave."""
        if self.current_wave >= len(WAVES):
            return False
        
        wave_config = WAVES[self.current_wave]
        self.enemies_to_spawn = wave_config["count"]
        self.enemies_spawned = 0
        self.spawn_timer = 0
        self.wave_active = True
        self.wave_timer = 0
        
        self.current_wave += 1
        return True
    
    def update(self, dt):
        """Update the wave manager.
        
        Args:
            dt: Delta time since last update
            
        Returns:
            Enemy: A new enemy to spawn, or None
        """
        if not self.wave_active:
            return None
        
        self.spawn_timer += dt
        self.wave_timer += dt
        
        enemy = None
        if self.spawn_timer >= self.spawn_interval and self.enemies_spawned < self.enemies_to_spawn:
            wave_num = max(0, self.current_wave - 1)
            enemy = Enemy(wave_number=wave_num)
            self.enemies_spawned += 1
            self.spawn_timer = 0
        
        if self.enemies_spawned >= self.enemies_to_spawn:
            self.wave_active = False
        
        return enemy
    
    def is_wave_complete(self, enemies):
        """Check if the current wave is complete.
        
        Args:
            enemies: List of current enemies
            
        Returns:
            bool: True if no enemies are alive and wave is done spawning
        """
        if self.wave_active:
            return False
        
        return all(not enemy.is_alive() or enemy.reached_end for enemy in enemies)
    
    def get_current_wave_number(self):
        """Get the current wave number (1-indexed).
        
        Returns:
            int: Current wave number
        """
        return self.current_wave
    
    def get_total_waves(self):
        """Get the total number of waves.
        
        Returns:
            int: Total number of waves
        """
        return len(WAVES)
    
    def is_all_waves_complete(self):
        """Check if all waves have been completed.
        
        Returns:
            bool: True if all waves are done
        """
        return self.current_wave > len(WAVES) and not self.wave_active
