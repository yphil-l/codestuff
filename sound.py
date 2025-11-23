"""Sound management system."""

import os
from config import ENABLE_SOUND, SOUND_VOLUME

try:
    import pygame.mixer as mixer
    PYGAME_AVAILABLE = True
except ImportError:
    PYGAME_AVAILABLE = False


class SoundManager:
    """Manages game sound effects."""
    
    def __init__(self):
        """Initialize the sound manager."""
        self.enabled = ENABLE_SOUND and PYGAME_AVAILABLE
        self.sounds = {}
        
        if self.enabled:
            try:
                mixer.init()
                self._load_sounds()
            except Exception as e:
                print(f"Sound initialization failed: {e}")
                self.enabled = False
    
    def _load_sounds(self):
        """Load sound effects."""
        sounds = {
            "tower_place": self._generate_beep(400, 0.1),
            "shoot": self._generate_beep(600, 0.08),
            "enemy_death": self._generate_beep(200, 0.15),
            "wave_start": self._generate_beep(800, 0.3),
            "game_over": self._generate_beep(100, 0.5),
            "victory": self._generate_beep(900, 0.4),
        }
        self.sounds = sounds
    
    def _generate_beep(self, frequency, duration):
        """Generate a simple beep sound."""
        if not PYGAME_AVAILABLE:
            return None
        
        try:
            sample_rate = 22050
            frames = int(duration * sample_rate)
            import array
            import math
            
            # Generate a sine wave
            arr = array.array('h')
            for i in range(frames):
                value = int(32767 * 0.3 * math.sin(2.0 * math.pi * frequency * i / sample_rate))
                arr.append(value)
                arr.append(value)  # Stereo
            
            sound = mixer.Sound(array.array('h', arr))
            sound.set_volume(SOUND_VOLUME)
            return sound
        except Exception as e:
            print(f"Failed to generate beep sound: {e}")
            return None
    
    def play(self, sound_name):
        """Play a sound effect."""
        if not self.enabled or sound_name not in self.sounds:
            return
        
        try:
            sound = self.sounds[sound_name]
            if sound:
                sound.play()
        except Exception as e:
            print(f"Failed to play sound {sound_name}: {e}")
    
    def stop_all(self):
        """Stop all playing sounds."""
        if self.enabled:
            try:
                mixer.stop()
            except Exception:
                pass
