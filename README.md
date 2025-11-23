# Tower Defense Game - Python Turtle Edition

A tower defense game built with Python's turtle graphics library featuring sound effects and multiple tower types.

## Features

### Core Gameplay
- **Tower Placement**: Select and place towers on the map to defend against enemies
- **Multiple Tower Types**: 
  - Basic Tower: Cost 150g, Range 120, Damage 10
  - Strong Tower: Cost 300g, Range 160, Damage 20
  - Laser Tower: Cost 500g, Range 200, Damage 30
- **Enemy Waves**: Progressively difficult waves with 5 different challenge levels
- **Health System**: Start with 20 lives; lose lives when enemies reach the end
- **Currency System**: Earn 25 gold per enemy defeated to buy towers

### Gameplay Mechanics
- **Tower Range Visualization**: See tower firing ranges on the map
- **Projectile System**: Watch towers shoot and track enemies
- **Enemy Health Indicators**: Color-coded health bars show enemy status
- **Wave Management**: Manage spawning and difficulty scaling
- **Win/Lose Conditions**: Victory when all waves complete, game over if lives reach 0

### Audio System
- Tower placement sound
- Projectile fire sound
- Enemy defeat/death sound
- Wave start alert
- Game over and victory sounds

### Controls
- **B**: Select/deselect Basic Tower
- **S**: Select/deselect Strong Tower
- **L**: Select/deselect Laser Tower
- **Click**: Place selected tower at cursor location
- **Space**: Start next wave (when no wave is active)
- **P**: Pause/Resume game
- **R**: Reset and restart game

## Installation

### Requirements
- Python 3.7+
- turtle (included in Python)
- pygame (optional, for enhanced audio)

### Setup

1. Clone or download this project
2. Install pygame for sound support (optional but recommended):
   ```bash
   pip install pygame
   ```

## Running the Game

```bash
python main.py
```

## Game Flow

1. **Start Menu**: Launch the game and read the instructions
2. **Place Towers**: Use B/S/L keys to select towers and click to place them
3. **Start Wave**: Press Space to begin the enemy wave
4. **Defend**: Watch your towers automatically target and shoot enemies
5. **Earn Gold**: Collect currency from defeated enemies
6. **Upgrade Defense**: Buy more towers to handle later waves
7. **Win/Lose**: Complete all 5 waves to victory or defend until you run out of lives

## Wave Progression

| Wave | Enemies | Health | Speed |
|------|---------|--------|-------|
| 1    | 5       | 1.0x   | 1.0x  |
| 2    | 8       | 1.2x   | 1.0x  |
| 3    | 12      | 1.4x   | 1.1x  |
| 4    | 15      | 1.6x   | 1.1x  |
| 5    | 20      | 1.8x   | 1.2x  |

## File Structure

- `main.py` - Entry point
- `game.py` - Main game class and game loop
- `tower.py` - Tower implementation and targeting logic
- `enemy.py` - Enemy unit implementation and movement
- `projectile.py` - Projectile system and collision detection
- `wave.py` - Wave management and spawning system
- `sound.py` - Audio manager for sound effects
- `config.py` - Game constants and configuration
- `README.md` - This file

## Game Tips

1. **Early Defense**: Build basic towers early to handle the first waves
2. **Map Control**: Spread towers across the map for better coverage
3. **Tower Placement**: Place towers where they can cover multiple path segments
4. **Save Gold**: Sometimes it's better to save gold for strong towers rather than basic ones
5. **Plan Ahead**: Look at the path and predict enemy positions
6. **Economy**: Balance between defense and economic growth

## Customization

You can modify `config.py` to customize:
- Tower types, costs, and stats
- Wave difficulty progression
- Enemy stats
- Map layout (path waypoints)
- Audio volume
- Screen resolution

## Troubleshooting

### No Sound
- Ensure pygame is installed: `pip install pygame`
- Check that `ENABLE_SOUND` is True in config.py
- Some systems may need pygame mixer initialization

### Performance Issues
- Reduce the number of towers on screen
- Lower the FPS in config.py if needed
- Close other applications

### Display Issues
- Make sure your screen resolution supports 1200x700
- Adjust `SCREEN_WIDTH` and `SCREEN_HEIGHT` in config.py

## Future Enhancements

- Additional tower types (ice, poison, splash damage)
- Different enemy types (fast, tank, flying)
- Tower upgrades
- Special abilities (slow, freeze, multi-shot)
- Custom map editor
- Leaderboard/high scores
- Save/load game state
- Multiplayer modes

## License

This project is open source and available for personal and educational use.

## Credits

Built with Python's turtle graphics library and pygame mixer for audio.

---

Enjoy defending your tower!
