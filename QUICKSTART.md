# Quick Start Guide - Tower Defense Game

## Installation

### Requirements
- Python 3.7 or higher
- pygame (optional, for sound effects)

### Setup Steps

1. **Install pygame (optional but recommended)**:
   ```bash
   pip install pygame
   ```

2. **Run the game**:
   ```bash
   python main.py
   ```

## First Game Tutorial

### Starting the Game
1. Launch the game with `python main.py`
2. Read the start menu instructions
3. Press **SPACE** to begin

### Placing Your First Tower
1. Press **B** to select a Basic Tower (150 gold)
2. Click on the left side of the map to place it
3. Your gold will decrease by 150

### Starting the First Wave
1. Press **SPACE** to start the wave
2. Enemies will spawn and move along the path
3. Your towers will automatically shoot enemies in range

### Surviving the Waves
1. When enemies die, you earn 25 gold
2. Place more towers to defend against stronger waves
3. Press **S** for Strong Towers (more damage) or **L** for Laser Towers (highest damage)
4. Be strategic - some towers are better in different positions

### Game Controls Reference

| Key | Action |
|-----|--------|
| **B** | Select/place Basic Tower (Cost: 150g) |
| **S** | Select/place Strong Tower (Cost: 300g) |
| **L** | Select/place Laser Tower (Cost: 500g) |
| **Click** | Place selected tower at cursor location |
| **SPACE** | Start next wave or begin game |
| **P** | Pause/Resume game |
| **R** | Reset and restart game |

## Tower Types

### Basic Tower
- **Cost**: 150 gold
- **Range**: 120 pixels
- **Damage**: 10 per shot
- **Fire Rate**: 0.8 shots/second
- **Best For**: Early game, economy

### Strong Tower
- **Cost**: 300 gold
- **Range**: 160 pixels
- **Damage**: 20 per shot
- **Fire Rate**: 1.2 shots/second
- **Best For**: Mid game, balanced defense

### Laser Tower
- **Cost**: 500 gold
- **Range**: 200 pixels
- **Damage**: 30 per shot
- **Fire Rate**: 1.5 shots/second
- **Best For**: Late game, high damage

## Wave Information

| Wave | Enemies | Health | Speed | Notes |
|------|---------|--------|-------|-------|
| 1 | 5 | Normal | Normal | Tutorial wave |
| 2 | 8 | 20% stronger | Same | Test your economy |
| 3 | 12 | 40% stronger | 10% faster | Need better towers |
| 4 | 15 | 60% stronger | 10% faster | Strategy matters |
| 5 | 20 | 80% stronger | 20% faster | Ultimate challenge |

## Winning Strategy Tips

### Early Game (Waves 1-2)
- Start with Basic Towers
- Focus on establishing a strong economy
- Place towers to cover the path

### Mid Game (Wave 3)
- Begin transitioning to Strong Towers
- Identify choke points in the path
- Keep 2-3 towers per path segment

### Late Game (Waves 4-5)
- Use Laser Towers for high damage
- Fill in gaps with Supporting Basic Towers
- Manage economy for late-game upgrades

## Common Mistakes to Avoid

1. **Placing all towers in one area** - Spread them out to cover the entire path
2. **Running out of money** - Balance spending with saving for future waves
3. **Ignoring tower range** - Place towers where they can overlap coverage
4. **Forgetting to start waves** - Press SPACE to begin each wave!

## Sound Issues?

If you don't hear sound:
- Ensure pygame is installed: `pip install pygame`
- Check system volume is not muted
- The game works fine without sound if pygame isn't available

## Performance Tips

- Close other applications for smoother gameplay
- If the game is slow, try pressing P to pause, then resume
- The game runs at 60 FPS on most systems

## Getting Help

- Read the README.md for detailed documentation
- Check config.py for all customizable settings
- Run `python test_game_logic.py` to verify installation

---

**Enjoy defending your tower and good luck!**
