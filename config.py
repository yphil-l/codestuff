"""Game configuration constants."""

SCREEN_WIDTH = 1200
SCREEN_HEIGHT = 700

GRID_SIZE = 40

MAP_WIDTH = SCREEN_WIDTH - 200
MAP_HEIGHT = SCREEN_HEIGHT - 100

COLOR_BACKGROUND = "#1a1a1a"
COLOR_GRID = "#333333"
COLOR_PATH = "#8b7355"
COLOR_TOWER_RANGE = "#00ff00"
COLOR_UI_BG = "#222222"
COLOR_UI_TEXT = "#ffffff"
COLOR_ENEMY = "#ff0000"
COLOR_PROJECTILE = "#ffff00"

INITIAL_LIVES = 20
INITIAL_CURRENCY = 100
CURRENCY_PER_KILL = 25

TOWER_BASE_COST = 150
TOWER_COST_MULTIPLIER = 1.3

TOWERS = {
    "basic": {
        "name": "Basic Tower",
        "cost": 150,
        "range": 120,
        "damage": 10,
        "fire_rate": 0.8,
        "color": "#0099ff",
        "projectile_speed": 8,
    },
    "strong": {
        "name": "Strong Tower",
        "cost": 300,
        "range": 160,
        "damage": 20,
        "fire_rate": 1.2,
        "color": "#ff6600",
        "projectile_speed": 10,
    },
    "laser": {
        "name": "Laser Tower",
        "cost": 500,
        "range": 200,
        "damage": 30,
        "fire_rate": 1.5,
        "color": "#ff00ff",
        "projectile_speed": 15,
    },
}

ENEMY_BASE_SPEED = 2
ENEMY_BASE_HEALTH = 20
ENEMY_BASE_SIZE = 15

WAVES = [
    {"count": 5, "health_multiplier": 1.0, "speed_multiplier": 1.0},
    {"count": 8, "health_multiplier": 1.2, "speed_multiplier": 1.0},
    {"count": 12, "health_multiplier": 1.4, "speed_multiplier": 1.1},
    {"count": 15, "health_multiplier": 1.6, "speed_multiplier": 1.1},
    {"count": 20, "health_multiplier": 1.8, "speed_multiplier": 1.2},
]

FPS = 60
GAME_SPEED = 1.0

PATH_WAYPOINTS = [
    (-450, 250),
    (-300, 250),
    (-300, 100),
    (-100, 100),
    (-100, -100),
    (100, -100),
    (100, 200),
    (300, 200),
    (300, -150),
    (450, -150),
]

SOUND_VOLUME = 0.7
ENABLE_SOUND = True
