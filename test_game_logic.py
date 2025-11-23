"""Test game logic without GUI."""

import sys

def test_imports():
    """Test that all modules can be imported."""
    try:
        import config
        import tower
        import enemy
        import projectile
        import wave
        import sound
        print("✓ All modules imported successfully")
        return True
    except Exception as e:
        print(f"✗ Import failed: {e}")
        return False


def test_tower_creation():
    """Test tower creation and properties."""
    from tower import Tower
    from config import TOWERS
    
    for tower_type in TOWERS:
        tower = Tower(100, 100, tower_type)
        assert tower.x == 100
        assert tower.y == 100
        assert tower.tower_type == tower_type
        assert tower.damage > 0
        assert tower.range > 0
        assert tower.cost > 0
    
    print("✓ Tower creation test passed")
    return True


def test_enemy_creation():
    """Test enemy creation and properties."""
    from enemy import Enemy
    
    enemy = Enemy(wave_number=0)
    assert enemy.health > 0
    assert enemy.speed > 0
    assert enemy.x == -450
    assert enemy.y == 250
    assert not enemy.reached_end
    
    print("✓ Enemy creation test passed")
    return True


def test_enemy_movement():
    """Test enemy movement along path."""
    from enemy import Enemy
    
    enemy = Enemy(wave_number=0)
    initial_pos = (enemy.x, enemy.y)
    
    for _ in range(10):
        enemy.update()
    
    assert enemy.x != initial_pos[0] or enemy.y != initial_pos[1]
    assert not enemy.reached_end
    print("✓ Enemy movement test passed")
    return True


def test_tower_targeting():
    """Test tower targeting."""
    from tower import Tower
    from enemy import Enemy
    
    tower = Tower(-450, 250, "basic")
    enemies = [Enemy(0), Enemy(0), Enemy(0)]
    
    target = tower.find_target(enemies)
    if target is not None:
        assert target in enemies
    
    tower2 = Tower(-450, 250, "laser")
    target2 = tower2.find_target(enemies)
    assert target2 is not None
    assert target2 in enemies
    print("✓ Tower targeting test passed")
    return True


def test_projectile_creation():
    """Test projectile creation."""
    from tower import Tower
    from enemy import Enemy
    from projectile import Projectile
    
    tower = Tower(100, 100, "basic")
    enemy = Enemy(0)
    projectile = Projectile(tower, enemy)
    
    assert projectile.x == tower.x
    assert projectile.y == tower.y
    assert projectile.target == enemy
    assert projectile.damage == tower.damage
    assert not projectile.hit
    
    print("✓ Projectile creation test passed")
    return True


def test_wave_manager():
    """Test wave manager."""
    from wave import WaveManager
    
    manager = WaveManager()
    assert manager.current_wave == 0
    assert manager.get_total_waves() == 5
    assert not manager.is_all_waves_complete()
    
    result = manager.start_wave()
    assert result == True
    assert manager.current_wave == 1
    assert manager.wave_active
    
    print("✓ Wave manager test passed")
    return True


def test_sound_manager():
    """Test sound manager initialization."""
    from sound import SoundManager
    
    manager = SoundManager()
    manager.play("tower_place")
    manager.stop_all()
    
    print("✓ Sound manager test passed")
    return True


def test_config_values():
    """Test configuration values."""
    from config import (
        SCREEN_WIDTH, SCREEN_HEIGHT, INITIAL_LIVES, INITIAL_CURRENCY,
        TOWERS, WAVES, PATH_WAYPOINTS
    )
    
    assert SCREEN_WIDTH > 0
    assert SCREEN_HEIGHT > 0
    assert INITIAL_LIVES > 0
    assert INITIAL_CURRENCY > 0
    assert len(TOWERS) >= 3
    assert len(WAVES) == 5
    assert len(PATH_WAYPOINTS) >= 2
    
    print("✓ Configuration test passed")
    return True


def main():
    """Run all tests."""
    tests = [
        test_imports,
        test_config_values,
        test_tower_creation,
        test_enemy_creation,
        test_enemy_movement,
        test_tower_targeting,
        test_projectile_creation,
        test_wave_manager,
        test_sound_manager,
    ]
    
    passed = 0
    failed = 0
    
    print("Running game logic tests...\n")
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"✗ {test.__name__} failed: {e}")
            failed += 1
    
    print(f"\n{'='*50}")
    print(f"Tests passed: {passed}/{len(tests)}")
    if failed > 0:
        print(f"Tests failed: {failed}/{len(tests)}")
        return False
    else:
        print("✓ All tests passed!")
        return True


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
