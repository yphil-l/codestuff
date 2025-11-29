from __future__ import annotations

from typing import List

from .base import ArtifactScanner
from .event_logs import EventLogScanner
from .filesystem import (
    ActivitiesTimelineScanner,
    AlternateDataStreamScanner,
    PrefetchAmcacheScanner,
    RecentJumpListScanner,
    RecycleBinScanner,
    ShadowCopyScanner,
    SpecialLocationsScanner,
    TaskSchedulerScanner,
    USNJournalScanner,
)
from .processes import EncryptedVolumeScanner, ProcessMemoryScanner
from .registry import RegistryScanner
from .user_activity import BrowserArtifactScanner, NetworkCacheScanner, WerScanner


def build_scanners() -> List[ArtifactScanner]:
    return [
        EventLogScanner(),
        RegistryScanner(),
        PrefetchAmcacheScanner(),
        USNJournalScanner(),
        TaskSchedulerScanner(),
        ActivitiesTimelineScanner(),
        BrowserArtifactScanner(),
        RecentJumpListScanner(),
        RecycleBinScanner(),
        ShadowCopyScanner(),
        AlternateDataStreamScanner(),
        ProcessMemoryScanner(),
        WerScanner(),
        NetworkCacheScanner(),
        EncryptedVolumeScanner(),
        SpecialLocationsScanner(),
    ]
