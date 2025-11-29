from __future__ import annotations

from typing import List

from .base import ArtifactScanner
from .bypass import BypassAnalyzerScanner
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


def build_scanners() -> List[ArtifactScanner]:
    return [
        EventLogScanner(),
        RegistryScanner(),
        PrefetchAmcacheScanner(),
        USNJournalScanner(),
        TaskSchedulerScanner(),
        ActivitiesTimelineScanner(),
        RecentJumpListScanner(),
        RecycleBinScanner(),
        ShadowCopyScanner(),
        AlternateDataStreamScanner(),
        ProcessMemoryScanner(),
        EncryptedVolumeScanner(),
        SpecialLocationsScanner(),
        BypassAnalyzerScanner(),
    ]
