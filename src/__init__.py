
self.tracking = None

if db is not None:
    self.tracking = TrackingManager(
        db=db,
        scan_callback=self._scheduled_tracking_scan,
    )
