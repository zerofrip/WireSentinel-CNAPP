use shared_types::ServiceEvent;

/// Emit CNAPP service events to downstream consumers.
pub trait CnappEventEmitter: Send + Sync {
    fn emit(&self, event: ServiceEvent);
}

/// No-op emitter for tests.
pub struct NullEmitter;

impl CnappEventEmitter for NullEmitter {
    fn emit(&self, _event: ServiceEvent) {}
}

/// Collect events in memory for tests.
pub struct CollectingEmitter {
    events: parking_lot::Mutex<Vec<ServiceEvent>>,
}

impl CollectingEmitter {
    pub fn new() -> Self {
        Self {
            events: parking_lot::Mutex::new(Vec::new()),
        }
    }

    pub fn drain(&self) -> Vec<ServiceEvent> {
        std::mem::take(&mut *self.events.lock())
    }
}

impl Default for CollectingEmitter {
    fn default() -> Self {
        Self::new()
    }
}

impl CnappEventEmitter for CollectingEmitter {
    fn emit(&self, event: ServiceEvent) {
        self.events.lock().push(event);
    }
}

impl<T: CnappEventEmitter + ?Sized> CnappEventEmitter for &T {
    fn emit(&self, event: ServiceEvent) {
        (*self).emit(event);
    }
}

impl<T: CnappEventEmitter + ?Sized> CnappEventEmitter for std::sync::Arc<T> {
    fn emit(&self, event: ServiceEvent) {
        self.as_ref().emit(event);
    }
}
