pub(crate) use implementation::AtomicU64;

mod implementation {
    use nostd::sync::atomic;

    pub(crate) struct AtomicU64(atomic::AtomicU64);

    impl AtomicU64 {
        pub(crate) const fn new(initial: u64) -> Self {
            Self(atomic::AtomicU64::new(initial))
        }

        pub(crate) fn fetch_add(&self, v: u64) -> u64 {
            self.0.fetch_add(v, atomic::Ordering::Relaxed)
        }
    }
}
