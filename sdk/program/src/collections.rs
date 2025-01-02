#[cfg(feature = "std")]
pub type AdaptiveSet<T> = std::collections::HashSet<T>;

#[cfg(feature = "std")]
pub type AdaptiveMap<K, V> = std::collections::HashMap<K, V>;

#[cfg(not(feature = "std"))]
pub type AdaptiveSet<T> = alloc::collections::BTreeSet<T>;

#[cfg(not(feature = "std"))]
pub type AdaptiveMap<K, V> = alloc::collections::BTreeMap<K, V>;
