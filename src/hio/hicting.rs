use indexmap::IndexMap;
use std::collections::HashMap;
use std::collections::VecDeque;

/// Mict - Multiple valued dictionary that maintains insertion order
/// Similar to Python's MultiDict but with additional LIFO access methods
#[derive(Debug, Clone)]
pub struct Mict<K, V>
where
    K: std::hash::Hash + Eq + Clone,
    V: Clone,
{
    // Using IndexMap to maintain insertion order of keys
    // Each key maps to a VecDeque for efficient FIFO/LIFO operations
    data: IndexMap<K, VecDeque<V>>,
}

impl<K, V> Mict<K, V>
where
    K: std::hash::Hash + Eq + Clone,
    V: Clone,
{
    /// Create a new empty Mict
    pub fn new() -> Self {
        Self {
            data: IndexMap::new(),
        }
    }

    /// Create a new Mict from an iterator of key-value pairs
    pub fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
    {
        let mut mict = Self::new();
        for (key, value) in iter {
            mict.add(key, value);
        }
        mict
    }

    /// Add a value to the key (appends to the value list)
    pub fn add(&mut self, key: K, value: V) {
        self.data
            .entry(key)
            .or_insert_with(VecDeque::new)
            .push_back(value);
    }

    /// Set the value for a key (replaces the entire value list with a single value)
    pub fn set(&mut self, key: K, value: V) {
        let mut deque = VecDeque::new();
        deque.push_back(value);
        self.data.insert(key, deque);
    }

    /// Get the first value for a key (FIFO - like MultiDict default behavior)
    pub fn get(&self, key: &K) -> Option<&V> {
        self.data.get(key).and_then(|deque| deque.front())
    }

    /// Get the last value for a key (LIFO - equivalent to nabone without default)
    pub fn get_last(&self, key: &K) -> Option<&V> {
        self.data.get(key).and_then(|deque| deque.back())
    }

    /// Get the last value for a key with default (equivalent to nab)
    pub fn nab(&self, key: &K, default: Option<V>) -> Option<V> {
        match self.data.get(key).and_then(|deque| deque.back()) {
            Some(value) => Some(value.clone()),
            None => default,
        }
    }

    /// Get the last value for a key or panic (equivalent to nabone)
    pub fn nabone(&self, key: &K) -> Result<V, String> {
        match self.data.get(key).and_then(|deque| deque.back()) {
            Some(value) => Ok(value.clone()),
            None => Err(format!("Key not found: {:?}", std::any::type_name::<K>())),
        }
    }

    /// Get all values for a key (FIFO order)
    pub fn get_all(&self, key: &K) -> Vec<V> {
        match self.data.get(key) {
            Some(deque) => deque.iter().cloned().collect(),
            None => Vec::new(),
        }
    }

    /// Get all values for a key in reverse order (LIFO - equivalent to naball)
    pub fn naball(&self, key: &K, default: Option<Vec<V>>) -> Option<Vec<V>> {
        match self.data.get(key) {
            Some(deque) => {
                let mut values: Vec<V> = deque.iter().cloned().collect();
                values.reverse();
                Some(values)
            }
            None => default,
        }
    }

    /// Get all keys (with duplicates removed, in insertion order)
    pub fn keys(&self) -> impl Iterator<Item = &K> {
        self.data.keys()
    }

    /// Get all values (in insertion order, with duplicates)
    pub fn values(&self) -> impl Iterator<Item = &V> {
        self.data.values().flat_map(|deque| deque.iter())
    }

    /// Get all key-value pairs (first value for each key - equivalent to firsts)
    pub fn firsts(&self) -> Vec<(K, V)> {
        self.data
            .iter()
            .filter_map(|(k, deque)| deque.front().map(|v| (k.clone(), v.clone())))
            .collect()
    }

    /// Get all key-value pairs (last value for each key - equivalent to lasts)
    pub fn lasts(&self) -> Vec<(K, V)> {
        self.data
            .iter()
            .filter_map(|(k, deque)| deque.back().map(|v| (k.clone(), v.clone())))
            .collect()
    }

    /// Check if key exists
    pub fn contains_key(&self, key: &K) -> bool {
        self.data.contains_key(key)
    }

    /// Get the number of unique keys
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Iterator over all key-value pairs (FIFO order)
    pub fn items(&self) -> impl Iterator<Item = (K, V)> + '_ {
        self.data
            .iter()
            .flat_map(|(k, deque)| deque.iter().map(move |v| (k.clone(), v.clone())))
    }
}

impl<K, V> Default for Mict<K, V>
where
    K: std::hash::Hash + Eq + Clone,
    V: Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> std::fmt::Display for Mict<K, V>
where
    K: std::hash::Hash + Eq + Clone + std::fmt::Debug,
    V: Clone + std::fmt::Debug,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Mict({:?})", self.items().collect::<Vec<_>>())
    }
}
