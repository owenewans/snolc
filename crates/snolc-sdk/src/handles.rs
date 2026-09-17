use std::marker::PhantomData;

use thiserror::Error;

#[derive(Debug, Eq, Hash, PartialEq)]
pub struct TypedHandle<T> {
    raw: u64,
    marker: PhantomData<fn() -> T>,
}

impl<T> Copy for TypedHandle<T> {}

impl<T> Clone for TypedHandle<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> TypedHandle<T> {
    pub fn from_raw(raw: u64) -> Self {
        Self {
            raw,
            marker: PhantomData,
        }
    }

    pub fn raw(self) -> u64 {
        self.raw
    }

    pub fn index(self) -> u32 {
        self.raw as u32
    }

    pub fn generation(self) -> u32 {
        (self.raw >> 32) as u32
    }
}

struct Slot<T> {
    generation: u32,
    value: Option<T>,
}

pub struct HandleTable<T> {
    owner: u32,
    limit: usize,
    slots: Vec<Slot<T>>,
    free: Vec<u32>,
}

impl<T> HandleTable<T> {
    pub fn new(owner: u32, limit: usize) -> Self {
        Self {
            owner,
            limit,
            slots: Vec::new(),
            free: Vec::new(),
        }
    }

    pub fn owner(&self) -> u32 {
        self.owner
    }

    pub fn insert(&mut self, value: T) -> Result<TypedHandle<T>, HandleError> {
        if let Some(index) = self.free.pop() {
            let slot = &mut self.slots[index as usize];
            slot.value = Some(value);
            return Ok(TypedHandle::from_raw(pack(index, slot.generation)));
        }
        if self.slots.len() >= self.limit || self.slots.len() > u32::MAX as usize {
            return Err(HandleError::Full);
        }
        let index = self.slots.len() as u32;
        self.slots.push(Slot {
            generation: 1,
            value: Some(value),
        });
        Ok(TypedHandle::from_raw(pack(index, 1)))
    }

    pub fn get(&self, handle: TypedHandle<T>) -> Result<&T, HandleError> {
        let slot = self
            .slots
            .get(handle.index() as usize)
            .ok_or(HandleError::Stale)?;
        if slot.generation != handle.generation() {
            return Err(HandleError::Stale);
        }
        slot.value.as_ref().ok_or(HandleError::Stale)
    }

    pub fn get_mut(&mut self, handle: TypedHandle<T>) -> Result<&mut T, HandleError> {
        let slot = self
            .slots
            .get_mut(handle.index() as usize)
            .ok_or(HandleError::Stale)?;
        if slot.generation != handle.generation() {
            return Err(HandleError::Stale);
        }
        slot.value.as_mut().ok_or(HandleError::Stale)
    }

    pub fn remove(&mut self, handle: TypedHandle<T>) -> Result<T, HandleError> {
        let slot = self
            .slots
            .get_mut(handle.index() as usize)
            .ok_or(HandleError::Stale)?;
        if slot.generation != handle.generation() {
            return Err(HandleError::Stale);
        }
        let value = slot.value.take().ok_or(HandleError::Stale)?;
        slot.generation = slot.generation.wrapping_add(1).max(1);
        self.free.push(handle.index());
        Ok(value)
    }
}

fn pack(index: u32, generation: u32) -> u64 {
    (u64::from(generation) << 32) | u64::from(index)
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum HandleError {
    #[error("handle table is full")]
    Full,
    #[error("handle is stale or belongs to another table")]
    Stale,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_handle_cannot_reach_reused_slot() {
        let mut table = HandleTable::new(7, 1);
        let first = table.insert("first").unwrap();
        assert_eq!(table.remove(first).unwrap(), "first");
        let second = table.insert("second").unwrap();
        assert_eq!(first.index(), second.index());
        assert_ne!(first.generation(), second.generation());
        assert_eq!(table.get(first), Err(HandleError::Stale));
        assert_eq!(table.get(second).unwrap(), &"second");
    }
}
