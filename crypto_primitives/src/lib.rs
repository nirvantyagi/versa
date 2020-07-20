use std::error::Error as ErrorTrait;

pub mod sparse_merkle_tree;

pub type Error = Box<dyn ErrorTrait>;


