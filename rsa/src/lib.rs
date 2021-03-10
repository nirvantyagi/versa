use std::error::Error as ErrorTrait;

pub mod bignat;
pub mod hog;
//pub mod kvac;
pub mod hash;
pub mod wesolowski;

pub type Error = Box<dyn ErrorTrait>;
