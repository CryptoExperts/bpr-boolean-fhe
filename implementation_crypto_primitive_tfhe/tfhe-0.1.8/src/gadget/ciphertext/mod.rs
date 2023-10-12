//! An encryption of a boolean message.
//!
//! This module implements the ciphertext structure containing an encryption of a Boolean message.

use crate::core_crypto::entities::*;
use std::collections::HashSet;

/// A structure containing a ciphertext, meant to encrypt a Boolean message.
///
/// It is used to evaluate a Boolean circuits homomorphically.
#[derive(Clone, Debug)]
pub enum Ciphertext {
    Encrypted(LweCiphertextOwned<u32>),
    Trivial(bool),
}

#[derive(Clone)]
pub struct Encoding{
    _false : HashSet<u32>,
    _true : HashSet<u32>,
    modulus : u32
}


impl Encoding{

    pub fn pretty_print(&self){
        println!("modulus : {}", self.modulus);
        print!("0 : {{");
        self._false.iter().for_each(|x| print!("{}, ", x));
        println!("}}");
        print!("1 : {{");
        self._true.iter().for_each(|x| print!("{}, ", x));
        println!("}}");
    }



    pub fn is_partition_containing(&self, bool : bool, value : u32) -> bool{
        if bool{
            self._true.contains(&value)
        }
        else{
            self._false.contains(&value)
        }
    }
    
    pub fn is_canonical(&self) -> bool{
        if self._false.len() == 1 && self._true.len() == 1{
            if self.modulus % 2 == 1{
                //if odd moudlo : just need disjunction
                self._false.iter().map(|x| *x).sum::<u32>() != self._true.iter().map(|x| *x).sum::<u32>()
            }
            else{
                //if even modulo : need negacyclicity
                self._false.iter().map(|x| *x).sum::<u32>() != self._true.iter().map(|x| *x).sum::<u32>() && self._false.iter().map(|x| *x).sum::<u32>() + self._true.iter().map(|x| *x).sum::<u32>() != self.modulus
            }
        }
        else{
            false
        }
    }


    pub fn get_values_if_canonical(&self) -> (u32, u32){
        assert!(self.is_canonical());
        (self._false.iter().next().unwrap().clone(), self._true.iter().next().unwrap().clone())
    }

    
    pub fn get_modulus(&self) -> u32{
        self.modulus
    }

    
    pub fn is_extrayable(&self) -> bool{
        if self.modulus % 2 == 1{
            for x in &self._false{
                if self.is_partition_containing(true, *x) {
                    return false;
                }
            }
            for x in &self._true{
                if self.is_partition_containing(false, *x) {
                    return false;
                }
            }
        }
        else{
            for x in &self._false{
                if self.is_partition_containing(true, *x) || self.is_partition_containing(false, (*x + self.modulus / 2) % self.modulus){
                    return false;
                }
            }
            for x in &self._true{
                if self.is_partition_containing(false, *x) || self.is_partition_containing(true, (*x + self.modulus / 2) % self.modulus){
                    return false;
                }
            }
        }
        true  
    }


    pub fn get_mono_encoding(&self, bool : bool) -> u32{
        assert!(self.is_canonical());
        if bool {self._true.iter().next().unwrap().clone()} else {self._false.iter().next().unwrap().clone()}
    }


    pub fn new(part_false : HashSet<u32>, part_true : HashSet<u32>, modulus : u32) -> Self{
        part_false.iter().for_each(|x| assert!(*x < modulus));
        part_true.iter().for_each(|x| assert!(*x < modulus));
        if part_true.is_disjoint(&part_false){
            Self {_false : part_false, _true : part_true, modulus}
        }
        else{
            panic!("Encoding not correct !");
        }
    }


    pub fn new_canonical(q_true : u32, modulus : u32) -> Self{
        Self::new(HashSet::from([0]), HashSet::from([q_true]), modulus)
    }
}
