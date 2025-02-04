//! An encryption of a boolean message.
//!
//! This module implements the ciphertext structure containing an encryption of a Boolean message.

use crate::core_crypto::entities::*;
use std::collections::HashSet;

/// A structure containing a ciphertext, meant to encrypt a Boolean message.
///
/// It is used to evaluate a Boolean circuits homomorphically.
#[derive(Clone, Debug)]
pub enum Ciphertext{
    BooleanEncrypted(LweCiphertextOwned<u32>, BooleanEncoding),
    ArithmeticEncrypted(LweCiphertextOwned<u32>, ArithmeticEncoding),
    Trivial(bool),
}

type ZpElem = u32;



pub trait Encoding{
    type Data;
    fn is_valid(&self) -> bool;
    fn pretty_print(&self);
    fn is_partition_containing(&self, element_of_zo : Self::Data, value : ZpElem) -> bool;
    fn is_canonical(&self) -> bool;
    ///fn get_values_if_canonical(&self) -> (u32, u32); pour l'instant je ne pense pas qu'il soit nécessaire dans Arithmetic
    fn get_modulus(&self) -> u32;
    fn negative_on_p_ring(&self, x : ZpElem) -> ZpElem;
    fn add_constant(&self, constant : ZpElem) -> Self;
}



#[derive(Clone, Debug)]
pub struct BooleanEncoding{
    _false : HashSet<ZpElem>,
    _true : HashSet<ZpElem>,
    modulus_p : u32
}


impl Encoding for BooleanEncoding{
    type Data = bool;


    fn is_valid(&self) -> bool{
        if self.modulus_p % 2 == 1{
            self._true.is_disjoint(&self._false)
        }
        else{
            for x in &self._false{
                if self.is_partition_containing(true, *x) || self.is_partition_containing(false, (*x + self.modulus_p / 2) % self.modulus_p){
                    return false;
                }
            }
            for x in &self._true{
                if self.is_partition_containing(false, *x) || self.is_partition_containing(true, (*x + self.modulus_p / 2) % self.modulus_p){
                    return false;
                }
            }
            true  
        }
    }

    fn pretty_print(&self){
        println!("p_modulus : {}", self.modulus_p);
        print!("0 : {{");
        self._false.iter().for_each(|x| print!("{}, ", x));
        println!("}}");
        print!("1 : {{");
        self._true.iter().for_each(|x| print!("{}, ", x));
        println!("}}");
    }


    fn is_partition_containing(&self, bool : bool, value : ZpElem) -> bool{
        if bool{
            self._true.contains(&value)
        }
        else{
            self._false.contains(&value)
        }
    }
    
    fn is_canonical(&self) -> bool{
        if self._false.len() == 1 && self._true.len() == 1{
            if self.modulus_p % 2 == 1{
                //if odd moudlo : just need disjunction
                self._false.iter().map(|x| *x).sum::<u32>() != self._true.iter().map(|x| *x).sum::<u32>()
            }
            else{
                //if even modulo : need negacyclicity 
                //TODO : remove : overkill because we have already checked negacyclicity
                self._false.iter().map(|x| *x).sum::<u32>() != self._true.iter().map(|x| *x).sum::<u32>() && self._false.iter().map(|x| *x).sum::<u32>() + self._true.iter().map(|x| *x).sum::<u32>() != self.modulus_p
            }
        }
        else{
            false
        }
    }

    fn get_modulus(&self) -> u32{
        self.modulus_p
    } 

    fn negative_on_p_ring(&self, x : ZpElem) -> ZpElem{
        // for x, return [p - x] % p. Do not mix up with opposite, a.k.a. x + p / 2 !
        (self.modulus_p - x) % self.modulus_p
    }

    fn add_constant(&self, constant : ZpElem) -> Self {
        Self{
            _false : self._false.iter().map(|x| (x + constant) % self.get_modulus()).collect(),
            _true : self._true.iter().map(|x| (x + constant) % self.get_modulus()).collect(),
            modulus_p : self.get_modulus()
        }
    }
}


impl BooleanEncoding{
    pub fn get_values_if_canonical(&self) -> (ZpElem, ZpElem){
        assert!(self.is_canonical());
        (self._false.iter().next().unwrap().clone(), self._true.iter().next().unwrap().clone())
    }


    pub fn get_mono_encoding(&self, bool : bool) -> u32{
        assert!(self.is_canonical());
        if bool {self._true.iter().next().unwrap().clone()} else {self._false.iter().next().unwrap().clone()}
    }

    pub fn new(part_false : HashSet<ZpElem>, part_true : HashSet<ZpElem>, modulus_p : u32) -> Self{
        part_false.iter().for_each(|x| assert!(*x < modulus_p));
        part_true.iter().for_each(|x| assert!(*x < modulus_p));
        let new_encoding = Self {_false : part_false, _true : part_true, modulus_p};
        if new_encoding.is_valid(){
            new_encoding
        }
        else{
            panic!("BooleanEncoding not correct !");
        }
    }

    pub fn new_canonical(d_true : ZpElem, modulus : u32) -> Self{
        Self::new(HashSet::from([0]), HashSet::from([d_true]), modulus)
    }

    pub fn multiply_constant(&self, constant : ZpElem) -> Self{
        Self::new(
            self._false.iter().map(|x| *x * constant % self.get_modulus()).collect(),
            self._true.iter().map(|x| *x * constant % self.get_modulus()).collect(),
            self.get_modulus()
        )
    }

    pub fn parity_encoding() -> Self{
        Self::new_canonical(1, 2)
    }
}


type ZoElem = u32;

#[derive(Clone, Debug)]
pub struct ArithmeticEncoding{
    origin_modulus : u32,   // o in the paper
    parts : Vec<HashSet<ZpElem>>,
    modulus_p : u32   //p in the paper
}



impl Encoding for ArithmeticEncoding{
    type Data = u32;
    
    fn is_valid(&self) -> bool {
        assert_eq!(self.origin_modulus, self.parts.len().try_into().unwrap());
        self.parts.iter().enumerate().all(|(i, part_1)| {
            self.parts.iter().skip(i + 1).all(|part_2| part_1.is_disjoint(part_2))
        }) //check disjonction of all parts
        & 
        match self.modulus_p % 2 == 1{
            true => true,
            false => (|| -> bool {//check negacyclicity : if a ZpElem belongs to the ith parts, its opposite on Zp should not belong to any part except the [-i]_o one.
                for i in (0..self.origin_modulus).map(|i| i as ZoElem){
                    let negative_i = self.negative_on_o_ring(i);
                    for x in self.get_part(i).iter().map(|x| *x as ZpElem){
                        let opposite_x = (x + self.modulus_p / 2) % self.modulus_p;
                        let forbidden_spots = self.parts.iter().enumerate().filter(|(j, _)| *j as ZoElem != negative_i).map(|(_, part)| part).fold(HashSet::new(), |acc, set| acc.union(set).cloned().collect());
                        if forbidden_spots.contains(&opposite_x){
                            return false
                        }
                    }
                }
                true
            })()
        }
    }


    fn pretty_print(&self) {
        println!("modulus : {}", self.modulus_p);
        self.parts.iter().enumerate().for_each(|(i, part)| {
            print!("{} : {{", i);
            part.iter().for_each(|x| print!("{}, ", x));
            println!("}}");
        })
    }

    fn is_partition_containing(&self, element_of_zo : u32, value : u32) -> bool {
        //est-ce que la partition associée à l'élément contient la valeur ?
        self.get_part(element_of_zo).contains(&value)
    }

    fn is_canonical(&self) -> bool {
        self.parts.iter().all(|part| part.len() == 1)
    }

    fn get_modulus(&self) -> u32 {
        self.modulus_p
    }

    fn negative_on_p_ring(&self, x : ZpElem) -> ZpElem{
        // for x, return [p - x] % p. Do not mix up with opposite, a.k.a. x + p / 2 !
        (self.modulus_p - x) % self.modulus_p
    }

    fn add_constant(&self, constant : ZpElem) -> Self {
        Self::new(
            self.origin_modulus, 
            self.parts.iter().map(|part| part.iter().map(|x| (x + constant) % self.get_modulus()).collect()).collect(), 
            self.get_modulus()
        )
    }
}


impl ArithmeticEncoding{
    pub fn get_origin_modulus(&self) -> u32{
        self.origin_modulus
    }

    pub fn get_part(&self, element_of_zo : ZoElem) -> &HashSet<u32>{
        &self.parts[element_of_zo as usize]
    }

    pub fn get_part_single_value_if_canonical(&self, element_of_zo : ZoElem) -> ZpElem{
        assert!(self.is_canonical());
        self.get_part(element_of_zo).iter().next().unwrap().to_owned()
    }


    pub fn negative_on_o_ring(&self, element_of_zo : ZoElem) -> ZoElem{
        (self.origin_modulus - element_of_zo) % self.origin_modulus
    }

    pub fn new(origin_modulus : u32, parts : Vec<HashSet<ZpElem>>, modulus_p : u32) -> Self{
        assert!(parts.iter().all(|part| part.iter().all(|x| *x < modulus_p)));
        let new_encoding = Self{origin_modulus, parts, modulus_p };
        if new_encoding.is_valid(){
            new_encoding
        }
        else{
            panic!("This Arithmetic Encoding is not correct !");
        }
    }


    pub fn new_canonical(origin_modulus : u32, values_for_singletons : Vec<ZpElem>, modulus_p : u32) -> Self{
        Self::new(origin_modulus, values_for_singletons.iter().map(|d| HashSet::from([*d])).collect(), modulus_p)
    }
}



#[test]
fn test_boolean_encoding(){
    let e = BooleanEncoding::new_canonical(2, 7);
    assert!(e.is_valid());
    let e = BooleanEncoding::new_canonical(1, 2);
    assert!(e.is_valid());
}

#[test]
#[should_panic]
fn bad_boolean_encoding_even_p(){
    let e = BooleanEncoding::new([0, 2].into(), [1].into(), 4);
}

#[test]
#[should_panic]
fn bad_boolean_encoding_duplicate_i(){
    let e = BooleanEncoding::new([0, 2].into(), [0].into(), 5);
}

#[test]
#[should_panic]
fn bad_arithmetic_encoding_duplicate_i(){
    let e = ArithmeticEncoding::new(3, [[0, 2].into(), [0].into(), [1].into()].into(), 5);
}

#[test]
#[should_panic]
fn bad_arithmetic_encoding_negacyclicity(){
    let e = ArithmeticEncoding::new_canonical(3, vec![1, 5, 2], 8);
}


#[test]
fn good_arithmetic_encoding_negacyclicity(){
    let e = ArithmeticEncoding::new_canonical(3, vec![2, 1, 5], 8);
}