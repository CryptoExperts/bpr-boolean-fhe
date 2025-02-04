use std::collections::HashSet;

use super::{prelude::*, ciphertext::{BooleanEncoding, Encoding}};


pub struct Gadget{
    encodings_in : Vec<BooleanEncoding>,
    encoding_inter : BooleanEncoding,
    encoding_out : BooleanEncoding,
    size_input : u32,
    true_result : Vec<bool> //index of an element encodes the input
}




impl Gadget{

    pub fn pretty_print(&self){
        self.encodings_in.iter().for_each(|e| print!("{}|", e.get_mono_encoding(true)));
        println!(" -> {}", self.encoding_out.get_mono_encoding(true));
    }

    pub fn get_encoding_in(&self, index : usize) -> &BooleanEncoding{
        &self.encodings_in[index]
    }

    pub fn get_encoding_out(&self) -> &BooleanEncoding{
        &self.encoding_out
    }


    pub fn get_modulus_in(&self) -> u32{
        self.get_encoding_in(0).get_modulus()
    }


    pub fn get_modulus_out(&self) -> u32{
        self.get_encoding_out().get_modulus()
    }



    pub fn new(encodings_in : Vec<BooleanEncoding>, encoding_inter : BooleanEncoding, encoding_out : BooleanEncoding, size_input : u32, true_fn : &dyn Fn(Vec<bool>) -> bool) -> Self{
        for e in &encodings_in{
            assert!(e.is_canonical());
        }
        assert!(encoding_out.is_canonical());
        let true_result : Vec<bool> = (0..1<<size_input).map(|x| true_fn(Self::split_int_in_booleans(x, size_input.try_into().unwrap(), false))).collect();
        Self{
            encodings_in, encoding_inter, encoding_out, size_input, true_result
        }
    }


    pub fn new_canonical(qis : Vec<u32>,  q_out : u32, p_in : u32, p_out : u32,  size_input : u32, true_fn : &dyn Fn(Vec<bool>) -> bool) -> Self{
        let encodings_in : Vec<BooleanEncoding> = qis.iter().map(|x| BooleanEncoding::new_canonical(*x, p_in)).collect();
        Self::new(encodings_in, Self::compute_canonical_encoding_inter(&qis, p_in, size_input, true_fn), BooleanEncoding::new_canonical(q_out, p_out), size_input, true_fn)
    }


    fn compute_canonical_encoding_inter(qis : &Vec<u32>, p : u32, size_input : u32, true_fn : &dyn Fn(Vec<bool>) -> bool) -> BooleanEncoding{
        let mut part_false : HashSet<u32> = HashSet::new();
        let mut part_true : HashSet<u32> = HashSet::new();
        for i in 0..1<<size_input{
            let input = Self::split_int_in_booleans(i, size_input as usize, true);
            let result : u32 = input.iter().zip(qis).map(|(b, q)| if *b {*q} else {0}).sum::<u32>() % p;
            if true_fn(input){
                assert!(! part_false.contains(&result));
                part_true.insert(result);
            }
            else{
                assert!(! part_true.contains(&result));
                part_false.insert(result);
            }
        }
        BooleanEncoding::new(part_false, part_true, p)
    }



    pub fn split_int_in_booleans(x : u32, expected_length : usize, big_endian : bool) -> Vec<bool>{
        //util function
        let mut res = Vec::new();
        let mut y = x;
        while y != 0{
            res.push(y % 2 == 1);
            y = y >> 1;
        }
        (0..expected_length - res.len()).for_each(|_i| res.push(false));
        if big_endian{  res.reverse(); }
        res
    }


    fn vec_bool_to_int(x : Vec<bool>, big_endian : bool) -> u32{
        let mut index = 0;
        let mut x_copy = x.clone();
        if big_endian{
            x_copy.reverse();
        }
        x_copy.iter()
        .enumerate()
        .for_each(|(i, x)| if *x {index = index + (1 << i)});
        index
    }


    pub fn test_full(&self, client_key : &ClientKey, server_key : &ServerKey){
        for x in 0..1 << self.size_input{
            println!("{}", x);
            let c_clear = Self::split_int_in_booleans(x, self.size_input as usize, false);
            c_clear.iter().for_each(|x| print!("| {} ", *x));
            println!(" -> {}", self.true_result[x as usize]);
            let c: Vec<Ciphertext> = c_clear.iter().enumerate().map(
                |(i, x_i)| client_key.encrypt_boolean(*x_i, &self.encodings_in[i])
            ).collect();
            let res: Ciphertext = self.exec(&c, &server_key);
            if (client_key.decrypt(&res) == 1) == self.true_result[x as usize]{  
                println!("valid");
            }
            else{
                println!("failed with float {}", client_key.decrypt_float_over_the_torus(&res));
            }
            assert_eq!((client_key.decrypt(&res) == 1), self.true_result[Self::vec_bool_to_int(c_clear, false) as usize]);
        }
        println!("TEST OK !");
    }


    pub fn exec_clear(&self, input : Vec<bool>) -> bool{
        self.true_result[Self::vec_bool_to_int(input, false) as usize]
    }

    
    pub fn exec(&self, input : &Vec<Ciphertext>, server_key : &ServerKey) -> Ciphertext{
        server_key.exec_gadget_with_extraction(&self.encodings_in, &self.encoding_inter, &self.encoding_out, &input)
    }


    pub fn cast_before_gadget(&self, coefficients : Vec<u32>, inputs : &Vec<Ciphertext>, server_key : &ServerKey) -> Vec<Ciphertext>{
        // input encodees sous {0}, {1}
        let mut result : Vec<Ciphertext> = Vec::new();
        inputs.iter().zip(coefficients).for_each(|(x, c)| if c != 0 {result.push(server_key.cast_encoding(x, c))});
        result
    }


    pub fn cast_before_gadget_from_1(&self, inputs : Vec<Ciphertext>, server_key : &ServerKey) -> Vec<Ciphertext>{
        let coefficients : Vec<u32>= self.encodings_in.iter().map(|e| e.get_mono_encoding(true)).collect();
        self.cast_before_gadget(coefficients, &inputs, server_key)
    }


    pub fn modulus_switching(&self, inputs : Vec<Ciphertext>, p_in_vec : Vec<u32>, p_out : u32, server_key : &ServerKey) -> Vec<Ciphertext> {
        assert_eq!(inputs.len(), p_in_vec.len());
        inputs.iter().zip(p_in_vec).map(|(x, p_i)| {
            if p_i != p_out {
                let gadget = Gadget::new_canonical(vec![1], 1, p_i, p_out, 1, &|x| {x[0]});
                gadget.exec(&vec![x.clone()], &server_key)
            } else {
            x.clone()
            }
        }).collect()
    }

}
