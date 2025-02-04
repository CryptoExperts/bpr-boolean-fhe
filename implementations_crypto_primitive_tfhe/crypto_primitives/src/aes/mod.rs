extern crate csv;


use std::{collections::HashSet, time::Instant};

use rayon::iter::{IntoParallelIterator, ParallelIterator};
use tfhe::gadget::{prelude::*, client_key};
use crate::aes::{clear::{clear_pre_circuit, clear_s_box_boyar, clear_post_circuit}, aes_utils::pretty_print_clear};

use self::{aes_utils::{key_expansion, u8_to_vec_bool, vec_bool_to_u8, pretty_print_encrypted}, linear_circuit::LinearCircuit, inner_boyar_sbox::NonLinearSboxState, inner_boyar_sbox::NonLinearSBox, clear::clear_mixcolumns};

mod aes_utils;
mod inner_boyar_sbox;
mod linear_circuit;
mod clear;


pub struct AESState{
    pub bits : Vec<Ciphertext>
}


impl AESState{
    pub fn tfhe_encryption_bits(m : &Vec<bool>, client_key : &ClientKey) -> Self{
        assert_eq!(m.len(), 128);

        let parity_encoding = BooleanEncoding::new_canonical(1, 2);
        Self { bits:  
            m.iter().map(|b| client_key.encrypt_boolean(*b, &parity_encoding)).collect()
        }
    }


    pub fn tfhe_decryption_bits(&self, client_key : &ClientKey) -> Vec<bool>{
        self.bits.iter().map(|c| client_key.decrypt(c) == 1).collect()       
    }


    pub fn tfhe_decryption_float_over_the_torus(&self, client_key : &ClientKey) -> Vec<f64>{
        self.bits.iter().map(|c| client_key.decrypt_float_over_the_torus(c)).collect()       
    }

    
    //getter
    pub fn square_getter(&self, row : usize, col : usize, bit : usize) -> &Ciphertext{
        &self.bits[col * 8 * 4 + row * 8 + bit]
    }
}



fn add_round_key(state : &AESState, round_key : &Vec<bool>, server_key:&ServerKey) -> AESState{
    assert_eq!(state.bits.len(), 128);
    assert_eq!(round_key.len(), 128);
    AESState { bits: state.bits.iter()
                                .zip(round_key)
                                .map(|(c, k)| if *k {server_key.simple_plaintext_sum(c, 1, 2)} else {c.to_owned()})
                                .collect()
            }
}



fn sub_bytes(state: &AESState, server_key:&ServerKey, client_key_debug : &ClientKey) -> AESState{
    // Slicing in 16 bytes:
    let clear_debug : Vec<bool> = state.bits.iter().map(|c| client_key_debug.decrypt(c) == 1).collect();
    AESState{
         bits : (0..16).map(|i| (i, state.bits[i * 8..(i+1)*8].to_vec())).map(
        |(i, slice)| {
            let mut pre_circuit = LinearCircuit::new(&slice);
            pre_circuit.execute_circuit(&server_key, "./src/aes/data/pre_circuit.txt", client_key_debug);
            let current = [vec![pre_circuit.x[7].clone()], pre_circuit.y].concat();

            // println!("Debug de subbytes : ");
            // pretty_print_encrypted(&current, &client_key_debug, 2);
            // pretty_print_clear(&clear_pre_circuit(&clear_debug[i * 8..(i+1)*8].to_vec()));
            // println!("////////////////////////");
            let mut non_linear_state = NonLinearSboxState::new(current, "./src/aes/data/gadgets_non_linear.txt", &server_key, client_key_debug);
            // println!("Debug de subbytes : ");
            // pretty_print_encrypted(
            //     &vec![vec![non_linear_state.bits.get("x7").unwrap().get(&11).unwrap().to_owned()], (1..22).map(|i| format!("y{}", i)).map(|s| non_linear_state.bits.get(&s).unwrap().get(&11).unwrap().to_owned()).collect()].concat(), 
            //     &client_key_debug, 11);
            // pretty_print_clear(&clear_pre_circuit(&clear_debug[i * 8..(i+1)*8].to_vec()));
            // println!("////////////////////////");


            non_linear_state.full_round_boyar(&server_key, client_key_debug, false);
            let current = non_linear_state.extract_and_cast_output(&server_key, client_key_debug);

            let mut post_circuit = LinearCircuit::new(&current);
            post_circuit.execute_circuit(&server_key, "./src/aes/data/post_circuit.txt", client_key_debug);
            post_circuit.y
        } ).collect::<Vec<Vec<Ciphertext>>>().concat()
    }
}


fn shift_rows(state : &AESState) -> AESState{
    AESState { bits: (0..4).map(|col|
        (0..4).map(|row|
            (0..8).map(|i_bit| 
                state.square_getter(row, (col + row) % 4, i_bit).to_owned()
            ).collect()
        ).collect::<Vec<Vec<Ciphertext>>>().concat()
    ).collect::<Vec<Vec<Ciphertext>>>().concat() 
    }
}


fn mix_columns(state : &AESState, server_key:&ServerKey, client_key_debug : &ClientKey) -> AESState{
    AESState {
        bits : (0..4).map(|col| {
            let mut circuit = LinearCircuit::new(&state.bits[col*32..(col + 1)*32].to_vec());
            circuit.execute_circuit(&server_key, "./src/aes/data/mixcolumns2.txt", &client_key_debug);
            circuit.y
        }).collect::<Vec<Vec<Ciphertext>>>().concat()
    }
}


pub fn run_aes(state: &AESState, server_key:&ServerKey, aes_key : Vec<bool>, client_key_debug : &ClientKey) -> AESState{
    //Debug
    let print_debug = |state : &AESState, expected : &str|{
        let result_debug = state.tfhe_decryption_bits(&client_key_debug);
        pretty_print_clear(&result_debug);
        println!("Expected\n{}", expected);
        println!();
    };

    let expected = vec![
        "00 10 20 30 40 50 60 70 80 90 a0 b0 c0 d0 e0 f0",
        "89 d8 10 e8 85 5a ce 68 2d 18 43 d8 cb 12 8f e4",
        "49 15 59 8f 55 e5 d7 a0 da ca 94 fa 1f 0a 63 f7",
        "fa 63 6a 28 25 b3 39 c9 40 66 8a 31 57 24 4d 17",
        "24 72 40 23 69 66 b3 fa 6e d2 75 32 88 42 5b 6c",
        "c8 16 77 bc 9b 7a c9 3b 25 02 79 92 b0 26 19 96",
        "c6 2f e1 09 f7 5e ed c3 cc 79 39 5d 84 f9 cf 5d",
        "d1 87 6c 0f 79 c4 30 0a b4 55 94 ad d6 6f f4 1f",
        "fd e3 ba d2 05 e5 d0 d7 35 47 96 4e f1 fe 37 f1",
        "bd 6e 7c 3d f2 b5 77 9e 0b 61 21 6e 8b 10 b6 89"
    ];

    // Key Expansion
    let round_keys = key_expansion(aes_key);

    // Initial round key addition
    let mut state =  add_round_key(state, &round_keys[0], server_key);
    print_debug(&state, expected[0]); 
    
    //9 full rounds
    for r in 0..9{
        println!("Round {}", r + 1);
        state = sub_bytes(&state, server_key, client_key_debug);
        state = shift_rows(&state);
        state = mix_columns(&state, server_key, client_key_debug);
        println!("Round keys :");
        pretty_print_clear(&round_keys[r + 1].to_vec());
        println!("\n");
        state = add_round_key(&state, &round_keys[r + 1], server_key);
        // print_debug(&state, &expected[r + 1]); 

    }
    state = sub_bytes(&state, server_key, client_key_debug);
    state = shift_rows(&state);
    state = add_round_key(&state, &round_keys[10], server_key);

    state
}




pub fn test_parameters_for_aes(){
    let (client_key, server_key) = gen_keys(&AES_PARAMETERS);

    let gadget_cast = Gadget::new(vec![BooleanEncoding::new_canonical(1, 2)], BooleanEncoding::new_canonical(1, 2), BooleanEncoding::new(HashSet::from([10]), HashSet::from([1]), 11), 1, &|x| {x[0]});
    gadget_cast.test_full(&client_key, &server_key);
    let sbox = NonLinearSBox::parse_file("./src/aes/data/gadgets_non_linear.txt");
    sbox.gadgets.values().for_each(|g| g.test_full(&client_key, &server_key));
}



pub fn demo_aes(){
    let (client_key, server_key) = gen_keys(&AES_PARAMETERS_40);

    let plaintext = vec![
        0x00, 0x11, 0x22, 0x33,
        0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb,
        0xcc, 0xdd, 0xee, 0xff,
    ];
    let aes_key = [
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f,
    ];

    let plaintext_bits = plaintext.iter().map(|byte| u8_to_vec_bool(*byte)).collect::<Vec<Vec<bool>>>().concat();
    let aes_key_bits = aes_key.iter().map(|byte| u8_to_vec_bool(*byte)).collect::<Vec<Vec<bool>>>().concat();

    let state = AESState::tfhe_encryption_bits(&plaintext_bits, &client_key);

    let start = Instant::now();
    let result = run_aes(&state, &server_key, aes_key_bits, &client_key);
    let stop = start.elapsed();
    println!("Time elapsed : {:?}", stop);


    let result_clear = result.tfhe_decryption_bits(&client_key);
    (0..16).for_each(|i| print!("{:02x} ", vec_bool_to_u8(&result_clear[i * 8..(i + 1) * 8].to_vec())));
    println!(); 
}
    
