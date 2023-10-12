use std::time::Instant;

use crate::{symmetric::State, utils::vec_bool_to_int};
use rayon::prelude::*;
use tfhe::gadget::prelude::*;



fn ascon_sbox(state : &State, server_key : &ServerKey) -> State{
    let HomFuncs = ascon_HomFuncs_creation();
    let all_q : Vec<Vec<u32>> = vec![vec![1, 2, 3, 7, 14], vec![1, 2, 2, 2, 4], vec![1, 2, 4, 4] ,vec![1, 1, 5, 5, 3], vec![1, 2, 4, 3]];

    let result : Vec<Ciphertext> = HomFuncs.par_iter().zip(all_q).map(|(HomFunc, vec_q)| {
        let inputs = HomFunc.cast_before_HomFunc(vec_q, &state.bits, server_key);
        HomFunc.exec(&inputs, server_key)
    }).collect();

    State { bits: result, size_state: 5 }
}


fn ascon_HomFuncs_creation() -> Vec<HomFunc>{
    let HomFunc0 = HomFunc::new_canonical(
        vec![1, 2, 3, 7, 14],
        1,
        17,
        17,
        5,
        & |x : Vec<bool>| -> bool{
            let table = vec![0, 0, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1];
            table[vec_bool_to_int(x, false)] == 1
        }
    );
    let HomFunc1 = HomFunc::new_canonical(
        vec![1, 2, 2, 2, 4],
        1,
        17,
        17,
        5,
        & |x : Vec<bool>| -> bool{
            let table = vec![0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0];
            table[vec_bool_to_int(x, false)] == 1
        }
    );
    let HomFunc2 = HomFunc::new_canonical(
        vec![1, 2, 4, 4],   // il y a un zéro dans la comb lin, je l'enlève et je filtre l'entrée dans la fonction de cast
        1,
        17,
        17,
        4,
        &|x : Vec<bool>| -> bool{
            assert_eq!(x.len(), 4);
            let table = vec![1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1];
            table[vec_bool_to_int(x, false)] == 1
        } 
    );
    let HomFunc3 = HomFunc::new_canonical(
        vec![1, 1, 5, 5, 3],
        1,
        17,
        17,
        5,
        &|x : Vec<bool>| -> bool{
            let table = vec![0, 1, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1];
            table[vec_bool_to_int(x, false)] == 1
        }
        
    );
    let HomFunc4 = HomFunc::new_canonical(
        vec![1, 2, 4, 3],
        1,
        17,
        17,
        4,
        &|x : Vec<bool>| -> bool{
            let x_with_zero = vec![x[0], x[1], false, x[2], x[3]];
            let table = vec![0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1];
            table[vec_bool_to_int(x_with_zero, false)] == 1
        }
    );
    vec![HomFunc0, HomFunc1, HomFunc2, HomFunc3, HomFunc4]
}





pub fn demo_ascon(){
    // a round of sbox of ascon
   //entrée encodée en little-endian, sortie en big_endian : (merci la spécif)
   let (client_key, server_key) = gen_keys(&ASCON_PARAMETERS);

   let encoding = Encoding::new_canonical(1, 17);

   let message = vec![true, true, false, false, false];
   let state = State::tfhe_encryption_bits(&message, &client_key, &encoding, 5);

   let start = Instant::now();
   let result = ascon_sbox(&state, &server_key);
   let stop = start.elapsed();
   println!("Elapsed : {:#?}", stop);
   let clear_result = result.tfhe_decryption_bits(&client_key, &encoding);
   clear_result.iter().for_each(|x| print!(" {} |", *x));
}
