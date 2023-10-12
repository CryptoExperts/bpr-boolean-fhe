use crate::symmetric::State;
use rayon::prelude::*;
use tfhe::gadget::prelude::*;
use std::time::Instant;




fn simon_feistel_round(state : &State, HomFunc : &HomFunc, server_key : &ServerKey, key : &Vec<bool>) -> State{
    let half_size = state.size_state() / 2;
    let (left, right) = state.split_half();
            

    let mut bits: Vec<Ciphertext> = (0..half_size).into_par_iter().map(|i| {
        let a = if i < 64 - 1 {left[i + 1].clone()} else {Ciphertext::Trivial(false)};
        let b = if i < 64 - 8 {left[i + 8].clone()} else {Ciphertext::Trivial(false)};
        let c = if i < 64 - 2 {server_key.cast_encoding(&left[i + 2].clone(), 2)} else {Ciphertext::Trivial(false)};
        let d = server_key.cast_encoding(&right[i].clone(), 2);
        let e = Ciphertext::Trivial(key[i]);
        HomFunc.exec(&vec![a, b, c, d, e], server_key)
    }).collect();


    left.iter().for_each(|b| bits.push(b.clone()));
    State {bits, size_state:state.size_state()}
}

 


fn homomorphic_simon(state : &State, server_key : &ServerKey, key_simon : &Vec<bool>) -> State{
    //creation of the HomFunc
    let HomFunc_simon = HomFunc::new_canonical(
        vec![1, 1, 2, 2, 2],
        1,
        9,
        9,
        5,
        &|x : Vec<bool>| -> bool{
            x[0] & x[1] ^ x[2] ^ x[3] ^ x[4]
        }        
    );

    let start: Instant = Instant::now();
    let mut current = simon_feistel_round(&state, &HomFunc_simon, &server_key, &key_simon);
    for _ in 0..68 - 1{
        current = simon_feistel_round(&current, &HomFunc_simon, &server_key, &key_simon);
    }
    let stop = start.elapsed();
    println!("Timing : {:?}", stop);
    current
}



pub fn demo_simon() {
    // a run of simon
    let (client_key, server_key) = gen_keys(&SIMON_PARAMETERS);

    let encoding = Encoding::new_canonical(1, 9);

    let message = String::from("sponsorssponsors");
    let key_simon = vec![false;64];
    let state = State::tfhe_encryption_from_string(&message, &client_key, &encoding, 128);

    let start = Instant::now();
    let result = homomorphic_simon(&state, &server_key, &key_simon);
    let stop = start.elapsed();
    println!("Elapsed : {:#?}", stop);
    let clear_result = result.tfhe_decryption_to_string(&client_key, &encoding);
    println!("{}", clear_result);
}