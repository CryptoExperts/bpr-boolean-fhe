use std::{collections::HashSet, time::Instant};

use tfhe::gadget::{prelude::*, ciphertext::BooleanEncoding};



#[derive(Clone)]
struct StateSHA{
    pub data : Vec<Vec<Vec<Ciphertext>>>
}



impl StateSHA{

    pub fn encrypt_from_string(s : &String, client_key : &ClientKey, encoding_in : &BooleanEncoding) -> Self
    {
        assert_eq!(s.len(), 5 * 5 * 8);
        //Conversion to vec of rust-booleans, then encryption
        let bytes : Vec<u8> = s.as_bytes().to_vec();
        let mut bits : Vec<bool> = Vec::new();
        for byte in bytes{
            for k in (0..8).rev(){
                let bit = if (byte >> k) % 2 == 1 {true} else {false};  //thanks rust
                bits.push(bit);
            }
        }
        let mut data = Vec::new();
        for i in 0..5{
            data.push(Vec::new());
            for j in 0..5{
                data[i].push(Vec::new());
                for k in 0..64{
                    data[i][j].push(client_key.encrypt_boolean(bits[(i * 5 + j) * 64 + k], encoding_in));
                }
            }
        }
        Self {data}
    }




    pub fn decrypt(&self, client_key : &ClientKey, encoding_out : &BooleanEncoding) -> String{
        let mut bits : Vec<bool> = Vec::new();
        for i in 0..5{
            for j in 0..5{
                for k in 0..64{
                    bits.push(client_key.decrypt(&self.data[i][j][k]) == 1);
                }
            }
        }
        let mut result = "".to_string();
        for idx in 0..(5 * 5 * 8){
            let char_val : u8 = bits[idx * 8..(idx + 1) * 8].iter().enumerate().map(|(k, bit)| -> u8 {if *bit {1 << (7 - k)} else {0}}).sum();
            result.push(char_val as char);
        }
        result
    }

    


    pub fn get(&self, i : usize, j : usize, k : usize) -> Ciphertext{
        self.data[i % 5][j % 5][k % 64].clone()
    }


    pub fn get_col(&self, j : usize, k : usize) -> Vec<Ciphertext>{
        (0..5).map(|i| self.get(i, j, k)).collect()
    }
}





/////Keccak
fn rho(state : StateSHA) -> StateSHA{
    let mut new_vectors = state.data.clone();
    let mut i = 0;
    let mut j = 1;
    for t in 0..24{
        let i_old = i;
        i = (3 * i + 2 * j) % 5;
        j = i_old;
        for k in 0..64{
            new_vectors[i][j][k] = state.get(i, j, k - (t + 1) * (t + 2) / 2);
        }
    }
    StateSHA {data : new_vectors}
}


fn pi(state : StateSHA) -> StateSHA{
    let mut new_vectors : Vec<Vec<Vec<Ciphertext>>> = Vec::new();
    for k in 0..5{
        new_vectors.push(Vec::new());
        for l in 0..5{
            new_vectors[k].push(Vec::new());
            for m in 0..64{
                new_vectors[k][l].push(state.get(l, 3 * (k - 3 * l), m));            //opération "duale" de celle de la spec (3 inverse de 2 dans Z5)
            }
        }
    }
    StateSHA {data : new_vectors}
}



fn cast_before_khi(state : StateSHA, gadget_cast : &Gadget, server_key : &ServerKey) -> StateSHA{
    let mut new_vectors : Vec<Vec<Vec<Ciphertext>>> = Vec::new();
    for i in 0..5{
        new_vectors.push(Vec::new());
        for j in 0..5{
            new_vectors[i].push(Vec::new());
            for k in 0..64{
                new_vectors[i][j].push(gadget_cast.exec(&vec![state.get(i, j, k)], server_key));
                new_vectors[i][j][k] = server_key.simple_plaintext_sum(&new_vectors[i][j][k], 2, 3);
            }
        }
    }
    StateSHA {data : new_vectors}
}



fn khi(state : StateSHA, gadget_khi : &Gadget, server_key : &ServerKey) -> StateSHA{
    let mut new_vectors : Vec<Vec<Vec<Ciphertext>>> = Vec::new();
    for i in 0..5{
        new_vectors.push(Vec::new());
        for j in 0..5{
            new_vectors[i].push(Vec::new());
            for k in 0..64{
                new_vectors[i][j].push(gadget_khi.exec(&vec![state.get(i, j, k), state.get(i, j+1, k), state.get(i, j+2, k)], server_key));
            }
        }
    }
    StateSHA {data : new_vectors}
}



fn theta(state : StateSHA, server_key : &ServerKey) -> StateSHA{
    let mut new_vectors : Vec<Vec<Vec<Ciphertext>>> = Vec::new();
    for i in 0..5{
        new_vectors.push(Vec::new());
        for j in 0..5{
            new_vectors[i].push(Vec::new());
            for k in 0..64{
                let mut input = state.get_col(j - 1, k);
                input.append(&mut state.get_col(j + 1, k - 1));
                input.push(state.get(i, j, k));
                new_vectors[i][j].push(server_key.simple_sum(&input));
            }
        }
    }
    StateSHA{  data : new_vectors  }
}









fn sha_3(input : StateSHA, server_key : &ServerKey) -> StateSHA{
    let gadget_khi_and = Gadget::new(
        vec![BooleanEncoding::new(HashSet::from([2]), HashSet::from([1]), 3) ; 2],
        BooleanEncoding::new(HashSet::from([1, 0]), HashSet::from([2]), 3),
        BooleanEncoding::new_canonical(1, 2),
        2,
        &|x : Vec<bool>| -> bool {  !(x[0] & x[1])  }
    );



    let gadget_cast_before_khi = Gadget::new(
        vec![BooleanEncoding::new_canonical(1, 2)],
        BooleanEncoding::new_canonical(1, 2),
        BooleanEncoding::new(HashSet::from([2]), HashSet::from([1]), 3),
        1,
        &|x : Vec<bool>| -> bool{   x[0]    }
    );

    //seulement un tour pour l'instant
    let state_theta = theta(input, &server_key);
    let state_rho = rho(state_theta);
    let state_pi = pi(state_rho);
    let state_before_khi = cast_before_khi(state_pi, &gadget_cast_before_khi, &server_key);
    let state_khi = khi(state_before_khi, &gadget_khi_and, server_key);
    //il manque les deux xors de khi et iota

    state_khi
}




pub fn demo_sha3() {
    // a run of sha3
    let (client_key, server_key) = gen_keys(&SHA3_PARAMETERS_40);
    let encoding_xor = BooleanEncoding::new_canonical(1, 2);

    let message = String::from("Cette phrase fait 200 caracteres, pas un de plus, et pas un de moins. C'est pratique parce que c'est exactement autant que l'etat interne de la permutation de Keccak dans la fonction de hachage SHA-3.");
 
    let state = StateSHA::encrypt_from_string(&message, &client_key, &encoding_xor);
    let start = Instant::now();
    let result = sha_3(state, &server_key);
    let stop = start.elapsed();
    println!("Time elapsed : {:?}", stop);

    let result_clear = result.decrypt(&client_key, &encoding_xor);
    println!("{}", result_clear);
}
