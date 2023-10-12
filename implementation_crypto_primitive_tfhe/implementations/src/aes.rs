extern crate csv;

use std::{collections::HashMap, time::Instant};
use std::error::Error;
use std::fs::File;
use csv::ReaderBuilder;
use rand::Rng;
use rayon::prelude::{IntoParallelRefIterator, ParallelIterator};
use tfhe::gadget::prelude::*;

use crate::utils::{vec_bool_to_int, int_to_vec_bool};

pub fn parse_file() -> Result<(HashMap<String, HomFunc>, HashMap<String, Vec<String>>, Vec<Vec<String>>), Box<dyn Error>> {
    let file_path = "../../aes/results/total.txt";

    // Open the CSV file
    let file = File::open(file_path)?;

    // Create a CSV reader with flexible options
    let mut rdr = ReaderBuilder::new()
        .has_headers(false)
        .delimiter(b';') // Set to false if your CSV file doesn't have headers
        .from_reader(file);

    // Storing the results in maps, as well as the topological order in a vec
    let mut topological_order:Vec<Vec<String>> = vec![vec![]];
    let mut all_q_ins : HashMap<String, Vec<u32>> = HashMap::new();
    let mut all_leaves : HashMap<String, Vec<String>> = HashMap::new();
    let mut all_p : HashMap<String, u32> = HashMap::new();
    let mut all_truth_tables : HashMap<String, Vec<bool>> = HashMap::new();

    // Iterate over each record in the CSV file
    for result in rdr.records() {
        // Unwrap the result or handle the error if there is one
        let record = result?;
        
        let name = String::from(&record[0]);

    
        if record[1].starts_with('[') && record[1].ends_with(']') {
            let inner_str = &record[1][1..record[1].len() - 1];

            let qs_in = inner_str
                .split(',')
                .map(|s| s.trim().parse().unwrap())
                .filter(|x| *x > 0)
                .collect();
            // println!("all_qs : {:?}", qs_in);

            all_q_ins.insert(name.clone(),  qs_in);
        }
        else {
            panic!("Invalid input format: Must start and end with square brackets.");
        }

       
        if record[2].starts_with('[') && record[2].ends_with(']') {
            // Remove the square brackets
            let inner_str = &record[2][1..record[2].len() - 1];
    
            // Split the inner string by commas and trim whitespace
            let leaves: Vec<String> = inner_str
                .split(',')
                .enumerate()
                .map(|(_, s)| {
                    let mut parts = s.trim().trim_matches('\'').trim().split('_');
                    parts.next().unwrap_or("").to_owned()
                })
                .map(String::from)
                .collect();
            
            // println!("leaves : {:?}", leaves);

            all_leaves.insert(name.clone(),  leaves);

        } else {
            panic!("Invalid input format: Must start and end with square brackets.");
        }


 
        let p : u32 = record[3].parse().unwrap_or(0);
        all_p.insert(name.clone(), p);

        

        if record[4].starts_with('[') && record[4].ends_with(']') {
            // Remove the square brackets
            let inner_str = &record[4][1..record[4].len() - 1];
    
            // Split the inner string by commas and trim whitespace
            let truth_table: Vec<bool> = inner_str
                .split(',')
                .map(|s| {
                    s.trim().eq(&'1'.to_string())
                })
                .collect();
  
            all_truth_tables.insert(name.clone(),  truth_table);

        } else {
            panic!("Invalid input format: Must start and end with square brackets.");
        }
           
        //Rangement dans l'ordre topologique (avec égalités)
        let l = topological_order.len();
        if all_leaves[&name].iter().any(|leaf| topological_order[l - 1].contains(leaf)){
            topological_order.push(vec![name.clone()]);
        }
        else{
            topological_order[l - 1].push(name.clone());
        }

    }


 

    //Creation of the HomFuncs
    let mut HomFuncs : HashMap<String, HomFunc> = HashMap::new();


    for step in &topological_order{
        for name in step{
            HomFuncs.insert(
                name.clone(), 
                HomFunc::new_canonical(
                    all_q_ins.get(name).unwrap().to_vec(), 
                    1,
                    *all_p.get(name).unwrap(),
                    *all_p.get(name).unwrap(),
                    all_q_ins.get(name).unwrap().len() as u32,
                    &(|v : Vec<bool>| all_truth_tables.get(name).unwrap()[vec_bool_to_int(v, true)])
                )
            );
        }
    }

    Ok((HomFuncs, all_leaves, topological_order))
}



pub struct AesState{
    pub bits : HashMap<String, HashMap<u32, Ciphertext>>,
    pub HomFuncs : HashMap<String, HomFunc>,
    leaves : HashMap<String, Vec<String>>,
    topological_order : Vec<Vec<String>>
}


impl AesState {
    pub fn tfhe_encryption_bits(m : &Vec<bool>, client_key : &ClientKey) -> Self{
        let Ok((HomFuncs, leaves, topological_order)) = parse_file() else{panic!()};
        assert_eq!(m.len(), 22);

        let mut bits : HashMap<String, HashMap<u32, Ciphertext>> = HashMap::new();
        // on traite x7 à part
        bits.insert(String::from("x7"), HashMap::new());
        HomFuncs.values().for_each(|HomFunc| {
            let p = HomFunc.get_encoding_in(0).get_modulus();
            if ! bits.get("x7").unwrap().contains_key(&p) {
                bits.get_mut("x7").unwrap().insert(p, client_key.encrypt(m[0], &Encoding::new_canonical(1, p)));
            }
        });

        //on fait les autres entrées à présent
        m.iter().enumerate().skip(1).for_each(|(i, x)| {
            let name = format!("y{}", i);
            bits.insert(name.clone(), HashMap::new());
            HomFuncs.values().for_each(|HomFunc| {
                let p = HomFunc.get_encoding_in(0).get_modulus();
                if ! bits[&name].contains_key(&p){
                    bits.get_mut(&name).unwrap().insert(p, client_key.encrypt(*x, &Encoding::new_canonical(1, p)));
                }
            })
        });


        Self {bits, HomFuncs, leaves, topological_order}
    }



    pub fn tfhe_decryption_bits(&self, client_key : &ClientKey) -> Vec<bool>{
        (0..18).map(|i| {
            let s = format!("z{}", i);
            let dict = self.bits.get(&s).unwrap();
            assert_eq!(dict.len(), 1);
            let (p, ciphertext) = dict.iter().next().unwrap();
            client_key.decrypt(&ciphertext, &Encoding::new_canonical(1, *p))
        }).collect()
    }


    fn evaluate_HomFunc_and_store_result(&self, node : &String, server_key : &ServerKey) -> HashMap<u32, Ciphertext> {
        assert!(! self.bits.contains_key(node));
        let HomFunc = self.HomFuncs.get(node).unwrap();
        let leaves = self.leaves.get(node).unwrap();
        let p_in = HomFunc.get_modulus_in();

        let mut input = leaves.iter().map(|s| { 
            self.bits.get(s).unwrap().get(&p_in).cloned().unwrap_or_else(|| {
                let (p_current, c) = self.bits.get(s).unwrap().iter().next().unwrap();
                Self::modswitch(&c, *p_current, p_in, server_key)
            }).clone()
        }).collect();

        input = HomFunc.cast_before_HomFunc_from_1(input, server_key);
        let result = HomFunc.exec(&input, server_key);
        HashMap::from([(HomFunc.get_modulus_out(), result)])
    }


    pub fn full_round_boyar(&mut self, server_key : &ServerKey){
        for step in self.topological_order.clone(){
            let results : Vec<HashMap<u32, Ciphertext>>= step.iter().map(|node| {self.evaluate_HomFunc_and_store_result(node, server_key)}).collect();
            results.into_iter().zip(step).for_each(|(r, n)| {self.bits.insert(n, r);});
        }
    }


    fn modswitch(input : &Ciphertext, p_in : u32, p_out : u32, server_key : &ServerKey) -> Ciphertext {
        let HomFunc = HomFunc::new_canonical(vec![1], 1, p_in, p_out, 1, &|x| {x[0]});
        HomFunc.exec(&vec![input.clone()], server_key)
    }

}



pub fn demo_aes(){
    let (client_key, server_key) = gen_keys(&AES_PARAMETERS);
    let mut rng = rand::thread_rng();

    let i: u32 = rng.gen_range(0..1<<21);
    let input: Vec<bool> = int_to_vec_bool(i.try_into().unwrap(), 22, false);

    let mut state = AesState::tfhe_encryption_bits(&input, &client_key);

    let start = Instant::now();
    state.full_round_boyar(&server_key);
    let stop = start.elapsed();
    println!("{:?} elapsed", stop);
    
    let result = state.tfhe_decryption_bits(&client_key);
    let true_result = clear_s_box_boyar(&input);
    if vec_bool_to_int(result, false) != vec_bool_to_int(true_result, false){
       panic!();
    }
}
    





pub fn clear_s_box_boyar(y : &Vec<bool>) -> Vec<bool> {
    let t2 = y[12] & y[15];
    let t3 = y[3] & y[6] ;
    let t4 = t3 ^ t2;
    let t5 = y[4] & y[0] ;
    let t6 = t5 ^ t2 ;
    let t7 = y[13] & y[16];
    let t8 = y[5] & y[1] ;
    let t9 = t8 ^ t7 ;
    let t10 = y[2] & y[7];
    let t11 = t10 ^ t7 ;
    let t12 = y[9] & y[11] ;
    let t13 = y[14] & y[17];
    let t14 = t13 ^ t12 ;
    let t15 = y[8] & y[10];
    let t16 = t15 ^ t12;
    let t17 = t4 ^ t14;
    let t18 = t6 ^ t16;
    let t19 = t9 ^ t14;
    let t20 = t11 ^ t16;
    let t21 = t17 ^ y[20];
    let t22 = t18 ^ y[19];
    let t23 = t19 ^ y[21];
    let t24 = t20 ^ y[18];
    let t25 = t21 ^ t22;
    let t26 = t21 & t23;
    let t27 = t24 ^ t26;
    let t28 = t25 & t27;
    let t29 = t28 ^ t22;
    let t30 = t23 ^ t24;
    let t31 = t22 ^ t26;
    let t32 = t31 & t30;
    let t33 = t32 ^ t24;
    let t34 = t23 ^ t33;
    let t35 = t27 ^ t33;
    let t36 = t24 & t35;
    let t37 = t36 ^ t34;
    let t38 = t27 ^ t36;
    let t39 = t29 & t38;
    let t40 = t25 ^ t39;
    let t41 = t40 ^ t37;
    let t42 = t29 ^ t33;
    let t43 = t29 ^ t40;
    let t44 = t33 ^ t37;
    let t45 = t42 ^ t41 ;
    let z0 = t44 & y[15];
    let z1 = t37 & y[6] ;
    let z2 = t33 & y[0] ;
    let z3 = t43 & y[16];
    let z4 = t40 & y[1] ;
    let z5 = t29 & y[7] ;
    let z6 = t42 & y[11];
    let z7 = t45 & y[17] ;
    let z8 = t41 & y[10] ;
    let z9 = t44 & y[12];
    let z10 = t37 & y[3];
    let z11 = t33 & y[4];
    let z12 = t43 & y[13];
    let z13 = t40 & y[5];
    let z14 = t29 & y[2];
    let z15 = t42 & y[9];
    let z16 = t45 & y[14];
    let z17 = t41 & y[8];
    vec![z0, z1, z2, z3, z4, z5, z6, z7, z8, z9, z10, z11, z12, z13, z14, z15, z16, z17]    
}