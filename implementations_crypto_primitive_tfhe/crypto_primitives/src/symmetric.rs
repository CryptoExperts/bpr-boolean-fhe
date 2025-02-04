use tfhe::gadget::{prelude::*, ciphertext::BooleanEncoding};



pub struct State{
    pub(crate) bits : Vec<Ciphertext>,
    pub(crate) size_state : usize
}


impl State{
    pub fn get(&self, i : usize) -> &Ciphertext{
        &self.bits[i]
    }

    pub fn set(&mut self, i : usize, bit : &Ciphertext){
        self.bits[i] = bit.clone();
    }

    pub fn size_state(&self) -> usize{
        self.size_state
    }

    pub fn split_half(&self) -> (Vec<Ciphertext>, Vec<Ciphertext>){
        assert_eq!(self.size_state() % 2, 0);
        let half_size = self.size_state() / 2;
        (self.bits[..half_size].to_vec(), self.bits[half_size..].to_vec())
    }
}


impl State{

    pub fn tfhe_encryption_bits(m : &Vec<bool>, client_key : &ClientKey, encoding_in : &BooleanEncoding, size_state : usize) -> Self{
        assert_eq!(m.len(), size_state);
        let mut bits : Vec<Ciphertext> = Vec::new();
        m.iter().for_each(|x| bits.push(client_key.encrypt_boolean(*x, encoding_in)));
        Self {bits, size_state}
    }


    pub fn tfhe_decryption_bits(&self, client_key : &ClientKey, encoding_out : &BooleanEncoding) -> Vec<bool>{
        self.bits.iter().map(|bit| client_key.decrypt(bit) == 1).collect()
    }
    

    pub fn tfhe_encryption_from_string(s : &String, client_key : &ClientKey, encoding_in : &BooleanEncoding, size_state : usize) -> Self
    {
        assert_eq!(s.len() * 8, size_state);
        //Conversion to vec of rust-booleans, then encryption
        let bytes : Vec<u8> = s.as_bytes().to_vec();
        let mut bits : Vec<Ciphertext> = Vec::new();
        for byte in bytes{
            for k in (0..8).rev(){
                let bit = (byte >> k) % 2 == 1;
                bits.push(client_key.encrypt_boolean(bit, encoding_in));
            }
        }
        Self {bits, size_state}
    }


    pub fn tfhe_decryption_to_string(&self, client_key : &ClientKey, encoding_out : &BooleanEncoding) -> String{
        let mut result = "".to_string();
        for idx in 0..self.size_state / 8{
            let char_val : u8 = self.bits[idx * 8..(idx + 1) * 8].iter().enumerate().map(|(k, bit)| -> u8 {if client_key.decrypt(bit) == 1 {1 << (7 - k)} else {0}}).sum();
            result.push(char_val as char);
        }
        result
    }


}




