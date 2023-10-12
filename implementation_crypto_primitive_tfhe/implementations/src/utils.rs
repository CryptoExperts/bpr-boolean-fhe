
pub fn vec_bool_to_int(x : Vec<bool>, big_endian:bool) -> usize{
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


pub fn int_to_vec_bool(x : usize, target_length : usize, big_endian:bool) -> Vec<bool>{
    let mut vec : Vec<bool> = Vec::new();
    let mut x = x;
    while x > 0{
        vec.push(x % 2 == 1);
        x = x >> 1;
    }
    for _ in 0..target_length - vec.len(){
        vec.push(false);
    }
    if big_endian{
        vec.reverse();
    }
    vec
}
