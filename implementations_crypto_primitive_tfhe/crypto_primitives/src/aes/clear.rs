pub fn clear_s_box_boyar(y : &Vec<bool>) -> Vec<bool> {
    assert_eq!(y.len(), 22);
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



pub fn clear_pre_circuit(x : &Vec<bool>)->Vec<bool>{
    assert_eq!(x.len(), 8);
    let y14 = x[3] ^ x[5];
    let y13 = x[0] ^ x[6];
    let y9 = x[0] ^ x[3];
    let y8 = x[0] ^ x[5];
    let t0 = x[1] ^ x[2];
    let y1 = t0 ^ x[7];
    let y4 = y1 ^ x[3];
    let y12 = y13 ^ y14;
    let y2 = y1 ^ x[0];
    let y5 = y1 ^ x[6];
    let y3 = y5 ^ y8;
    let t1 = x[4] ^ y12;
    let y15 = t1 ^ x[5];
    let y20 = t1 ^ x[1];
    let y6 = y15 ^ x[7];
    let y10 = y15 ^ t0;
    let y11 = y20 ^ y9;
    let y7 = x[7] ^ y11;
    let y17 = y10 ^ y11;
    let y19 = y10 ^ y8;
    let y16 = t0 ^ y11;
    let y21 = y13 ^ y16;
    let y18 = x[0] ^ y16;
    vec![x[7], y1, y2, y3, y4, y5, y6, y7, y8, y9, y10, y11, y12, y13, y14, y15, y16, y17, y18, y19, y20, y21]
}


pub fn clear_post_circuit(x : &Vec<bool>)->Vec<bool>{
    let t46 = x[15] ^ x[16];
    let t47 = x[10] ^ x[11];
    let t48 = x[5] ^ x[13];
    let t49 = x[9] ^ x[10];
    let t50 = x[2] ^ x[12];
    let t51 = x[2] ^ x[5];
    let t52 = x[7] ^ x[8];
    let t53 = x[0] ^ x[3];
    let t54 = x[6] ^ x[7];
    let t55 = x[16] ^ x[17];
    let t56 = x[12] ^ t48;
    let t57 = t50 ^ t53;
    let t58 = x[4] ^ t46;
    let t59 = x[3] ^ t54;
    let t60 = t46 ^ t57;
    let t61 = x[14] ^ t57;
    let t62 = t52 ^ t58;
    let t63 = t49 ^ t58;
    let t64 = x[4] ^ t59;
    let t65 = t61 ^ t62;
    let t66 = x[1] ^ t63;
    let y0 = t59 ^ t63;
    let y6 = !(t56 ^ t62);
    let y7 = !(t48 ^ t60);
    let t67 = t64 ^ t65;
    let y3 = t53 ^ t66;
    let y4 = t51 ^ t66;
    let y5 = t47 ^ t65;
    let y1 = !(t64 ^ y3);
    let y2 = !(t55 ^ t67);
    vec![y0, y1, y2, y3, y4, y5, y6, y7]
}




pub fn clear_mixcolumns(x : &Vec<bool>) -> Vec<bool>{
    assert_eq!(x.len(), 32);
    let t0 = x[0] ^ x[8];
    let t1 = x[16] ^ x[24];
    let t2 = x[1] ^ x[9];
    let t3 = x[17] ^ x[25];
    let t4 = x[2] ^ x[10];
    let t5 = x[18] ^ x[26];
    let t6 = x[3] ^ x[11];
    let t7 = x[19] ^ x[27];
    let t8 = x[4] ^ x[12];
    let t9 = x[20] ^ x[28];
    let t10 = x[5] ^ x[13];
    let t11 = x[21] ^ x[29];
    let t12 = x[6] ^ x[14];
    let t13 = x[22] ^ x[30];
    let t14 = x[23] ^ x[31];
    let t15 = x[7] ^ x[15];
    let t16 = x[8] ^ t1;
    let y0 = t15 ^ t16;
    let t17 = x[7] ^ x[23];
    let t18 = x[24] ^ t0;
    let y16 = t14 ^ t18;
    let t19 = t1 ^ y16;
    let y24 = t17 ^ t19;
    let t20 = x[27] ^ t14;
    let t21 = t0 ^ y0;
    let y8 = t17 ^ t21;
    let t22 = t5 ^ t20;
    let y19 = t6 ^ t22;
    let t23 = x[11] ^ t15;
    let t24 = t7 ^ t23;
    let y3 = t4 ^ t24;
    let t25 = x[2] ^ x[18];
    let t26 = t17 ^ t25;
    let t27 = t9 ^ t23;
    let t28 = t8 ^ t20;
    let t29 = x[10] ^ t2;
    let y2 = t5 ^ t29;
    let t30 = x[26] ^ t3;
    let y18 = t4 ^ t30;
    let t31 = x[9] ^ x[25];
    let t32 = t25 ^ t31;
    let y10 = t30 ^ t32;
    let y26 = t29 ^ t32;
    let t33 = x[1] ^ t18;
    let t34 = x[30] ^ t11;
    let y22 = t12 ^ t34;
    let t35 = x[14] ^ t13;
    let y6 = t10 ^ t35;
    let t36 = x[5] ^ x[21];
    let t37 = x[30] ^ t17;
    let t38 = x[17] ^ t16;
    let t39 = x[13] ^ t8;
    let y5 = t11 ^ t39;
    let t40 = x[12] ^ t36;
    let t41 = x[29] ^ t9;
    let y21 = t10 ^ t41;
    let t42 = x[28] ^ t40;
    let y13 = t41 ^ t42;
    let y29 = t39 ^ t42;
    let t43 = x[15] ^ t12;
    let y7 = t14 ^ t43;
    let t44 = x[14] ^ t37;
    let y31 = t43 ^ t44;
    let t45 = x[31] ^ t13;
    let y15 = t44 ^ t45;
    let y23 = t15 ^ t45;
    let t46 = t12 ^ t36;
    let y14 = y6 ^ t46;
    let t47 = t31 ^ t33;
    let y17 = t19 ^ t47;
    let t48 = t6 ^ y3;
    let y11 = t26 ^ t48;
    let t49 = t2 ^ t38;
    let y25 = y24 ^ t49;
    let t50 = t7 ^ y19;
    let y27 = t26 ^ t50;
    let t51 = x[22] ^ t46;
    let y30 = t11 ^ t51;
    let t52 = x[19] ^ t28;
    let y20 = x[28] ^ t52;
    let t53 = x[3] ^ t27;
    let y4 = x[12] ^ t53;
    let t54 = t3 ^ t33;
    let y9 = y8 ^ t54;
    let t55 = t21 ^ t31;
    let y1 = t38 ^ t55;
    let t56 = x[4] ^ t17;
    let t57 = x[19] ^ t56;
    let y12 = t27 ^ t57;
    let t58 = x[3] ^ t28;
    let t59 = t17 ^ t58;
    let y28 = x[20] ^ t59;
    vec![y0, y1, y2, y3, y4, y5, y6, y7, y8, y9, y10, y11, y12, y13, y14, y15, y16, y17, y18, y19, y20, y21, y22, y23, y24, y25, y26, y27, y28, y29, y30, y31]
}