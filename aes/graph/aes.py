S_BOX = """t2 = y12 & y15
t3 = y3 & y6 
t4 = t3 ^ t2
t5 = y4 & x7 
t6 = t5 ^ t2 
t7 = y13 & y16
t8 = y5 & y1 
t9 = t8 ^ t7 
t10 = y2 & y7
t11 = t10 ^ t7 
t12 = y9 & y11 
t13 = y14 & y17
t14 = t13 ^ t12 
t15 = y8 & y10
t16 = t15 ^ t12
t17 = t4 ^ t14
t18 = t6 ^ t16
t19 = t9 ^ t14
t20 = t11 ^ t16
t21 = t17 ^ y20
t22 = t18 ^ y19
t23 = t19 ^ y21
t24 = t20 ^ y18
t25 = t21 ^ t22
t26 = t21 & t23
t27 = t24 ^ t26
t28 = t25 & t27
t29 = t28 ^ t22
t30 = t23 ^ t24
t31 = t22 ^ t26
t32 = t31 & t30
t33 = t32 ^ t24
t34 = t23 ^ t33
t35 = t27 ^ t33
t36 = t24 & t35
t37 = t36 ^ t34
t38 = t27 ^ t36
t39 = t29 & t38
t40 = t25 ^ t39
t41 = t40 ^ t37
t42 = t29 ^ t33
t43 = t29 ^ t40
t44 = t33 ^ t37
t45 = t42 ^ t41 
z0 = t44 & y15
z1 = t37 & y6 
z2 = t33 & x7 
z3 = t43 & y16
z4 = t40 & y1 
z5 = t29 & y7 
z6 = t42 & y11
z7 = t45 & y17 
z8 = t41 & y10 
z9 = t44 & y12
z10 = t37 & y3
z11 = t33 & y4
z12 = t43 & y13
z13 = t40 & y5
z14 = t29 & y2
z15 = t42 & y9
z16 = t45 & y14
z17 = t41 & y8"""