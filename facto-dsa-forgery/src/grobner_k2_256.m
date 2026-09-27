// Real 256-bit K2 recovery attempt (public key only). Measures the ACTUAL F4 step-degree
// climb and wall time, to replace the semi-regular model extrapolation (2^65) with data.
SetNthreads(64);
SetVerbose("Groebner",1);
SetVerbose("Faugere",1);
load "keys/pk256.m";              // q, n=17, r=34, m=32, C, Mons
F:=GF(q); SetSeed(12345);
Pz<[z]>:=PolynomialRing(F,r);
P:=[ &+[ F!C[t][i]*z[Mons[i][1]]*z[Mons[i][2]]*z[Mons[i][3]] : i in [1..#Mons] | C[t][i] ne 0 ] : t in [1..m] ];
// restrict to a random (n+1)-dim chart -> n=17 affine variables, grevlex
W:=RandomMatrix(F,n+1,r);
Pu<[u]>:=PolynomialRing(F,n,"grevlex");
zu:=[ &+[ W[i][j]*(i le n select u[i] else 1) : i in [1..n+1] ] : j in [1..r] ];
Psys:=[ Evaluate(p,zu): p in P ];
printf "=== 256-bit restricted system: %o cubics in %o vars ===\n", #Psys, n;
t0:=Realtime();
I:=ideal<Pu| Psys>;
GB:=GroebnerBasis(I);
t1:=Realtime();
printf "GB DONE  time %o s  #GB %o\n", t1-t0, #GB;
V:=Variety(I);
printf "Variety time %o s total  #rational sols %o\n", Realtime()-t0, #V;
for s in V do
  v:=Vector(F,[ &+[ W[i][j]*(i le n select s[i] else 1) : i in [1..n+1] ] : j in [1..r] ]);
  J:=Matrix(F,[[Evaluate(Derivative(p,z[j]),Eltseq(v)) : j in [1..r]] : p in P]);
  Kr:=Nullspace(Transpose(J));
  ok:= Dimension(Kr) eq n and forall{p: p in P | Evaluate(p, Eltseq(&+[Random(F)*b : b in Basis(Kr)])) eq 0};
  printf "candidate: dim ker DP_v=%o  P vanishes on ker: %o\n", Dimension(Kr), ok;
  if ok then printf "K2BASIS %o\n", [Eltseq(b): b in Basis(Kr)]; end if;
end for;
quit;
