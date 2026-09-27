// Independent K2 recovery by restricted Groebner. INPUT: public key only (pk128.m). Output: candidate K2 basis.
load "keys/pk128.m";
F:=GF(q); SetSeed(12345);
Pz<[z]>:=PolynomialRing(F,r);
P:=[ &+[ F!C[t][i]*z[Mons[i][1]]*z[Mons[i][2]]*z[Mons[i][3]] : i in [1..#Mons] | C[t][i] ne 0 ] : t in [1..m] ];
W:=RandomMatrix(F,n+1,r);
Pu<[u]>:=PolynomialRing(F,n,"grevlex");
zu:=[ &+[ W[i][j]*(i le n select u[i] else 1) : i in [1..n+1] ] : j in [1..r] ];
t0:=Realtime(); I:=ideal<Pu| [Evaluate(p,zu): p in P]>;
GB:=GroebnerBasis(I); t1:=Realtime();
printf "GB time %o s\n", t1-t0;
V:=Variety(I); printf "Variety time %o s total, #rational sols %o\n", Realtime()-t0, #V;
// public-only filter: v in K2 iff dim ker DP_v = n and P vanishes on ker DP_v (check random point)
for s in V do
  v:=Vector(F,[ &+[ W[i][j]*(i le n select s[i] else 1) : i in [1..n+1] ] : j in [1..r] ]);
  J:=Matrix(F,[[Evaluate(Derivative(p,z[j]),Eltseq(v)) : j in [1..r]] : p in P]);
  Kr:=Nullspace(Transpose(J));
  ok:= Dimension(Kr) eq n and forall{p: p in P | Evaluate(p, Eltseq(&+[Random(F)*b : b in Basis(Kr)])) eq 0};
  printf "candidate: dim ker DP_v=%o, P vanishes on ker: %o\n", Dimension(Kr), ok;
  if ok then printf "K2BASIS %o\n", [Eltseq(b): b in Basis(Kr)]; end if;
end for;
quit;
