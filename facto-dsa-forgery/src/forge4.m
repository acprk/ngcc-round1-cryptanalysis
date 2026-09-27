load "keys/pk128.m"; load "keys/k2_128.m";
F:=GF(q); SetSeed(2024);
hstr:=[x: x in Split(Read("keys/h128.txt")," ")| x ne ""]; h:=Vector(F,[F!StringToInteger(x): x in hstr]);
Pz<[z]>:=PolynomialRing(F,r);
P:=[ &+[ F!C[t][i]*z[Mons[i][1]]*z[Mons[i][2]]*z[Mons[i][3]] : i in [1..#Mons] | C[t][i] ne 0 ] : t in [1..m] ];
K2:=Matrix(F,K2rows);
V:=VectorSpace(F,r); K2sp:=sub<V|RowSequence(K2)>; comp:=[]; Bb:=Basis(K2sp);
for i in [1..r] do e:=V.i; if not (e in sub<V|Bb cat comp>) then Append(~comp,e); end if; if #comp eq n then break; end if; end for;
evalP:=func<vv | Vector(F,[Evaluate(P[t],Eltseq(vv)): t in [1..m]])>;
tri:=func<x,y,zz | (F!6)^-1*( evalP(x+y+zz)-evalP(x+y)-evalP(x+zz)-evalP(y+zz)+evalP(x)+evalP(y)+evalP(zz) )>;
ks:=[K2[i]: i in [1..n]];
c0t:=&+[Random(F)*comp[i]: i in [1..n]];
pairs:=[]; Ms:=[]; W:=VectorSpace(F,m); cur:=sub<W|>;
for i in [1..n] do for j in [i..n] do
  Mij:=Matrix(F,[ Eltseq(tri(ks[i],ks[j], V.a)) : a in [1..r] ]);
  vij:=Vector(F,[ &+[c0t[a]*Mij[a][t]: a in [1..r]] : t in [1..m]]);
  if not (vij in cur) then Append(~pairs,<i,j>); Append(~Ms,Mij); cur:=sub<W|Basis(cur) cat [vij]>; end if;
  if #pairs eq n then break; end if;
end for; if #pairs eq n then break; end if; end for;
// Lp(c0) = Ms[p] applied to c0 (m-vector). colspace over p = L(y0).
Lofc0:=func<c0 | [ Vector(F,[&+[c0[a]*Ms[p][a][t]:a in [1..r]]:t in [1..m]]) : p in [1..n] ]>;
good:=0; solvable:=0; t0:=Realtime(); FZ:=false;
for attempt in [1..60] do
  if Realtime()-t0 gt 1800 then break; end if;
  // fix 7 alpha random, solve for 3 alpha + 10 cc s.t. sum cc_p Lp(c0(alpha))=h
  BR<[g]>:=PolynomialRing(F, 3+n, "grevlex"); // g[1..3]=free alpha (positions 1..3), g[4..13]=cc
  afix:=[Random(F): i in [1..n-3]];
  alphasym:=[ i le 3 select g[i] else BR!afix[i-3] : i in [1..n] ];
  c0s:=[ &+[alphasym[a]*comp[a][j]: a in [1..n]] : j in [1..r] ];
  Lps:=[ [ &+[ c0s[a]*Ms[p][a][t] : a in [1..r] ] : t in [1..m] ] : p in [1..n] ];
  bil:=[ (&+[ g[3+p]*Lps[p][t] : p in [1..n] ]) - h[t] : t in [1..m] ];
  Ib:=ideal<BR|bil>;
  if Dimension(Ib) ne 0 then continue; end if;
  Vb:=Variety(Ib);
  for sb in Vb do
    alpha:=[ i le 3 select sb[i] else afix[i-3] : i in [1..n] ];
    c0:=&+[alpha[a]*comp[a]: a in [1..n]];
    Ly:=sub<W|Lofc0(c0)>;
    if not (h in Ly) then continue; end if;
    good+:=1;
    Qw<[w]>:=PolynomialRing(F,n,"grevlex");
    zexpr:=[ c0[j] + &+[w[i]*K2[i][j]: i in [1..n]] : j in [1..r] ];
    Iq:=ideal<Qw|[ Evaluate(P[t],zexpr)-h[t] : t in [1..m] ]>;
    if Dimension(Iq) ne 0 then continue; end if;
    Vq:=Variety(Iq);
    if #Vq gt 0 then
      solvable+:=1;
      ws:=Vq[1]; zz:=Vector(F,[ c0[j]+&+[ws[i]*K2[i][j]:i in [1..n]]:j in [1..r]]);
      if evalP(zz) eq h and not FZ then
        printf "FORGE_OK ZSIG %o\n", [Integers()!x: x in Eltseq(zz)]; FZ:=true;
      end if;
    end if;
  end for;
  printf "  [attempt %o] good_cosets=%o solvable=%o time=%o\n", attempt, good, solvable, Realtime()-t0;
  if FZ and solvable ge 1 then break; end if;
end for;
printf "MEAS good=%o solvable=%o forged=%o time=%o s\n", good, solvable, FZ, Realtime()-t0;
quit;
