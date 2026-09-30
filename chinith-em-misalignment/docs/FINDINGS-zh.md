# Chinith 对外候选清单（2026-09-30，未经 PM 批准不得外发）

去重基准：作者 9/30 回复 issue 1–4；changke 9/30（ctr 不递增 + §3.3 未计 opening 接受率，= ngcc.dev sign-05-3）；ngcc.dev sign-05-1/2/3；Martin 稿件；ICCS 占位哈希规则（A-1 撤回）。
已剔除：编辑性问题（UV-7..10, A-7, A-9）；与 changke 重叠的 A-8（Topen 接受率）；与 issue 2–4 同根的 B-2/B-3a/B-3b/B-4/UV-11。

| # | 条目 | 层 | 证据 | 状态 |
|---|---|---|---|---|
| 1 | uBlockith-EM 关系错位一个分组：spec p.68 step 6 + p.69 steps 9/17（EM 下 ℓke=0，w̃ 已含 S0）→ w⋆ = in‖in‖S2…S22‖out；末轮读 S22 而非 out，pk2 从未进入约束。代码同构（ublockith_ublock_256.c:181,190,264; ublock_constraints.c:778-784）。修 ã0 后两个 EM 参数集诚实签名 100% 被拒；偏移 +1 块后 5/5 通过 | spec+impl | C-harness a0check；主 agent 复核 p.68-69、spec 行 652/4088 | CONFIRMED |
| 1b | 规格字面 EM 关系退化为 DR₀(in)=in（pk1 决定的前 2 轮不动点），pk2 自由——归约已在明文层演示。E2 猜测-确定攻击：nibble 交错固定 g=108 位后残余系统 SAT 秒级判定；代价 2^g·T_wrong ≈ 2^135.5（主 agent 在真实 pk1 上独立复测：8 次猜错拒绝均值 17.1 s、最大 30.7 s，C(108)=135.5；种植实例 22.4 s，135.8）。对约 63% 存在不动点的公钥，规格字面版 uBlockith-EM 可对任意消息/任意 pk2 全称伪造，≈2^135.5 ≪ 声称 2^256。仅打规格字面；代码末轮读 out 不受此影响。见 E-em-fixedpoint.md §E2、E-fixedpoint/vg108_*.log | spec | E2 + vg108 复测 | CONFIRMED（证书式，外推 2^108 枚举未执行）；break_score 3 |
| 2 | Vistrutith QuickSilver 聚合错误：证明者把三个不同约束的常数项当作同一多项式的 (a0,a1,a2)（vistrutith_vistrutah_512.c:144），验证者算 k_norm+Δk_io0+Δ²k_io1（:166-170），中间系数被丢弃；修 ã0 后两个参数集 100% 失败；须重写证明者，非 Deg2To3 问题 | impl | C-harness valchk（1728 约束值=0）+ a0check NO | CONFIRMED |
| 3 | issue 2 类掩码/参数错误在 uBlockith/Vistrutith 章节未被勘误：uBlockith.OWFProve p.69 steps 17–19（u0*, u1*+v0*, v1* 应为 v0*, u0*+v1*, u1*）；uBlockith.Sign p.71 两分支相同、EM 角色错；Vistrutith.Sign p.92 参数互换 | spec | C 报告 UV-4/UV-5 | CONFIRMED（spec 层） |
| 4 | 无法仅凭规格复现 KAT：SM4th-ti Table 10 α8 为代码生成元的 4 次幂；Table 8 为 uBlock-128/256 置换；F_{2^64..2^512} 不可约多项式未给；Ballet-256/Vistrutah-512 PRG 未定义 | spec | A 报告 A-2/A-3/A-4，C 报告 UV-6 | CONFIRMED |
| 5 | ρ 长度与规格不符（spec ξ=λ+128；代码 128/256/512 不等），H3 输入长度 4λ+ξ 与实际 3λ+ξ 不符 | spec+impl | A-5 | CONFIRMED（低） |
| 备选 | B-1 EM 非法私钥 free() 未初始化指针；A-6 BAVC.Reconstruct step 20 字面拒绝诚实 opening | impl / spec | — | 低 |
