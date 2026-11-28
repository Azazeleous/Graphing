from __future__ import annotations
import hashlib, hmac, math, random
from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

# ==============================================================================
# 1. CRYPTOGRAPHIC PRIMITIVES, HARDENED MMR & INTERPUNCT CONSISTENCY
# ==============================================================================

def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def hash_leaf(key: str, value: str) -> str:
    return sha256_hex(b"\x00" + key.encode("utf-8") + b":" + value.encode("utf-8"))

def hash_pair(left: str, right: str) -> str:
    return sha256_hex(b"\x01" + bytes.fromhex(left) + bytes.fromhex(right))

def hash_root_with_size(bagged_peaks: str, size: int) -> str:
    return sha256_hex(b"\x02" + size.to_bytes(8, "big") + bytes.fromhex(bagged_peaks))

@dataclass
class MMRProof:
    key: str
    value: str
    leaf_index: int
    mmr_size: int
    siblings: List[Tuple[str, str]]
    other_peaks_left: List[str]
    other_peaks_right: List[str]
    root_hash: str
    epoch: int

class HardenedMMRStore:
    def __init__(self):
        self.nodes: List[str] = []
        self.peaks: List[Tuple[int, int]] = []
        self.children: Dict[int, Tuple[int, int]] = {}
        self.leaf_count: int = 0
        self.leaf_positions: List[int] = []
        self.leaf_kv: List[Tuple[str, str]] = []
        self.latest_leaf_for_key: Dict[str, int] = {}
        self.epoch: int = 0
        self.interpunct_peaks: Dict[int, List[Tuple[int, str]]] = {}
        self.interpunct_sizes: Dict[int, int] = {}
        self.interpunct_roots: Dict[int, str] = {}

    def append(self, key: str, value: str) -> Tuple[int, str]:
        lh = hash_leaf(key, value)
        pos = len(self.nodes)
        self.nodes.append(lh)
        self.leaf_positions.append(pos)
        self.leaf_kv.append((key, value))
        leaf_idx = self.leaf_count
        self.latest_leaf_for_key[key] = leaf_idx
        self.leaf_count += 1

        curr_h, curr_idx = 0, pos
        while self.peaks and self.peaks[-1][0] == curr_h:
            _, left_idx = self.peaks.pop()
            parent_h = hash_pair(self.nodes[left_idx], self.nodes[curr_idx])
            p_idx = len(self.nodes)
            self.nodes.append(parent_h)
            self.children[p_idx] = (left_idx, curr_idx)
            curr_idx = p_idx
            curr_h += 1
        self.peaks.append((curr_h, curr_idx))

        self.epoch += 1
        root = self.compute_root()
        self.interpunct_peaks[self.epoch] = [(h, self.nodes[idx]) for h, idx in self.peaks]
        self.interpunct_sizes[self.epoch] = self.leaf_count
        self.interpunct_roots[self.epoch] = root
        return leaf_idx, root

    @staticmethod
    def _bag_peaks(peak_hashes: List[str], size: int) -> str:
        if not peak_hashes:
            return sha256_hex(b"EMPTY_MMR_ROOT")
        bag = peak_hashes[-1]
        for i in range(len(peak_hashes) - 2, -1, -1):
            bag = hash_pair(peak_hashes[i], bag)
        return hash_root_with_size(bag, size)

    def compute_root(self) -> str:
        return self._bag_peaks([self.nodes[idx] for _, idx in self.peaks], self.leaf_count)

    def generate_proof(self, key: str) -> Optional[MMRProof]:
        if key not in self.latest_leaf_for_key:
            return None
        leaf_idx = self.latest_leaf_for_key[key]
        k, v = self.leaf_kv[leaf_idx]

        acc, peak_list_idx, local_idx = 0, 0, leaf_idx
        for p_i, (h, _) in enumerate(self.peaks):
            span = 1 << h
            if leaf_idx < acc + span:
                peak_list_idx = p_i
                local_idx = leaf_idx - acc
                break
            acc += span

        peak_h, peak_node_idx = self.peaks[peak_list_idx]
        down_sibs: List[Tuple[str, str]] = []
        curr_node = peak_node_idx
        for bit_pos in range(peak_h - 1, -1, -1):
            l_child, r_child = self.children[curr_node]
            if (local_idx >> bit_pos) & 1:
                down_sibs.append((self.nodes[l_child], "L"))
                curr_node = r_child
            else:
                down_sibs.append((self.nodes[r_child], "R"))
                curr_node = l_child

        return MMRProof(
            key=k,
            value=v,
            leaf_index=leaf_idx,
            mmr_size=self.leaf_count,
            siblings=list(reversed(down_sibs)),
            other_peaks_left=[self.nodes[idx] for _, idx in self.peaks[:peak_list_idx]],
            other_peaks_right=[self.nodes[idx] for _, idx in self.peaks[peak_list_idx + 1:]],
            root_hash=self.compute_root(),
            epoch=self.epoch,
        )

    def generate_prefix_consistency_witness(
        self, old_epoch: int
    ) -> Tuple[List[str], List[List[Tuple[str, str]]]]:
        old_peaks = self.interpunct_peaks[old_epoch]
        merkle_paths: List[List[Tuple[str, str]]] = []
        acc = 0
        for old_h, old_hash in old_peaks:
            p_acc, target_peak_idx = 0, 0
            for p_i, (cur_h, _) in enumerate(self.peaks):
                span = 1 << cur_h
                if acc < p_acc + span:
                    target_peak_idx = p_i
                    break
                p_acc += span
            cur_h, cur_node = self.peaks[target_peak_idx]
            local_start = acc - p_acc
            down_sibs: List[Tuple[str, str]] = []
            for bit_pos in range(cur_h - 1, old_h - 1, -1):
                l_c, r_c = self.children[cur_node]
                if (local_start >> bit_pos) & 1:
                    down_sibs.append((self.nodes[l_c], "L"))
                    cur_node = r_c
                else:
                    down_sibs.append((self.nodes[r_c], "R"))
                    cur_node = l_c
            assert self.nodes[cur_node] == old_hash
            merkle_paths.append(list(reversed(down_sibs)))
            acc += (1 << old_h)
        return [h for _, h in old_peaks], merkle_paths

    @staticmethod
    def verify_proof(proof: MMRProof, trusted_root: str) -> bool:
        if proof.root_hash != trusted_root:
            return False
        curr = hash_leaf(proof.key, proof.value)
        for sib, side in proof.siblings:
            curr = hash_pair(curr, sib) if side == "R" else hash_pair(sib, curr)
        all_peaks = proof.other_peaks_left + [curr] + proof.other_peaks_right
        return HardenedMMRStore._bag_peaks(all_peaks, proof.mmr_size) == trusted_root


# ==============================================================================
# 2. SEQUENTIAL PRIME & COPRIME INVERSE 6-LOOP DUAL-DOMAIN FABRIC
# ==============================================================================

def next_primes(count: int, coprime_to: int) -> List[int]:
    primes, cand = [], 2
    while len(primes) < count:
        if all(cand % d != 0 for d in range(2, math.isqrt(cand) + 1)) and math.gcd(cand, coprime_to) == 1:
            primes.append(cand)
        cand += 1
    return primes

def smallest_prime_gt(n: int) -> int:
    cand = max(2, n + 1)
    while True:
        if all(cand % d != 0 for d in range(2, math.isqrt(cand) + 1)):
            return cand
        cand += 1

@dataclass
class TreeCoord:
    path: Tuple[int, ...]

    @property
    def depth(self) -> int:
        return len(self.path)

    def distance_to(self, other: TreeCoord) -> int:
        lca = 0
        for a, b in zip(self.path, other.path):
            if a == b:
                lca += 1
            else:
                break
        return self.depth + other.depth - 2 * lca

@dataclass
class DomainNode:
    node_id: str
    domain: str
    index_in_domain: int
    group_id: int
    phase_slot: int
    secret_key: bytes
    parent_id: Optional[str] = None
    children_ids: Set[str] = field(default_factory=set)
    coord: TreeCoord = field(default_factory=lambda: TreeCoord(()))
    prev_coord: Optional[TreeCoord] = None
    skip_fingers: Dict[str, TreeCoord] = field(default_factory=dict)
    twisted_partner_id: Optional[str] = None
    finalized_epoch: int = 0
    finalized_root: str = sha256_hex(b"EMPTY_MMR_ROOT")

    def sign(self, epoch: int, root_hash: str) -> str:
        return hmac.new(self.secret_key, f"{epoch}:{root_hash}".encode(), hashlib.sha256).hexdigest()

class DualDomainCoprimeFabric:
    def __init__(self, nodes_per_domain: int = 36, max_deg: int = 3, seed: int = 2026):
        assert nodes_per_domain % 6 == 0, "Each structured loop requires 6 nodes."
        self.nodes_per_domain = nodes_per_domain
        self.max_deg = max_deg
        self.modulus_m = smallest_prime_gt(nodes_per_domain)
        self.rng = random.Random(seed)
        self.mmr = HardenedMMRStore()
        self.domains: Dict[str, Dict[str, DomainNode]] = {"A": {}, "B": {}}
        self.roots: Dict[str, Optional[str]] = {"A": None, "B": None}
        self.seq_primes = next_primes(nodes_per_domain // 6 + 6, self.modulus_m)
        self.coprime_pairs = [(p, pow(p, -1, self.modulus_m)) for p in self.seq_primes]
        self._init_domains()

    def _init_domains(self) -> None:
        for dom in ["A", "B"]:
            for i in range(self.nodes_per_domain):
                nid = f"{dom}-{i:02d}"
                node = DomainNode(
                    node_id=nid,
                    domain=dom,
                    index_in_domain=i,
                    group_id=i // 6,
                    phase_slot=i % 6,
                    secret_key=hashlib.sha256(f"sk:{nid}".encode()).digest(),
                )
                self.domains[dom][nid] = node
                if self.roots[dom] is None:
                    self.roots[dom] = nid
                    node.coord = TreeCoord(())
                else:
                    cands = [
                        n for k, n in self.domains[dom].items()
                        if k != nid and len(n.children_ids) < self.max_deg
                    ]
                    parent = min(cands, key=lambda n: (n.coord.depth, len(n.children_ids)))
                    port = len(parent.children_ids)
                    parent.children_ids.add(nid)
                    node.parent_id = parent.node_id
                    node.coord = TreeCoord(parent.coord.path + (port,))
        self._build_coprime_6_loops_and_fingers()

    def _build_coprime_6_loops_and_fingers(self) -> None:
        for dom in ["A", "B"]:
            active_ids = sorted(self.domains[dom].keys())
            n_active = len(active_ids)
            if not n_active:
                continue
            for nid in active_ids:
                node = self.domains[dom][nid]
                p, p_inv = self.coprime_pairs[node.group_id % len(self.coprime_pairs)]
                stride = p if dom == "A" else p_inv

                loop_targets = []
                for j in range(1, 6):
                    mpos = ((node.index_in_domain + j * stride) % self.modulus_m) % n_active
                    pid = active_ids[mpos]
                    if pid != nid:
                        loop_targets.append(pid)

                others = [
                    o for o in self.domains[dom].values()
                    if o.node_id != nid and o.node_id not in loop_targets
                ]
                budget = max(2, int(math.ceil(1.5 * math.log2(max(2, n_active)))))
                pool = [(o, 1.0 / max(1, node.coord.distance_to(o.coord))) for o in others]
                chosen = list(loop_targets)
                for _ in range(min(budget, len(pool))):
                    tot = sum(w for _, w in pool)
                    r = self.rng.random() * tot
                    acc = 0.0
                    for pi, (o, w) in enumerate(pool):
                        acc += w
                        if acc >= r:
                            chosen.append(o.node_id)
                            pool.pop(pi)
                            break
                node.skip_fingers = {pid: self.domains[dom][pid].coord for pid in chosen}

                opp_dom = "B" if dom == "A" else "A"
                opp_active = sorted(self.domains[opp_dom].keys())
                if opp_active:
                    opp_idx = (
                        node.index_in_domain * p_inv if dom == "A" else node.index_in_domain * p
                    ) % len(opp_active)
                    node.twisted_partner_id = opp_active[opp_idx]

    def hrw_owner(self, domain: str, key: str) -> str:
        active = list(self.domains[domain].keys())
        return max(active, key=lambda nid: int(sha256_hex(f"{nid}:{key}".encode()), 16))

    def route_within_domain(self, dom: str, src: str, dst: str, use_fingers: bool = True) -> List[str]:
        nodes = self.domains[dom]
        t_coord = nodes[dst].coord
        visited, path, curr = set(), [src], src
        while curr != dst and len(path) <= len(nodes) * 2:
            visited.add(curr)
            c = nodes[curr]
            nbrs = (
                ([c.parent_id] if c.parent_id and c.parent_id in nodes else [])
                + [x for x in c.children_ids if x in nodes]
                + ([f for f in c.skip_fingers if f in nodes] if use_fingers else [])
            )
            unvis = [nid for nid in set(nbrs) if nid not in visited]
            if not unvis:
                break
            best = min(unvis, key=lambda nid: (0 if nid == dst else 1, nodes[nid].coord.distance_to(t_coord)))
            path.append(best)
            curr = best
        return path

    def simulate_churn(self, dom: str, failing_id: str) -> int:
        nodes = self.domains[dom]
        dead = nodes.pop(failing_id)
        orphans = list(dead.children_ids)
        if dead.parent_id and dead.parent_id in nodes:
            nodes[dead.parent_id].children_ids.discard(failing_id)
        if self.roots[dom] == failing_id:
            new_root = min(nodes.values(), key=lambda n: (n.coord.depth, n.node_id))
            if new_root.parent_id and new_root.parent_id in nodes:
                nodes[new_root.parent_id].children_ids.discard(new_root.node_id)
            new_root.parent_id = None
            self.roots[dom] = new_root.node_id
            self._prop(dom, new_root.node_id, TreeCoord(()))
            orphans = [o for o in orphans if o != new_root.node_id]

        reparented = 0
        for oid in orphans:
            if oid not in nodes:
                continue
            orphan = nodes[oid]
            cands = sorted(
                [n for nid, n in nodes.items() if nid != oid and not self._is_anc(dom, oid, nid)],
                key=lambda n: (len(n.children_ids) >= self.max_deg, n.coord.depth, len(n.children_ids)),
            )
            np = cands[0]
            port = len(np.children_ids)
            np.children_ids.add(oid)
            orphan.parent_id = np.node_id
            reparented += self._prop(dom, oid, TreeCoord(np.coord.path + (port,)))
        self._build_coprime_6_loops_and_fingers()
        return reparented

    def _is_anc(self, dom: str, anc: str, nid: str) -> bool:
        c = self.domains[dom].get(nid)
        while c and c.parent_id:
            if c.parent_id == anc:
                return True
            c = self.domains[dom].get(c.parent_id)
        return False

    def _prop(self, dom: str, start: str, coord: TreeCoord) -> int:
        nodes = self.domains[dom]
        n = nodes[start]
        if n.coord != coord:
            n.prev_coord = n.coord
            n.coord = coord
        cnt = 1
        for i, cid in enumerate(sorted(n.children_ids)):
            if cid in nodes:
                cnt += self._prop(dom, cid, TreeCoord(coord.path + (i,)))
        return cnt

    def bft_seal_interpunct(self, key: str, value: str) -> str:
        _, root = self.mmr.append(key, value)
        epoch = self.mmr.epoch
        all_nodes = list(self.domains["A"].values()) + list(self.domains["B"].values())
        q_bft = (2 * len(all_nodes)) // 3 + 1
        sigs = [(n.node_id, n.sign(epoch, root)) for n in all_nodes[:q_bft]]
        valid_sigs = sum(
            1 for nid, sig in sigs
            if hmac.compare_digest(
                sig,
                (self.domains["A"].get(nid) or self.domains["B"][nid]).sign(epoch, root),
            )
        )
        assert valid_sigs >= q_bft
        for n in all_nodes:
            n.finalized_epoch = epoch
            n.finalized_root = root
        return root


# ==============================================================================
# 3. DEFI CONDUCTIVE TWISTED-PAIR CHARGE ZONE
# ==============================================================================

class ConductiveTwistedPairChargeZone:
    STABLES = {"USDC", "USDT", "DAI"}
    VOLATILES = {"ETH", "BTC", "YGG", "SOL"}

    def __init__(self, fabric: DualDomainCoprimeFabric, amp_A: float = 100.0):
        self.fabric = fabric
        self.amp_A = amp_A
        self.reserves_A: Dict[str, float] = {
            "USDC": 1_000_000.0, "USDT": 1_000_000.0, "DAI": 1_000_000.0,
            "ETH": 500.0, "BTC": 25.0, "YGG": 2_000_000.0, "SOL": 10_000.0,
        }
        self.reserves_B: Dict[str, float] = dict(self.reserves_A)
        self.active_rivers: List[Tuple[str, str, str, float]] = []
        self.gross_flow_volume: Dict[str, float] = Counter()
        self.net_settled_volume: Dict[str, float] = Counter()
        self.fee_collected: Dict[str, float] = Counter()

    @staticmethod
    def stableswap_D(x: float, y: float, A: float) -> float:
        S = x + y
        if S == 0:
            return 0.0
        D, Ann = S, A * 4.0
        for _ in range(64):
            D_P = (D * D * D) / (4.0 * x * y)
            D_prev = D
            D = ((Ann * S + 2.0 * D_P) * D) / ((Ann - 1.0) * D + 3.0 * D_P)
            if abs(D - D_prev) <= 1e-9:
                break
        return D

    @staticmethod
    def stableswap_get_y(x_new: float, D: float, A: float) -> float:
        Ann = A * 4.0
        c = (D * D * D) / (4.0 * x_new * Ann)
        b = x_new + D / Ann
        y = D
        for _ in range(64):
            y_prev = y
            y = (y * y + c) / (2.0 * y + b - D)
            if abs(y - y_prev) <= 1e-9:
                break
        return y

    def dynamic_conductance_fee(self, coin: str, flow_A_to_B: bool) -> float:
        rA, rB = self.reserves_A[coin], self.reserves_B[coin]
        q = (rA - rB) / max(1e-9, rA + rB)
        base = 0.0004 if coin in self.STABLES else 0.0030
        if flow_A_to_B:
            return max(0.00005, base * (1.0 + 4.0 * q) if q >= 0 else base * max(0.125, 1.0 + 2.0 * q))
        return max(0.00005, base * (1.0 - 4.0 * q))

    def cross_domain_swap(
        self, src_dom: str, coin_in: str, coin_out: str, amount_in: float
    ) -> Tuple[float, float, str]:
        dst_dom = "B" if src_dom == "A" else "A"
        fee_rate = self.dynamic_conductance_fee(coin_in, flow_A_to_B=(src_dom == "A"))
        fee = amount_in * fee_rate
        net_in = amount_in - fee
        self.fee_collected[coin_in] += fee

        x = self.reserves_A[coin_in] + self.reserves_B[coin_in]
        y = self.reserves_A[coin_out] + self.reserves_B[coin_out]
        if coin_in in self.STABLES and coin_out in self.STABLES:
            D = self.stableswap_D(x, y, self.amp_A)
            y_new = self.stableswap_get_y(x + net_in, D, self.amp_A)
        else:
            y_new = (x * y) / (x + net_in)
        amount_out = y - y_new

        if src_dom == "A":
            self.reserves_A[coin_in] += amount_in
            self.reserves_B[coin_out] -= amount_out
        else:
            self.reserves_B[coin_in] += amount_in
            self.reserves_A[coin_out] -= amount_out

        root = self.fabric.bft_seal_interpunct(
            f"swap:{src_dom}->{dst_dom}:{coin_in}:{coin_out}:{self.fabric.mmr.epoch + 1}",
            f"in={amount_in:.4f},out={amount_out:.4f},fee={fee:.4f}",
        )
        return amount_out, fee_rate, root

    def step_bilateral_rivers(self, num_ticks: int = 100) -> Dict[str, float]:
        for _ in range(num_ticks):
            by_coin_A_to_B: Dict[str, float] = Counter()
            by_coin_B_to_A: Dict[str, float] = Counter()
            for src_dom, _, coin, rate in self.active_rivers:
                self.gross_flow_volume[coin] += rate
                if src_dom == "A":
                    by_coin_A_to_B[coin] += rate
                else:
                    by_coin_B_to_A[coin] += rate
            for coin in set(by_coin_A_to_B) | set(by_coin_B_to_A):
                net_delta = by_coin_A_to_B[coin] - by_coin_B_to_A[coin]
                self.net_settled_volume[coin] += abs(net_delta)
                self.reserves_A[coin] += net_delta
                self.reserves_B[coin] -= net_delta

        summary = ",".join(
            f"{c}:{self.reserves_A[c]:.2f}/{self.reserves_B[c]:.2f}"
            for c in sorted(self.reserves_A)
        )
        self.fabric.bft_seal_interpunct(f"river_interpunct:{self.fabric.mmr.epoch + 1}", summary)
        return {
            c: 100.0 * (1.0 - self.net_settled_volume[c] / max(1e-9, self.gross_flow_volume[c]))
            for c in self.gross_flow_volume
        }