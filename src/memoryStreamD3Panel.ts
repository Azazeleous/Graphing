import * as d3 from 'd3';
import { memoryFabric, type SystemEventRecord } from './memoryFabric.ts';
import {
  sparseBandEngine,
  AXIS_FACE_PAIRS,
  BASE_BLOCKS_PER_SET,
  MERKLE_NODES_PER_SET,
  TOTAL_HYPER_BLOCKS,
  SPARSE_BAND_TOTAL_BYTES,
  SPARSE_PAYLOAD_PARTITION_BYTES,
  SPARSE_TAIL_RESERVED_BITS,
  type MultiFacetedMatchResult,
  type SpreadsheetPrismCell,
} from './sparseBandCryptoEngine.ts';
import { refreshConvergenceState } from './livingSystemConvergence.ts';

type StreamFilter = 'ALL' | 'POW_BLOCK_ACCEPTED' | 'SPARSE_BAND_INGEST' | 'COPRIME_INVERSE_SOLVE';

interface LinkedStreamNode {
  seq: number;
  event: SystemEventRecord;
  merkleRoot: string;
  shortRoot: string;
  blockLabel: string;
  laneLabel: string;
  digestShort: string;
  rootBucketIndex: number;
}

export function initMemoryStreamD3Panel(): void {
  let activeFilter: StreamFilter = 'ALL';
  let followLive = true;
  let selectedEventId: string | null = null;
  let lastMatch: MultiFacetedMatchResult | null = null;
  let renderPending = false;

  const scheduleRender = (): void => {
    if (renderPending) return;
    renderPending = true;
    requestAnimationFrame(() => {
      renderPending = false;
      renderStreamGraph();
      renderSummaryStats();
    });
  };

  function getEventColor(ev: SystemEventRecord): string {
    if (ev.verificationStatus === 'RED') return '#f43f5e';
    if (ev.operation === 'POW_BLOCK_ACCEPTED') return '#10b981';
    if (ev.operation === 'SPARSE_BAND_INGEST') return '#38bdf8';
    if (ev.operation === 'COPRIME_INVERSE_SOLVE') return '#f59e0b';
    return '#a78bfa';
  }

  function renderSummaryStats(): void {
    const summary = sparseBandEngine.getSummary();
    const setText = (id: string, text: string) => {
      const el = document.getElementById(id);
      if (el) el.textContent = text;
    };
    setText('d3-stream-events-cnt', `${memoryFabric.events.length.toLocaleString()} EVTS`);
    setText(
      'd3-stream-capacity-meta',
      `${BASE_BLOCKS_PER_SET.toLocaleString()}×3 (${TOTAL_HYPER_BLOCKS.toLocaleString()}) BLKS · ${MERKLE_NODES_PER_SET.toLocaleString()} NODES/SET`
    );
    setText(
      'sparse-band-metrics-ui',
      `Cells: ${summary.populatedCellsCount.toLocaleString()} · Bands: ${summary.populatedBandsCount} · 8,000,000B + ${SPARSE_TAIL_RESERVED_BITS.toLocaleString()}b Tail (${(summary.tailSequenceLength).toLocaleString()} ch)`
    );
    setText(
      'sparse-band-roots-ui',
      `Set1: 0x${summary.setRootsHex[0].slice(0, 10)}… · Set2: 0x${summary.setRootsHex[1].slice(0, 10)}… · Set3: 0x${summary.setRootsHex[2].slice(0, 10)}…`
    );
    renderSheetCellsTable();
  }

  function renderSheetCellsTable(): void {
    const bodyEl = document.getElementById('sparse-cells-list');
    if (!bodyEl) return;
    const recent = sparseBandEngine.cells.slice(-8).reverse();
    bodyEl.textContent = '';

    for (const c of recent) {
      const isHighlighted = lastMatch?.matchedCell?.cellSeqIndex === c.cellSeqIndex;
      const row = document.createElement('button');
      row.type = 'button';
      row.className = isHighlighted
        ? 'w-full text-left bg-emerald-950/60 border border-emerald-400/70 rounded px-2 py-1 space-y-0.5 transition-colors'
        : 'w-full text-left bg-slate-950 hover:bg-slate-900 border border-slate-800 rounded px-2 py-1 space-y-0.5 transition-colors';

      const top = document.createElement('div');
      top.className = 'flex justify-between items-center gap-1 text-[8.5px] tabular-nums';
      const left = document.createElement('span');
      left.className = 'text-cyan-300 font-semibold truncate';
      left.textContent = `[${c.cellRef}] S${c.setIndex + 1}·${c.faceLabel}·M${c.macroClusterId}·B#${c.blockIndex}·Orb${c.orbIndex}`;
      const right = document.createElement('span');
      right.className = 'text-amber-300 shrink-0';
      right.textContent = `L${c.laneId} ${c.directionalGlyph} · ${c.deweyAddress}`;
      top.appendChild(left);
      top.appendChild(right);

      const mid = document.createElement('div');
      mid.className = 'text-[8px] text-slate-200 truncate';
      mid.textContent = `Val: ${c.rawValue}`;

      const bot = document.createElement('div');
      bot.className = 'text-[7.5px] text-slate-400 tabular-nums truncate';
      bot.textContent = `BLAKE2b-128: ${c.blake2b128Hex} · SHA256d: ${c.sha256dHex.slice(0, 16)}… · @${c.byteOffset.toLocaleString()}B/${SPARSE_BAND_TOTAL_BYTES.toLocaleString()}B`;

      row.appendChild(top);
      row.appendChild(mid);
      row.appendChild(bot);
      row.addEventListener('click', () => {
        const input = document.getElementById('automatch-query-input') as HTMLInputElement | null;
        if (input) input.value = c.deweyAddress;
        executeAutoMatch(c.deweyAddress);
      });
      bodyEl.appendChild(row);
    }
  }

  function renderRubikCrossSectionSample(match: MultiFacetedMatchResult | null): void {
    const host = document.getElementById('audit-rubik-hypercube-sample');
    if (!host) return;

    const width = Math.max(250, Math.floor(host.clientWidth || 310));
    const height = 176;
    const cx = width / 2;
    const cy = height / 2;

    const svg = d3
      .select(host)
      .selectAll<SVGSVGElement, null>('svg.rubik-sample-svg')
      .data([null])
      .join('svg')
      .attr('class', 'rubik-sample-svg block w-full')
      .attr('viewBox', `0 0 ${width} ${height}`)
      .attr('height', height);

    const activeFace = match?.matchedCell?.faceLabel ?? 'TOP';
    const activePair = match?.matchedCell?.axisPairId ?? 0;
    const activeOrb = match?.matchedCell?.orbIndex ?? 0;
    const activeGlyph = match?.lane?.directionalGlyph ?? '<^>';

    // Outer Doubled Shell (2x scale hypercube bounding frame)
    svg
      .selectAll<SVGRectElement, null>('rect.outer-hypercube-shell')
      .data([null])
      .join('rect')
      .attr('class', 'outer-hypercube-shell')
      .attr('x', cx - 108)
      .attr('y', cy - 76)
      .attr('width', 216)
      .attr('height', 152)
      .attr('rx', 6)
      .attr('fill', 'rgba(15,23,42,0.45)')
      .attr('stroke', '#38bdf8')
      .attr('stroke-opacity', 0.45)
      .attr('stroke-dasharray', '4,3');

    // Inner Cube Assembly Frame
    svg
      .selectAll<SVGRectElement, null>('rect.inner-rubik-cube')
      .data([null])
      .join('rect')
      .attr('class', 'inner-rubik-cube')
      .attr('x', cx - 64)
      .attr('y', cy - 46)
      .attr('width', 128)
      .attr('height', 92)
      .attr('rx', 4)
      .attr('fill', 'rgba(15,23,42,0.85)')
      .attr('stroke', '#10b981')
      .attr('stroke-opacity', 0.55);

    // 3 Axis Pairs = 6 Individual Faces converging into the Dynamic Core Center
    const faceNodes: Array<{
      face: 'TOP' | 'BOTTOM' | 'LEFT' | 'RIGHT' | 'FRONT' | 'BACK';
      pairId: 0 | 1 | 2;
      x: number;
      y: number;
      outerX: number;
      outerY: number;
      col: string;
      dirLabel: string;
    }> = [
      { face: 'TOP', pairId: 0, x: cx, y: cy - 46, outerX: cx, outerY: cy - 72, col: '#10b981', dirLabel: '<^> TOP' },
      { face: 'BOTTOM', pairId: 0, x: cx, y: cy + 46, outerX: cx, outerY: cy + 72, col: '#f59e0b', dirLabel: 'v BOTTOM' },
      { face: 'LEFT', pairId: 1, x: cx - 64, y: cy, outerX: cx - 98, outerY: cy, col: '#38bdf8', dirLabel: '^> LEFT' },
      { face: 'RIGHT', pairId: 1, x: cx + 64, y: cy, outerX: cx + 98, outerY: cy, col: '#38bdf8', dirLabel: '><^ RIGHT' },
      { face: 'FRONT', pairId: 2, x: cx - 34, y: cy - 22, outerX: cx - 72, outerY: cy - 52, col: '#f43f5e', dirLabel: 'FRONT' },
      { face: 'BACK', pairId: 2, x: cx + 34, y: cy + 22, outerX: cx + 72, outerY: cy + 52, col: '#a78bfa', dirLabel: 'BACK' },
    ];

    // Convergence rays from Doubled Outer Shell -> Inner Faces -> Dynamic Core Center
    svg
      .selectAll<SVGLineElement, (typeof faceNodes)[number]>('line.core-converge-ray')
      .data(faceNodes, (d) => d.face)
      .join('line')
      .attr('class', 'core-converge-ray')
      .attr('x1', (d) => d.outerX)
      .attr('y1', (d) => d.outerY)
      .attr('x2', cx)
      .attr('y2', cy)
      .attr('stroke', (d) => d.col)
      .attr('stroke-width', (d) => (d.face === activeFace ? 2.2 : 1.0))
      .attr('stroke-opacity', (d) => (d.face === activeFace ? 0.95 : 0.35));

    // Outer 6 face anchor pads (doubled shell)
    svg
      .selectAll<SVGRectElement, (typeof faceNodes)[number]>('rect.outer-face-pad')
      .data(faceNodes, (d) => d.face)
      .join('rect')
      .attr('class', 'outer-face-pad')
      .attr('x', (d) => d.outerX - 18)
      .attr('y', (d) => d.outerY - 8)
      .attr('width', 36)
      .attr('height', 16)
      .attr('rx', 2.5)
      .attr('fill', (d) => (d.pairId === activePair ? 'rgba(56,189,248,0.22)' : 'rgba(15,23,42,0.92)'))
      .attr('stroke', (d) => d.col)
      .attr('stroke-width', (d) => (d.face === activeFace ? 1.8 : 0.9));

    svg
      .selectAll<SVGTextElement, (typeof faceNodes)[number]>('text.outer-face-txt')
      .data(faceNodes, (d) => d.face)
      .join('text')
      .attr('class', 'outer-face-txt')
      .attr('x', (d) => d.outerX)
      .attr('y', (d) => d.outerY + 3)
      .attr('text-anchor', 'middle')
      .attr('fill', '#e2e8f0')
      .attr('font-size', '6.5px')
      .attr('font-family', 'monospace')
      .text((d) => d.dirLabel);

    // Dynamic Core Center + 6 Inner Sierpinski Orb Prisms ring
    const orbAngles = d3.range(6).map((i) => ({
      orb: i,
      angle: (i / 6) * Math.PI * 2 - Math.PI / 2,
    }));

    svg
      .selectAll<SVGCircleElement, (typeof orbAngles)[number]>('circle.core-sierpinski-orb')
      .data(orbAngles, (d) => d.orb)
      .join('circle')
      .attr('class', 'core-sierpinski-orb')
      .attr('cx', (d) => cx + Math.cos(d.angle) * 18)
      .attr('cy', (d) => cy + Math.sin(d.angle) * 18)
      .attr('r', (d) => (d.orb === activeOrb ? 5.2 : 3.6))
      .attr('fill', (d) => (d.orb === activeOrb ? '#facc15' : '#06b6d4'))
      .attr('fill-opacity', (d) => (d.orb === activeOrb ? 0.95 : 0.6))
      .attr('stroke', '#020617')
      .attr('stroke-width', 1);

    svg
      .selectAll<SVGCircleElement, null>('circle.dynamic-core-center')
      .data([null])
      .join('circle')
      .attr('class', 'dynamic-core-center')
      .attr('cx', cx)
      .attr('cy', cy)
      .attr('r', 8.5)
      .attr('fill', '#10b981')
      .attr('fill-opacity', 0.32)
      .attr('stroke', '#facc15')
      .attr('stroke-width', 1.4);

    svg
      .selectAll<SVGTextElement, null>('text.rubik-core-caption')
      .data([null])
      .join('text')
      .attr('class', 'rubik-core-caption')
      .attr('x', cx)
      .attr('y', 11)
      .attr('text-anchor', 'middle')
      .attr('fill', '#94a3b8')
      .attr('font-size', '7px')
      .attr('font-family', 'monospace')
      .text(`2× SHELL + 3 AXIS PAIRS (T/B=1, L/R=1, F/B=1) · CORE ORB #${activeOrb} (${activeGlyph})`);
  }

  function renderStreamGraph(): void {
    const container = document.getElementById('audit-d3-memory-stream');
    const detailEl = document.getElementById('d3-stream-selected-detail');
    if (!container) return;

    const allEvents = memoryFabric.getRecentEventsWithMerkle(48);
    const filtered =
      activeFilter === 'ALL' ? allEvents : allEvents.filter((e) => e.operation === activeFilter);
    const visibleEvents = filtered.slice(-14);

    const setRoots = sparseBandEngine.getSummary().setRootsHex;
    const distinctRoots: string[] = [];
    const linkedNodes: LinkedStreamNode[] = visibleEvents.map((ev, i) => {
      const rootHex = ev.receipt?.merkleRoot || setRoots[i % 3] || '0'.repeat(64);
      let rIdx = distinctRoots.indexOf(rootHex);
      if (rIdx === -1) {
        rIdx = distinctRoots.length;
        distinctRoots.push(rootHex);
      }
      return {
        seq: i,
        event: ev,
        merkleRoot: rootHex,
        shortRoot: `0x${rootHex.slice(0, 8)}`,
        blockLabel: ev.receipt ? `#${ev.receipt.blockIndex}` : ev.operation.slice(0, 6),
        laneLabel:
          ev.receipt?.coprimeLaneId !== undefined ? `L${ev.receipt.coprimeLaneId}` : ev.sourceModule.slice(0, 6),
        digestShort: ev.receipt?.blake2b128Hex
          ? ev.receipt.blake2b128Hex.slice(0, 8)
          : ev.outputFingerprint.replace(/^0x/, '').slice(0, 8),
        rootBucketIndex: rIdx,
      };
    });

    if (followLive && linkedNodes.length > 0 && !selectedEventId) {
      selectedEventId = linkedNodes[linkedNodes.length - 1].event.eventId;
    }

    const width = Math.max(260, Math.floor(container.clientWidth || 310));
    const height = 186;
    const margin = { top: 22, right: 14, bottom: 24, left: 14 };
    const innerW = width - margin.left - margin.right;

    const svg = d3
      .select(container)
      .selectAll<SVGSVGElement, null>('svg.memory-stream-svg')
      .data([null])
      .join('svg')
      .attr('class', 'memory-stream-svg block w-full')
      .attr('viewBox', `0 0 ${width} ${height}`)
      .attr('height', height);

    const rootG = svg
      .selectAll<SVGGElement, null>('g.stream-root')
      .data([null])
      .join('g')
      .attr('class', 'stream-root')
      .attr('transform', `translate(${margin.left},${margin.top})`);

    // Track labels
    rootG
      .selectAll<SVGTextElement, null>('text.rail-top-label')
      .data([null])
      .join('text')
      .attr('class', 'rail-top-label')
      .attr('x', 0)
      .attr('y', -8)
      .attr('fill', '#38bdf8')
      .attr('font-size', '7.5px')
      .attr('font-family', 'monospace')
      .text(`MEMORYFABRIC STREAM (${linkedNodes.length} visible)`);

    rootG
      .selectAll<SVGTextElement, null>('text.rail-bot-label')
      .data([null])
      .join('text')
      .attr('class', 'rail-bot-label')
      .attr('x', 0)
      .attr('y', height - margin.top - 6)
      .attr('fill', '#facc15')
      .attr('font-size', '7.5px')
      .attr('font-family', 'monospace')
      .text(`MERKLE ROOT UPDATES (${distinctRoots.length} roots · 14-Level / 16,383 nodes)`);

    const eventY = 24;
    const rootY = 112;

    const xEventScale = d3
      .scalePoint<number>()
      .domain(linkedNodes.map((n) => n.seq))
      .range([14, innerW - 14])
      .padding(0.4);

    const xRootScale = d3
      .scalePoint<number>()
      .domain(distinctRoots.map((_, idx) => idx))
      .range([22, innerW - 22])
      .padding(0.4);

    // Guide rails
    rootG
      .selectAll<SVGLineElement, number>('line.stream-rail')
      .data([eventY, rootY])
      .join('line')
      .attr('class', 'stream-rail')
      .attr('x1', 0)
      .attr('x2', innerW)
      .attr('y1', (d) => d)
      .attr('y2', (d) => d)
      .attr('stroke', 'rgba(148,163,184,0.18)')
      .attr('stroke-dasharray', '2,2');

    // Links from Event Blocks -> Corresponding Merkle Root Updates
    const linkGen = d3
      .linkVertical<LinkedStreamNode, { x: number; y: number }>()
      .source((d) => ({ x: xEventScale(d.seq) ?? 0, y: eventY + 12 }))
      .target((d) => ({ x: xRootScale(d.rootBucketIndex) ?? 0, y: rootY - 10 }))
      .x((p) => p.x)
      .y((p) => p.y);

    rootG
      .selectAll<SVGPathElement, LinkedStreamNode>('path.event-merkle-link')
      .data(linkedNodes, (d) => d.event.eventId)
      .join('path')
      .attr('class', 'event-merkle-link')
      .attr('d', (d) => linkGen(d) ?? '')
      .attr('fill', 'none')
      .attr('stroke', (d) => getEventColor(d.event))
      .attr('stroke-width', (d) => (d.event.eventId === selectedEventId ? 2.2 : 1.15))
      .attr('stroke-opacity', (d) => (d.event.eventId === selectedEventId ? 0.95 : 0.42));

    // Sequential block-to-block stream chain arrows along top rail
    const chainPairs = linkedNodes.slice(1).map((n, i) => ({ prev: linkedNodes[i], next: n }));
    rootG
      .selectAll<SVGLineElement, (typeof chainPairs)[number]>('line.stream-chain-step')
      .data(chainPairs, (d) => `${d.prev.event.eventId}->${d.next.event.eventId}`)
      .join('line')
      .attr('class', 'stream-chain-step')
      .attr('x1', (d) => xEventScale(d.prev.seq) ?? 0)
      .attr('x2', (d) => xEventScale(d.next.seq) ?? 0)
      .attr('y1', eventY)
      .attr('y2', eventY)
      .attr('stroke', '#38bdf8')
      .attr('stroke-opacity', 0.48)
      .attr('stroke-width', 1.4);

    // Event block nodes (top rail)
    const evNodes = rootG
      .selectAll<SVGGElement, LinkedStreamNode>('g.stream-event-block')
      .data(linkedNodes, (d) => d.event.eventId)
      .join((enter) => {
        const gEnter = enter.append('g').attr('class', 'stream-event-block').style('cursor', 'pointer');
        gEnter.append('rect').attr('rx', 3);
        gEnter.append('text').attr('class', 'ev-lbl').attr('text-anchor', 'middle');
        return gEnter;
      });

    evNodes
      .attr('transform', (d) => `translate(${xEventScale(d.seq) ?? 0},${eventY})`)
      .on('click', (_ev, d) => {
        selectedEventId = d.event.eventId;
        followLive = false;
        renderStreamGraph();
        if (d.event.receipt?.deweyAddress) {
          executeAutoMatch(d.event.receipt.deweyAddress);
        } else {
          window.dispatchEvent(
            new CustomEvent('gaia-hypercube-highlight', {
              detail: {
                blockIndex: d.event.receipt?.blockIndex ?? 0,
                orbIndex: d.event.receipt?.orbIndex ?? 0,
                laneId: d.event.receipt?.coprimeLaneId ?? 0,
                eventId: d.event.eventId,
              },
            })
          );
        }
      });

    evNodes
      .select<SVGRectElement>('rect')
      .attr('x', -11)
      .attr('y', -11)
      .attr('width', 22)
      .attr('height', 22)
      .attr('fill', (d) => (d.event.eventId === selectedEventId ? '#0f172a' : '#020617'))
      .attr('stroke', (d) => (d.event.eventId === selectedEventId ? '#facc15' : getEventColor(d.event)))
      .attr('stroke-width', (d) => (d.event.eventId === selectedEventId ? 2 : 1.1));

    evNodes
      .select<SVGTextElement>('text.ev-lbl')
      .attr('y', 3)
      .attr('fill', '#e2e8f0')
      .attr('font-size', '6.5px')
      .attr('font-family', 'monospace')
      .text((d) => d.blockLabel.slice(0, 5));

    // Merkle root nodes (bottom rail)
    const rootNodes = rootG
      .selectAll<SVGGElement, string>('g.stream-merkle-root')
      .data(distinctRoots, (r) => r)
      .join((enter) => {
        const gEnter = enter.append('g').attr('class', 'stream-merkle-root');
        gEnter.append('polygon');
        gEnter.append('text').attr('class', 'rt-lbl').attr('text-anchor', 'middle');
        return gEnter;
      });

    rootNodes.attr('transform', (_r, idx) => `translate(${xRootScale(idx) ?? 0},${rootY})`);

    rootNodes
      .select<SVGPolygonElement>('polygon')
      .attr('points', '0,-10 10,0 0,10 -10,0')
      .attr('fill', (r) => {
        const selNode = linkedNodes.find((n) => n.event.eventId === selectedEventId);
        return selNode && selNode.merkleRoot === r ? 'rgba(250,204,21,0.35)' : 'rgba(56,189,248,0.16)';
      })
      .attr('stroke', (r) => {
        const selNode = linkedNodes.find((n) => n.event.eventId === selectedEventId);
        return selNode && selNode.merkleRoot === r ? '#facc15' : '#38bdf8';
      })
      .attr('stroke-width', 1.25);

    rootNodes
      .select<SVGTextElement>('text.rt-lbl')
      .attr('y', 19)
      .attr('fill', '#cbd5e1')
      .attr('font-size', '6.5px')
      .attr('font-family', 'monospace')
      .text((r) => `0x${r.slice(0, 6)}`);

    // Render selected block inspector bar
    const sel = linkedNodes.find((n) => n.event.eventId === selectedEventId) ?? linkedNodes[linkedNodes.length - 1];
    if (detailEl && sel) {
      const r = sel.event.receipt;
      detailEl.textContent = `${sel.event.eventId} [${sel.event.operation}] · Root 0x${sel.merkleRoot.slice(0, 12)}… · ${
        r?.deweyAddress ? `Dewey ${r.deweyAddress} · Lane L${r.coprimeLaneId ?? 0} · ` : ''
      }Eval ${sel.event.admissionEvaluationId}`;
    }

    renderRubikCrossSectionSample(lastMatch);
  }

  function executeAutoMatch(query: string): MultiFacetedMatchResult {
    const res = sparseBandEngine.solveMultiFacetedMatch(query);
    lastMatch = res;

    const statusEl = document.getElementById('automatch-result-ui');
    if (statusEl) {
      if (res.found && res.matchedCell && res.lane) {
        const c = res.matchedCell;
        statusEl.className =
          'bg-emerald-950/50 p-2 rounded border border-emerald-500/45 text-[8.5px] text-emerald-200 space-y-0.5 tabular-nums';
        statusEl.textContent =
          `EXACT MATCH (${res.matchStrategy} · ${res.admissionVerdict}) · ` +
          `${c.faceLabel} Axis#${c.axisPairId} · MacroCube #${c.macroClusterId} · Blk #${c.blockIndex} · Orb #${c.orbIndex}/5 · ` +
          `Lane L${res.lane.laneId} (${res.lane.directionalGlyph}) · Fwd=${res.forwardCoordinate} ↔ Inv=${res.inverseCoordinate} (T⁻¹=${res.verifiedInverseIdentity ? 'OK' : 'FAIL'}) · ` +
          `Dewey ${c.deweyAddress} · Rainbow ${c.rainbowBucketKey} · ` +
          `Band @${c.byteOffset.toLocaleString()}/${SPARSE_PAYLOAD_PARTITION_BYTES.toLocaleString()}B`;
      } else {
        statusEl.className =
          'bg-slate-950 p-2 rounded border border-rose-500/40 text-[8.5px] text-rose-300 space-y-0.5 tabular-nums';
        statusEl.textContent = `${res.admissionVerdict} · ${res.reason}`;
      }
    }

    if (res.found && res.matchedCell) {
      const c = res.matchedCell;
      memoryFabric.recordSparseBandEvent({
        operation: 'COPRIME_INVERSE_SOLVE',
        sourceModule: 'SparseBandCryptoEngine',
        blockIndex: c.blockIndex,
        merkleRoot: res.merkleRootAtLookup,
        activeMerkleNodes: Math.min(MERKLE_NODES_PER_SET, sparseBandEngine.cells.length * 2),
        blake2b512Hex: c.blake2b512Hex,
        blake2b128Hex: c.blake2b128Hex,
        sha256dHex: c.sha256dHex,
        deweyAddress: c.deweyAddress,
        coprimeLaneId: c.laneId,
        orbIndex: c.orbIndex,
        sparseBandOffset: c.byteOffset,
        creedEvaluationId: res.admissionEvaluationId,
      });

      window.dispatchEvent(
        new CustomEvent('gaia-hypercube-highlight', {
          detail: {
            setIndex: c.setIndex,
            axisPairId: c.axisPairId,
            faceLabel: c.faceLabel,
            macroClusterId: c.macroClusterId,
            blockIndex: c.blockIndex,
            orbIndex: c.orbIndex,
            laneId: c.laneId,
            deweyAddress: c.deweyAddress,
          },
        })
      );
      refreshConvergenceState(true);
    }

    renderRubikCrossSectionSample(res);
    renderSheetCellsTable();
    return res;
  }

  function handleSpreadsheetIngest(name: string, text: string): void {
    const out = sparseBandEngine.ingestSpreadsheetDocument(name, text);
    const msgEl = document.getElementById('sparse-ingest-status-ui');
    if (out.admitted && out.insertedCells.length > 0) {
      const first: SpreadsheetPrismCell = out.insertedCells[0];
      memoryFabric.recordSparseBandEvent({
        operation: 'SPARSE_BAND_INGEST',
        sourceModule: `Spreadsheet:${name}`,
        blockIndex: first.blockIndex,
        merkleRoot: out.merkleRootHex,
        activeMerkleNodes: Math.min(MERKLE_NODES_PER_SET, sparseBandEngine.cells.length * 2),
        blake2b512Hex: first.blake2b512Hex,
        blake2b128Hex: first.blake2b128Hex,
        sha256dHex: first.sha256dHex,
        deweyAddress: first.deweyAddress,
        coprimeLaneId: first.laneId,
        orbIndex: first.orbIndex,
        sparseBandOffset: first.byteOffset,
        prismsEncodedDelta: out.insertedCells.length,
        creedEvaluationId: out.evaluationId,
      });
      if (msgEl) {
        msgEl.className = 'text-[8.5px] text-emerald-300 tabular-nums';
        msgEl.textContent = `INGESTED ${out.insertedCells.length} cells (${name}) · Merkle 0x${out.merkleRootHex.slice(0, 12)}… · Eval ${out.evaluationId}`;
      }
      refreshConvergenceState(true);
      executeAutoMatch(first.deweyAddress);
    } else if (msgEl) {
      msgEl.className = 'text-[8.5px] text-rose-300 tabular-nums';
      msgEl.textContent = `INGEST ${out.verdict}: ${out.blockedReason || 'No cells parsed'}`;
    }
    scheduleRender();
  }

  // Bind controls
  document.querySelectorAll<HTMLButtonElement>('.btn-stream-filter').forEach((btn) => {
    btn.addEventListener('click', () => {
      activeFilter = (btn.dataset.filter as StreamFilter) || 'ALL';
      document.querySelectorAll<HTMLButtonElement>('.btn-stream-filter').forEach((b) => {
        const active = b.dataset.filter === activeFilter;
        b.className = active
          ? 'btn-stream-filter px-1.5 py-0.5 rounded bg-cyan-500/25 text-cyan-200 border border-cyan-400/50 text-[8px] font-semibold'
          : 'btn-stream-filter px-1.5 py-0.5 rounded bg-slate-900 text-slate-400 border border-slate-700 text-[8px] hover:text-slate-200';
      });
      scheduleRender();
    });
  });

  const followBtn = document.getElementById('btn-stream-follow');
  if (followBtn) {
    followBtn.addEventListener('click', () => {
      followLive = !followLive;
      if (followLive) selectedEventId = null;
      followBtn.textContent = followLive ? 'LIVE: ON' : 'LIVE: PAUSED';
      followBtn.className = followLive
        ? 'px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-400/40 text-[8px] font-semibold'
        : 'px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-200 border border-amber-400/40 text-[8px] font-semibold';
      scheduleRender();
    });
  }

  const autoMatchBtn = document.getElementById('btn-automatch-find');
  const autoMatchInput = document.getElementById('automatch-query-input') as HTMLInputElement | null;
  if (autoMatchBtn && autoMatchInput) {
    autoMatchBtn.addEventListener('click', () => executeAutoMatch(autoMatchInput.value));
    autoMatchInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') executeAutoMatch(autoMatchInput.value);
    });
  }

  const sampleSheetBtn = document.getElementById('btn-sparse-load-sample');
  if (sampleSheetBtn) {
    sampleSheetBtn.addEventListener('click', () => {
      const csvSample = [
        'AssetID,AxisPair,CoprimeLane,PayloadNote,DeweyClass',
        'BAND-001,TOP_BOTTOM=1,L00,Genesis Coprime Anchor 97152,500',
        'BAND-002,LEFT_RIGHT=1,L16,Sierpinski 6-Orb Spatial Lattice,511',
        'BAND-003,FRONT_BACK=1,L32,Outer 2x Hypercube Convergence,522',
        'BAND-004,CORE_NEXUS,L48,BLAKE2b-512 + SHA256d Proof Cell,500',
      ].join('\n');
      const txtEl = document.getElementById('sparse-sheet-paste') as HTMLTextAreaElement | null;
      if (txtEl) txtEl.value = csvSample;
      handleSpreadsheetIngest('COPRIME_HYPERCUBE_SAMPLE.csv', csvSample);
    });
  }

  const ingestPasteBtn = document.getElementById('btn-sparse-ingest-paste');
  if (ingestPasteBtn) {
    ingestPasteBtn.addEventListener('click', () => {
      const txtEl = document.getElementById('sparse-sheet-paste') as HTMLTextAreaElement | null;
      const val = txtEl?.value || '';
      handleSpreadsheetIngest('MANUAL_SHEET_BATCH.csv', val);
    });
  }

  const fileInput = document.getElementById('sparse-sheet-file') as HTMLInputElement | null;
  if (fileInput) {
    fileInput.addEventListener('change', () => {
      const f = fileInput.files?.[0];
      if (!f) return;
      const reader = new FileReader();
      reader.onload = () => {
        const text = typeof reader.result === 'string' ? reader.result : '';
        handleSpreadsheetIngest(f.name, text);
      };
      reader.readAsText(f);
    });
  }

  // Subscribe to live MemoryFabric & Convergence events
  memoryFabric.subscribe(() => scheduleRender());
  sparseBandEngine.subscribe(() => scheduleRender());
  window.addEventListener('convergence-state-updated', () => scheduleRender());
  window.addEventListener('gaia-tab-changed', (ev: Event) => {
    const custom = ev as CustomEvent<{ tab: string }>;
    if (custom.detail?.tab === 'receipt') {
      requestAnimationFrame(() => scheduleRender());
    }
  });

  // Expose inspect helper for debugging / convergence consumers
  (window as unknown as Record<string, unknown>).__gaiaMemoryStreamD3 = {
    forceRender: scheduleRender,
    executeAutoMatch,
    ingestSpreadsheet: handleSpreadsheetIngest,
    getAxisPairs: () => AXIS_FACE_PAIRS,
  };

  scheduleRender();
}
