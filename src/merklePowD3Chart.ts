import * as d3 from 'd3';

export interface PowProgressSample {
  blocksMined: number;
  activeNodes: number;
  hashRate?: number;
  merkleRoot?: string;
  levelCounts?: number[];
  timestamp?: number;
}

const MAX_BLOCKS = 16384;
const MAX_MERKLE_NODES = 32767;
const LEVEL_CAPACITIES = [16384, 8192, 4096, 2048, 1024, 512, 256, 128, 64, 32, 16, 8, 4, 2, 1]; // 15 levels

export function computeTheoreticalMerkleNodes(blocksMined: number): number {
  const b = Math.max(0, Math.min(MAX_BLOCKS, Math.floor(blocksMined)));
  if (b === 0) return 0;
  let total = 0;
  let levelActive = b;
  for (let lvl = 0; lvl < LEVEL_CAPACITIES.length; lvl++) {
    const add = Math.min(LEVEL_CAPACITIES[lvl], levelActive);
    total += add;
    levelActive = Math.ceil(levelActive / 2);
  }
  return total;
}

export function computeLevelFillCounts(blocksMined: number): number[] {
  const b = Math.max(0, Math.min(MAX_BLOCKS, Math.floor(blocksMined)));
  const counts: number[] = [];
  let levelActive = b;
  for (let lvl = 0; lvl < LEVEL_CAPACITIES.length; lvl++) {
    counts.push(Math.min(LEVEL_CAPACITIES[lvl], levelActive));
    levelActive = Math.ceil(levelActive / 2);
  }
  return counts;
}

export function initMerklePowD3Chart(): void {
  const samples: PowProgressSample[] = [
    {
      blocksMined: 0,
      activeNodes: 0,
      hashRate: 0,
      merkleRoot: '0x000000000000',
      levelCounts: new Array(15).fill(0),
      timestamp: Date.now(),
    },
  ];

  let zoomToActive = true;
  let lastRenderAt = 0;
  let pendingTimer: number | null = null;
  let latestSample: PowProgressSample = samples[0];

  function recordSample(sample: PowProgressSample): void {
    const blocksMined = Math.max(0, Math.min(MAX_BLOCKS, Math.floor(sample.blocksMined)));
    const activeNodes = Math.max(0, Math.min(MAX_MERKLE_NODES, Math.floor(sample.activeNodes)));
    const normalized: PowProgressSample = {
      blocksMined,
      activeNodes,
      hashRate: sample.hashRate ?? 0,
      merkleRoot: sample.merkleRoot ?? '',
      levelCounts:
        Array.isArray(sample.levelCounts) && sample.levelCounts.length === 15
          ? sample.levelCounts
          : computeLevelFillCounts(blocksMined),
      timestamp: sample.timestamp ?? Date.now(),
    };
    latestSample = normalized;

    const last = samples[samples.length - 1];
    if (blocksMined > last.blocksMined) {
      samples.push(normalized);
      if (samples.length > 240) {
        // Preserve genesis point (index 0) and downsample middle slightly if needed
        samples.splice(1, 1);
      }
    } else if (blocksMined === last.blocksMined) {
      samples[samples.length - 1] = normalized;
    }

    scheduleRender();
  }

  function scheduleRender(): void {
    const now = performance.now();
    if (now - lastRenderAt >= 120) {
      if (pendingTimer !== null) {
        window.clearTimeout(pendingTimer);
        pendingTimer = null;
      }
      render();
      return;
    }
    if (pendingTimer === null) {
      pendingTimer = window.setTimeout(() => {
        pendingTimer = null;
        render();
      }, 130);
    }
  }

  function updateKpis(s: PowProgressSample): void {
    const kpiNodes = document.getElementById('d3-kpi-nodes');
    const kpiBlocks = document.getElementById('d3-kpi-blocks');
    const kpiFill = document.getElementById('d3-kpi-fill');
    const kpiDelta = document.getElementById('d3-kpi-delta');
    const theoretical = computeTheoreticalMerkleNodes(s.blocksMined);
    const fillPct = ((s.activeNodes / MAX_MERKLE_NODES) * 100).toFixed(1);
    const delta = s.activeNodes - theoretical;

    if (kpiNodes) kpiNodes.textContent = `${s.activeNodes.toLocaleString()} / 32,767`;
    if (kpiBlocks) kpiBlocks.textContent = `${s.blocksMined.toLocaleString()} / 16,384`;
    if (kpiFill) kpiFill.textContent = `${fillPct}%`;
    if (kpiDelta) kpiDelta.textContent = delta === 0 ? 'Δ 0 EXACT' : `Δ ${delta > 0 ? '+' : ''}${delta}`;
  }

  function render(): void {
    lastRenderAt = performance.now();
    const chartEl = document.getElementById('audit-d3-merkle-pow');
    const levelsEl = document.getElementById('audit-d3-levels');
    const tooltipEl = document.getElementById('d3-chart-tooltip');
    updateKpis(latestSample);

    if (!chartEl || chartEl.offsetParent === null) return;

    const width = Math.max(250, Math.floor(chartEl.clientWidth || 300));
    const height = 148;
    const margin = { top: 10, right: 12, bottom: 24, left: 38 };
    const innerW = width - margin.left - margin.right;
    const innerH = height - margin.top - margin.bottom;

    const xMax = zoomToActive
      ? Math.max(32, Math.min(MAX_BLOCKS, Math.ceil(Math.max(latestSample.blocksMined * 1.25, 32))))
      : MAX_BLOCKS;
    const yMaxTheory = computeTheoreticalMerkleNodes(xMax);
    const yMax = zoomToActive
      ? Math.max(64, Math.min(MAX_MERKLE_NODES, Math.ceil(Math.max(yMaxTheory, latestSample.activeNodes) * 1.12)))
      : MAX_MERKLE_NODES;

    const xScale = d3.scaleLinear().domain([0, xMax]).range([0, innerW]);
    const yScale = d3.scaleLinear().domain([0, yMax]).range([innerH, 0]);

    // Build theoretical curve points across xMax
    const theoryPts: Array<{ x: number; y: number }> = [];
    const steps = 48;
    for (let i = 0; i <= steps; i++) {
      const b = Math.round((i / steps) * xMax);
      theoryPts.push({ x: b, y: computeTheoreticalMerkleNodes(b) });
    }

    const visibleSamples = samples.filter((d) => d.blocksMined <= xMax);
    if (visibleSamples.length === 1 && latestSample.blocksMined > 0) {
      visibleSamples.push(latestSample);
    }

    const svg = d3
      .select(chartEl)
      .selectAll<SVGSVGElement, null>('svg.merkle-pow-svg')
      .data([null])
      .join('svg')
      .attr('class', 'merkle-pow-svg block w-full overflow-visible')
      .attr('viewBox', `0 0 ${width} ${height}`)
      .attr('height', height);

    const g = svg
      .selectAll<SVGGElement, null>('g.plot-root')
      .data([null])
      .join('g')
      .attr('class', 'plot-root')
      .attr('transform', `translate(${margin.left},${margin.top})`);

    // Horizontal gridlines
    const yTicks = yScale.ticks(4);
    g.selectAll<SVGLineElement, number>('line.grid-y')
      .data(yTicks)
      .join('line')
      .attr('class', 'grid-y')
      .attr('x1', 0)
      .attr('x2', innerW)
      .attr('y1', (d) => yScale(d))
      .attr('y2', (d) => yScale(d))
      .attr('stroke', 'rgba(148,163,184,0.14)')
      .attr('stroke-dasharray', '2,2');

    // Axes
    const xAxis = d3
      .axisBottom(xScale)
      .ticks(4)
      .tickFormat((v) => (Number(v) >= 1000 ? `${(Number(v) / 1000).toFixed(1)}k` : String(v)));
    const yAxis = d3
      .axisLeft(yScale)
      .ticks(4)
      .tickFormat((v) => (Number(v) >= 1000 ? `${(Number(v) / 1000).toFixed(1)}k` : String(v)));

    const gx = g
      .selectAll<SVGGElement, null>('g.x-axis')
      .data([null])
      .join('g')
      .attr('class', 'x-axis')
      .attr('transform', `translate(0,${innerH})`)
      .call(xAxis);
    gx.selectAll('path,line').attr('stroke', 'rgba(148,163,184,0.35)');
    gx.selectAll('text').attr('fill', '#94a3b8').attr('font-size', '8.5px').attr('font-family', 'monospace');

    const gy = g
      .selectAll<SVGGElement, null>('g.y-axis')
      .data([null])
      .join('g')
      .attr('class', 'y-axis')
      .call(yAxis);
    gy.selectAll('path,line').attr('stroke', 'rgba(148,163,184,0.35)');
    gy.selectAll('text').attr('fill', '#94a3b8').attr('font-size', '8.5px').attr('font-family', 'monospace');

    // Area + Line generators
    const areaGen = d3
      .area<PowProgressSample>()
      .x((d) => xScale(d.blocksMined))
      .y0(innerH)
      .y1((d) => yScale(d.activeNodes))
      .curve(d3.curveMonotoneX);

    const lineGen = d3
      .line<PowProgressSample>()
      .x((d) => xScale(d.blocksMined))
      .y((d) => yScale(d.activeNodes))
      .curve(d3.curveMonotoneX);

    const theoryLineGen = d3
      .line<{ x: number; y: number }>()
      .x((d) => xScale(d.x))
      .y((d) => yScale(d.y))
      .curve(d3.curveMonotoneX);

    // Gradient def
    const defs = svg
      .selectAll<SVGDefsElement, null>('defs')
      .data([null])
      .join('defs');
    const grad = defs
      .selectAll<SVGLinearGradientElement, null>('linearGradient#merkleAreaGrad')
      .data([null])
      .join('linearGradient')
      .attr('id', 'merkleAreaGrad')
      .attr('x1', '0%')
      .attr('y1', '0%')
      .attr('x2', '0%')
      .attr('y2', '100%');
    grad
      .selectAll<SVGStopElement, { off: string; col: string; op: number }>('stop')
      .data([
        { off: '0%', col: '#38bdf8', op: 0.38 },
        { off: '100%', col: '#38bdf8', op: 0.02 },
      ])
      .join('stop')
      .attr('offset', (d) => d.off)
      .attr('stop-color', (d) => d.col)
      .attr('stop-opacity', (d) => d.op);

    g.selectAll<SVGPathElement, PowProgressSample[]>('path.merkle-area')
      .data([visibleSamples])
      .join('path')
      .attr('class', 'merkle-area')
      .attr('fill', 'url(#merkleAreaGrad)')
      .attr('d', areaGen);

    g.selectAll<SVGPathElement, Array<{ x: number; y: number }>>('path.merkle-theory')
      .data([theoryPts])
      .join('path')
      .attr('class', 'merkle-theory')
      .attr('fill', 'none')
      .attr('stroke', '#facc15')
      .attr('stroke-width', 1.25)
      .attr('stroke-dasharray', '3,3')
      .attr('stroke-opacity', 0.78)
      .attr('d', theoryLineGen);

    g.selectAll<SVGPathElement, PowProgressSample[]>('path.merkle-live-line')
      .data([visibleSamples])
      .join('path')
      .attr('class', 'merkle-live-line')
      .attr('fill', 'none')
      .attr('stroke', '#38bdf8')
      .attr('stroke-width', 2)
      .attr('d', lineGen);

    // Frontier Marker
    const fx = xScale(Math.min(xMax, latestSample.blocksMined));
    const fy = yScale(Math.min(yMax, latestSample.activeNodes));

    g.selectAll<SVGLineElement, number>('line.frontier-guide')
      .data([fx])
      .join('line')
      .attr('class', 'frontier-guide')
      .attr('x1', (d) => d)
      .attr('x2', (d) => d)
      .attr('y1', 0)
      .attr('y2', innerH)
      .attr('stroke', 'rgba(52,211,153,0.45)')
      .attr('stroke-dasharray', '2,2');

    g.selectAll<SVGCircleElement, PowProgressSample>('circle.frontier-dot')
      .data([latestSample])
      .join('circle')
      .attr('class', 'frontier-dot')
      .attr('cx', fx)
      .attr('cy', fy)
      .attr('r', 3.5)
      .attr('fill', '#34d399')
      .attr('stroke', '#0f172a')
      .attr('stroke-width', 1.25);

    // Crosshair hover elements
    const hoverLine = g
      .selectAll<SVGLineElement, null>('line.hover-crosshair')
      .data([null])
      .join('line')
      .attr('class', 'hover-crosshair')
      .attr('y1', 0)
      .attr('y2', innerH)
      .attr('stroke', 'rgba(226,232,240,0.45)')
      .attr('stroke-width', 1)
      .style('opacity', 0);

    const hoverDot = g
      .selectAll<SVGCircleElement, null>('circle.hover-dot')
      .data([null])
      .join('circle')
      .attr('class', 'hover-dot')
      .attr('r', 3.5)
      .attr('fill', '#facc15')
      .attr('stroke', '#020617')
      .style('opacity', 0);

    const bisect = d3.bisector<PowProgressSample, number>((d) => d.blocksMined).center;

    g.selectAll<SVGRectElement, null>('rect.hover-overlay')
      .data([null])
      .join('rect')
      .attr('class', 'hover-overlay')
      .attr('width', innerW)
      .attr('height', innerH)
      .attr('fill', 'transparent')
      .style('cursor', 'crosshair')
      .on('mousemove', (event) => {
        const [mx] = d3.pointer(event);
        const hoveredBlock = Math.max(0, Math.min(xMax, Math.round(xScale.invert(mx))));
        const idx = bisect(visibleSamples, hoveredBlock);
        const pt = visibleSamples[Math.max(0, Math.min(visibleSamples.length - 1, idx))];
        const theory = computeTheoreticalMerkleNodes(hoveredBlock);

        const cx = xScale(pt ? pt.blocksMined : hoveredBlock);
        const cy = yScale(pt ? pt.activeNodes : theory);

        hoverLine.attr('x1', cx).attr('x2', cx).style('opacity', 1);
        hoverDot.attr('cx', cx).attr('cy', cy).style('opacity', 1);

        if (tooltipEl) {
          tooltipEl.classList.remove('hidden');
          tooltipEl.textContent = pt
            ? `Blk ${pt.blocksMined.toLocaleString()}: ${pt.activeNodes.toLocaleString()} live nodes (bound ${computeTheoreticalMerkleNodes(pt.blocksMined).toLocaleString()}) · ${(pt.hashRate || 0).toLocaleString()} H/s`
            : `Blk ${hoveredBlock}: bound ${theory.toLocaleString()} nodes`;
        }
      })
      .on('mouseleave', () => {
        hoverLine.style('opacity', 0);
        hoverDot.style('opacity', 0);
        if (tooltipEl) tooltipEl.classList.add('hidden');
      });

    // Render 13-level Merkle pyramid bar fill breakdown (L0..L12)
    if (levelsEl) {
      const lvCounts = latestSample.levelCounts ?? computeLevelFillCounts(latestSample.blocksMined);
      const lWidth = Math.max(250, Math.floor(levelsEl.clientWidth || width));
      const lHeight = 52;
      const lm = { top: 6, right: 6, bottom: 14, left: 6 };
      const lw = lWidth - lm.left - lm.right;
      const lh = lHeight - lm.top - lm.bottom;

      const levelData = LEVEL_CAPACITIES.map((cap, lvl) => ({
        lvl,
        cap,
        active: lvCounts[lvl] ?? 0,
        ratio: cap > 0 ? Math.min(1, (lvCounts[lvl] ?? 0) / cap) : 0,
      }));

      const xBand = d3
        .scaleBand<number>()
        .domain(levelData.map((d) => d.lvl))
        .range([0, lw])
        .padding(0.18);
      const yBar = d3.scaleLinear().domain([0, 1]).range([lh, 0]);

      const lSvg = d3
        .select(levelsEl)
        .selectAll<SVGSVGElement, null>('svg.merkle-levels-svg')
        .data([null])
        .join('svg')
        .attr('class', 'merkle-levels-svg block w-full')
        .attr('viewBox', `0 0 ${lWidth} ${lHeight}`)
        .attr('height', lHeight);

      const lg = lSvg
        .selectAll<SVGGElement, null>('g.levels-root')
        .data([null])
        .join('g')
        .attr('class', 'levels-root')
        .attr('transform', `translate(${lm.left},${lm.top})`);

      lg.selectAll<SVGRectElement, (typeof levelData)[number]>('rect.lvl-bg')
        .data(levelData, (d) => d.lvl)
        .join('rect')
        .attr('class', 'lvl-bg')
        .attr('x', (d) => xBand(d.lvl) ?? 0)
        .attr('y', 0)
        .attr('width', xBand.bandwidth())
        .attr('height', lh)
        .attr('rx', 1.5)
        .attr('fill', 'rgba(15,23,42,0.9)')
        .attr('stroke', 'rgba(51,65,85,0.75)')
        .attr('stroke-width', 0.75);

      lg.selectAll<SVGRectElement, (typeof levelData)[number]>('rect.lvl-fill')
        .data(levelData, (d) => d.lvl)
        .join('rect')
        .attr('class', 'lvl-fill')
        .attr('x', (d) => xBand(d.lvl) ?? 0)
        .attr('y', (d) => yBar(d.ratio))
        .attr('width', xBand.bandwidth())
        .attr('height', (d) => lh - yBar(d.ratio))
        .attr('rx', 1.5)
        .attr('fill', (d) => (d.lvl === 13 ? '#facc15' : d.ratio > 0 ? '#38bdf8' : '#1e293b'));

      lg.selectAll<SVGTextElement, (typeof levelData)[number]>('text.lvl-lbl')
        .data(levelData, (d) => d.lvl)
        .join('text')
        .attr('class', 'lvl-lbl')
        .attr('x', (d) => (xBand(d.lvl) ?? 0) + xBand.bandwidth() / 2)
        .attr('y', lh + 10)
        .attr('text-anchor', 'middle')
        .attr('fill', '#94a3b8')
        .attr('font-size', '7.5px')
        .attr('font-family', 'monospace')
        .text((d) => `L${d.lvl}`);
    }
  }

  // Event listeners
  window.addEventListener('gaia-pow-progress', (ev: Event) => {
    const custom = ev as CustomEvent<PowProgressSample>;
    if (custom.detail) {
      recordSample(custom.detail);
    }
  });

  window.addEventListener('convergence-state-updated', (ev: Event) => {
    const conv = (ev as CustomEvent<{
      acceptedBlocksCount?: number;
      latestActiveMerkleNodes?: number;
      latestMerkleRoot?: string | null;
    }>).detail;
    if (conv && typeof conv.acceptedBlocksCount === 'number') {
      recordSample({
        blocksMined: conv.acceptedBlocksCount,
        activeNodes: conv.latestActiveMerkleNodes ?? latestSample.activeNodes,
        hashRate: latestSample.hashRate ?? 0,
        merkleRoot: conv.latestMerkleRoot ?? latestSample.merkleRoot ?? '',
        timestamp: Date.now(),
      });
    }
  });

  window.addEventListener('gaia-tab-changed', (ev: Event) => {
    const custom = ev as CustomEvent<{ tab: string }>;
    if (custom.detail?.tab === 'receipt') {
      requestAnimationFrame(() => render());
    }
  });

  const zoomBtn = document.getElementById('btn-d3-zoom-mode');
  if (zoomBtn) {
    zoomBtn.addEventListener('click', () => {
      zoomToActive = !zoomToActive;
      zoomBtn.textContent = zoomToActive ? 'SCALE: ACTIVE' : 'SCALE: 8,192';
      render();
    });
  }

  const container = document.getElementById('audit-d3-merkle-pow');
  if (container && typeof ResizeObserver !== 'undefined') {
    const ro = new ResizeObserver(() => scheduleRender());
    ro.observe(container);
  }

  (window as unknown as Record<string, unknown>).__gaiaMerkleD3 = {
    pushSample: recordSample,
    forceRender: render,
    getSamples: () => samples.slice(),
  };

  render();
}
