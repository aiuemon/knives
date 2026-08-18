export interface PieChartSlice {
	key: string;
	label: string;
	value: number;
}

// SVGの円弧パス用の固定パレット。スライス数がこれを超える場合は循環する。
const PALETTE = [
	"#6366f1",
	"#ec4899",
	"#f59e0b",
	"#10b981",
	"#3b82f6",
	"#ef4444",
	"#8b5cf6",
	"#14b8a6",
	"#f97316",
	"#84cc16",
	"#06b6d4",
	"#a855f7",
	"#eab308",
	"#22c55e",
	"#0ea5e9",
];

function polarToCartesian(cx: number, cy: number, r: number, angleDeg: number) {
	const rad = ((angleDeg - 90) * Math.PI) / 180;
	return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
}

// 12時の方向から時計回りにstartAngle〜endAngle(度)の扇形パスを描く。
function arcPath(
	cx: number,
	cy: number,
	r: number,
	startAngle: number,
	endAngle: number,
) {
	const start = polarToCartesian(cx, cy, r, startAngle);
	const end = polarToCartesian(cx, cy, r, endAngle);
	const largeArcFlag = endAngle - startAngle > 180 ? 1 : 0;
	return `M ${cx} ${cy} L ${start.x} ${start.y} A ${r} ${r} 0 ${largeArcFlag} 1 ${end.x} ${end.y} Z`;
}

// 手組みのSVG円グラフ + 凡例。外部チャートライブラリは追加しない方針
// (ShortURLStatsPageの折れ線グラフと同じ考え方)。
export function PieChart({
	title,
	ariaLabel,
	data,
}: {
	title: string;
	ariaLabel: string;
	data: PieChartSlice[];
}) {
	const total = data.reduce((sum, d) => sum + d.value, 0);

	return (
		<div>
			<h2 className="mb-3 text-lg font-medium">{title}</h2>
			{total === 0 ? (
				<p className="text-gray-500">この期間のクリックはありません。</p>
			) : (
				<div className="flex flex-wrap items-center gap-6">
					<svg
						viewBox="0 0 100 100"
						role="img"
						aria-label={ariaLabel}
						className="h-40 w-40 shrink-0"
					>
						{data.length === 1 ? (
							// 100%単一スライスは円弧の始点=終点になり描画が
							// 崩れるため、円として描く。
							<circle cx="50" cy="50" r="45" fill={PALETTE[0]}>
								<title>{`${data[0].label}: ${data[0].value}件 (100.0%)`}</title>
							</circle>
						) : (
							(() => {
								let cumulative = 0;
								return data.map((d, i) => {
									const startAngle = (cumulative / total) * 360;
									cumulative += d.value;
									const endAngle = (cumulative / total) * 360;
									return (
										<path
											key={d.key}
											d={arcPath(50, 50, 45, startAngle, endAngle)}
											fill={PALETTE[i % PALETTE.length]}
										>
											<title>{`${d.label}: ${d.value}件 (${((d.value / total) * 100).toFixed(1)}%)`}</title>
										</path>
									);
								});
							})()
						)}
					</svg>
					<ul className="flex-1 space-y-1 text-sm">
						{data.map((d, i) => (
							<li key={d.key} className="flex items-center gap-2">
								<span
									aria-hidden="true"
									className="h-3 w-3 shrink-0 rounded-sm"
									style={{ backgroundColor: PALETTE[i % PALETTE.length] }}
								/>
								<span className="text-gray-600 dark:text-gray-300">
									{d.label}
								</span>
								<span className="text-gray-400">
									{d.value}件 ({((d.value / total) * 100).toFixed(1)}%)
								</span>
							</li>
						))}
					</ul>
				</div>
			)}
		</div>
	);
}
