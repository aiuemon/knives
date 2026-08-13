import type { SVGProps } from "react";

// 操作ボタンを表示するアイコン群。ボタン本体の aria-label/title で
// アクセシブルネームを持たせる前提のため、アイコン自体は常に
// aria-hidden にして装飾扱いにする。
type IconProps = SVGProps<SVGSVGElement>;

function baseProps(props: IconProps): IconProps {
	return {
		viewBox: "0 0 20 20",
		width: 16,
		height: 16,
		fill: "none",
		stroke: "currentColor",
		strokeWidth: 1.5,
		strokeLinecap: "round",
		strokeLinejoin: "round",
		...props,
	};
}

export function PencilIcon(props: IconProps) {
	return (
		<svg aria-hidden="true" {...baseProps(props)}>
			<path d="M13.5 3.5 16.5 6.5 6.5 16.5H3.5V13.5L13.5 3.5Z" />
		</svg>
	);
}

export function TrashIcon(props: IconProps) {
	return (
		<svg aria-hidden="true" {...baseProps(props)}>
			<path d="M4 6h12" />
			<path d="M8 6V4.5A1.5 1.5 0 0 1 9.5 3h1A1.5 1.5 0 0 1 12 4.5V6" />
			<path d="M5.5 6 6 16a1 1 0 0 0 1 1h6a1 1 0 0 0 1-1l.5-10" />
			<path d="M8.5 9v4.5" />
			<path d="M11.5 9v4.5" />
		</svg>
	);
}

export function KeyIcon(props: IconProps) {
	return (
		<svg aria-hidden="true" {...baseProps(props)}>
			<circle cx="7" cy="13" r="3.25" />
			<path d="M9.3 10.7 15.5 4.5" />
			<path d="M13.5 6.5 15.5 8.5" />
			<path d="M11.5 8.5 13 10" />
		</svg>
	);
}

export function PowerIcon(props: IconProps) {
	return (
		<svg aria-hidden="true" {...baseProps(props)}>
			<path d="M10 3.5V9.5" />
			<path d="M6 5.7A5.5 5.5 0 1 0 14 5.7" />
		</svg>
	);
}

export function ChartIcon(props: IconProps) {
	return (
		<svg aria-hidden="true" {...baseProps(props)}>
			<path d="M4 16.5h12" />
			<path d="M6.5 16.5V11" />
			<path d="M10 16.5V6.5" />
			<path d="M13.5 16.5V9" />
		</svg>
	);
}
