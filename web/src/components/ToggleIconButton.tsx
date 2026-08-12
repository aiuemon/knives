import type { ReactNode } from "react";

// admin権限付与/剥奪・凍結/凍結解除・有効化/無効化のような、同じアイコンを
// 状態に応じて出し分けるボタンは、アイコン色だけでは ON/OFF が分かりにくい
// (利用者からのフィードバックで判明)。背景・枠線色でも状態を示す。
type Color = "indigo" | "red" | "green";

const COLOR_CLASSES: Record<Color, string> = {
	indigo:
		"border-indigo-300 bg-indigo-100 text-indigo-600 dark:border-indigo-700 dark:bg-indigo-900/40 dark:text-indigo-400",
	red: "border-red-300 bg-red-100 text-red-600 dark:border-red-700 dark:bg-red-900/40 dark:text-red-400",
	green:
		"border-green-300 bg-green-100 text-green-600 dark:border-green-700 dark:bg-green-900/40 dark:text-green-400",
};

type ToggleIconButtonProps = {
	active: boolean;
	color: Color;
	icon: ReactNode;
	ariaLabel: string;
	title?: string;
	onClick: () => void;
	disabled?: boolean;
};

export function ToggleIconButton({
	active,
	color,
	icon,
	ariaLabel,
	title,
	onClick,
	disabled,
}: ToggleIconButtonProps) {
	return (
		<button
			type="button"
			disabled={disabled}
			aria-label={ariaLabel}
			title={title ?? ariaLabel}
			onClick={onClick}
			className={`rounded border p-1.5 disabled:opacity-50 ${
				active ? COLOR_CLASSES[color] : "border-gray-300 dark:border-gray-600"
			}`}
		>
			{icon}
		</button>
	);
}
