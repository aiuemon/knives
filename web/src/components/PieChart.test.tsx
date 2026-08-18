import { cleanup, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";
import { PieChart } from "./PieChart";

describe("PieChart", () => {
	afterEach(() => {
		cleanup();
	});

	it("shows an empty-state message when there is no data", () => {
		render(<PieChart title="OS別" ariaLabel="OS別の円グラフ" data={[]} />);
		expect(
			screen.getByText("この期間のクリックはありません。"),
		).toBeInTheDocument();
	});

	it("renders one legend entry per slice with count and percentage", () => {
		render(
			<PieChart
				title="OS別"
				ariaLabel="OS別の円グラフ"
				data={[
					{ key: "windows", label: "Windows", value: 3 },
					{ key: "macos", label: "macOS", value: 1 },
				]}
			/>,
		);

		expect(screen.getByText("Windows")).toBeInTheDocument();
		expect(screen.getByText("3件 (75.0%)")).toBeInTheDocument();
		expect(screen.getByText("macOS")).toBeInTheDocument();
		expect(screen.getByText("1件 (25.0%)")).toBeInTheDocument();

		const chart = screen.getByRole("img", { name: "OS別の円グラフ" });
		expect(chart.querySelectorAll("path")).toHaveLength(2);
	});

	it("renders a single circle (not a degenerate arc) when there is only one slice", () => {
		render(
			<PieChart
				title="OS別"
				ariaLabel="OS別の円グラフ"
				data={[{ key: "windows", label: "Windows", value: 5 }]}
			/>,
		);

		const chart = screen.getByRole("img", { name: "OS別の円グラフ" });
		expect(chart.querySelectorAll("circle")).toHaveLength(1);
		expect(chart.querySelectorAll("path")).toHaveLength(0);
		expect(
			within(chart).getByText("Windows: 5件 (100.0%)"),
		).toBeInTheDocument();
	});
});
