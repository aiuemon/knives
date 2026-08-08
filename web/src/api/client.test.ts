import { describe, expect, it } from "vitest";
import { ApiError } from "./client";

describe("ApiError", () => {
	it("carries the HTTP status alongside the message", () => {
		const err = new ApiError(404, "not found");
		expect(err.status).toBe(404);
		expect(err.message).toBe("not found");
		expect(err).toBeInstanceOf(Error);
	});
});
