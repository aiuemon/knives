/// <reference types="vitest/config" />

import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// docker compose経由で1つのFQDN配下に統合する際、nginxが/appをこのVite
// devサーバへ、/api/apiサービスへ、それ以外を短縮URLリダイレクトサービスへ
// 転送する(deploy/nginx/nginx.conf)。SPAは常に/app配下が正になるため、
// bareでpnpm devする場合もhttp://localhost:5173/app/を開く。
const proxyPort = process.env.PROXY_PORT;

export default defineConfig({
	plugins: [react(), tailwindcss()],
	base: "/app/",
	server: {
		host: true,
		// nginx経由でアクセスするとHostヘッダがknives.localhostになるため、
		// Vite 5+のHost検証(CVE対策)を通すために許可する。
		allowedHosts: ["knives.localhost"],
		proxy: {
			"/api": "http://localhost:8080",
		},
		// PROXY_PORT未設定(bareでのpnpm dev)時はViteの既定のHMR接続先算出に
		// 任せる。compose経由の場合、ブラウザはコンテナ内の5173ではなく
		// nginxが公開するPROXY_PORT宛にHMR用WebSocketを繋ぎ直す必要がある。
		...(proxyPort ? { hmr: { clientPort: Number(proxyPort) } } : {}),
	},
	test: {
		environment: "jsdom",
		setupFiles: ["./src/test/setup.ts"],
	},
});
