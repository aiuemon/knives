// Package useragent classifies a raw User-Agent string into a coarse OS
// category and a version-independent browser family, for the OS別/
// ブラウザ別統計(4節)。cmd/workerがclick_events取り込み時に一度だけ
// 呼び出し、結果をos/browser列に保存する(referrer_hostと同じ考え方:
// 集計のたびに毎回パースし直すのは非効率なため)。
package useragent

import (
	"strings"

	mua "github.com/mileusna/useragent"
)

// Categorize maps rawUA to an OS category (~20種類。Windows/macOS/iOS/
// iPadOS/Android/Ubuntu/Debian/FreeBSD等)とブラウザファミリー
// (バージョン差異は同一視)。どちらも判定できない場合は空文字を返す。
//
// 既知の制約:
//   - iPadOS: 既定設定のSafariはiOS 13以降、User-AgentがmacOSと完全に
//     同一になる(Apple独自の仕様)ため、User-Agent文字列だけからは
//     原理的に判別できないケースがある。
//   - Linuxディストリビューション(Ubuntu/Debian等): ブラウザが
//     User-Agentにディストリ名を含める場合のみ判別できる。含めない
//     場合は単に「Linux」に分類される。
func Categorize(rawUA string) (os, browser string) {
	if strings.TrimSpace(rawUA) == "" {
		return "", ""
	}
	ua := mua.Parse(rawUA)
	return categorizeOS(ua, rawUA), ua.Name
}

func categorizeOS(ua mua.UserAgent, rawUA string) string {
	switch ua.OS {
	case mua.Windows:
		return "Windows"
	case mua.WindowsPhone:
		return "Windows Phone"
	case mua.MacOS:
		if strings.Contains(rawUA, "iPad") {
			return "iPadOS"
		}
		return "macOS"
	case mua.IOS:
		if strings.Contains(rawUA, "iPad") {
			return "iPadOS"
		}
		return "iOS"
	case mua.Android:
		return "Android"
	case mua.ChromeOS:
		return "Chrome OS"
	case mua.FreeBSD:
		return "FreeBSD"
	case mua.BlackBerry:
		return "BlackBerry OS"
	case mua.Harmony:
		return "HarmonyOS"
	case mua.Linux:
		return categorizeLinuxDistro(rawUA)
	}

	// mileusna/useragentが分類しないOS群を、生文字列の既知トークンで補う。
	switch {
	case strings.Contains(rawUA, "Silk"):
		return "Fire OS"
	case strings.Contains(rawUA, "KAIOS"):
		return "KaiOS"
	case strings.Contains(rawUA, "Apple TV"), strings.Contains(rawUA, "tvOS"):
		return "tvOS"
	case strings.Contains(rawUA, "Apple Watch"), strings.Contains(rawUA, "watchOS"):
		return "watchOS"
	case strings.Contains(rawUA, "FreeBSD"):
		// mileusna/useragentのFreeBSD判定は特定のトークン形式
		// (例: Konqueror系UA)にしか反応しないため、Firefox等の
		// 一般的な "X11; FreeBSD amd64; rv:..." 形式を補う。
		return "FreeBSD"
	case strings.Contains(rawUA, "OpenBSD"):
		return "OpenBSD"
	case strings.Contains(rawUA, "NetBSD"):
		return "NetBSD"
	case strings.Contains(rawUA, "SunOS"):
		return "Solaris"
	default:
		return ""
	}
}

func categorizeLinuxDistro(rawUA string) string {
	switch {
	case strings.Contains(rawUA, "Ubuntu"):
		return "Ubuntu"
	case strings.Contains(rawUA, "Debian"):
		return "Debian"
	case strings.Contains(rawUA, "Fedora"):
		return "Fedora"
	case strings.Contains(rawUA, "Arch Linux"), strings.Contains(rawUA, "; Arch"):
		return "Arch Linux"
	default:
		return "Linux"
	}
}
