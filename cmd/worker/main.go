// Command worker consumes click events asynchronously, performs statistics
// rollups, and refreshes SAML/OIDC IdP metadata. See docs/architecture.md, 6節.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	slog.Info("worker starting")

	// TODO: Redis Stream("clicks")のconsumer groupから読み取り、
	// click_events へのバルクINSERTとclick_stats_dailyの日次UPSERTを行う
	// (冪等キーによるat-least-once対応)。SAML/OIDCメタデータの定期更新も
	// ここに実装する。

	<-ctx.Done()
	slog.Info("worker shutting down")
}
