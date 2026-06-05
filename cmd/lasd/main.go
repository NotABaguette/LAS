package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/NotABaguette/LAS/internal/config"
	"github.com/NotABaguette/LAS/internal/control"
	"github.com/NotABaguette/LAS/internal/router"
	"github.com/NotABaguette/LAS/internal/web"
)

func main() {
	var (
		configPath = flag.String("config", "/etc/las/router.json", "router config path")
		webDir     = flag.String("web-dir", "/usr/share/las/web", "static web UI directory")
		listen     = flag.String("listen", "", "override UI listen address")
		apply      = flag.Bool("apply", false, "execute generated system changes instead of dry-run")
		planOnly   = flag.Bool("plan", false, "print generated apply plan and exit")
		validate   = flag.Bool("validate", false, "validate config and exit")
		initConfig = flag.Bool("init-config", false, "write a default config if the path does not exist")
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	if *initConfig {
		if err := config.Init(*configPath); err != nil {
			fatal(logger, err)
		}
		fmt.Printf("created %s\n", *configPath)
		return
	}

	if *validate || *planOnly {
		cfg, err := config.Load(*configPath)
		if err != nil {
			fatal(logger, err)
		}
		if *validate {
			fmt.Println("config is valid")
			return
		}
		plan, err := router.BuildPlan(cfg)
		if err != nil {
			fatal(logger, err)
		}
		data, err := plan.JSON()
		if err != nil {
			fatal(logger, err)
		}
		fmt.Println(string(data))
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	server := web.New(web.Options{
		ConfigPath: *configPath,
		WebDir:     *webDir,
		Listen:     *listen,
		Apply:      *apply,
	}, logger)
	if err := server.Serve(ctx); err != nil && ctx.Err() == nil {
		fatal(logger, err)
	}
}

func fatal(logger *slog.Logger, err error) {
	logger.Error("fatal", "error", err)
	os.Exit(1)
}

func executeForCLI(ctx context.Context, plan control.Plan, apply bool) ([]control.Result, error) {
	return control.Executor{DryRun: !apply}.Execute(ctx, plan)
}
