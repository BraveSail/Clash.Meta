package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/metacubex/mihomo/common/cmd"
	"github.com/metacubex/mihomo/common/yaml"
	"github.com/metacubex/mihomo/component/age"
	"github.com/metacubex/mihomo/component/generator"
	"github.com/metacubex/mihomo/component/geodata"
	"github.com/metacubex/mihomo/component/hubprofile"
	"github.com/metacubex/mihomo/component/updater"
	"github.com/metacubex/mihomo/config"
	C "github.com/metacubex/mihomo/constant"
	"github.com/metacubex/mihomo/constant/features"
	"github.com/metacubex/mihomo/hub"
	"github.com/metacubex/mihomo/hub/executor"
	"github.com/metacubex/mihomo/log"
	"github.com/metacubex/mihomo/rules/provider"

	"go.uber.org/automaxprocs/maxprocs"
)

var (
	version                       bool
	testConfig                    bool
	geodataMode                   bool
	homeDir                       string
	configFile                    string
	configString                  string
	configBytes                   []byte
	ageSecretKey                  string
	externalUI                    string
	externalController            string
	externalControllerTLS         string
	externalControllerUnix        string
	externalControllerPipe        string
	externalControllerRoutingMark int
	secret                        string
	postUp                        string
	postDown                      string
)

func getIntEnv(key string) int {
	value := os.Getenv(key)
	intValue, _ := strconv.Atoi(value)
	return intValue
}

func init() {
	flag.StringVar(&homeDir, "d", os.Getenv("CLASH_HOME_DIR"), "set configuration directory")
	flag.StringVar(&configFile, "f", os.Getenv("CLASH_CONFIG_FILE"), "specify configuration file")
	flag.StringVar(&configString, "config", os.Getenv("CLASH_CONFIG_STRING"), "specify base64-encoded configuration string")
	flag.StringVar(&ageSecretKey, "age-secret-key", os.Getenv("CLASH_AGE_SECRET_KEY"), "specify age secret key to decrypt configuration")
	flag.StringVar(&externalUI, "ext-ui", os.Getenv("CLASH_OVERRIDE_EXTERNAL_UI_DIR"), "override external ui directory")
	flag.StringVar(&externalController, "ext-ctl", os.Getenv("CLASH_OVERRIDE_EXTERNAL_CONTROLLER"), "override external controller address")
	flag.StringVar(&externalControllerTLS, "ext-ctl-tls", os.Getenv("CLASH_OVERRIDE_EXTERNAL_CONTROLLER_TLS"), "override external controller tls address")
	flag.StringVar(&externalControllerUnix, "ext-ctl-unix", os.Getenv("CLASH_OVERRIDE_EXTERNAL_CONTROLLER_UNIX"), "override external controller unix address")
	flag.StringVar(&externalControllerPipe, "ext-ctl-pipe", os.Getenv("CLASH_OVERRIDE_EXTERNAL_CONTROLLER_PIPE"), "override external controller pipe address")
	flag.IntVar(&externalControllerRoutingMark, "ext-ctl-routing-mark", getIntEnv("CLASH_OVERRIDE_EXTERNAL_CONTROLLER_ROUTING_MARK"), "override external controller routing mark")
	flag.StringVar(&secret, "secret", os.Getenv("CLASH_OVERRIDE_SECRET"), "override secret for RESTful API")
	flag.StringVar(&postUp, "post-up", os.Getenv("CLASH_POST_UP"), "set post-up script")
	flag.StringVar(&postDown, "post-down", os.Getenv("CLASH_POST_DOWN"), "set post-down script")
	flag.BoolVar(&geodataMode, "m", false, "set geodata mode")
	flag.BoolVar(&version, "v", false, "show current version of mihomo")
	flag.BoolVar(&testConfig, "t", false, "test configuration and exit")
	flag.Parse()
}

func main() {
	// Defensive programming: panic when code mistakenly calls net.DefaultResolver
	net.DefaultResolver.PreferGo = true
	net.DefaultResolver.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		//panic("should never be called")
		buf := make([]byte, 1024)
		for {
			n := runtime.Stack(buf, true)
			if n < len(buf) {
				buf = buf[:n]
				break
			}
			buf = make([]byte, 2*len(buf))
		}
		fmt.Fprintf(os.Stderr, "panic: should never be called\n\n%s", buf) // always print all goroutine stack
		os.Exit(2)
		return nil, nil
	}

	_, _ = maxprocs.Set(maxprocs.Logger(func(string, ...any) {}))

	if len(os.Args) > 1 && os.Args[1] == "convert-ruleset" {
		provider.ConvertMain(os.Args[2:])
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "generate" {
		generator.Main(os.Args[2:])
		return
	}

	if len(os.Args) > 1 && os.Args[1] == "age" {
		age.Main(os.Args[2:])
		return
	}

	if version {
		fmt.Printf("Mihomo Meta %s %s %s with %s %s\n",
			C.Version, runtime.GOOS, runtime.GOARCH, runtime.Version(), C.BuildTime)
		if tags := features.Tags(); len(tags) != 0 {
			fmt.Printf("Use tags: %s\n", strings.Join(tags, ", "))
		}

		return
	}

	if homeDir != "" {
		if !filepath.IsAbs(homeDir) {
			currentDir, _ := os.Getwd()
			homeDir = filepath.Join(currentDir, homeDir)
		}
		C.SetHomeDir(homeDir)
	}

	if geodataMode {
		geodata.SetGeodataMode(true)
	}

	if ageSecretKey != "" {
		if err := age.VeritySecretKeys(ageSecretKey); err != nil {
			log.Errorln("Parse age-secret-key error: %s", err.Error())
		}
		age.SetGlobalSecretKeys(ageSecretKey)
	}

	if configString != "" {
		var err error
		configBytes, err = base64.StdEncoding.DecodeString(configString)
		if err != nil {
			log.Fatalln("Initial configuration error: %s", err.Error())
			return
		}
	} else if configFile == "-" {
		var err error
		configBytes, err = io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalln("Initial configuration error: %s", err.Error())
			return
		}
	} else {
		if configFile != "" {
			if !filepath.IsAbs(configFile) {
				currentDir, _ := os.Getwd()
				configFile = filepath.Join(currentDir, configFile)
			}
		} else {
			configFile = filepath.Join(C.Path.HomeDir(), C.Path.Config())
		}
		C.SetConfig(configFile)

		if err := config.Init(C.Path.HomeDir()); err != nil {
			log.Fatalln("Initial configuration directory error: %s", err.Error())
		}
	}

	if testConfig {
		if len(configBytes) != 0 {
			if _, err := executor.ParseWithBytes(configBytes); err != nil {
				log.Errorln(err.Error())
				fmt.Println("configuration test failed")
				os.Exit(1)
			}
		} else {
			if _, err := executor.Parse(); err != nil {
				log.Errorln(err.Error())
				fmt.Printf("configuration file %s test failed\n", C.Path.Config())
				os.Exit(1)
			}
		}
		fmt.Printf("configuration file %s test is successful\n", C.Path.Config())
		return
	}

	var options []hub.Option
	if externalUI != "" {
		options = append(options, hub.WithExternalUI(externalUI))
	}
	if externalController != "" {
		options = append(options, hub.WithExternalController(externalController))
	}
	if externalControllerTLS != "" {
		options = append(options, hub.WithExternalControllerTLS(externalControllerTLS))
	}
	if externalControllerUnix != "" {
		options = append(options, hub.WithExternalControllerUnix(externalControllerUnix))
	}
	if externalControllerPipe != "" {
		options = append(options, hub.WithExternalControllerPipe(externalControllerPipe))
	}
	if externalControllerRoutingMark != 0 {
		options = append(options, hub.WithExternalControllerRoutingMark(externalControllerRoutingMark))
	}
	if secret != "" {
		options = append(options, hub.WithSecret(secret))
	}

	if err := hub.Parse(configBytes, options...); err != nil {
		log.Fatalln("Parse config error: %s", err.Error())
	}

	if updater.GeoAutoUpdate() {
		updater.RegisterGeoUpdater()
	}

	if postDown != "" {
		defer func() {
			if _, err := cmd.ExecShell(postDown); err != nil {
				log.Errorln("post-down script error: %s", err.Error())
			}
		}()
	}
	if postUp != "" {
		if _, err := cmd.ExecShell(postUp); err != nil {
			log.Fatalln("post-up script error: %s", err.Error())
		}
	}

	defer executor.Shutdown()

	// A device that names a hub takes its configuration from there and keeps
	// taking it: pulled now, and pushed when the dashboard saves. Without this
	// the core reads its file once, so a box running it alone - an ONT, a
	// router - could only be reconfigured by hand and by restart.
	stopProfile := startHubProfile()
	defer stopProfile()

	termSign := make(chan os.Signal, 1)
	hupSign := make(chan os.Signal, 1)
	signal.Notify(termSign, syscall.SIGINT, syscall.SIGTERM)
	signal.Notify(hupSign, syscall.SIGHUP)
	for {
		select {
		case <-termSign:
			return
		case <-hupSign:
			if err := hub.Parse(configBytes, options...); err != nil {
				log.Errorln("Parse config error: %s", err.Error())
			}
		}
	}
}

// startHubProfile puts the hub channel into service when the configuration
// that was just loaded asks for one, and returns how to stop it.
//
// The YAML it receives is parsed and switched in through the executor, the
// same way any other configuration change is, so a pushed profile takes effect
// exactly as the app's own updates do.
func startHubProfile() func() {
	block := hubBlockFromConfig()
	if !block.Enabled() {
		return func() {}
	}
	if err := block.Validate(); err != nil {
		log.Warnln("[Profile] the hub block is incomplete, staying on the file: %s", err.Error())
		return func() {}
	}

	ctx, cancel := context.WithCancel(context.Background())
	client, err := hubprofile.New(*block, func(pulled []byte) error {
		// ParseWithBytes, not hub.Parse: the pulled YAML is a whole
		// configuration, and hub.Parse would read it from the file this one is
		// being written beside.
		parsed, err := executor.ParseWithBytes(pulled)
		if err != nil {
			return err
		}
		hub.ApplyConfig(parsed)
		return nil
	})
	if err != nil {
		log.Warnln("[Profile] %s", err.Error())
		cancel()
		return func() {}
	}
	log.Infoln("[Profile] this device takes its configuration from %s as %q", block.URL, block.ID)
	client.Start(ctx)
	return cancel
}

// hubBlockFromConfig reads the hub block out of the configuration the core was
// started with - from the bytes when they were given inline, and from the file
// otherwise.
//
// It is read from the raw configuration rather than the parsed one: the parsed
// configuration keeps only what the core runs, and this block describes how the
// core is to be kept up to date, which is not part of that.
func hubBlockFromConfig() *hubprofile.Config {
	if len(configBytes) != 0 {
		var raw config.RawConfig
		if err := yaml.Unmarshal(configBytes, &raw); err != nil {
			log.Debugln("[Profile] the configuration could not be read for a hub block: %s", err.Error())
			return nil
		}
		return raw.Hub
	}
	buf, err := os.ReadFile(C.Path.Config())
	if err != nil {
		log.Debugln("[Profile] the configuration file could not be read for a hub block: %s", err.Error())
		return nil
	}
	var raw config.RawConfig
	if err := yaml.Unmarshal(buf, &raw); err != nil {
		log.Debugln("[Profile] the configuration file could not be read for a hub block: %s", err.Error())
		return nil
	}
	return raw.Hub
}
