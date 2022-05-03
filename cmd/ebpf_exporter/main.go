package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"log"
	"net/http"

	"github.com/cloudflare/ebpf_exporter/config"
	"github.com/cloudflare/ebpf_exporter/exporter"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/version"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
	yaml "gopkg.in/yaml.v2"
)

func main() {
	configFile := kingpin.Flag("config.file", "Config file path").File()
	debug := kingpin.Flag("debug", "Enable debug").Bool()
	listenAddress := kingpin.Flag("web.listen-address", "The address to listen on for HTTP requests").Default(":9435").String()
	metricsPath := kingpin.Flag("web.telemetry-path", "Path under which to expose metrics").Default("/metrics").String()
	kingpin.Version(version.Print("ebpf_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	config := config.Config{}

	err := yaml.NewDecoder(*configFile).Decode(&config)
	if err != nil {
		log.Fatalf("Error reading config file: %s", err)
	}

	e, err := exporter.New(config)
	if err != nil {
		log.Fatalf("Error creating exporter: %s", err)
	}

	err = e.Attach()
	if err != nil {
		log.Fatalf("Error attaching exporter: %s", err)
	}

	log.Printf("Starting with %d programs found in the config", len(config.Programs))

	err = prometheus.Register(version.NewCollector("ebpf_exporter"))
	if err != nil {
		log.Fatalf("Error registering version collector: %s", err)
	}

	err = prometheus.Register(e)
	if err != nil {
		log.Fatalf("Error registering exporter: %s", err)
	}

	mux := http.NewServeMux()

	mux.Handle(*metricsPath, promhttp.Handler())
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, err = w.Write([]byte(`<html>
			<head><title>eBPF Exporter</title></head>
			<body>
			<h1>eBPF Exporter</h1>
			<p><a href="` + *metricsPath + `">Metrics</a></p>
			</body>
			</html>`))
		if err != nil {
			log.Fatalf("Error sending response body: %s", err)
		}
	})

	if *debug {
		log.Printf("Debug enabled, exporting raw tables on /tables")
		mux.HandleFunc("/tables", e.TablesHandler)
	}

	var handler http.Handler = mux

	if len(config.BasicAuthUsers) > 0 {
		handler = basicAuthHandler(config.BasicAuthUsers, handler)
	}

	log.Printf("Listening on %s", *listenAddress)
	err = http.ListenAndServe(*listenAddress, handler)
	if err != nil {
		log.Fatalf("Error listening on %s: %s", *listenAddress, err)
	}
}

func basicAuthHandler(users map[string]string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, auth := r.BasicAuth()

		if !auth {
			w.Header().Set("WWW-Authenticate", "Basic")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		expectedPassword, userValid := users[user]

		// Ensure a constant-time lookup even if the password is invalid.
		if !userValid {
			// Ensure constant time compare
			expectedPassword = "someinvalidpassword"
		}

		expectedHash := sha256.Sum256([]byte(expectedPassword))
		passwordHash := sha256.Sum256([]byte(password))

		passwordMatch := subtle.ConstantTimeCompare(passwordHash[:], expectedHash[:]) == 1

		if !passwordMatch || !userValid {
			w.Header().Set("WWW-Authenticate", "Basic")
			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}
