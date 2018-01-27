package restic

import (
	"errors"
	"log"
	"net/http"
	"path/filepath"

	"github.com/ncw/rclone/cmd"
	"github.com/ncw/rclone/cmd/serve/restic/restserver"
	"github.com/ncw/rclone/fs"
	"github.com/spf13/cobra"
)

// Command definition for cobra
var Command = &cobra.Command{
	Use:           "restic remote:path",
	Short:         "Serve the remote with a REST server for use with restic",
	SilenceErrors: true,
	SilenceUsage:  true,
	Run: func(command *cobra.Command, args []string) {
		cmd.CheckArgs(1, 1, command, args)
		f := cmd.NewFsSrc(args)
		cmd.Run(false, true, command, func() error {
			return serveRestic(f)
		})
	},
}

func init() {
	flags := Command.Flags()
	flags.StringVar(&restserver.Config.Listen, "listen", restserver.Config.Listen, "listen address")
	flags.StringVar(&restserver.Config.Log, "log", restserver.Config.Log, "log HTTP requests in the combined log format")
	flags.StringVar(&restserver.Config.Path, "path", restserver.Config.Path, "data directory")
	flags.BoolVar(&restserver.Config.TLS, "tls", restserver.Config.TLS, "turn on TLS support")
	flags.StringVar(&restserver.Config.TLSCert, "tls-cert", restserver.Config.TLSCert, "TLS certificate path")
	flags.StringVar(&restserver.Config.TLSKey, "tls-key", restserver.Config.TLSKey, "TLS key path")
	flags.BoolVar(&restserver.Config.AppendOnly, "append-only", restserver.Config.AppendOnly, "enable append only mode")
	flags.BoolVar(&restserver.Config.Prometheus, "prometheus", restserver.Config.Prometheus, "enable Prometheus metrics")
}

var version = "manually"

func tlsSettings() (bool, string, string, error) {
	var key, cert string
	enabledTLS := restserver.Config.TLS
	if !enabledTLS && (restserver.Config.TLSKey != "" || restserver.Config.TLSCert != "") {
		return false, "", "", errors.New("requires enabled TLS")
	} else if !enabledTLS {
		return false, "", "", nil
	}
	if restserver.Config.TLSKey != "" {
		key = restserver.Config.TLSKey
	} else {
		key = filepath.Join(restserver.Config.Path, "private_key")
	}
	if restserver.Config.TLSCert != "" {
		cert = restserver.Config.TLSCert
	} else {
		cert = filepath.Join(restserver.Config.Path, "public_key")
	}
	return enabledTLS, key, cert, nil
}

func serveRestic(f fs.Fs) error {
	restserver.Config.FS = f
	restserver.Config.Debug = fs.Config.LogLevel <= fs.LogLevelDebug
	// Use fast list for restic server since we are definitely buffering all objects in memory
	fs.Config.UseListR = true

	mux := restserver.NewMux()

	var handler http.Handler
	htpasswdFile, err := restserver.NewHtpasswdFromFile(filepath.Join(restserver.Config.Path, ".htpasswd"))
	if err != nil {
		handler = mux
		log.Println("Authentication disabled")
	} else {
		handler = restserver.AuthHandler(htpasswdFile, mux)
		log.Println("Authentication enabled")
	}

	enabledTLS, privateKey, publicKey, err := tlsSettings()
	if err != nil {
		return err
	}
	if !enabledTLS {
		log.Printf("Starting server on %s\n", restserver.Config.Listen)
		err = http.ListenAndServe(restserver.Config.Listen, handler)
	} else {
		log.Println("TLS enabled")
		log.Printf("Private key: %s", privateKey)
		log.Printf("Public key(certificate): %s", publicKey)
		log.Printf("Starting server on %s\n", restserver.Config.Listen)
		err = http.ListenAndServeTLS(restserver.Config.Listen, publicKey, privateKey, handler)
	}

	return err
}
