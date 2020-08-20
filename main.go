package main

import (
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	"github.com/juju/loggo"
	"flag"
	"log"
	"strings"
)

var logger loggo.Logger

func main() {
	var err error

	configFile := flag.String("c", "/etc/config.xml", "path to config file")
	debug      := flag.Bool("d", false, "enable debugging outputs")
	showTime   := flag.Bool("t", false, "show time in logs")
	flag.Parse()

	if *debug {
		logger = initLoggingDebug("webexec", *showTime)
		logger.SetLogLevel(loggo.DEBUG)
	} else {
		logger = initLoggingNormal("webexec", *showTime)
		logger.SetLogLevel(loggo.INFO)
	}
	logger.Infof("Program starting")

	config, err := loadConfig(*configFile)
	if err != nil {
		logger.Errorf("Cannot load config \"%s\": %s", *configFile, err)
		os.Exit(1)
	}

	var runningServers []*http.Server

	for _, server := range config.Servers {
		// prepare handler
		handler := requestsHandler{
			urls : server.Urls,
			log  : logger.Child(strings.Replace(fmt.Sprintf("%s:%d", server.Ip, server.Port), ".", "-", -1)),
		}

		// prepare the server
		httpServer := http.Server{
			Addr              : fmt.Sprintf("%s:%d", server.Ip, server.Port),
			Handler           : handler,
			ReadHeaderTimeout : 10*time.Second,
			ReadTimeout       : time.Duration(server.Timeout)*time.Second,
			IdleTimeout       : 60*time.Second,
			ErrorLog          : log.New(loggoWriter{log:logger.Child("httpserver")}, "", 0),
		}

		// if we have got ssl key and cert start as HTTPs server
		// otherwise plain http
		if len(server.SslKey) > 0 && len(server.SslCrt) > 0 {
			crt, key := server.SslCrt, server.SslKey
			logger.Debugf("Starting SSL server on %s with cert %s and key %s\n",
				httpServer.Addr, crt, key)

			go func() {
				err = httpServer.ListenAndServeTLS(crt, key)
				if err != nil {
					logger.Errorf("Cannot start HTTPs server: %s", err)
					os.Exit(1)
				}
			}()
			runningServers = append(runningServers, &httpServer)

		} else {
			logger.Debugf("Starting plaintext server on %s\n",
				httpServer.Addr)

			go func() {
				err = httpServer.ListenAndServe()
				if err != nil {
					logger.Errorf("Cannot start HTTP server: %s", err)
					os.Exit(1)
				}
			}()
			runningServers = append(runningServers, &httpServer)
		}
	}

	// wait for signal to terminate
	term := make(chan os.Signal)
	signal.Notify(term, os.Interrupt, syscall.SIGTERM)

	outer: for {
		select {
		case <-term:
			logger.Infof("Signal SIGTERM received")
			break outer
		case <-time.After(1 * time.Second):
//			logger.Debugf("Currently running servers: %d", len(runningServers))
		}
	}

	for _, httpServer := range runningServers {
		logger.Infof("Closing server at %s", httpServer.Addr)
		httpServer.Close()
	}

	logger.Infof("Program terminated")
}
