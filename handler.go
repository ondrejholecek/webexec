package main

import (
	"net/http"
	"net/url"
	"github.com/juju/loggo"
	"time"
	"fmt"
	"io"
	"strings"
)

type requestsHandler struct {
	urls   []Curl
	log    loggo.Logger
}

func (h requestsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log := h.log.Child(strings.Replace(fmt.Sprintf("%s", r.RemoteAddr), ".", "-", -1))
	log = log.Child(fmt.Sprintf("%d", time.Now().Unix()))
	log.Infof("Incoming request for %s", r.URL)

	var matched bool
	for _, curl := range h.urls {
		if curl.Path != r.URL.Path { continue }
		//
		matched = true
		log.Infof("Matched section \"%s\", reading from field(s) %s, using command \"%s\"",
			curl.Path, curl.Fields, strings.TrimSpace(curl.Command.Command))

		proc := processor{
			shell    : curl.Command.Shell,
			command  : strings.TrimSpace(curl.Command.Command),
			params   : curl.Command.Params,
			user     : curl.Command.User,
			group    : curl.Command.Group,
			chroot   : curl.Command.Chroot,
			log      : log,
		}

		proc.inputReader, proc.inputWriter   = io.Pipe()
		proc.outputReader, proc.outputWriter = io.Pipe()

		//
		params, err := url.ParseQuery(r.URL.RawQuery)
		if err != nil {
			log.Warningf("Cannot parse query parameters: %s", err)
		}

		proc.contentType = curl.ContentType
		proc.fields      = curl.Fields

		proc.fileName    = params.Get("filename")
		if len(proc.fileName) == 0 {
			proc.fileName = "converted"
			log.Infof("No filename given, using \"%s\"", proc.fileName)
		} else {
			log.Infof("Provided filename \"%s\"", proc.fileName)
		}

		if proc.process(w, r) {
			log.Infof("Processor finished successfully")
		} else {
			log.Infof("Processor finished with error")
		}

		break
	}

	if !matched {
		log.Warningf("No section matched")
		http.NotFoundHandler().ServeHTTP(w, r)
	}
}

