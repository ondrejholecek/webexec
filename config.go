package main

import (
	"encoding/xml"
	"io/ioutil"
	"fmt"
)

type Ccommand struct {
	User    string   `xml:"user,attr"`
	Group   string   `xml:"group,attr"`
	Chroot  string   `xml:"chroot,attr"`
	Shell   string   `xml:"shell,attr"`
	Command string   `xml:",chardata"`
	Params  []string `xml:"param"`
}

type Curl struct {
	Path         string     `xml:"path,attr"`
	Fields       []string   `xml:"field"`
	Command      Ccommand   `xml:"command"`
	ContentType  string     `xml:"contentType"`
}

type Cserver struct {
	Ip      string        `xml:"ip,attr"`
	Port    uint16        `xml:"port,attr"`
	SslKey  string        `xml:"key,attr"`
	SslCrt  string        `xml:"cert,attr"`
	Timeout uint64        `xml:"timeout,attr"`
	Urls    []Curl        `xml:"url"`
}

type Cwebexec struct {
	XMLName     xml.Name    `xml:"webexec"`
	Servers     []Cserver   `xml:"server"`
}

func loadConfig(filename string) (*Cwebexec, error) {
	var err error

	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("unable to read config: %s", err)
	}

	var config Cwebexec
	err = xml.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("unable to decode config: %s", err)
	}

	return &config, nil
}
