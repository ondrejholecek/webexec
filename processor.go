package main

import (
	"github.com/juju/loggo"
	"io"
	"os/exec"
	"os/user"
	"net/http"
	"net/url"
	"strconv"
	"syscall"
	"strings"
	"fmt"
)

type processor struct {
	shell           string
	command         string
	params          []string
	user            string
	group           string
	chroot          string
	log             loggo.Logger

	inputWriter     *io.PipeWriter
	inputReader     *io.PipeReader
	outputWriter    *io.PipeWriter
	outputReader    *io.PipeReader

	fields          []string
	contentType     string
	fileName        string
}

func (p *processor) convert(done chan bool) {
	var err error

	var cmd *exec.Cmd
	if len(p.shell) > 0 {
		cmd = exec.Command(p.shell, "-c", p.command)
		p.log.Infof("Initializing convertor using shell: %s -c '%s'", p.shell, p.command)
		if len(p.params) > 0 {
			p.log.Warningf("Ignoring explicit command parameters because shell execution is in use")
		}
	} else {
		cmd = exec.Command(p.command, p.params...)
		p.log.Infof("Initializing convertor without shell: '%s' using params: '%s'", p.command, strings.Join(p.params, "', '"))
	}

	cmd.Stdin  = p.inputReader
	cmd.Stdout = p.outputWriter

	// get uid and gid of requested user
	// if no user or group was specified, the result will be current one
	uid, gid, err := p.getUidGid(p.user, p.group)
	if err != nil {
		p.log.Errorf("Cannot get effective UID and GID: %s", err)
		p.log.Errorf("Will not start the convertor")

	} else {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: uid, Gid: gid}
		cmd.SysProcAttr.Chroot = p.chroot

		p.log.Infof("Starting convertor as UID %d and GID %d with chroot \"%s\"", uid, gid, p.chroot)
		// command should be running until inputReader is closed
		// (or until there is an error)
		err = cmd.Run()
		if err != nil {
			p.log.Errorf("Cannot run command: %s", err)
		} else {
			p.log.Infof("Convertor finished")
		}
	}

	// close input read as we will not be reading any more data
	// (regardless on error/success state)
	p.inputReader.Close()

	// close the output writer to signalize all input data has been processed
	p.outputWriter.Close()

	// because this will be run from gorutine, signalize termination
	done <- true
}

func (p *processor) serve(w http.ResponseWriter, done chan bool) {
	if len(p.contentType) > 0 { w.Header().Set("Content-Type", p.contentType) }
	if len(p.fileName)    > 0 { w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=\"%s\"", url.QueryEscape(p.fileName)))
	}

	var total uint64
	data := make([]byte, 1024*500)

	// read output file until EOF
	for {
		rd, err := p.outputReader.Read(data)
		if err == io.EOF {
			p.log.Debugf("Source data ends")
			break
		}

		if err != nil {
			p.log.Errorf("Cannot read from output data: %s", err)
			break
		} else {
			cnt, err := w.Write(data[:rd])
			if err != nil {
				p.log.Errorf("Unable to write data to client: %s", err)
				break
			}
			total += uint64(cnt)

			// flusher is to allow streaming, however it is not so useful
			// if the application caches full input before it start providing output
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			} else {
				p.log.Warningf("Response does not support Flush() for streaming")
			}
		}
	}

	p.outputReader.Close()
	p.log.Debugf("Sent %d bytes of data to client", total)

	// signalize we are done
	done <- true
}

func (p *processor) process(w http.ResponseWriter, r *http.Request) (bool) {
	// stream-analyze each MIME part
	// and copy data from Wireshark_FileInput and Wireshark_TextInput field
	// be careful that if data is present it both it will be concatenated in resulting pcap file
	mpr, err := r.MultipartReader()
	if err != nil {
		p.log.Errorf("Cannot get multipart reader: %s", err)
		return false
	}

	convertDone := make(chan bool)
	serveDone   := make(chan bool)

	p.log.Debugf("Starting gorutine \"convert\"")
	go p.convert(convertDone)
	p.log.Debugf("Starting gorutine \"serve\"")
	go p.serve(w, serveDone)

	// read from input
	p.log.Debugf("Reading input data")

	var total uint64
	var fieldsUsed uint64

	for {
		// analyze each MIME part independently
		part, err := mpr.NextPart()
		if err == io.EOF { break }
		if err != nil {
			p.log.Errorf("Cannot get next MIME part: %s", err)
			return false
		}

		// check if this field name should be used
		currentField := part.FormName()
		var use bool
		for _, acceptField := range p.fields {
			if currentField == acceptField {
				use = true
				break
			}
		}

		// if it should, stream its content to input data
		if use {
			p.log.Debugf("Copying MIME part \"%s\"", currentField)
			fieldsUsed += 1

			cnt, err := io.Copy(p.inputWriter, part)
			if err != nil {
				p.log.Errorf("Cannot copy content of field \"%s\": %s", currentField, err)
				return false
			}

			p.log.Debugf("Copied %d bytes from MIME part \"%s\"", cnt, currentField)
			total += uint64(cnt)
		}
	}

	// when everything from source is read, close input writer to signalize
	// there are no more data 
	p.log.Debugf("All input text read, %d fields used, %d bytes analyzed", fieldsUsed, total)
	p.inputWriter.Close()

	// the close of input writer is detected by convert (puts EOF on stdin)
	// then convert closes outputWriter and terminates
	p.log.Debugf("Waiting for gorutine \"convert\" to finish")
	<-convertDone
	// the close of output writer is subsequently detected by serve
	// and it also terminates
	p.log.Debugf("Waiting for gorutine \"serve\" to finish")
	<-serveDone

	// and we are done
	p.log.Infof("Request finished")
	return true
}

func (p *processor) getUidGid(username, groupname string) (uint32, uint32, error) {
	// current user & group info
	var cUid uint64 // current UID
	var cGid uint64 // current GIO

	cUser, err := user.Current()
	if err != nil {
		return 0, 0, fmt.Errorf("cannot get current user info: %s", err)
	}

	cUid, err = strconv.ParseUint(cUser.Uid, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("cannot convert current user id \"%s\": %s", cUser.Uid, err)
	}

	cGid, err = strconv.ParseUint(cUser.Gid, 10, 32)
	if err != nil {
		return 0, 0, fmt.Errorf("cannot convert current group id \"%s\": %s", cUser.Gid, err)
	}

	p.log.Debugf("Current user is \"%s\", with UID %d and GID %d", cUser.Username, cUid, cGid)


	// requested uid and gid

	var rUid uint64 // requested UID
	var rGid uint64 // requested GID

	if len(username) == 0 {
		rUid = cUid
	} else {
		rUser, err := user.Lookup(username)
		if err != nil {
			return 0, 0, fmt.Errorf("cannot find user \"%s\": %s", username, err)
		}
		rUid, err = strconv.ParseUint(rUser.Uid, 10, 32)
		if err != nil {
			return 0, 0, fmt.Errorf("cannot convert requested user \"%s\" id \"%s\": %s", username, rUser.Uid, err)
		}
	}

	if len(groupname) == 0 {
		rGid = cGid
	} else {
		rGroup, err := user.LookupGroup(groupname)
		if err != nil {
			return 0, 0, fmt.Errorf("cannot find group \"%s\": %s", groupname, err)
		}
		rGid, err = strconv.ParseUint(rGroup.Gid, 10, 32)
		if err != nil {
			return 0, 0, fmt.Errorf("cannot convert requested group \"%s\" id \"%s\": %s", groupname, rGroup.Gid, err)
		}
	}

	//
	return uint32(rUid), uint32(rGid), nil
}

