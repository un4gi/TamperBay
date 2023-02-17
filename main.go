package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
)

const REQ_DATA string = "verb=tampering"

var (
	bodyLength    int
	hostname      string
	requestStatus int
	timeout       int64
	uniqueHeaders int
)

func main() {
	flag.Int64Var(&timeout, "t", 180, "the max time to wait before timeout (in seconds).")
	flag.StringVar(&hostname, "u", "", "the hostname or IP to perform verb tampering against.")
	flag.Parse()

	if hostname == "" {
		log.Fatal("Must provide a hostname or IP.")
	} else {
		if !strings.HasPrefix(hostname, "https://") && !strings.HasPrefix(hostname, "http://") {
			hostname = "https://" + hostname
		}
	}

	log.Info("Making OPTIONS request...")
	makeRequest("OPTIONS", hostname, timeout, nil)

	time.Sleep(1 * time.Second)

	log.Info("Making HEAD request...")
	makeRequest("HEAD", hostname, timeout, nil)

	time.Sleep(1 * time.Second)

	log.Info("Making GET request...")
	makeRequest("GET", hostname, timeout, nil)

	time.Sleep(1 * time.Second)

	log.Info("Making POST request...")
	makeRequest("POST", hostname, timeout, bytes.NewBuffer([]byte(REQ_DATA)))

	time.Sleep(1 * time.Second)

	log.Info("Making PUT request...")
	makeRequest("PUT", hostname, timeout, bytes.NewBuffer([]byte(REQ_DATA)))

	time.Sleep(1 * time.Second)

	log.Info("Making TRACE request...")
	makeRequest("TRACE", hostname, timeout, nil)

	time.Sleep(1 * time.Second)

	log.Info("Making CONNECT request...")
	makeRequest("CONNECT", hostname, timeout, nil)
}

func makeRequest(method, target string, timeout int64, reqData io.Reader) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	req, err := http.NewRequest(method, target, reqData)
	if err != nil && err != context.Canceled && err != io.EOF {
		log.Fatal("Error: could not create HTTP request - ", err)
	}

	req.Header.Set("User-Agent", "TamperBay")

	resp, err := http.DefaultClient.Do(req.WithContext(ctx))
	if err != nil && err != context.Canceled && err != io.EOF {
		log.Fatal("Error: response not received - ", err)
	}

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Error: Could not convert response body to byte array - ", err)
	}

	bodyString := string(bodyBytes)

	requestStatus = resp.StatusCode
	bodyLength = len(bodyString)
	uniqueHeaders = len(resp.Header)

	if method == "OPTIONS" {
		log.Info("Checking for allowed methods...")
		if resp.Header.Get("Allow") == "" {
			log.Warn("The OPTIONS method does not appear to be properly implemented. No allowed methods were discovered.")
		} else {
			log.Infof("Allowed methods: %s", resp.Header.Get("Allow"))
		}
	} else if method == "TRACE" {
		log.Info("Checking for proxy servers...")
		if resp.Header.Get("Via") == "" {
			log.Warn("The TRACE method may not be implemented. No proxy servers were identified.")
		} else {
			log.Infof("Proxy Servers identified: %s", resp.Header.Get("Via"))
		}
	} else if method == "CONNECT" {
		if resp.StatusCode == 407 {
			log.Warn("The CONNECT method is implemented, but proxy authentication is required.")
		}
	}

	lwf(requestStatus, bodyLength, uniqueHeaders, method)
}

func lwf(status, bodyLength, uniqueHeaders int, method string) {
	log.WithFields(log.Fields{
		"Status":          status,
		"Response Length": bodyLength,
		"Unique Headers":  uniqueHeaders,
	}).Info(method + " request completed.")
}
