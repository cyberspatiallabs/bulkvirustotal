package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type AnalysisResponse struct {
	Data AnalysisData `json:"data"`
}

type AnalysisData struct {
	Type  string            `json:"type"`
	ID    string            `json:"id"`
	Links AnalysisDataLinks `json:"links"`
}

type AnalysisDataLinks struct {
	Self string `json:"self"`
}

func main() {

	logger, err := zap.Config{
		Level:             zap.NewAtomicLevelAt(zap.DebugLevel),
		Development:       false,
		DisableCaller:     false,
		DisableStacktrace: false,
		Encoding:          "console",
		EncoderConfig: zapcore.EncoderConfig{
			TimeKey:       "eventTime",
			LevelKey:      "level",
			NameKey:       "logger",
			CallerKey:     "caller",
			MessageKey:    "message",
			StacktraceKey: "stacktrace",
			LineEnding:    zapcore.DefaultLineEnding,
			EncodeLevel: func(l zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
				switch l {
				case zapcore.DebugLevel:
					enc.AppendString("DEBUG")
				case zapcore.InfoLevel:
					enc.AppendString("INFO")
				case zapcore.WarnLevel:
					enc.AppendString("WARNING")
				case zapcore.ErrorLevel:
					enc.AppendString("ERROR")
				case zapcore.DPanicLevel:
					enc.AppendString("CRITICAL")
				case zapcore.PanicLevel:
					enc.AppendString("ALERT")
				case zapcore.FatalLevel:
					enc.AppendString("EMERGENCY")
				}
			},
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeDuration: zapcore.SecondsDurationEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
		},
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stdout"},
	}.Build()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	zap.ReplaceGlobals(logger)

	apiKey := flag.String("apikey", "", "VirusTotal API key")
	filename := flag.String("file", "", "File containing domains")
	sleepTime := flag.Int("delay", 20, "Delay between API lookups")
	flag.Parse()

	if *apiKey == "" || *filename == "" {
		fmt.Println("Please provide the API key and filename")
		return
	}

	printBanner()

	file, err := os.Open(*filename)
	if err != nil {
		zap.S().Errorf("Failed to open file: %v\n", err)
		return

	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {

		domain := strings.TrimSpace(scanner.Text())
		if domain != "" {
			fmt.Printf("Performing lookup for domain: %s\n", domain)
			err := performLookup(domain, *apiKey)
			if err != nil {
				zap.S().Errorf("Error occurred during lookup: %v\n", err)
			}

			waitTime := time.Duration(*sleepTime)

			time.Sleep(waitTime * time.Second)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error occurred while reading the file: %v\n", err)
	}
}

func performLookup(domain string, apiKey string) error {
	url := "https://www.virustotal.com/api/v3/urls"

	payload := strings.NewReader(fmt.Sprintf("url=%s", domain))

	req, err := http.NewRequest("POST", url, payload)
	if err != nil {
		fmt.Errorf("%+v", err)
		return err
	}

	req.Header.Add("accept", "application/json")
	req.Header.Add("content-type", "application/x-www-form-urlencoded")
	req.Header.Set("x-apikey", apiKey)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		zap.S().Errorf("%+v", err)
		return err
	}

	defer res.Body.Close()

	code := res.StatusCode
	if code != 200 {
		zap.S().Errorf("Status code for url %s was %d", url, code)
		zap.S().Errorf(res.Status)
	}

	body, _ := io.ReadAll(res.Body)

	var ar AnalysisResponse
	err = json.Unmarshal(body, &ar)
	if err != nil {
		zap.S().Errorf("%+v", err)
		return err
	}
	if ar.Data.ID == "" {

		zap.S().Errorf("No analysis ID returned for %s", url)
		zap.S().Errorf("status was %d", res.StatusCode)
		return nil

	} else {

		printAnalysis(ar.Data.ID, apiKey)
		return nil
	}

}

func printAnalysis(analysisId string, apiKey string) error {

	url := fmt.Sprintf("https://www.virustotal.com/api/v3/analyses/%s", analysisId)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		zap.S().Errorf("%+v", err)
		return err
	}

	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", apiKey)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		zap.S().Errorf("%+v", err)
		return err
	}

	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		zap.S().Errorf("%+v", err)
		return err
	}

	fmt.Println(string(body))
	return nil
}

func printBanner() {

	s := `
.______    __    __   __       __  ___ ____    ____ .___________.
|   _  \  |  |  |  | |  |     |  |/  / \   \  /   / |           |
|  |_)  | |  |  |  | |  |     |  '  /   \   \/   /   ---|  |----
|   _  <  |  |  |  | |  |     |    <     \      /       |  |     
|  |_)  | |  ----  | |  ----. |  .  \     \    /        |  |     
|______/   \______/  |_______||__|\__\     \__/         |__|     `

	fmt.Printf("%+v\n\n", s)

}
