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
	apiKey := flag.String("apikey", "", "API key")
	filename := flag.String("file", "", "File containing domains")
	flag.Parse()

	if *apiKey == "" || *filename == "" {
		fmt.Println("Please provide the API key and filename")
		return
	}

	printBanner()

	file, err := os.Open(*filename)
	if err != nil {
		fmt.Printf("Failed to open file: %v\n", err)
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
				fmt.Printf("Error occurred during lookup: %v\n", err)
			}

			// Wait for 15 seconds between lookups
			waitTime := time.Duration(15)
			fmt.Printf("(sleeping to not exceed API throttle)\n")
			time.Sleep(waitTime * time.Second)
		}
	}

	if err := scanner.Err(); err != nil {
		fmt.Printf("Error occurred while reading the file: %v\n", err)
	}
}

func performLookup(domain string, apiKey string) error {
	url := string([]byte{104, 116, 116, 112, 115, 58, 47, 47, 119, 119, 119, 46, 118, 105, 114, 117, 115, 116, 111, 116, 97, 108, 46, 99, 111, 109, 47, 97, 112, 105, 47, 118, 51, 47, 117, 114, 108, 115})

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
		fmt.Errorf("%+v", err)
		return err
	}

	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)

	var ar AnalysisResponse
	err = json.Unmarshal(body, &ar)
	if err != nil {
		return err
	}
	printAnalysis(ar.Data.ID, apiKey)
	return nil
}

func printAnalysis(analysisId string, apiKey string) error {

	url := string([]byte{104, 116, 116, 112, 115, 58, 47, 47, 119, 119, 119, 46, 118, 105, 114, 117, 115, 116, 111, 116, 97, 108, 46, 99, 111, 109, 47, 97, 112, 105, 47, 118, 51, 47, 97, 110, 97, 108, 121, 115, 101, 115, 47}) + analysisId

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Errorf("%+v", err)
		return err
	}

	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", apiKey)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Errorf("%+v", err)
		return err
	}

	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		fmt.Errorf("%+v", err)
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
