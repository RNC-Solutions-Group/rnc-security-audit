// CP0 representative benchmark scanner. Disposable, not the production engine.
// Rules are loaded from a shared TSV so Go and Rust execute identical regexes,
// candidate validation and output accounting.
package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
)

type rule struct {
	id      string
	capture int
	family  string
	re      *regexp.Regexp
}

type fileResult struct {
	keys []string
}

func loadRules(path string, limit int) ([]rule, error) {
	handle, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	var rules []rule
	scanner := bufio.NewScanner(handle)
	scanner.Buffer(make([]byte, 4096), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimPrefix(scanner.Text(), "\ufeff")
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "\t", 4)
		if len(parts) != 4 {
			return nil, fmt.Errorf("invalid rule line: %q", line)
		}
		capture, err := strconv.Atoi(parts[1])
		if err != nil || (capture != 0 && capture != 1) {
			return nil, fmt.Errorf("invalid capture group in %q", line)
		}
		compiled, err := regexp.Compile(parts[3])
		if err != nil {
			return nil, fmt.Errorf("invalid regex for %s: %w", parts[0], err)
		}
		rules = append(rules, rule{id: parts[0], capture: capture, family: parts[2], re: compiled})
		if limit > 0 && len(rules) >= limit {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(rules) == 0 {
		return nil, fmt.Errorf("no rules loaded")
	}
	return rules, nil
}

func validMarker(value []byte, family string) bool {
	if len(value) < 16 || len(value) > 96 {
		return false
	}
	text := string(value)
	prefix := "RNC_SYNTH_KEY_" + family + "_"
	if !strings.HasPrefix(text, prefix) {
		return false
	}
	for _, char := range value {
		if !((char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '_') {
			return false
		}
	}
	suffix := strings.TrimPrefix(text, prefix)
	if len(suffix) < 4 || strings.HasSuffix(suffix, "_") {
		return false
	}
	if strings.Contains(suffix, "DECOY") || strings.Contains(suffix, "FAKE") {
		return false
	}
	return true
}

func scanWindow(data []byte, absoluteOffset int, rules []rule, path string, seen map[string]struct{}) {
	for _, item := range rules {
		for _, match := range item.re.FindAllSubmatchIndex(data, -1) {
			start, end := match[0], match[1]
			if item.capture == 1 {
				if len(match) < 4 || match[2] < 0 || match[3] < 0 {
					continue
				}
				start, end = match[2], match[3]
			}
			if start < 0 || end <= start {
				continue
			}
			if !validMarker(data[start:end], item.family) {
				continue
			}
			key := fmt.Sprintf("%s\t%s\t%d\t%d\n", item.id, path, start+absoluteOffset, end+absoluteOffset)
			seen[key] = struct{}{}
		}
	}
}

func scanWhole(data []byte, rules []rule, path string) []string {
	seen := make(map[string]struct{})
	scanWindow(data, 0, rules, path, seen)
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	return keys
}

func scanStream(path string, rules []rule, rel string) ([]string, error) {
	handle, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	const chunkSize = 256 * 1024
	const overlap = 8192
	buffer := make([]byte, chunkSize)
	carry := make([]byte, 0, overlap)
	base := 0
	seen := make(map[string]struct{})
	for {
		n, readErr := handle.Read(buffer)
		if n > 0 {
			window := make([]byte, 0, len(carry)+n)
			window = append(window, carry...)
			window = append(window, buffer[:n]...)
			offset := base - len(carry)
			scanWindow(window, offset, rules, rel, seen)
			base += n
			if len(window) > overlap {
				carry = append(carry[:0], window[len(window)-overlap:]...)
			} else {
				carry = append(carry[:0], window...)
			}
		}
		if readErr != nil {
			if readErr.Error() == "EOF" {
				break
			}
			return nil, readErr
		}
	}
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	return keys, nil
}

func readManifest(path string) ([]string, error) {
	handle, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	var files []string
	scanner := bufio.NewScanner(handle)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		files = append(files, filepath.ToSlash(line))
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("manifest contains no files")
	}
	return files, nil
}

func safeJoin(root, relative string) (string, error) {
	clean := filepath.Clean(filepath.FromSlash(relative))
	if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("manifest path escapes corpus root: %s", relative)
	}
	joined := filepath.Join(root, clean)
	resolvedRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.Abs(joined)
	if err != nil {
		return "", err
	}
	if resolved != resolvedRoot && !strings.HasPrefix(resolved, resolvedRoot+string(filepath.Separator)) {
		return "", fmt.Errorf("manifest path escapes corpus root: %s", relative)
	}
	return resolved, nil
}

func process(files []string, root string, rules []rule, mode string, threads int) ([]string, error) {
	results := make([]fileResult, len(files))
	jobs := make(chan int)
	var wait sync.WaitGroup
	var firstErr error
	var errorLock sync.Mutex
	workers := threads
	if workers > len(files) {
		workers = len(files)
	}
	for worker := 0; worker < workers; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for index := range jobs {
				relative := files[index]
				full, err := safeJoin(root, relative)
				if err != nil {
					errorLock.Lock()
					if firstErr == nil {
						firstErr = err
					}
					errorLock.Unlock()
					continue
				}
				var keys []string
				if mode == "stream" {
					keys, err = scanStream(full, rules, relative)
				} else {
					data, readErr := os.ReadFile(full)
					if readErr != nil {
						err = readErr
					} else {
						keys = scanWhole(data, rules, relative)
					}
				}
				if err != nil {
					errorLock.Lock()
					if firstErr == nil {
						firstErr = err
					}
					errorLock.Unlock()
					continue
				}
				results[index] = fileResult{keys: keys}
			}
		}()
	}
	for index := range files {
		jobs <- index
	}
	close(jobs)
	wait.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	keys := make([]string, 0)
	for _, result := range results {
		keys = append(keys, result.keys...)
	}
	return keys, nil
}

func fnv(keys []string) uint64 {
	hash := uint64(14695981039346656037)
	for _, key := range keys {
		for _, value := range []byte(key) {
			hash ^= uint64(value)
			hash *= 1099511628211
		}
	}
	return hash
}

func main() {
	if len(os.Args) != 11 {
		fmt.Fprintln(os.Stderr, "usage: scanner --corpus DIR --manifest FILE --rules FILE --mode whole|stream --threads N")
		os.Exit(64)
	}
	var corpus, manifest, rulesPath, mode string
	threads := 1
	for index := 1; index < len(os.Args); index += 2 {
		switch os.Args[index] {
		case "--corpus":
			corpus = os.Args[index+1]
		case "--manifest":
			manifest = os.Args[index+1]
		case "--rules":
			rulesPath = os.Args[index+1]
		case "--mode":
			mode = os.Args[index+1]
		case "--threads":
			parsed, err := strconv.Atoi(os.Args[index+1])
			if err != nil || parsed < 1 {
				fmt.Fprintln(os.Stderr, "threads must be a positive integer")
				os.Exit(64)
			}
			threads = parsed
		default:
			fmt.Fprintf(os.Stderr, "unknown argument %s\n", os.Args[index])
			os.Exit(64)
		}
	}
	if corpus == "" || manifest == "" || rulesPath == "" || (mode != "whole" && mode != "stream") {
		fmt.Fprintln(os.Stderr, "missing required argument or invalid mode")
		os.Exit(64)
	}
	limit := 0
	if strings.Contains(filepath.Base(rulesPath), "basic") {
		limit = 8
	}
	rules, err := loadRules(rulesPath, limit)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	files, err := readManifest(manifest)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	keys, err := process(files, corpus, rules, mode, threads)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	sort.Strings(keys)
	fmt.Printf("count=%d checksum=%016x rules=%d mode=%s threads=%d\n", len(keys), fnv(keys), len(rules), mode, threads)
}
