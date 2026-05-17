package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
)

type TrapRouteFile struct {
	Routes []TrapRouteConfig `json:"routes"`
}

type TrapV3UsersFile struct {
	Users []V3Credentials `json:"users"`
}

type TrapRouteConfig struct {
	SourceCIDR string `json:"source_cidr"`
	TargetURL  string `json:"target_url"`
}

type trapRoute struct {
	sourceCIDR string
	network    *net.IPNet
	targetURL  string
	prefixBits int
}

type TrapRouter struct {
	routes        []trapRoute
	defaultTarget string
}

func LoadTrapRouter(path, defaultTarget string) (*TrapRouter, error) {
	if defaultTarget != "" {
		if err := validateHTTPURL(defaultTarget); err != nil {
			return nil, fmt.Errorf("invalid trap default target URL: %w", err)
		}
	}
	router := &TrapRouter{defaultTarget: defaultTarget}
	if path == "" {
		return router, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read trap routes file: %w", err)
	}
	var file TrapRouteFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return nil, fmt.Errorf("decode trap routes file: %w", err)
	}
	for _, route := range file.Routes {
		if strings.TrimSpace(route.SourceCIDR) == "" || strings.TrimSpace(route.TargetURL) == "" {
			return nil, fmt.Errorf("trap routes require source_cidr and target_url")
		}
		_, network, err := net.ParseCIDR(route.SourceCIDR)
		if err != nil {
			return nil, fmt.Errorf("invalid trap source CIDR %q: %w", route.SourceCIDR, err)
		}
		if err := validateHTTPURL(route.TargetURL); err != nil {
			return nil, fmt.Errorf("invalid trap target URL for %q: %w", route.SourceCIDR, err)
		}
		ones, _ := network.Mask.Size()
		router.routes = append(router.routes, trapRoute{sourceCIDR: route.SourceCIDR, network: network, targetURL: route.TargetURL, prefixBits: ones})
	}
	sort.SliceStable(router.routes, func(i, j int) bool {
		return router.routes[i].prefixBits > router.routes[j].prefixBits
	})
	return router, nil
}

func (r *TrapRouter) Match(ip net.IP) (string, string, bool) {
	for _, route := range r.routes {
		if route.network.Contains(ip) {
			return route.targetURL, route.sourceCIDR, true
		}
	}
	if r.defaultTarget != "" {
		return r.defaultTarget, "", true
	}
	return "", "", false
}

func validateHTTPURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("scheme must be http or https")
	}
	if parsed.Host == "" {
		return fmt.Errorf("host is required")
	}
	return nil
}

type TrapPayload struct {
	ReceivedAt        time.Time `json:"received_at"`
	SourceIP          string    `json:"source_ip"`
	SourcePort        int       `json:"source_port"`
	Version           string    `json:"version"`
	IsInform          bool      `json:"is_inform,omitempty"`
	MatchedSourceCIDR string    `json:"matched_source_cidr,omitempty"`
	TrapOID           string    `json:"trap_oid,omitempty"`
	Uptime            any       `json:"uptime,omitempty"`
	Varbinds          []VarBind `json:"varbinds"`
}

type trapJob struct {
	targetURL string
	payload   TrapPayload
}

type TrapService struct {
	cfg       Config
	logger    *slog.Logger
	stats     *Stats
	router    *TrapRouter
	client    *http.Client
	decoder   *gosnmp.GoSNMP
	queue     chan trapJob
	conn      *net.UDPConn
	wg        sync.WaitGroup
	readDone  chan struct{}
	workerCtx context.Context
	cancel    context.CancelFunc
}

func NewTrapService(cfg Config, logger *slog.Logger, stats *Stats, client *http.Client) (*TrapService, error) {
	router, err := LoadTrapRouter(cfg.TrapRoutesFile, cfg.TrapDefaultTargetURL)
	if err != nil {
		return nil, err
	}
	if cfg.TrapEnabled && len(router.routes) == 0 && router.defaultTarget == "" {
		return nil, fmt.Errorf("trap routes file or default target URL is required when traps are enabled")
	}
	if client == nil {
		client = &http.Client{Timeout: cfg.TrapForwardTimeout}
	}
	decoder, err := newTrapDecoder(cfg)
	if err != nil {
		return nil, err
	}
	service := &TrapService{
		cfg:      cfg,
		logger:   logger,
		stats:    stats,
		router:   router,
		client:   client,
		decoder:  decoder,
		queue:    make(chan trapJob, cfg.TrapForwardQueueSize),
		readDone: make(chan struct{}),
	}
	if !cfg.TrapEnabled {
		close(service.readDone)
	}
	return service, nil
}

func newTrapDecoder(cfg Config) (*gosnmp.GoSNMP, error) {
	logger := gosnmp.NewLogger(log.New(io.Discard, "", 0))
	decoder := &gosnmp.GoSNMP{Logger: logger}
	if cfg.TrapV3UsersFile == "" {
		return decoder, nil
	}
	data, err := os.ReadFile(cfg.TrapV3UsersFile)
	if err != nil {
		return nil, fmt.Errorf("read trap v3 users file: %w", err)
	}
	var file TrapV3UsersFile
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return nil, fmt.Errorf("decode trap v3 users file: %w", err)
	}
	if len(file.Users) == 0 {
		return nil, fmt.Errorf("trap v3 users file must contain at least one user")
	}
	table := gosnmp.NewSnmpV3SecurityParametersTable(logger)
	for i := range file.Users {
		user := &file.Users[i]
		if err := validateV3Credentials(user); err != nil {
			return nil, fmt.Errorf("trap v3 users[%d]: %w", i, err)
		}
		params := &gosnmp.UsmSecurityParameters{
			UserName:                 user.Username,
			AuthenticationProtocol:   v3AuthProtocol(user.AuthProtocol),
			AuthenticationPassphrase: user.AuthPassphrase,
			PrivacyProtocol:          v3PrivProtocol(user.PrivProtocol),
			PrivacyPassphrase:        user.PrivPassphrase,
		}
		if err := table.Add(user.Username, params); err != nil {
			return nil, fmt.Errorf("trap v3 users[%d]: %w", i, err)
		}
	}
	decoder.Version = gosnmp.Version3
	decoder.SecurityModel = gosnmp.UserSecurityModel
	decoder.TrapSecurityParametersTable = table
	return decoder, nil
}

func (s *TrapService) Start(ctx context.Context) error {
	if !s.cfg.TrapEnabled {
		return nil
	}
	addr, err := net.ResolveUDPAddr("udp", s.cfg.TrapListenAddress)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	s.conn = conn
	s.workerCtx, s.cancel = context.WithCancel(ctx)
	for range s.cfg.TrapForwardWorkers {
		s.wg.Add(1)
		go s.worker()
	}
	s.wg.Add(1)
	go s.readLoop()
	return nil
}

func (s *TrapService) Close() {
	if s.conn != nil {
		_ = s.conn.Close()
	}
	<-s.readDone
	if s.cancel != nil {
		s.cancel()
	}
	close(s.queue)
	s.wg.Wait()
}

func (s *TrapService) readLoop() {
	defer s.wg.Done()
	defer close(s.readDone)
	buf := make([]byte, s.cfg.TrapMaxPacketBytes)
	for {
		n, addr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.logger.Info("trap receive failed", "outcome", "decode_error")
			continue
		}
		s.stats.RecordTrapReceived()
		packet, err := s.decoder.UnmarshalTrap(buf[:n], false)
		if err != nil {
			s.stats.RecordTrapRejected()
			s.logger.Info("trap rejected", "source_ip", addr.IP.String(), "outcome", "decode_error")
			continue
		}
		s.handlePacket(packet, addr)
	}
}

func (s *TrapService) handlePacket(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) {
	if !supportedTrapPacket(packet) {
		s.stats.RecordTrapRejected()
		s.logger.Info("trap rejected", "source_ip", addr.IP.String(), "outcome", "unsupported_version")
		return
	}
	if packet.Version == gosnmp.Version2c && !s.communityAllowed(packet.Community) {
		s.stats.RecordTrapRejected()
		s.logger.Info("trap rejected", "source_ip", addr.IP.String(), "outcome", "community_rejected")
		return
	}
	targetURL, matchedCIDR, ok := s.router.Match(addr.IP)
	if !ok {
		s.stats.RecordTrapUnmatched()
		s.logger.Info("trap not routed", "source_ip", addr.IP.String(), "outcome", "route_not_found")
		return
	}
	payload, err := buildTrapPayload(packet, addr, matchedCIDR)
	if err != nil {
		s.stats.RecordTrapRejected()
		s.logger.Info("trap rejected", "source_ip", addr.IP.String(), "outcome", "decode_error")
		return
	}
	s.stats.RecordTrapDecoded()
	select {
	case s.queue <- trapJob{targetURL: targetURL, payload: payload}:
		s.stats.RecordTrapQueued()
	default:
		s.stats.RecordTrapForwardFailure(matchedCIDR)
		s.logger.Info("trap dropped", "source_ip", addr.IP.String(), "matched_source_cidr", matchedCIDR, "outcome", "queue_full")
	}
	if packet.PDUType == gosnmp.InformRequest {
		s.sendInformResponse(packet, addr)
	}
}

func supportedTrapPacket(packet *gosnmp.SnmpPacket) bool {
	versionSupported := packet.Version == gosnmp.Version2c || packet.Version == gosnmp.Version3
	pduSupported := packet.PDUType == gosnmp.SNMPv2Trap || packet.PDUType == gosnmp.InformRequest
	return versionSupported && pduSupported
}

func (s *TrapService) sendInformResponse(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) {
	if s.conn == nil {
		return
	}
	packet.PDUType = gosnmp.GetResponse
	packet.Error = gosnmp.NoError
	packet.ErrorIndex = 0
	payload, err := packet.MarshalMsg()
	if err != nil {
		s.logger.Info("inform response failed", "source_ip", addr.IP.String(), "outcome", "encode_error")
		return
	}
	if _, err := s.conn.WriteToUDP(payload, addr); err != nil {
		s.logger.Info("inform response failed", "source_ip", addr.IP.String(), "outcome", "send_error")
	}
}

func (s *TrapService) communityAllowed(community string) bool {
	if len(s.cfg.TrapAllowedCommunities) == 0 {
		return true
	}
	for _, allowed := range s.cfg.TrapAllowedCommunities {
		if allowed == community {
			return true
		}
	}
	return false
}

func buildTrapPayload(packet *gosnmp.SnmpPacket, addr *net.UDPAddr, matchedCIDR string) (TrapPayload, error) {
	values, err := convertPDU(packet.Variables, len(packet.Variables))
	if err != nil {
		return TrapPayload{}, err
	}
	payload := TrapPayload{
		ReceivedAt:        time.Now().UTC(),
		SourceIP:          addr.IP.String(),
		SourcePort:        addr.Port,
		Version:           trapVersion(packet.Version),
		IsInform:          packet.PDUType == gosnmp.InformRequest,
		MatchedSourceCIDR: matchedCIDR,
		Varbinds:          values,
	}
	for _, value := range values {
		switch value.OID {
		case ".1.3.6.1.6.3.1.1.4.1.0":
			if s, ok := value.Value.(string); ok {
				payload.TrapOID = NormalizeOID(s)
			}
		case ".1.3.6.1.2.1.1.3.0":
			payload.Uptime = value.Value
		}
	}
	return payload, nil
}

func trapVersion(version gosnmp.SnmpVersion) string {
	switch version {
	case gosnmp.Version3:
		return "3"
	default:
		return "2c"
	}
}

func (s *TrapService) worker() {
	defer s.wg.Done()
	for job := range s.queue {
		s.forward(job)
	}
}

func (s *TrapService) forward(job trapJob) {
	body, err := json.Marshal(job.payload)
	if err != nil {
		s.stats.RecordTrapForwardFailure(job.payload.MatchedSourceCIDR)
		return
	}
	var lastErr error
	start := time.Now()
	for attempt := 0; attempt <= s.cfg.TrapForwardRetries; attempt++ {
		req, err := http.NewRequestWithContext(s.workerCtx, http.MethodPost, job.targetURL, bytes.NewReader(body))
		if err != nil {
			lastErr = err
			break
		}
		req.Header.Set("Content-Type", "application/json")
		if s.cfg.TrapForwardAuthHeader != "" {
			req.Header.Set("Authorization", s.cfg.TrapForwardAuthHeader)
		}
		resp, err := s.client.Do(req)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				s.stats.RecordTrapForwardSuccess(job.payload.MatchedSourceCIDR, time.Since(start))
				return
			}
			if resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
				lastErr = fmt.Errorf("webhook returned status %d", resp.StatusCode)
				break
			}
			lastErr = fmt.Errorf("webhook returned status %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		if attempt < s.cfg.TrapForwardRetries {
			s.stats.RecordTrapRetry()
			timer := time.NewTimer(time.Duration(1<<attempt) * 100 * time.Millisecond)
			select {
			case <-timer.C:
			case <-s.workerCtx.Done():
				timer.Stop()
				return
			}
		}
	}
	s.stats.RecordTrapForwardFailure(job.payload.MatchedSourceCIDR)
	outcome := "forward_http_error"
	if ne, ok := lastErr.(net.Error); ok && ne.Timeout() {
		outcome = "forward_timeout"
	} else if lastErr != nil && strings.Contains(strings.ToLower(lastErr.Error()), "connection") {
		outcome = "forward_connection_error"
	}
	s.logger.Info("trap forward failed",
		"source_ip", job.payload.SourceIP,
		"matched_source_cidr", job.payload.MatchedSourceCIDR,
		"trap_oid", job.payload.TrapOID,
		"outcome", outcome,
	)
}
