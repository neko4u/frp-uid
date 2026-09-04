// Copyright 2017 fatedier, fatedier@gmail.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"cmp"
	"encoding/json"
	"net"
	"net/http"
	"slices"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/fatedier/frp/pkg/config/types"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/metrics/mem"
	httppkg "github.com/fatedier/frp/pkg/util/http"
	"github.com/fatedier/frp/pkg/util/log"
	netpkg "github.com/fatedier/frp/pkg/util/net"
	"github.com/fatedier/frp/pkg/util/version"
)

type GeneralResponse struct {
	Code int
	Msg  string
}

func (svr *Service) registerRouteHandlers(helper *httppkg.RouterRegisterHelper) {
	helper.Router.HandleFunc("/healthz", svr.healthz)
	subRouter := helper.Router.NewRoute().Subrouter()

	subRouter.Use(helper.AuthMiddleware.Middleware)

	// metrics
	if svr.cfg.EnablePrometheus {
		subRouter.Handle("/metrics", promhttp.Handler())
	}

	// apis
	subRouter.HandleFunc("/api/serverinfo", svr.apiServerInfo).Methods("GET")
	subRouter.HandleFunc("/api/proxy/{type}", svr.apiProxyByType).Methods("GET")
	subRouter.HandleFunc("/api/proxy/{type}/{name}", svr.apiProxyByTypeAndName).Methods("GET")
	subRouter.HandleFunc("/api/traffic/{name}", svr.apiProxyTraffic).Methods("GET")
	subRouter.HandleFunc("/api/proxies", svr.deleteProxies).Methods("DELETE")

	// view
	subRouter.Handle("/favicon.ico", http.FileServer(helper.AssetsFS)).Methods("GET")
	subRouter.PathPrefix("/static/").Handler(
		netpkg.MakeHTTPGzipHandler(http.StripPrefix("/static/", http.FileServer(helper.AssetsFS))),
	).Methods("GET")

	subRouter.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/static/", http.StatusMovedPermanently)
	})

	//fork: uid 管理 API（绕过 Auth  仅限 127.0.0.1,本地调用）
	uidRouter := helper.Router.NewRoute().Subrouter()
	uidRouter.Use(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			addr := r.RemoteAddr
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				host = addr
			}
			if host != "127.0.0.1" {
				http.Error(w, `{"code":403,"msg":"仅允许本机访问"}`, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	uidRouter.HandleFunc("/api/uid_connections", svr.apiListUidConnections).Methods("GET")
	uidRouter.HandleFunc("/api/uid_connection/{uid}", svr.apiGetUidConnectionByUid).Methods("GET")
	uidRouter.HandleFunc("/api/uid_connection/{uid}/close", svr.apiCloseUidConnectionByUid).Methods("POST")
	uidRouter.HandleFunc("/api/uid_blacklist", svr.apiGetBlacklist).Methods("GET")
	uidRouter.HandleFunc("/api/uid_blacklist/add", svr.apiAddBlacklist).Methods("POST")
	uidRouter.HandleFunc("/api/uid_blacklist/remove", svr.apiRemoveBlacklist).Methods("POST")
}

type serverInfoResp struct {
	Version               string `json:"version"`
	BindPort              int    `json:"bindPort"`
	VhostHTTPPort         int    `json:"vhostHTTPPort"`
	VhostHTTPSPort        int    `json:"vhostHTTPSPort"`
	TCPMuxHTTPConnectPort int    `json:"tcpmuxHTTPConnectPort"`
	KCPBindPort           int    `json:"kcpBindPort"`
	QUICBindPort          int    `json:"quicBindPort"`
	SubdomainHost         string `json:"subdomainHost"`
	MaxPoolCount          int64  `json:"maxPoolCount"`
	MaxPortsPerClient     int64  `json:"maxPortsPerClient"`
	HeartBeatTimeout      int64  `json:"heartbeatTimeout"`
	AllowPortsStr         string `json:"allowPortsStr,omitempty"`
	TLSForce              bool   `json:"tlsForce,omitempty"`

	TotalTrafficIn  int64            `json:"totalTrafficIn"`
	TotalTrafficOut int64            `json:"totalTrafficOut"`
	CurConns        int64            `json:"curConns"`
	ClientCounts    int64            `json:"clientCounts"`
	ProxyTypeCounts map[string]int64 `json:"proxyTypeCount"`
}

// /healthz
func (svr *Service) healthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(200)
}

// /api/serverinfo
func (svr *Service) apiServerInfo(w http.ResponseWriter, r *http.Request) {
	res := GeneralResponse{Code: 200}
	defer func() {
		log.Infof("http response [%s]: code [%d]", r.URL.Path, res.Code)
		w.WriteHeader(res.Code)
		if len(res.Msg) > 0 {
			_, _ = w.Write([]byte(res.Msg))
		}
	}()

	log.Infof("http request: [%s]", r.URL.Path)
	serverStats := mem.StatsCollector.GetServer()
	svrResp := serverInfoResp{
		Version:               version.Full(),
		BindPort:              svr.cfg.BindPort,
		VhostHTTPPort:         svr.cfg.VhostHTTPPort,
		VhostHTTPSPort:        svr.cfg.VhostHTTPSPort,
		TCPMuxHTTPConnectPort: svr.cfg.TCPMuxHTTPConnectPort,
		KCPBindPort:           svr.cfg.KCPBindPort,
		QUICBindPort:          svr.cfg.QUICBindPort,
		SubdomainHost:         svr.cfg.SubDomainHost,
		MaxPoolCount:          svr.cfg.Transport.MaxPoolCount,
		MaxPortsPerClient:     svr.cfg.MaxPortsPerClient,
		HeartBeatTimeout:      svr.cfg.Transport.HeartbeatTimeout,
		AllowPortsStr:         types.PortsRangeSlice(svr.cfg.AllowPorts).String(),
		TLSForce:              svr.cfg.Transport.TLS.Force,

		TotalTrafficIn:  serverStats.TotalTrafficIn,
		TotalTrafficOut: serverStats.TotalTrafficOut,
		CurConns:        serverStats.CurConns,
		ClientCounts:    serverStats.ClientCounts,
		ProxyTypeCounts: serverStats.ProxyTypeCounts,
	}

	buf, _ := json.Marshal(&svrResp)
	res.Msg = string(buf)
}

type BaseOutConf struct {
	v1.ProxyBaseConfig
}

type TCPOutConf struct {
	BaseOutConf
	RemotePort int `json:"remotePort"`
}

type TCPMuxOutConf struct {
	BaseOutConf
	v1.DomainConfig
	Multiplexer     string `json:"multiplexer"`
	RouteByHTTPUser string `json:"routeByHTTPUser"`
}

type UDPOutConf struct {
	BaseOutConf
	RemotePort int `json:"remotePort"`
}

type HTTPOutConf struct {
	BaseOutConf
	v1.DomainConfig
	Locations         []string `json:"locations"`
	HostHeaderRewrite string   `json:"hostHeaderRewrite"`
}

type HTTPSOutConf struct {
	BaseOutConf
	v1.DomainConfig
}

type STCPOutConf struct {
	BaseOutConf
}

type XTCPOutConf struct {
	BaseOutConf
}

func getConfByType(proxyType string) any {
	switch v1.ProxyType(proxyType) {
	case v1.ProxyTypeTCP:
		return &TCPOutConf{}
	case v1.ProxyTypeTCPMUX:
		return &TCPMuxOutConf{}
	case v1.ProxyTypeUDP:
		return &UDPOutConf{}
	case v1.ProxyTypeHTTP:
		return &HTTPOutConf{}
	case v1.ProxyTypeHTTPS:
		return &HTTPSOutConf{}
	case v1.ProxyTypeSTCP:
		return &STCPOutConf{}
	case v1.ProxyTypeXTCP:
		return &XTCPOutConf{}
	default:
		return nil
	}
}

// Get proxy info.
type ProxyStatsInfo struct {
	Name            string `json:"name"`
	Conf            any    `json:"conf"`
	ClientVersion   string `json:"clientVersion,omitempty"`
	TodayTrafficIn  int64  `json:"todayTrafficIn"`
	TodayTrafficOut int64  `json:"todayTrafficOut"`
	CurConns        int64  `json:"curConns"`
	LastStartTime   string `json:"lastStartTime"`
	LastCloseTime   string `json:"lastCloseTime"`
	Status          string `json:"status"`
}

type GetProxyInfoResp struct {
	Proxies []*ProxyStatsInfo `json:"proxies"`
}

// /api/proxy/:type
func (svr *Service) apiProxyByType(w http.ResponseWriter, r *http.Request) {
	res := GeneralResponse{Code: 200}
	params := mux.Vars(r)
	proxyType := params["type"]

	defer func() {
		log.Infof("http response [%s]: code [%d]", r.URL.Path, res.Code)
		w.WriteHeader(res.Code)
		if len(res.Msg) > 0 {
			_, _ = w.Write([]byte(res.Msg))
		}
	}()
	log.Infof("http request: [%s]", r.URL.Path)

	proxyInfoResp := GetProxyInfoResp{}
	proxyInfoResp.Proxies = svr.getProxyStatsByType(proxyType)
	slices.SortFunc(proxyInfoResp.Proxies, func(a, b *ProxyStatsInfo) int {
		return cmp.Compare(a.Name, b.Name)
	})

	buf, _ := json.Marshal(&proxyInfoResp)
	res.Msg = string(buf)
}

func (svr *Service) getProxyStatsByType(proxyType string) (proxyInfos []*ProxyStatsInfo) {
	proxyStats := mem.StatsCollector.GetProxiesByType(proxyType)
	proxyInfos = make([]*ProxyStatsInfo, 0, len(proxyStats))
	for _, ps := range proxyStats {
		proxyInfo := &ProxyStatsInfo{}
		if pxy, ok := svr.pxyManager.GetByName(ps.Name); ok {
			content, err := json.Marshal(pxy.GetConfigurer())
			if err != nil {
				log.Warnf("marshal proxy [%s] conf info error: %v", ps.Name, err)
				continue
			}
			proxyInfo.Conf = getConfByType(ps.Type)
			if err = json.Unmarshal(content, &proxyInfo.Conf); err != nil {
				log.Warnf("unmarshal proxy [%s] conf info error: %v", ps.Name, err)
				continue
			}
			proxyInfo.Status = "online"
			if pxy.GetLoginMsg() != nil {
				proxyInfo.ClientVersion = pxy.GetLoginMsg().Version
			}
		} else {
			proxyInfo.Status = "offline"
		}
		proxyInfo.Name = ps.Name
		proxyInfo.TodayTrafficIn = ps.TodayTrafficIn
		proxyInfo.TodayTrafficOut = ps.TodayTrafficOut
		proxyInfo.CurConns = ps.CurConns
		proxyInfo.LastStartTime = ps.LastStartTime
		proxyInfo.LastCloseTime = ps.LastCloseTime
		proxyInfos = append(proxyInfos, proxyInfo)
	}
	return
}

// Get proxy info by name.
type GetProxyStatsResp struct {
	Name            string `json:"name"`
	Conf            any    `json:"conf"`
	TodayTrafficIn  int64  `json:"todayTrafficIn"`
	TodayTrafficOut int64  `json:"todayTrafficOut"`
	CurConns        int64  `json:"curConns"`
	LastStartTime   string `json:"lastStartTime"`
	LastCloseTime   string `json:"lastCloseTime"`
	Status          string `json:"status"`
}

// /api/proxy/:type/:name
func (svr *Service) apiProxyByTypeAndName(w http.ResponseWriter, r *http.Request) {
	res := GeneralResponse{Code: 200}
	params := mux.Vars(r)
	proxyType := params["type"]
	name := params["name"]

	defer func() {
		log.Infof("http response [%s]: code [%d]", r.URL.Path, res.Code)
		w.WriteHeader(res.Code)
		if len(res.Msg) > 0 {
			_, _ = w.Write([]byte(res.Msg))
		}
	}()
	log.Infof("http request: [%s]", r.URL.Path)

	var proxyStatsResp GetProxyStatsResp
	proxyStatsResp, res.Code, res.Msg = svr.getProxyStatsByTypeAndName(proxyType, name)
	if res.Code != 200 {
		return
	}

	buf, _ := json.Marshal(&proxyStatsResp)
	res.Msg = string(buf)
}

func (svr *Service) getProxyStatsByTypeAndName(proxyType string, proxyName string) (proxyInfo GetProxyStatsResp, code int, msg string) {
	proxyInfo.Name = proxyName
	ps := mem.StatsCollector.GetProxiesByTypeAndName(proxyType, proxyName)
	if ps == nil {
		code = 404
		msg = "no proxy info found"
	} else {
		if pxy, ok := svr.pxyManager.GetByName(proxyName); ok {
			content, err := json.Marshal(pxy.GetConfigurer())
			if err != nil {
				log.Warnf("marshal proxy [%s] conf info error: %v", ps.Name, err)
				code = 400
				msg = "parse conf error"
				return
			}
			proxyInfo.Conf = getConfByType(ps.Type)
			if err = json.Unmarshal(content, &proxyInfo.Conf); err != nil {
				log.Warnf("unmarshal proxy [%s] conf info error: %v", ps.Name, err)
				code = 400
				msg = "parse conf error"
				return
			}
			proxyInfo.Status = "online"
		} else {
			proxyInfo.Status = "offline"
		}
		proxyInfo.TodayTrafficIn = ps.TodayTrafficIn
		proxyInfo.TodayTrafficOut = ps.TodayTrafficOut
		proxyInfo.CurConns = ps.CurConns
		proxyInfo.LastStartTime = ps.LastStartTime
		proxyInfo.LastCloseTime = ps.LastCloseTime
		code = 200
	}

	return
}

// /api/traffic/:name
type GetProxyTrafficResp struct {
	Name       string  `json:"name"`
	TrafficIn  []int64 `json:"trafficIn"`
	TrafficOut []int64 `json:"trafficOut"`
}

func (svr *Service) apiProxyTraffic(w http.ResponseWriter, r *http.Request) {
	res := GeneralResponse{Code: 200}
	params := mux.Vars(r)
	name := params["name"]

	defer func() {
		log.Infof("http response [%s]: code [%d]", r.URL.Path, res.Code)
		w.WriteHeader(res.Code)
		if len(res.Msg) > 0 {
			_, _ = w.Write([]byte(res.Msg))
		}
	}()
	log.Infof("http request: [%s]", r.URL.Path)

	trafficResp := GetProxyTrafficResp{}
	trafficResp.Name = name
	proxyTrafficInfo := mem.StatsCollector.GetProxyTraffic(name)

	if proxyTrafficInfo == nil {
		res.Code = 404
		res.Msg = "no proxy info found"
		return
	}
	trafficResp.TrafficIn = proxyTrafficInfo.TrafficIn
	trafficResp.TrafficOut = proxyTrafficInfo.TrafficOut

	buf, _ := json.Marshal(&trafficResp)
	res.Msg = string(buf)
}

// DELETE /api/proxies?status=offline
func (svr *Service) deleteProxies(w http.ResponseWriter, r *http.Request) {
	res := GeneralResponse{Code: 200}

	log.Infof("http request: [%s]", r.URL.Path)
	defer func() {
		log.Infof("http response [%s]: code [%d]", r.URL.Path, res.Code)
		w.WriteHeader(res.Code)
		if len(res.Msg) > 0 {
			_, _ = w.Write([]byte(res.Msg))
		}
	}()

	status := r.URL.Query().Get("status")
	if status != "offline" {
		res.Code = 400
		res.Msg = "status only support offline"
		return
	}
	cleared, total := mem.StatsCollector.ClearOfflineProxies()
	log.Infof("cleared [%d] offline proxies, total [%d] proxies", cleared, total)
}

// fork: uid 管理 API 处理函数

// GET /api/uid_connections —   所有在线 uid 连接概览
func (svr *Service) apiListUidConnections(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	connections := svr.ctlManager.GetAllByUid()
	_ = json.NewEncoder(w).Encode(map[string]any{
		"code":  0,
		"msg":   "success",
		"data":  connections,
		"total": len(connections),
	})
}

// GET /api/uid_connection/{uid} —  指定 uid 的连接详情
func (svr *Service) apiGetUidConnectionByUid(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	uid := mux.Vars(r)["uid"]
	ctl, ok := svr.ctlManager.GetByUid(uid)
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 1, "msg": "uid 没有活跃连接"})
		return
	}
	info := UidConnectionInfo{
		Uid:           uid,
		RunID:         ctl.runID,
		User:          ctl.loginMsg.User,
		ClientAddr:    ctl.conn.RemoteAddr().String(),
		ClientVersion: ctl.loginMsg.Version,
	}
	ctl.mu.RLock()
	info.ProxyCount = len(ctl.proxies)
	ctl.mu.RUnlock()
	_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "msg": "success", "data": info})
}

// POST /api/uid_connection/{uid}/close?reason=xxx
// 主动断开（发 ServerClose，不入黑名单）
func (svr *Service) apiCloseUidConnectionByUid(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	uid := mux.Vars(r)["uid"]
	reason := r.URL.Query().Get("reason")
	if err := svr.ctlManager.CloseByUid(uid, reason); err != nil {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 1, "msg": err.Error()})
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "msg": "closed"})
}

// GET /api/uid_blacklist — 列出黑名单 uid
func (svr *Service) apiGetBlacklist(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	var list []string
	UidBlacklist.Range(func(key, _ any) bool {
		list = append(list, key.(string))
		return true
	})
	_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "msg": "success", "data": list})
}

// POST /api/uid_blacklist/add?uid=xxx — 加入黑名单
func (svr *Service) apiAddBlacklist(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	uid := r.URL.Query().Get("uid")
	if uid == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 1, "msg": "uid 参数不能为空"})
		return
	}
	UidBlacklist.Store(uid, true)
	_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "msg": "added"})
}

// POST /api/uid_blacklist/remove?uid=xxx — 移除黑名单
func (svr *Service) apiRemoveBlacklist(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	uid := r.URL.Query().Get("uid")
	if uid == "" {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"code": 1, "msg": "uid 参数不能为空"})
		return
	}
	UidBlacklist.Delete(uid)
	_ = json.NewEncoder(w).Encode(map[string]any{"code": 0, "msg": "removed"})
}
