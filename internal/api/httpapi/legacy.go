package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/alexlafalce/ZTGotroller/internal/controller"
	"github.com/alexlafalce/ZTGotroller/internal/domain"
	"github.com/alexlafalce/ZTGotroller/internal/store"
)

const legacyControllerAPIVersion = 3

type legacyAPI struct {
	service *controller.Service
}

type legacyNetworkPatch struct {
	Name              *string                       `json:"name"`
	Private           *bool                         `json:"private"`
	MTU               *int                          `json:"mtu"`
	MulticastLimit    *int                          `json:"multicastLimit"`
	EnableBroadcast   *bool                         `json:"enableBroadcast"`
	V4AssignMode      *legacyV4AssignMode           `json:"v4AssignMode"`
	V6AssignMode      *legacyV6AssignMode           `json:"v6AssignMode"`
	Routes            *[]legacyRoute                `json:"routes"`
	IPAssignmentPools *[]legacyIPPool               `json:"ipAssignmentPools"`
	DNS               *domain.DNSConfig             `json:"dns"`
	Rules             *[]map[string]json.RawMessage `json:"rules"`
	Capabilities      *[]legacyCapability           `json:"capabilities"`
	Tags              *[]legacyTag                  `json:"tags"`
	AuthTokens        *map[string]uint64            `json:"authTokens"`
	RulesSource       *string                       `json:"rulesSource"`
	RemoteTraceTarget *string                       `json:"remoteTraceTarget"`
	RemoteTraceLevel  *uint64                       `json:"remoteTraceLevel"`
	SSOEnabled        *bool                         `json:"ssoEnabled"`
}

type legacyV4AssignMode struct {
	ZT bool `json:"zt"`
}

type legacyV6AssignMode struct {
	RFC4193  bool `json:"rfc4193"`
	ZT       bool `json:"zt"`
	SixPlane bool `json:"6plane"`
}

type legacyRoute struct {
	Target string  `json:"target"`
	Via    *string `json:"via"`
}

type legacyIPPool struct {
	Start string `json:"ipRangeStart"`
	End   string `json:"ipRangeEnd"`
}

type legacyCapability struct {
	ID      uint32                       `json:"id"`
	Default bool                         `json:"default"`
	Rules   []map[string]json.RawMessage `json:"rules"`
}

type legacyTag struct {
	ID      uint32  `json:"id"`
	Default *uint32 `json:"default"`
}

type legacyMemberPatch struct {
	Name                     *string       `json:"name"`
	Authorized               *bool         `json:"authorized"`
	ActiveBridge             *bool         `json:"activeBridge"`
	NoAutoAssignIPs          *bool         `json:"noAutoAssignIps"`
	IPAssignments            *[]netip.Addr `json:"ipAssignments"`
	Capabilities             *[]uint32     `json:"capabilities"`
	Tags                     *[][]uint32   `json:"tags"`
	AuthenticationExpiryTime *uint64       `json:"authenticationExpiryTime"`
	AuthenticationURL        *string       `json:"authenticationURL"`
	RemoteTraceTarget        *string       `json:"remoteTraceTarget"`
	RemoteTraceLevel         *uint64       `json:"remoteTraceLevel"`
	SSOExempt                *bool         `json:"ssoExempt"`
}

func registerLegacyRoutes(mux *http.ServeMux, service *controller.Service) {
	api := &legacyAPI{service: service}
	mux.HandleFunc("GET /status", api.status)
	mux.HandleFunc("GET /controller", api.controllerStatus)
	mux.HandleFunc("GET /controller/network", api.listNetworks)
	mux.HandleFunc("GET /unstable/controller/network", api.listNetworksDetailed)
	mux.HandleFunc("POST /controller/network", api.createNetwork)
	mux.HandleFunc("PUT /controller/network", api.createNetwork)
	mux.HandleFunc("GET /controller/network/{networkID}", api.getNetwork)
	mux.HandleFunc("POST /controller/network/{networkID}", api.putNetwork)
	mux.HandleFunc("PUT /controller/network/{networkID}", api.putNetwork)
	mux.HandleFunc("DELETE /controller/network/{networkID}", api.deleteNetwork)
	mux.HandleFunc("GET /controller/network/{networkID}/member", api.listMembers)
	mux.HandleFunc("GET /unstable/controller/network/{networkID}/member", api.listMembersDetailed)
	mux.HandleFunc("GET /controller/network/{networkID}/member/{nodeID}", api.getMember)
	mux.HandleFunc("POST /controller/network/{networkID}/member/{nodeID}", api.putMember)
	mux.HandleFunc("PUT /controller/network/{networkID}/member/{nodeID}", api.putMember)
	mux.HandleFunc("DELETE /controller/network/{networkID}/member/{nodeID}", api.deleteMember)
}

func (api *legacyAPI) status(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, map[string]any{
		"address":           string(api.service.ControllerID()),
		"online":            true,
		"tcpFallbackActive": false,
		"versionMajor":      0,
		"versionMinor":      1,
		"versionRev":        0,
		"version":           "ZTGotroller",
	})
}

func (api *legacyAPI) controllerStatus(response http.ResponseWriter, _ *http.Request) {
	writeJSON(response, http.StatusOK, map[string]any{
		"controller":    true,
		"apiVersion":    legacyControllerAPIVersion,
		"clock":         time.Now().UnixMilli(),
		"databaseReady": true,
	})
}

func (api *legacyAPI) listNetworks(response http.ResponseWriter, request *http.Request) {
	networks, err := api.service.ListNetworks(request.Context())
	if err != nil {
		writeError(response, err)
		return
	}
	ids := make([]string, 0, len(networks))
	for _, network := range networks {
		ids = append(ids, string(network.ID))
	}
	writeJSON(response, http.StatusOK, ids)
}

func (api *legacyAPI) listNetworksDetailed(response http.ResponseWriter, request *http.Request) {
	networks, err := api.service.ListNetworks(request.Context())
	if err != nil {
		writeError(response, err)
		return
	}
	data := make([]map[string]any, 0, len(networks))
	for _, network := range networks {
		members, err := api.service.ListMembers(request.Context(), network.ID)
		if err != nil {
			writeError(response, err)
			return
		}
		item := renderLegacyNetwork(network)
		authorized := 0
		for _, member := range members {
			if member.Authorized {
				authorized++
			}
		}
		item["meta"] = map[string]any{
			"totalMemberCount":      len(members),
			"authorizedMemberCount": authorized,
		}
		data = append(data, item)
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"data": data,
		"meta": map[string]any{"networkCount": len(data)},
	})
}

func (api *legacyAPI) createNetwork(response http.ResponseWriter, request *http.Request) {
	var patch legacyNetworkPatch
	if !decodeLegacyJSON(response, request, &patch) {
		return
	}
	name := ""
	if patch.Name != nil {
		name = *patch.Name
	}
	network, err := api.service.CreateRandomNetwork(request.Context(), name)
	if err != nil {
		writeError(response, err)
		return
	}
	network, err = api.applyNetworkPatch(request, network, patch)
	if err != nil {
		writeError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, renderLegacyNetwork(network))
}

func (api *legacyAPI) getNetwork(response http.ResponseWriter, request *http.Request) {
	network, ok := api.networkFromPath(response, request)
	if !ok {
		return
	}
	writeJSON(response, http.StatusOK, renderLegacyNetwork(network))
}

func (api *legacyAPI) putNetwork(response http.ResponseWriter, request *http.Request) {
	rawID := strings.ToLower(request.PathValue("networkID"))
	if strings.HasSuffix(rawID, "______") && len(rawID) == 16 {
		if rawID[:10] != string(api.service.ControllerID()) {
			writeJSON(response, http.StatusBadRequest, errorResponse{Error: "network prefix does not match controller"})
			return
		}
		var patch legacyNetworkPatch
		if !decodeLegacyJSON(response, request, &patch) {
			return
		}
		name := ""
		if patch.Name != nil {
			name = *patch.Name
		}
		network, err := api.service.CreateRandomNetwork(request.Context(), name)
		if err == nil {
			network, err = api.applyNetworkPatch(request, network, patch)
		}
		if err != nil {
			writeError(response, err)
			return
		}
		writeJSON(response, http.StatusOK, renderLegacyNetwork(network))
		return
	}
	id, ok := legacyNetworkID(response, request.PathValue("networkID"))
	if !ok {
		return
	}
	var patch legacyNetworkPatch
	if !decodeLegacyJSON(response, request, &patch) {
		return
	}
	network, err := api.service.GetNetwork(request.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		sequence, parseErr := strconv.ParseUint(string(id)[10:], 16, 32)
		if parseErr != nil {
			writeJSON(response, http.StatusBadRequest, errorResponse{Error: "invalid network ID"})
			return
		}
		name := ""
		if patch.Name != nil {
			name = *patch.Name
		}
		network, err = api.service.CreateNetwork(request.Context(), uint32(sequence), name)
	}
	if err != nil {
		writeError(response, err)
		return
	}
	network, err = api.applyNetworkPatch(request, network, patch)
	if err != nil {
		writeError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, renderLegacyNetwork(network))
}

func (api *legacyAPI) deleteNetwork(response http.ResponseWriter, request *http.Request) {
	network, ok := api.networkFromPath(response, request)
	if !ok {
		return
	}
	if err := api.service.DeleteNetwork(request.Context(), network.ID); err != nil {
		writeError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, renderLegacyNetwork(network))
}

func (api *legacyAPI) listMembers(response http.ResponseWriter, request *http.Request) {
	id, ok := legacyNetworkID(response, request.PathValue("networkID"))
	if !ok {
		return
	}
	members, err := api.service.ListMembers(request.Context(), id)
	if err != nil {
		writeError(response, err)
		return
	}
	result := make(map[string]uint64, len(members))
	for _, member := range members {
		result[string(member.NodeID)] = member.Revision
	}
	writeJSON(response, http.StatusOK, result)
}

func (api *legacyAPI) listMembersDetailed(response http.ResponseWriter, request *http.Request) {
	id, ok := legacyNetworkID(response, request.PathValue("networkID"))
	if !ok {
		return
	}
	members, err := api.service.ListMembers(request.Context(), id)
	if err != nil {
		writeError(response, err)
		return
	}
	data := make([]map[string]any, 0, len(members))
	authorized := 0
	for _, member := range members {
		data = append(data, renderLegacyMember(member))
		if member.Authorized {
			authorized++
		}
	}
	writeJSON(response, http.StatusOK, map[string]any{
		"data": data,
		"meta": map[string]any{"totalCount": len(data), "authorizedCount": authorized},
	})
}

func (api *legacyAPI) getMember(response http.ResponseWriter, request *http.Request) {
	member, ok := api.memberFromPath(response, request)
	if !ok {
		return
	}
	writeJSON(response, http.StatusOK, renderLegacyMember(member))
}

func (api *legacyAPI) putMember(response http.ResponseWriter, request *http.Request) {
	networkID, ok := legacyNetworkID(response, request.PathValue("networkID"))
	if !ok {
		return
	}
	nodeID, ok := legacyNodeID(response, request.PathValue("nodeID"))
	if !ok {
		return
	}
	var patch legacyMemberPatch
	if !decodeLegacyJSON(response, request, &patch) {
		return
	}
	member, err := api.service.RegisterMember(request.Context(), networkID, nodeID)
	if err != nil {
		writeError(response, err)
		return
	}
	update := controller.MemberUpdate{
		Name: member.Name, ActiveBridge: member.ActiveBridge, NoAutoAssign: member.NoAutoAssign,
		IPAssignments: member.IPAssignments, Capabilities: member.Capabilities, Tags: member.Tags,
		AuthenticationExpiryTime: member.AuthenticationExpiryTime,
		AuthenticationURL:        member.AuthenticationURL, RemoteTraceTarget: member.RemoteTraceTarget,
		RemoteTraceLevel: member.RemoteTraceLevel, SSOExempt: member.SSOExempt,
	}
	if patch.Name != nil {
		update.Name = *patch.Name
	}
	if patch.ActiveBridge != nil {
		update.ActiveBridge = *patch.ActiveBridge
	}
	if patch.NoAutoAssignIPs != nil {
		update.NoAutoAssign = *patch.NoAutoAssignIPs
	}
	if patch.IPAssignments != nil {
		update.IPAssignments = *patch.IPAssignments
	}
	if patch.Capabilities != nil {
		update.Capabilities = uniqueUint32(*patch.Capabilities)
	}
	if patch.Tags != nil {
		update.Tags = legacyMemberTags(*patch.Tags)
	}
	if patch.AuthenticationExpiryTime != nil {
		update.AuthenticationExpiryTime = *patch.AuthenticationExpiryTime
	}
	if patch.AuthenticationURL != nil {
		update.AuthenticationURL = *patch.AuthenticationURL
	}
	if patch.RemoteTraceTarget != nil {
		update.RemoteTraceTarget = *patch.RemoteTraceTarget
	}
	if patch.RemoteTraceLevel != nil {
		update.RemoteTraceLevel = *patch.RemoteTraceLevel
	}
	if patch.SSOExempt != nil {
		update.SSOExempt = *patch.SSOExempt
	}
	member, err = api.service.UpdateMember(request.Context(), networkID, nodeID, update, member.Revision)
	if err != nil {
		writeError(response, err)
		return
	}
	if patch.Authorized != nil && member.Authorized != *patch.Authorized {
		member, err = api.service.SetMemberAuthorization(
			request.Context(), networkID, nodeID, *patch.Authorized, member.Revision,
		)
		if err != nil {
			writeError(response, err)
			return
		}
	}
	writeJSON(response, http.StatusOK, renderLegacyMember(member))
}

func (api *legacyAPI) deleteMember(response http.ResponseWriter, request *http.Request) {
	member, ok := api.memberFromPath(response, request)
	if !ok {
		return
	}
	if err := api.service.DeleteMember(request.Context(), member.NetworkID, member.NodeID); err != nil {
		writeError(response, err)
		return
	}
	writeJSON(response, http.StatusOK, renderLegacyMember(member))
}

func (api *legacyAPI) applyNetworkPatch(
	request *http.Request,
	network domain.Network,
	patch legacyNetworkPatch,
) (domain.Network, error) {
	update := controller.NetworkUpdate{
		Name: network.Name, Private: network.Private, MTU: network.MTU,
		MulticastLimit: network.MulticastLimit, EnableBroadcast: network.EnableBroadcast,
		Assignment: network.Assignment, Routes: network.Routes, IPPools: network.IPPools,
		DNS: network.DNS, Rules: network.Rules, Capabilities: network.Capabilities, Tags: network.Tags,
		AuthTokens: network.AuthTokens, RulesSource: network.RulesSource,
		RemoteTraceTarget: network.RemoteTraceTarget, RemoteTraceLevel: network.RemoteTraceLevel,
		SSOEnabled: network.SSOEnabled,
	}
	if patch.Name != nil {
		update.Name = *patch.Name
	}
	if patch.Private != nil {
		update.Private = *patch.Private
	}
	if patch.MTU != nil {
		update.MTU = *patch.MTU
	}
	if patch.MulticastLimit != nil {
		update.MulticastLimit = *patch.MulticastLimit
	}
	if patch.EnableBroadcast != nil {
		update.EnableBroadcast = *patch.EnableBroadcast
	}
	if patch.V4AssignMode != nil {
		update.Assignment.IPv4ZeroTier = patch.V4AssignMode.ZT
	}
	if patch.V6AssignMode != nil {
		update.Assignment.IPv6RFC4193 = patch.V6AssignMode.RFC4193
		update.Assignment.IPv6ZeroTier = patch.V6AssignMode.ZT
		update.Assignment.IPv6SixPlane = patch.V6AssignMode.SixPlane
	}
	if patch.Routes != nil {
		update.Routes = parseLegacyRoutes(*patch.Routes)
	}
	if patch.IPAssignmentPools != nil {
		update.IPPools = parseLegacyPools(*patch.IPAssignmentPools)
	}
	if patch.DNS != nil {
		update.DNS = patch.DNS
	}
	if patch.Rules != nil {
		update.Rules = parseLegacyRules(*patch.Rules)
	}
	if patch.Capabilities != nil {
		update.Capabilities = parseLegacyCapabilities(*patch.Capabilities)
	}
	if patch.Tags != nil {
		update.Tags = make([]domain.TagDefinition, 0, len(*patch.Tags))
		for _, tag := range *patch.Tags {
			value := uint32(0)
			if tag.Default != nil {
				value = *tag.Default
			}
			update.Tags = append(update.Tags, domain.TagDefinition{ID: tag.ID, Default: value})
		}
	}
	if patch.AuthTokens != nil {
		update.AuthTokens = *patch.AuthTokens
	}
	if patch.RulesSource != nil {
		update.RulesSource = *patch.RulesSource
	}
	if patch.RemoteTraceTarget != nil {
		update.RemoteTraceTarget = *patch.RemoteTraceTarget
	}
	if patch.RemoteTraceLevel != nil {
		update.RemoteTraceLevel = *patch.RemoteTraceLevel
	}
	if patch.SSOEnabled != nil {
		update.SSOEnabled = *patch.SSOEnabled
	}
	return api.service.UpdateNetwork(request.Context(), network.ID, update, network.Revision)
}

func (api *legacyAPI) networkFromPath(
	response http.ResponseWriter, request *http.Request,
) (domain.Network, bool) {
	id, ok := legacyNetworkID(response, request.PathValue("networkID"))
	if !ok {
		return domain.Network{}, false
	}
	network, err := api.service.GetNetwork(request.Context(), id)
	if err != nil {
		writeError(response, err)
		return domain.Network{}, false
	}
	return network, true
}

func (api *legacyAPI) memberFromPath(
	response http.ResponseWriter, request *http.Request,
) (domain.Member, bool) {
	networkID, ok := legacyNetworkID(response, request.PathValue("networkID"))
	if !ok {
		return domain.Member{}, false
	}
	nodeID, ok := legacyNodeID(response, request.PathValue("nodeID"))
	if !ok {
		return domain.Member{}, false
	}
	member, err := api.service.GetMember(request.Context(), networkID, nodeID)
	if err != nil {
		writeError(response, err)
		return domain.Member{}, false
	}
	return member, true
}

func legacyNetworkID(response http.ResponseWriter, value string) (domain.NetworkID, bool) {
	value = strings.ToLower(value)
	if strings.HasSuffix(value, "______") && len(value) == 16 {
		value = value[:10] + "000001"
	}
	id, err := domain.ParseNetworkID(value)
	if err != nil {
		writeJSON(response, http.StatusBadRequest, errorResponse{Error: err.Error()})
		return "", false
	}
	return id, true
}

func legacyNodeID(response http.ResponseWriter, value string) (domain.NodeID, bool) {
	id, err := domain.ParseNodeID(strings.ToLower(value))
	if err != nil {
		writeJSON(response, http.StatusBadRequest, errorResponse{Error: err.Error()})
		return "", false
	}
	return id, true
}

func decodeLegacyJSON(response http.ResponseWriter, request *http.Request, destination any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(response, request.Body, 64<<20))
	if err := decoder.Decode(destination); err != nil {
		writeJSON(response, http.StatusBadRequest, errorResponse{Error: "invalid JSON body"})
		return false
	}
	return true
}

func renderLegacyNetwork(network domain.Network) map[string]any {
	routes := make([]map[string]any, 0, len(network.Routes))
	for _, route := range network.Routes {
		item := map[string]any{"target": route.Target.String(), "via": nil}
		if route.Via.IsValid() {
			item["via"] = route.Via.String()
		}
		routes = append(routes, item)
	}
	pools := make([]map[string]string, 0, len(network.IPPools))
	for _, pool := range network.IPPools {
		pools = append(pools, map[string]string{
			"ipRangeStart": pool.Start.String(), "ipRangeEnd": pool.End.String(),
		})
	}
	capabilities := make([]map[string]any, 0, len(network.Capabilities))
	for _, capability := range network.Capabilities {
		capabilities = append(capabilities, map[string]any{
			"id": capability.ID, "default": capability.Default,
			"rules": renderLegacyRules(capability.Rules),
		})
	}
	tags := make([]map[string]any, 0, len(network.Tags))
	for _, tag := range network.Tags {
		tags = append(tags, map[string]any{"id": tag.ID, "default": tag.Default})
	}
	return map[string]any{
		"id": string(network.ID), "nwid": string(network.ID), "name": network.Name,
		"private": network.Private, "creationTime": network.CreatedAt.UnixMilli(),
		"revision": network.Revision, "mtu": network.MTU,
		"multicastLimit": network.MulticastLimit, "enableBroadcast": network.EnableBroadcast,
		"v4AssignMode": map[string]bool{"zt": network.Assignment.IPv4ZeroTier},
		"v6AssignMode": map[string]bool{
			"rfc4193": network.Assignment.IPv6RFC4193,
			"zt":      network.Assignment.IPv6ZeroTier,
			"6plane":  network.Assignment.IPv6SixPlane,
		},
		"routes": routes, "ipAssignmentPools": pools, "dns": network.DNS,
		"rules":        renderLegacyRules(network.Rules),
		"capabilities": capabilities, "tags": tags,
		"authTokens": network.AuthTokens, "rulesSource": network.RulesSource,
		"remoteTraceTarget": nullableString(network.RemoteTraceTarget),
		"remoteTraceLevel":  network.RemoteTraceLevel, "ssoEnabled": network.SSOEnabled,
		"objtype": "network", "lastModified": network.UpdatedAt.UnixMilli(),
	}
}

func renderLegacyMember(member domain.Member) map[string]any {
	ips := make([]string, 0, len(member.IPAssignments))
	for _, address := range member.IPAssignments {
		ips = append(ips, address.String())
	}
	tags := make([][2]uint32, 0, len(member.Tags))
	for _, tag := range member.Tags {
		tags = append(tags, [2]uint32{tag.ID, tag.Value})
	}
	return map[string]any{
		"id": string(member.NodeID), "address": string(member.NodeID),
		"nwid": string(member.NetworkID), "name": member.Name,
		"authorized": member.Authorized, "activeBridge": member.ActiveBridge,
		"noAutoAssignIps": member.NoAutoAssign, "ipAssignments": ips,
		"capabilities": member.Capabilities, "tags": tags,
		"creationTime": member.CreatedAt.UnixMilli(), "revision": member.Revision,
		"lastAuthorizedTime":       unixMilliOrZero(member.LastAuthorizedAt),
		"lastDeauthorizedTime":     unixMilliOrZero(member.LastDeauthorizedAt),
		"authenticationExpiryTime": member.AuthenticationExpiryTime,
		"authenticationURL":        member.AuthenticationURL,
		"remoteTraceTarget":        nullableString(member.RemoteTraceTarget),
		"remoteTraceLevel":         member.RemoteTraceLevel, "ssoExempt": member.SSOExempt,
		"identity": "", "hidden": false, "objtype": "member",
		"online": false, "lastSeen": int64(0), "physicalAddress": "",
		"clientVersionMajor": 0, "clientVersionMinor": 0,
		"clientVersionRev": 0, "clientVersionProtocol": 0,
		"vMajor": 0, "vMinor": 0, "vRev": 0, "vProto": 0,
		"lastAuthorizedCredential": nil, "lastAuthorizedCredentialType": "",
	}
}

func unixMilliOrZero(value time.Time) int64 {
	if value.IsZero() {
		return 0
	}
	return value.UnixMilli()
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func parseLegacyRoutes(input []legacyRoute) []domain.Route {
	result := make([]domain.Route, 0, len(input))
	for _, value := range input {
		target, err := netip.ParsePrefix(value.Target)
		if err != nil {
			continue
		}
		route := domain.Route{Target: target.Masked()}
		if value.Via != nil {
			if via, err := netip.ParseAddr(*value.Via); err == nil && via.Is4() == target.Addr().Is4() {
				route.Via = via
			}
		}
		result = append(result, route)
	}
	return result
}

func parseLegacyPools(input []legacyIPPool) []domain.IPPool {
	result := make([]domain.IPPool, 0, len(input))
	for _, value := range input {
		start, startErr := netip.ParseAddr(value.Start)
		end, endErr := netip.ParseAddr(value.End)
		if startErr == nil && endErr == nil && start.Is4() == end.Is4() && start.Compare(end) <= 0 {
			result = append(result, domain.IPPool{Start: start, End: end})
		}
	}
	return result
}

func parseLegacyRules(input []map[string]json.RawMessage) []domain.Rule {
	result := make([]domain.Rule, 0, len(input))
	for _, raw := range input {
		var rule domain.Rule
		_ = json.Unmarshal(raw["type"], &rule.Type)
		_ = json.Unmarshal(raw["not"], &rule.Negate)
		_ = json.Unmarshal(raw["or"], &rule.Or)
		delete(raw, "type")
		delete(raw, "not")
		delete(raw, "or")
		if len(raw) > 0 {
			rule.Parameters = raw
		}
		if rule.Type != "" {
			result = append(result, rule)
		}
	}
	return result
}

func renderLegacyRules(input []domain.Rule) []map[string]any {
	result := make([]map[string]any, 0, len(input))
	for _, rule := range input {
		item := map[string]any{"type": rule.Type, "not": rule.Negate, "or": rule.Or}
		for key, raw := range rule.Parameters {
			var value any
			if json.Unmarshal(raw, &value) == nil {
				item[key] = value
			}
		}
		result = append(result, item)
	}
	return result
}

func parseLegacyCapabilities(input []legacyCapability) []domain.Capability {
	result := make([]domain.Capability, 0, len(input))
	for _, value := range input {
		result = append(result, domain.Capability{
			ID: value.ID, Default: value.Default, Rules: parseLegacyRules(value.Rules),
		})
	}
	return result
}

func legacyMemberTags(input [][]uint32) []domain.TagValue {
	byID := make(map[uint32]uint32)
	for _, pair := range input {
		if len(pair) == 2 {
			byID[pair[0]] = pair[1]
		}
	}
	result := make([]domain.TagValue, 0, len(byID))
	for id, value := range byID {
		result = append(result, domain.TagValue{ID: id, Value: value})
	}
	return result
}

func uniqueUint32(input []uint32) []uint32 {
	seen := make(map[uint32]struct{}, len(input))
	result := make([]uint32, 0, len(input))
	for _, value := range input {
		if _, ok := seen[value]; !ok {
			seen[value] = struct{}{}
			result = append(result, value)
		}
	}
	return result
}
