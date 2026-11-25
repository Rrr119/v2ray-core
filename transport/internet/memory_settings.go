package internet

import "github.com/v2fly/v2ray-core/v5/transport/internet/pqkem"

// MemoryStreamConfig is a parsed form of StreamConfig. This is used to reduce number of Protobuf parsing.
type MemoryStreamConfig struct {
	ProtocolName     string
	ProtocolSettings interface{}
	SecurityType     string
	SecuritySettings interface{}
	SocketSettings   *SocketConfig
	PQKEM            *pqkem.Config
}

// ToMemoryStreamConfig converts a StreamConfig to MemoryStreamConfig. It returns a default non-nil MemoryStreamConfig for nil input.
func ToMemoryStreamConfig(s *StreamConfig) (*MemoryStreamConfig, error) {
	ets, err := s.GetEffectiveTransportSettings()
	if err != nil {
		return nil, err
	}

	mss := &MemoryStreamConfig{
		ProtocolName:     s.GetEffectiveProtocol(),
		ProtocolSettings: ets,
	}

	if s != nil {
		mss.SocketSettings = s.SocketSettings
		pqkemConfig, err := pqkemConfigFromStreamSettings(s)
		if err != nil {
			return nil, err
		}
		mss.PQKEM = pqkemConfig
	}

	if s != nil && s.HasSecuritySettings() {
		ess, err := s.GetEffectiveSecuritySettings()
		if err != nil {
			return nil, err
		}
		mss.SecurityType = s.SecurityType
		mss.SecuritySettings = ess
	}

	return mss, nil
}
