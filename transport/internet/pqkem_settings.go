package internet

import (
	"encoding/json"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/v2fly/v2ray-core/v5/common/serial"
	"github.com/v2fly/v2ray-core/v5/transport/internet/pqkem"
)

const PQKEMTransportName = "pqkem"

// AttachPQKEMConfig stores PQ settings as an auxiliary transport setting.
// Using the existing TransportConfig/Any extension point keeps the setting
// intact through V2Ray's protobuf configuration decoding.
func AttachPQKEMConfig(settings *StreamConfig, config *pqkem.Config) error {
	if settings == nil || config == nil {
		return nil
	}
	data, err := json.Marshal(config)
	if err != nil {
		return newError("failed to encode PQ KEM settings").Base(err)
	}
	settings.TransportSettings = append(settings.TransportSettings, &TransportConfig{
		ProtocolName: PQKEMTransportName,
		Settings:     serial.ToTypedMessage(&wrapperspb.BytesValue{Value: data}),
	})
	return nil
}

func pqkemConfigFromStreamSettings(settings *StreamConfig) (*pqkem.Config, error) {
	if settings == nil {
		return nil, nil
	}
	for _, transportSetting := range settings.TransportSettings {
		if transportSetting == nil {
			continue
		}
		if transportSetting.ProtocolName != PQKEMTransportName &&
			transportSetting.GetUnifiedProtocolName() != PQKEMTransportName {
			continue
		}
		if transportSetting.Settings == nil {
			return nil, newError("empty PQ KEM settings")
		}

		var value wrapperspb.BytesValue
		if err := proto.Unmarshal(transportSetting.Settings.Value, &value); err != nil {
			return nil, newError("failed to decode PQ KEM settings").Base(err)
		}
		var config pqkem.Config
		if err := json.Unmarshal(value.Value, &config); err != nil {
			return nil, newError("failed to parse PQ KEM settings").Base(err)
		}
		return &config, nil
	}
	return nil, nil
}
