package profiles

import (
	"math"

	"github.com/bogdanfinn/fhttp/http2"
	tls "github.com/bogdanfinn/utls"
)

var MMSIos2 = getMMSClientProfile2()

func getMMSClientProfile2() ClientProfile {
	clientHelloId := tls.ClientHelloID{
		Client:  "MMSIos",
		Version: "2",
		Seed:    nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					0x1301,
					0x1302,
					0x1303,
					0xc02b,
					0xc02f,
					0xc02c,
					0xc030,
					0xcca9,
					0xcca8,
					0xc009,
					0xc013,
					0xc00a,
					0xc014,
					0x009c,
					0x009d,
					0x002f,
					0x0035,
					0x000a,
				},
				CompressionMethods: []uint8{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.CurveID(0x001d),
						tls.CurveID(0x0017),
						tls.CurveID(0x0018),
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []uint8{
						tls.PointFormatUncompressed,
					}},
					&tls.SessionTicketExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						0x0403,
						0x0804,
						0x0401,
						0x0503,
						0x0805,
						0x0501,
						0x0806,
						0x0601,
						0x0201,
					}},
					&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
				},
			}, nil
		},
	}

	settings := map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      4096,
		http2.SettingEnablePush:           1,
		http2.SettingMaxConcurrentStreams: 100,
		http2.SettingInitialWindowSize:    2097152,
		http2.SettingMaxFrameSize:         16384,
		http2.SettingMaxHeaderListSize:    math.MaxUint32,
	}

	settingsOrder := []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
		http2.SettingMaxHeaderListSize,
	}
	pseudoHeaderOrder := []string{
		":method",
		":scheme",
		":path",
		":authority",
	}

	return NewClientProfile(clientHelloId, settings, settingsOrder, pseudoHeaderOrder, 15663105, nil, nil)
}

var MMSIos3 = getMMSClientProfile3()

func getMMSClientProfile3() ClientProfile {
	clientHelloId := tls.ClientHelloID{
		Client:  "MMSIos",
		Version: "3",
		Seed:    nil,
		SpecFactory: func() (tls.ClientHelloSpec, error) {
			return tls.ClientHelloSpec{
				CipherSuites: []uint16{
					tls.GREASE_PLACEHOLDER,
					0x1301,
					0x1302,
					0x1303,
					0xc02c,
					0xc02b,
					0xcca9,
					0xc030,
					0xc02f,
					0xcca8,
					0xc00a,
					0xc009,
					0xc014,
					0xc013,
				},
				CompressionMethods: []uint8{
					tls.CompressionNone,
				},
				Extensions: []tls.TLSExtension{
					&tls.UtlsGREASEExtension{},
					&tls.SNIExtension{},
					&tls.ExtendedMasterSecretExtension{},
					&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
					&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
						tls.GREASE_PLACEHOLDER,
						0x001d,
						0x0017,
						0x0018,
						0x0019,
					}},
					&tls.SupportedPointsExtension{SupportedPoints: []uint8{
						tls.PointFormatUncompressed,
					}},
					&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
					&tls.StatusRequestExtension{},
					&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
						0x0403,
						0x0804,
						0x0401,
						0x0503,
						0x0203,
						0x0805,
						0x0501,
						0x0806,
						0x0601,
						0x0201,
					}},
					&tls.SCTExtension{},
					&tls.KeyShareExtension{[]tls.KeyShare{
						{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
						{Group: tls.X25519},
					}},
					&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
						tls.PskModeDHE,
					}},
					&tls.SupportedVersionsExtension{Versions: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.VersionTLS13,
						tls.VersionTLS12,
					}},
					&tls.UtlsCompressCertExtension{[]tls.CertCompressionAlgo{
						tls.CertCompressionZlib,
					}},
					&tls.UtlsGREASEExtension{},
					&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
				},
			}, nil
		},
	}

	settings := map[http2.SettingID]uint32{
		http2.SettingHeaderTableSize:      4096,
		http2.SettingEnablePush:           1,
		http2.SettingMaxConcurrentStreams: 100,
		http2.SettingInitialWindowSize:    2097152,
		http2.SettingMaxFrameSize:         16384,
		http2.SettingMaxHeaderListSize:    math.MaxUint32,
	}

	settingsOrder := []http2.SettingID{
		http2.SettingHeaderTableSize,
		http2.SettingEnablePush,
		http2.SettingMaxConcurrentStreams,
		http2.SettingInitialWindowSize,
		http2.SettingMaxFrameSize,
		http2.SettingMaxHeaderListSize,
	}
	pseudoHeaderOrder := []string{
		":method",
		":scheme",
		":path",
		":authority",
	}

	return NewClientProfile(clientHelloId, settings, settingsOrder, pseudoHeaderOrder, 15663105, nil, nil)
}

var APP_1 = getApp1Profile()

func getApp1Profile() ClientProfile {
	settings := map[http2.SettingID]uint32{
		http2.SettingInitialWindowSize:    2097152,
		http2.SettingMaxConcurrentStreams: 100,
	}
	settingsOrder := []http2.SettingID{
		http2.SettingInitialWindowSize,
		http2.SettingMaxConcurrentStreams,
	}
	pseudoHeaderOrder := []string{
		":method",
		":scheme",
		":path",
		":authority",
	}
	connectionFlow := uint32(10485760)
	specFactory := func() (tls.ClientHelloSpec, error) {
		return tls.ClientHelloSpec{
			CipherSuites: []uint16{
				tls.GREASE_PLACEHOLDER, 4865, 4866, 4867, 49196, 49195, 52393, 49200, 49199, 52392, 49162, 49161, 49172, 49171,
				157, 156, 53, 47, 49160, 49170, 10,
			},
			CompressionMethods: []uint8{tls.CompressionNone},
			Extensions: []tls.TLSExtension{
				&tls.UtlsGREASEExtension{},
				&tls.SNIExtension{},
				&tls.UtlsExtendedMasterSecretExtension{},
				&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
				&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
					tls.CurveID(tls.GREASE_PLACEHOLDER),
					tls.X25519,
					tls.CurveP256,
					tls.CurveP384,
					tls.CurveP521,
				}},
				&tls.SupportedPointsExtension{SupportedPoints: []byte{0}},
				&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&tls.StatusRequestExtension{},
				&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
					tls.ECDSAWithP256AndSHA256,
					tls.PSSWithSHA256,
					tls.PKCS1WithSHA256,
					tls.ECDSAWithP384AndSHA384,
					tls.ECDSAWithSHA1,
					tls.PSSWithSHA384,
					tls.PSSWithSHA384,
					tls.PKCS1WithSHA384,
					tls.PSSWithSHA512,
					tls.PKCS1WithSHA512,
					tls.PKCS1WithSHA1,
				}},
				&tls.SCTExtension{},
				&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
					{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: tls.X25519},
				}},
				&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
				&tls.SupportedVersionsExtension{Versions: []uint16{
					tls.GREASE_PLACEHOLDER,
					tls.VersionTLS13,
					tls.VersionTLS12,
					tls.VersionTLS11,
					tls.VersionTLS10,
				}},
				&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{tls.CertCompressionZlib}},
				&tls.UtlsGREASEExtension{},
				&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
			},
		}, nil
	}
	ccp := NewClientProfile(tls.ClientHelloID{
		Client:      "iPhone",
		Version:     "1",
		Seed:        nil,
		SpecFactory: specFactory,
	}, settings, settingsOrder, pseudoHeaderOrder, connectionFlow, nil, nil)
	return ccp
}

var APP_2 = getApp2Profile()

func getApp2Profile() ClientProfile {
	settings := map[http2.SettingID]uint32{
		http2.SettingEnablePush:           0,
		http2.SettingInitialWindowSize:    2097152,
		http2.SettingMaxConcurrentStreams: 100,
	}
	settingsOrder := []http2.SettingID{
		http2.SettingEnablePush,
		http2.SettingInitialWindowSize,
		http2.SettingMaxConcurrentStreams,
	}
	pseudoHeaderOrder := []string{
		":method",
		":scheme",
		":path",
		":authority",
	}
	connectionFlow := uint32(10485760)
	specFactory := func() (tls.ClientHelloSpec, error) {
		return tls.ClientHelloSpec{
			CipherSuites: []uint16{
				tls.GREASE_PLACEHOLDER, 4865, 4866, 4867, 49196, 49195, 52393, 49200, 49199, 52392, 49162, 49161, 49172, 49171,
			},
			CompressionMethods: []uint8{tls.CompressionNone},
			Extensions: []tls.TLSExtension{
				&tls.UtlsGREASEExtension{},
				&tls.SNIExtension{},
				&tls.UtlsExtendedMasterSecretExtension{},
				&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
				&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
					tls.CurveID(tls.GREASE_PLACEHOLDER),
					tls.X25519,
					tls.CurveP256,
					tls.CurveP384,
					tls.CurveP521,
				}},
				&tls.SupportedPointsExtension{SupportedPoints: []byte{0}},
				&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
				&tls.StatusRequestExtension{},
				&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
					tls.ECDSAWithP256AndSHA256,
					tls.PSSWithSHA256,
					tls.PKCS1WithSHA256,
					tls.ECDSAWithP384AndSHA384,
					tls.ECDSAWithSHA1,
					tls.PSSWithSHA384,
					tls.PSSWithSHA384,
					tls.PKCS1WithSHA384,
					tls.PSSWithSHA512,
					tls.PKCS1WithSHA512,
					tls.PKCS1WithSHA1,
				}},
				&tls.SCTExtension{},
				&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
					{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
					{Group: tls.X25519},
				}},
				&tls.PSKKeyExchangeModesExtension{Modes: []uint8{tls.PskModeDHE}},
				&tls.SupportedVersionsExtension{Versions: []uint16{
					tls.GREASE_PLACEHOLDER,
					tls.VersionTLS13,
					tls.VersionTLS12,
				}},
				&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{tls.CertCompressionZlib}},
				&tls.UtlsGREASEExtension{},
				&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
			},
		}, nil
	}
	ccp := NewClientProfile(tls.ClientHelloID{
		Client:      "iPhone",
		Version:     "1",
		Seed:        nil,
		SpecFactory: specFactory,
	}, settings, settingsOrder, pseudoHeaderOrder, connectionFlow, []http2.Priority{}, &http2.PriorityParam{})
	//}, settings, settingsOrder, pseudoHeaderOrder, connectionFlow, nil, nil)

	return ccp
}
