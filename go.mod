module github.com/raphaelthomas/ssh_transport_exporter

go 1.26.0

require (
	github.com/alecthomas/kingpin v2.2.6+incompatible
	github.com/prometheus/client_golang v1.25.0
	github.com/prometheus/client_model v0.6.3
	github.com/prometheus/common v0.72.1
	golang.org/x/crypto v0.58.0
	golang.org/x/sys v0.49.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/alecthomas/template v0.0.0-20190718012654-fb15b899a751 // indirect
	github.com/alecthomas/units v0.0.0-20240927000941-0f3dac36c52b // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/prometheus/procfs v0.23.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

replace golang.org/x/crypto => github.com/raphaelthomas/crypto v0.0.0-20261028074818-af722c6c9852
