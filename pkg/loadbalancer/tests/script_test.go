// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tests

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"maps"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	uhive "github.com/cilium/hive"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/cilium/hive/script"
	"github.com/cilium/hive/script/scripttest"
	"github.com/cilium/statedb"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	daemonk8s "github.com/cilium/cilium/daemon/k8s"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/datapath/tables"
	envoyCfg "github.com/cilium/cilium/pkg/envoy/config"
	"github.com/cilium/cilium/pkg/hive"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client/testutils"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	k8sTestutils "github.com/cilium/cilium/pkg/k8s/testutils"
	"github.com/cilium/cilium/pkg/k8s/version"
	"github.com/cilium/cilium/pkg/kpr"
	"github.com/cilium/cilium/pkg/lbipamconfig"
	"github.com/cilium/cilium/pkg/loadbalancer"
	lbcell "github.com/cilium/cilium/pkg/loadbalancer/cell"
	lbmaps "github.com/cilium/cilium/pkg/loadbalancer/maps"
	lbreconciler "github.com/cilium/cilium/pkg/loadbalancer/reconciler"
	"github.com/cilium/cilium/pkg/loadbalancer/writer"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/maglev"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/node/addressing"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/nodeipamconfig"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/source"
	"github.com/cilium/cilium/pkg/testutils"
	"github.com/cilium/cilium/pkg/time"
)

var debug = flag.Bool("debug", false, "Enable debug logging")

// TestPrivilegedScript runs script tests when privileged.
// This exists solely to satisfy 'tests-privileged-only' make target and to not
// run the tests twice when privileged.
func TestPrivilegedScript(t *testing.T) {
	testutils.PrivilegedTest(t)
	testScript(t)
}

// TestScript runs script tests when non-privileged.
func TestScript(t *testing.T) {
	if testutils.IsPrivileged() {
		t.Skip("Skipping in favour of TestPrivilegedScript")
	} else {
		testScript(t)
	}
}

func testScript(t *testing.T) {
	// version/capabilities are unfortunately a global variable, so we're forcing it here.
	// This makes it difficult to have different k8s version/capabilities (e.g. use Endpoints
	// not EndpointSlice) in the tests here, which is why we're currently only testing against
	// the default.
	// Issue for fixing this: https://github.com/cilium/cilium/issues/35537
	version.Force(k8sTestutils.DefaultVersion)

	// Set the node name
	nodeTypes.SetName("testnode")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	scripttest.Test(t,
		ctx,
		func(t testing.TB, args []string) *script.Engine {
			var opts []hivetest.LogOption
			if *debug {
				opts = append(opts, hivetest.LogLevel(slog.LevelDebug))
				logging.SetLogLevel(slog.LevelDebug)
			}
			log := hivetest.Logger(t, opts...)

			h := hive.New(
				k8sClient.FakeClientCell(),
				daemonk8s.ResourcesCell,
				k8sTables.TablesCell,
				cell.Config(envoyCfg.SecretSyncConfig{}),

				cell.Config(loadbalancer.TestConfig{
					// By default 10% of the time the LBMap operations fail
					TestFaultProbability: 0.1,
				}),
				metrics.Cell,
				maglev.Cell,
				lbipamconfig.Cell,
				nodeipamconfig.Cell,
				node.LocalNodeStoreTestCell,
				cell.Provide(
					func() cmtypes.ClusterInfo { return cmtypes.ClusterInfo{} },
					func(cfg loadbalancer.TestConfig) *loadbalancer.TestConfig { return &cfg },
					tables.NewNodeAddressTable,
					statedb.RWTable[tables.NodeAddress].ToTable,
					source.NewSources,
					func(cfg loadbalancer.TestConfig) *option.DaemonConfig {
						return &option.DaemonConfig{
							EnableIPv4: true,
							EnableIPv6: true,
						}
					},
					func() kpr.KPRConfig {
						return kpr.KPRConfig{
							KubeProxyReplacement: true,
						}
					},
					func(ops *lbreconciler.BPFOps, lns *node.LocalNodeStore, w *writer.Writer, waitFn loadbalancer.InitWaitFunc) uhive.ScriptCmdsOut {
						return uhive.NewScriptCmds(testCommands{w, lns, ops, waitFn}.cmds())
					},
				),

				lbcell.Cell,
			)

			flags := pflag.NewFlagSet("", pflag.ContinueOnError)
			h.RegisterFlags(flags)

			// Set some defaults
			flags.Set("lb-retry-backoff-min", "10ms") // as we're doing fault injection we want
			flags.Set("lb-retry-backoff-max", "10ms") // tiny backoffs
			flags.Set("bpf-lb-maglev-table-size", "1021")

			// Expand $WORK in args. Used by testdata/file.txtar.
			// This works by creating a new temporary directory for this test (e.g. /tmp/<tempdir/002)
			// and replacing the directory with /001 which is the temp directory that scripttest created.
			tempDir := filepath.Join(filepath.Dir(t.TempDir()), "001")
			for i := range args {
				args[i] = strings.ReplaceAll(args[i], "$WORK", tempDir)
			}

			// Parse the shebang arguments in the script.
			require.NoError(t, flags.Parse(args), "flags.Parse")

			t.Cleanup(func() {
				assert.NoError(t, h.Stop(log, context.TODO()))
			})
			cmds, err := h.ScriptCommands(log)
			require.NoError(t, err, "ScriptCommands")
			maps.Insert(cmds, maps.All(script.DefaultCmds()))

			conds := map[string]script.Cond{
				"privileged": script.BoolCondition("testutils.IsPrivileged", testutils.IsPrivileged()),
			}
			return &script.Engine{
				Cmds:             cmds,
				Conds:            conds,
				RetryInterval:    20 * time.Millisecond,
				MaxRetryInterval: 500 * time.Millisecond,
			}
		},
		[]string{
			/* empty environment */
		}, "testdata/*.txtar")
}

type testCommands struct {
	w      *writer.Writer
	lns    *node.LocalNodeStore
	ops    *lbreconciler.BPFOps
	waitFn loadbalancer.InitWaitFunc
}

func (tc testCommands) cmds() map[string]script.Cmd {
	return map[string]script.Cmd{
		"test/update-backend-health":        tc.updateHealth(),
		"test/bpfops-reset":                 tc.opsReset(),
		"test/bpfops-summary":               tc.opsSummary(),
		"test/set-node-labels":              tc.setNodeLabels(),
		"test/set-node-ip":                  tc.setNodeIP(),
		"test/set-is-service-healthchecked": tc.setIsServiceHealthChecked(),
		"test/init-wait":                    tc.initWait(),
		"test/dump-lbmap":                   tc.dumpLBMap(),
	}
}

func (tc testCommands) updateHealth() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Update backend healthyness",
			Args:    "service-name backend-addr healthy",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 3 {
				return nil, fmt.Errorf("%w: expected service name, backend address and health", script.ErrUsage)
			}
			ns, name, _ := strings.Cut(args[0], "/")
			svc := loadbalancer.NewServiceName(ns, name)

			var beAddr loadbalancer.L3n4Addr
			if err := beAddr.ParseFromString(args[1]); err != nil {
				return nil, err
			}

			healthy, err := strconv.ParseBool(args[2])
			if err != nil {
				return nil, err
			}

			txn := tc.w.WriteTxn()
			_, err = tc.w.UpdateBackendHealth(txn, svc, beAddr, healthy)
			if err != nil {
				txn.Abort()
				return nil, err
			}
			txn.Commit()
			return nil, nil
		})
}

func (tc testCommands) opsReset() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Reset and restart BPF ops",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return nil, tc.ops.ResetAndRestore()
		})
}

func (tc testCommands) opsSummary() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Write out summary of BPFOps state",
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return func(s *script.State) (stdout string, stderr string, err error) {
				stdout = tc.ops.StateSummary()
				return
			}, nil
		})
}

func (tc testCommands) setNodeLabels() script.Cmd {
	return script.Command(
		script.CmdUsage{Summary: "Set local node labels", Args: "key=value..."},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			labels := map[string]string{}
			for _, arg := range args {
				key, value, found := strings.Cut(arg, "=")
				if !found {
					return nil, fmt.Errorf("bad key=value: %q", arg)
				}
				labels[key] = value
			}
			tc.lns.Update(func(n *node.LocalNode) {
				n.Labels = labels
				s.Logf("Labels set to %v\n", labels)
			})
			return nil, nil
		})
}

func (tc testCommands) setNodeIP() script.Cmd {
	return script.Command(
		script.CmdUsage{Summary: "Set local node IP", Args: "ip"},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("%w: expected 'ip'", script.ErrUsage)
			}
			ip := net.ParseIP(args[0])
			tc.lns.Update(func(n *node.LocalNode) {
				n.IPAddresses = []nodeTypes.Address{
					{Type: addressing.NodeExternalIP, IP: ip},
				}
				s.Logf("NodeIP set to %s\n", ip)
			})
			return nil, nil
		})
}

func (tc testCommands) setIsServiceHealthChecked() script.Cmd {
	return script.Command(
		script.CmdUsage{Summary: "Set isIServiceHealthChecked that reports services as being healthchecked based on the presence of the given annotation", Args: "annotation"},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 1 {
				return nil, fmt.Errorf("%w: expected 'annotation'", script.ErrUsage)
			}

			tc.w.SetIsServiceHealthCheckedFunc(func(svc *loadbalancer.Service) bool {
				return svc.Annotations != nil && svc.Annotations[args[0]] != ""
			})
			return nil, nil
		})
}

func (tc testCommands) initWait() script.Cmd {
	return script.Command(
		script.CmdUsage{Summary: "Wait for InitWaitFunc() to return"},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			return nil, tc.waitFn(s.Context())
		})
}

// dumpLBMap builds a Service4Value or Service6Value and prints its String()
// output. The value is stored via ToNetwork() before String()'s ToHost()
// round-trips it, mirroring a real 'cilium map get' dump and keeping the output
// byte-order independent.
//
// With --l7 the L7LB flag is set and <id> is the Envoy proxy port, stored in the
// BackendID union in network byte order and decoded by GetL7LBProxyPort();
// otherwise <id> is a plain backend identifier.
func (tc testCommands) dumpLBMap() script.Cmd {
	return script.Command(
		script.CmdUsage{
			Summary: "Format a service map value via Service{4,6}Value.String()",
			Args:    "<family: 4|6> <id> <count> <qcount> <revnat>",
			Flags: func(fs *pflag.FlagSet) {
				fs.Bool("l7", false, "Build an L7 entry: <id> is the Envoy proxy port")
			},
		},
		func(s *script.State, args ...string) (script.WaitFunc, error) {
			if len(args) != 5 {
				return nil, fmt.Errorf("%w: expected family, id, count, qcount, revnat", script.ErrUsage)
			}

			var val lbmaps.ServiceValue
			switch args[0] {
			case "4":
				val = &lbmaps.Service4Value{}
			case "6":
				val = &lbmaps.Service6Value{}
			default:
				return nil, fmt.Errorf("invalid family %q: want 4 or 6", args[0])
			}

			isL7, err := s.Flags.GetBool("l7")
			if err != nil {
				return nil, err
			}

			id, err := strconv.ParseUint(args[1], 10, 32)
			if err != nil {
				return nil, fmt.Errorf("invalid id %q: %w", args[1], err)
			}
			count, err := strconv.Atoi(args[2])
			if err != nil {
				return nil, fmt.Errorf("invalid count %q: %w", args[2], err)
			}
			qcount, err := strconv.Atoi(args[3])
			if err != nil {
				return nil, fmt.Errorf("invalid qcount %q: %w", args[3], err)
			}
			revnat, err := strconv.Atoi(args[4])
			if err != nil {
				return nil, fmt.Errorf("invalid revnat %q: %w", args[4], err)
			}

			val.SetFlags(uint16(loadbalancer.NewSvcFlag(&loadbalancer.SvcFlagParam{
				SvcType:        loadbalancer.SVCTypeLoadBalancer,
				IsRoutable:     true,
				L7LoadBalancer: isL7,
			})))
			if isL7 {
				val.SetL7LBProxyPort(uint16(id))
			} else {
				val.SetBackendID(loadbalancer.BackendID(id))
			}
			val.SetCount(count)
			val.SetQCount(qcount)
			val.SetRevNat(revnat)

			return func(*script.State) (stdout, stderr string, err error) {
				return val.ToNetwork().String() + "\n", "", nil
			}, nil
		})
}
