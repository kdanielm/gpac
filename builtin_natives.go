package gpac

import (
	"context"
	"net"
	"net/netip"
	"strings"

	"github.com/dop251/goja"
)

var builtinNatives = map[string]func(*goja.Runtime) func(call goja.FunctionCall) goja.Value{
	"dnsResolve":    dnsResolve,
	"dnsResolveEx":  dnsResolveEx,
	"myIpAddress":   myIPAddress,
	"myIpAddressEx": myIPAddressEx,
	"isInNetEx":     isInNetEx,
}

func dnsResolve(vm *goja.Runtime) func(call goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		arg := call.Argument(0)
		if arg == nil || arg.Equals(goja.Undefined()) {
			return goja.Null()
		}

		host := arg.String()

		//ips, err := net.LookupIP(host)
		ips, err := net.DefaultResolver.LookupIP(context.TODO(), "ip4", host)
		if err != nil {
			return goja.Null()
		}

		return vm.ToValue(ips[0].String())
	}
}

func dnsResolveEx(vm *goja.Runtime) func(call goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		arg := call.Argument(0)
		if arg == nil || arg.Equals(goja.Undefined()) {
			return goja.Null()
		}

		host := arg.String()
		ips, err := net.DefaultResolver.LookupIP(context.TODO(), "ip", host)

		if err != nil {
			return goja.Null()
		}

		return vm.ToValue(ips[0].String())
	}
}

func myIPAddress(vm *goja.Runtime) func(call goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		ifs, err := net.Interfaces()
		if err != nil {
			return goja.Null()
		}

		for _, ifn := range ifs {
			if ifn.Flags&net.FlagUp != net.FlagUp {
				continue
			}

			addrs, err := ifn.Addrs()
			if err != nil {
				continue
			}

			for _, addr := range addrs {
				ip, ok := addr.(*net.IPNet)
				isV6 := ip.IP.To4() == nil
				if ok && ip.IP.IsGlobalUnicast() && !isV6 {
					ipstr := ip.IP.String()
					return vm.ToValue(ipstr)
				}
			}
		}
		return goja.Null()
	}
}

func myIPAddressEx(vm *goja.Runtime) func(call goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		ifs, err := net.Interfaces()
		if err != nil {
			return goja.Null()
		}

		var addresses []string

		for _, ifn := range ifs {
			if ifn.Flags&net.FlagUp != net.FlagUp {
				continue
			}

			addrs, err := ifn.Addrs()

			if err != nil {
				continue
			}

			for _, addr := range addrs {
				ip, ok := addr.(*net.IPNet)
				if ok && ip.IP.IsGlobalUnicast() {
					ipstr := ip.IP.String()
					addresses = append(addresses, ipstr)

				}
			}
		}

		if len(addresses) == 0 {
			return goja.Null()
		} else {
			return vm.ToValue(strings.Join(addresses, ";"))
		}
	}
}

func isInNetEx(vm *goja.Runtime) func(call goja.FunctionCall) goja.Value {
	return func(call goja.FunctionCall) goja.Value {
		arg1 := call.Argument(0)
		if arg1 == nil || arg1.Equals(goja.Undefined()) {
			return goja.Null()
		}

		arg2 := call.Argument(1)
		if arg2 == nil || arg2.Equals(goja.Undefined()) {
			return goja.Null()
		}

		host := arg1.String()
		network := arg2.String()

		parsedNet, err := netip.ParsePrefix(network)

		if err != nil {
			return goja.Null()
		}

		parsedHost, err := netip.ParseAddr(host)

		if err != nil {
			return goja.Null()
		}

		netContainsHost := parsedNet.Contains(parsedHost)

		return vm.ToValue(netContainsHost)
	}
}
