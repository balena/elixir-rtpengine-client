# RtpEngineClient

[![Hex.pm](https://img.shields.io/hexpm/l/rtpengineclient.svg "BSD Licensed")](https://github.com/balena/elixir-rtpengine-client/blob/master/LICENSE)
[![Hex version](https://img.shields.io/hexpm/v/rtpengineclient.svg "Hex version")](https://hex.pm/packages/rtpengineclient)
[![Build Status](https://travis-ci.org/balena/elixir-rtpengine-client.svg)](https://travis-ci.org/balena/elixir-rtpengine-client)
[![Open Source Helpers](https://www.codetriage.com/balena/elixir-rtpengine-client/badges/users.svg)](https://www.codetriage.com/balena/elixir-rtpengine-client)

This is an Elixir client for the Sipwise NGCP RtpEngine proxy. This client
assumes you have configured the daemon to support the NG protocol, where the
RtpEngine can rewrite the SDP parameters (argument `--listen-ng`).

## Installation

The package can be installed by adding `rtpengineclient` to your list of
dependencies in `mix.exs`:

```elixir
def deps do
  [{:rtpengineclient, "~> 0.1.6"}]
end
```

Further documentation can found at
[https://hexdocs.pm/rtpengineclient](https://hexdocs.pm/rtpengineclient).

## Copyright

Copyright (c) 2017 Guilherme Balena Versiani. See [LICENSE](LICENSE) for
further details.
