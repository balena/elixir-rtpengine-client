# RtpEngineClient

This is an Elixir client for the Sipwise NGCP RtpEngine proxy. This client
assumes you have configured the daemon to support the NG protocol, where the
RtpEngine can rewrite the SDP parameters (argument `--listen-ng`).

## Installation

The package can be installed by adding `rtpengineclient` to your list of
dependencies in `mix.exs`:

```elixir
def deps do
  [{:rtpengineclient, "~> 0.1.2"}]
end
```

Further documentation can found at
[https://hexdocs.pm/rtpengineclient](https://hexdocs.pm/rtpengineclient).
