defmodule RtpEngineClient do
  @moduledoc """
  This is a client for the Sipwise NGCP RtpEngine proxy. This client assumes
  you have configured the daemon to support the NG protocol, where the
  RtpEngine can rewrite the SDP parameters (argument `--listen-ng`).
  """

  use GenServer

  require Logger

  defmodule State do
    @moduledoc false

    @doc false
    defstruct [
      socket: nil,
      address: nil,
      port: nil,
      pending: %{}
    ]
  end

  @type sdp :: String.t
  @type call_id :: String.t
  @type from_tag :: String.t
  @type to_tag :: String.t

  @type offer_opts :: [offer_option]
  @type ans_opts :: [answer_option]

  @type offer_option ::
    branch_option |
    flags_option |
    replace_option |
    direction_option |
    received_from_option |
    ice_option |
    transport_protocol_option |
    media_address_option |
    address_family_option |
    rtcp_mux_option |
    tos_option |
    dtls_option |
    sdes_option |
    record_call_option |
    metadata_option

  @type answer_option ::
    branch_option |
    flags_option |
    replace_option |
    received_from_option |
    ice_option |
    transport_protocol_option |
    media_address_option |
    address_family_option |
    rtcp_mux_option |
    tos_option |
    dtls_option |
    sdes_option |
    record_call_option |
    metadata_option

  @type branch_option :: {:branch, String.t}

  @type flags_option :: {:flags, [flag_option]}
  @type flag_option ::
    :sip_source_address |
    :trust_address |
    :symmetric |
    :asymmetric |
    :unidirectional |
    :strict_source |
    :media_handover |
    :reset |
    :port_latching |
    :record_call

  @type replace_option ::
    {:replace, [:origin | :session_connection]}

  @type direction_option ::
    {:direction,
        {String.t | :round_robin_calls, String.t | :round_robin_calls}}

  @type received_from_option ::
    {:received_from,
        {family :: :inet | :inet6, String.t} | :inet.ip_address()}

  @type ice_option ::
    {:ice, :remove | :force | :force_relay}

  @type transport_protocol_option ::
    {:transport_protocol, String.t}

  @type media_address_option ::
    {:media_address, String.t | :inet.ip_address()}

  @type address_family_option ::
    {:address_family, :inet | :inet6}

  @type rtcp_mux_option ::
    {:rtcp_mux, [:offer | :demux | :accept | :reject]}

  @type tos_option ::
    {:tos, integer}

  @type dtls_option ::
    {:dtls, false | :passive}

  @type sdes_option ::
    {:sdes, false | [sdes_flags]}
  @type sdes_flags ::
    :unencrypted_srtp |
    :unencrypted_srtcp |
    :unauthenticated_srtp |
    :encrypted_srtp |
    :encrypted_srtcp |
    :authenticated_srtp

  @type record_call_option ::
    {:record_call, boolean}

  @type metadata_option ::
    {:metadata, String.t}

  @type on_ping ::
    :ok | {:error, reason :: term}

  @type on_reply ::
    {:ok, sdp} |
    {:error, reason :: term}

  @type delete_options :: [delete_option]
  @type delete_option ::
    branch_option |
    to_tag_option |
    {:flags, [:fatal]} |
    {:delay, seconds :: integer}

  @type to_tag_option ::
    {:to_tag, String.t}

  @type on_delete ::
    :ok | {:error, reason :: term}

  @type list_opts :: [list_option]
  @type list_option ::
    {:limit, max_results :: integer}

  @type on_list ::
    {:ok, list :: term} | {:error, reason :: term}

  @type query_opts :: [query_option]
  @type query_option ::
    {:from_tag, String.t} |
    to_tag_option

  @type on_query ::
    {:ok, call_info :: term} | {:error, reason :: term}

  @doc """
  Starts the RtpEngine client.

  The `rtpengine_address` parameter is an URI in the form of
  `"udp://hostname:port"`, where the `hostname` and `port` are those of the
  RtpEngine instance to access. If `port` is omitted, the UDP port 2223 is
  assumed.
  """
  @spec start_link(String.t) :: GenServer.on_start
  def start_link(rtpengine_address) do
    uri = rtpengine_address |> URI.parse()

    if uri.scheme != "udp" do
      raise "invalid rtpengine uri scheme #{inspect uri.scheme}"
    end

    address = {uri.host, if(uri.port == nil, do: 2223, else: uri.port)}

    GenServer.start_link(__MODULE__, address, [name: __MODULE__])
  end

  @doc """
  Pings the RtpEngine service.
  """
  @spec ping(timeout :: integer) :: on_ping
  def ping(timeout \\ 10_000) do
    do_send(%{"command" => "ping"}, timeout)
  end

  defp do_send(message, timeout) do
    GenServer.call(__MODULE__, {:send, message, timeout}, :infinity)
  end

  @doc """
  Sends a SDP offer to RtpEngine proxy.

  `sdp` is the complete SDP body as string. `call_id` is the SIP Call-ID header
  value as string. `from_tag` is the SIP `From` header `tag` parameter as
  string.

  The `timeout` parameter indicates the time in milliseconds to wait for a
  RtpEngine response, the default is 10 seconds.

  Optional parameters are:

  * `:branch` is the topmost SIP `Via` header `branch` parameter as string.
    Used to additionally refine the matching logic between media streams and
    calls and call branches.
  * `:flags` is an atom list of:
    - `:sip_source_address` ignores any IP addresses given in the SDP body and
      use the source address of the received SIP message (given in
      `:received_from`) as default endpoint address. This was the default
      behaviour of older versions of RtpEngine and can still be made the
      default behaviour through the `--sip-source` CLI switch. Can be
      overridden through the `:media_address` key.
    - `:trust_address` does the opposite of `:sip_source_address`. This is the
      default behaviour unless the CLI switch `--sip-source` is active.
      Corresponds to the rtpproxy `r` flag.  Can be overridden through the
      `:media_address` key.
    - `:symmetric` corresponds to the rtpproxy `w` flag. Not used by RtpEngine
      as this is the default, unless `:asymmetric` is specified.
    - `:asymmetric` corresponds to the rtpproxy `a` flag. Advertises an RTP
      endpoint which uses asymmetric RTP, which disables learning of endpoint
      addresses (see below).
    - `:unidirectional` kernelizes also one-way rtp media.
    - `:strict_source` continues to inspect the source address and port of
      incoming packets after the learning phase and compare them with the
      endpoint address that has been learned before. If there's a mismatch, the
      packet will be dropped and not forwarded. Without this flag, RtpEngine
      will attempt to learn the correct endpoint address for every stream
      during the first few seconds after signalling by observing the source
      address and port of incoming packets (unless `:asymmetric` is specified).
      Afterwards, source address and port of incoming packets are normally
      ignored and packets are forwarded regardless of where they're coming
      from.
    - `:media_handover` is similar to the `:strict_source` option, but instead
      of dropping packets when the source address or port don't match, the
      endpoint address will be re-learned and moved to the new address. This
      allows endpoint addresses to change on the fly without going through
      signalling again. Note that this opens a security hole and potentially
      allows RTP streams to be hijacked, either partly or in whole.
    - `:reset` causes RtpEngine to un-learn certain aspects of the RTP
      endpoints involved, such as support for ICE or support for SRTP. For
      example, if `ice: :force` is given, then RtpEngine will initially offer
      ICE to the remote endpoint. However, if a subsequent answer from that
      same endpoint indicates that it doesn't support ICE, then no more ICE
      offers will be made towards that endpoint, even if `ice: :force` is still
      specified. With the reset flag given, this aspect will be un-learned and
      RtpEngine will again offer ICE to this endpoint. This flag is valid only
      in an offer message and is useful when the call has been transferred to a
      new endpoint without change of `From` or `To` tags.
    - `:port_latching` forces RtpEngine to retain its local ports during a
      signalling exchange even when the remote endpoint changes its port.
    - `:record_call` is identical to setting `record_call: true` (see below).
  * `:replace` is similar to the flags list. Controls which parts of the SDP
    body should be rewritten. Contains zero or more of:
    - `:origin` replaces the address found in the origin (`o=`) line of the SDP
      body. Corresponds to rtpproxy `o` flag.
    - `:session_connection` replaces the address found in the session-level
      connection (`c=`) line of the SDP body. Corresponds to rtpproxy `c` flag.
  * `:direction` contains a tuple of two strings and corresponds to the rtpproxy
    `e` and `i` flags. Each element must correspond to one of the named logical
    interfaces configured on the command line (through `--interface`). For
    example, if there is one logical interface named `pub` and another one
    named `priv`, then if side A (originator of the message) is considered to
    be on the private network and side B (destination of the message) on the
    public network, then that would be rendered as `direction: {"priv",
    "pub"}`. This only needs to be done for an initial offer; for the answer
    and any subsequent offers (between the same endpoints) RtpEngine will
    remember the selected network interface. A direction keyword is
    `:round_robin_calls`. If this is specified, a round robin algorithm runs
    for choosing the logical interface for the current stream (e.g. audio,
    video). The algorithm checks that all local interfaces of the tried
    logical interface have free ports for call streams. If a logical interface
    fails the check, the next one is tried. If there is no logical interface
    found with this property, it fallbacks to the default behaviour (e.g.
    return first logical interface in `--interface` list even if no free ports
    are available). The attribute is ignored for answers because the logical
    interface was already selected at offers. Note that naming an interface as
    `round-robin-calls` and trying to select it using direction *will run the
    above algorithm*!
  * `:received_from` contains a tuple of two elements where the first element
    denotes the address family (`:inet` or `:inet6`) and the second element is
    the SIP message's source address itself. It can be also the SIP message's
    source IP address tuple as specified in `:inet.ip_address()`, and in this
    case the family is obtained automatically. Used if SDP addresses are
    neither trusted (through the flag `:sip_source_address` or the command line
    argument `--sip-source`) nor the `:media_address` key is present.
  * `:ice` contains either `:remove`, `:force` or `:force_relay`. With
    `:remove`, any ICE attributes are stripped from the SDP body. With
    `:force`, ICE attributes are first stripped, then new attributes are
    generated and inserted, which leaves the media proxy as the only ICE
    candidate. The default behavior (no ICE key present at all) is: if no ICE
    attributes are present, a new set is generated and the media proxy lists
    itself as ICE candidate; otherwise, the media proxy inserts itself as a
    low-priority candidate. With `:force_relay`, existing ICE candidates are
    left in place except relay type candidates, and RtpEngine inserts itself as
    a relay candidate. It will also leave SDP `c=` and `m=` lines unchanged.
    This flag operates independently of the replace flags.
  * `:transport_protocol` rewrites the transport protocol specified in the SDP
    body. The media proxy expects to receive this protocol on the allocated
    ports, and will talk this protocol when sending packets out. Translation
    between different transport protocols will happen as necessary. Valid
    values are: `"RTP/AVP"`, `"RTP/AVPF"`, `"RTP/SAVP"`, `"RTP/SAVPF"`.
  * `:media_address` can be used to override both the addresses present in the
    SDP body and the received from address. Contains either an IPv4 or an IPv6
    address, expressed as simple string or one of the `:inet.ip_address()`
    tuples. The format must be dotted-quad notation for IPv4 or RFC 5952
    notation for IPv6. It's up to the RTP proxy to determine the address family
    type.
  * `:address_family` is either `:inet` or `:inet6` to select the primary
    address family in the substituted SDP body. The default is to auto-detect
    the address family if possible (if the recieving end is known already) or
    otherwise to leave it unchanged.
  * `:rtcp_mux` is a list of atoms controlling the behaviour regarding rtcp-mux
    (multiplexing RTP and RTCP on a single port, RFC 5761). The default
    behaviour is to go along with the client's preference. The list can contain
    zero of more of the following atoms. Note that some of them are mutually
    exclusive.
    - `:offer` instructs RtpEngine to always offer rtcp-mux, even if the client
      itself doesn't offer it.
    - `:demux` don't offer it to the other side if the client is offering
      rtcp-mux, but accept it back to the offering client.
    - `:accept` instructs RtpEngine to accept rtcp-mux and also offer it to the
      other side if it has been offered.
    - `:reject` rejects rtcp-mux if it has been offered. Can be used together
      with `:offer` to achieve the opposite effect of `:demux`.
  * `:tos` contains an integer representing the TOS value used in outgoing RTP
    packets of all RTP streams in all directions. If a negative value is used,
    the previously used TOS value is left unchanged. If this key is not present
    or its value is too large (256 or more), then the TOS value is reverted to
    the default (as per `--tos` command line argument).
  * `:dtls` contains either `false` or `:passive`, and influences the behaviour
    of DTLS-SRTP. Their meanings are:
    - `false` prevents RtpEngine from offering or acceping DTLS-SRTP when
      otherwise it would. The default is to offer DTLS-SRTP when encryption is
      desired and to favour it over SDES when accepting an offer.
    - `:passive` instructs RtpEngine to prefer the passive (i.e. server) role
      for the DTLS handshake. The default is to take the active (client) role
      if possible. This is useful in cases where the SRTP endpoint isn't able
      to receive or process the DTLS handshake packets, for example when it's
      behind NAT or needs to finish ICE processing first.
  * `:sdes` is a list of options controlling the behaviour regarding SDES. The
    default is to offer SDES without any session parameters when encryption is
    desired, and to accept it when DTLS-SRTP is unavailable. If two SDES
    endpoints are connected to each other, then the default is to offer SDES
    with the same options as were received from the other endpoint.
    - `false` prevents RtpEngine from offering SDES, leaving DTLS-SRTP as the
      other option.
    - `:unencrypted_srtp`, `:unencrypted_srtcp` and `:unauthenticated_srtp`
      enable the respective SDES session parameter (see section 6.3 or RFC
      4568). The default is to copy these options from the offering client, or
      not to have them enabled if SDES wasn't offered.
    - `:encrypted_srtp`, `:encrypted_srtcp` and `:authenticated_srtp` negates
      the respective option. This is useful if one of the session parameters
      was offered by an SDES endpoint, but it should not be offered on the far
      side if this endpoint also speaks SDES.
  * `:record_call` is a boolean flag telling whether to record the call to PCAP
    files. If the call is recorded, it will generate PCAP files for each stream
    and a metadata file for each call. Note that RtpEngine will not force
    itself into the media path, and other flags like `ice: :force` may be
    necessary to ensure the call is recorded. See the `--recording-dir`
    RtpEngine argument. Enabling call recording via this option has the same
    effect as doing it separately via the start recording message, except that
    this option guarantees that the entirety of the call gets recorded,
    including all details such as SDP bodies passing through RtpEngine.
  * `:metadata` is a generic metadata string. The metadata will be written to
    the bottom of metadata files within `/path/to/recording_dir/metadata/`.
    This can be used to record additional information about recorded calls.
    `:metadata` values passed in through subsequent messages will overwrite
    previous metadata values. See the `--recording-dir` RtpEngine argument.
  """
  @spec offer(sdp, call_id, from_tag, offer_opts, timeout) :: on_reply
  def offer(sdp, call_id, from_tag, opts \\ [], timeout \\ 10_000)
      when is_list(opts) and is_integer(timeout) do
    message = %{
      "command" => "offer",
      "sdp" => sdp,
      "call-id" => call_id,
      "from-tag" => from_tag
    }

    allowed = [
      :branch,
      :flags,
      :replace,
      :direction,
      :received_from,
      :ice,
      :transport_protocol,
      :media_address,
      :address_family,
      :rtcp_mux,
      :tos,
      :dtls,
      :sdes,
      :record_call,
      :metadata
    ]

    message =
      message
      |> Map.merge(translate_options(opts, allowed))

    do_send(message, timeout)
  end

  @doc """
  Sends a SDP answer to RtpEngine proxy.

  `sdp` is the complete SDP body as string. `call_id` is the SIP Call-ID header
  value as string. `from_tag` is the SIP `From` header `tag` parameter as
  string. `to_tag` is the SIP `To` header `tag` parameter as string.

  The `timeout` parameter indicates the time in milliseconds to wait for a
  RtpEngine response, the default is 10 seconds.
 
  The optional parameters are identical to the `offer/5` function, except that
  the `:direction` does not make sense in the answer message.
  """
  @spec answer(sdp, call_id, from_tag, to_tag, ans_opts, timeout) :: on_reply
  def answer(sdp, call_id, from_tag, to_tag, opts \\ [], timeout \\ 10_000)
      when is_list(opts) and is_integer(timeout) do
    message = %{
      "command" => "answer",
      "sdp" => sdp,
      "call-id" => call_id,
      "from-tag" => from_tag,
      "to-tag" => to_tag
    }

    allowed = [
      :branch,
      :flags,
      :replace,
      :received_from,
      :ice,
      :transport_protocol,
      :media_address,
      :address_family,
      :rtcp_mux,
      :tos,
      :dtls,
      :sdes,
      :record_call,
      :metadata
    ]

    message =
      message
      |> Map.merge(translate_options(opts, allowed))

    do_send(message, timeout)
  end

  @doc """
  Deletes a call created by the `offer/5` and `answer/6` functions.

  `call_id` is the SIP Call-ID header value as string. `from_tag` is the SIP
  `From` header `tag` parameter as string.

  The `timeout` parameter indicates the time in milliseconds to wait for a
  RtpEngine response, the default is 10 seconds.

  Optional parameters are:

  * `:to_tag` is the SIP `To` header `tag` parameter as string. Used to
    additionally refine the matching logic between media streams and calls and
    call branches.
  * `:branch` is the topmost SIP `Via` header `branch` parameter as string.
    Used to additionally refine the matching logic between media streams and
    calls and call branches.
  * `:flags` specifies a list of flags to turn on:
    - `:fatal` specifies that any non-syntactical error encountered when
      deleting the stream (such as unknown `call_id`) shall result in an error.
      The default is to log warnings and return `:ok`.
  * `:delay` specifies an integer representing the time in seconds in which the
    call should be deleted. If zero, the call will be immediately deleted.
  """
  @spec delete(call_id, from_tag, delete_options, timeout) :: on_delete
  def delete(call_id, from_tag, opts \\ [], timeout \\ 10_000)
      when is_list(opts) and is_integer(timeout) do
    message = %{
      "command" => "delete",
      "call-id" => call_id,
      "from-tag" => from_tag
    }

    message =
      message
      |> Map.merge(translate_delete_options(opts))

    do_send(message, timeout)
  end

  @doc """
  Lists the currently active call-ids.

  You may specify an optional argument `:limit` that indicates the maximum
  number of results in the reply, otherwise the default is 32.

  The `timeout` parameter indicates the time in milliseconds to wait for a
  RtpEngine response, the default is 10 seconds.
  """
  @spec list(list_opts, timeout) :: on_list
  def list(opts \\ [], timeout \\ 10_000)
      when is_list(opts) and is_integer(timeout) do
    message = %{"command" => "list"}

    message =
      if Keyword.has_key?(opts, :limit) do
        Map.put(message, "limit", opts[:limit])
      else
        message
      end

    do_send(message, timeout)
  end

  @doc """
  Queries a specific active call.

  `call_id` is the SIP `Call-ID` header value as string.
  
  Among the optional parameters, you may specify the `from_tag` as being the
  SIP `From` header `tag` parameter as string, and the `to_tag` as the SIP `To`
  header `tag` parameter as string.
  """
  @spec query(call_id, query_opts, timeout) :: on_query
  def query(call_id, opts \\ [], timeout \\ 10_000) do
    message = %{
      "command" => "query",
      "call-id" => call_id
    }

    message =
      if Keyword.has_key?(opts, :from_tag) do
        Map.put(message, "from-tag", opts[:from_tag])
      else
        message
      end

    message =
      if Keyword.has_key?(opts, :to_tag) do
        Map.put(message, "to-tag", opts[:to_tag])
      else
        message
      end

    do_send(message, timeout)
  end

  @doc false
  def init({host, port}) do
    case Socket.Address.for(host, :inet) do
      {:ok, [rtpengine_address|_]} ->
        options = [as: :binary, mode: :active, local: [address: "127.0.0.1"]]
        socket = Socket.UDP.open!(options)

        {:ok, {address, listen_port}} = :inet.sockname(socket)
        Logger.info("#{inspect self()} started rtpengine plug " <>
                    "#{:inet.ntoa(address)}:#{listen_port}/udp for " <>
                    "rtpengine-ng #{:inet.ntoa(rtpengine_address)}:" <>
                    "#{port}/udp")
 
        {:ok, %State{socket: socket, address: rtpengine_address, port: port}}
      {:error, reason} ->
        Logger.warn("#{inspect self()} rtpengine plug error for " <>
                    "#{host}:#{port}: #{inspect reason}")
        {:stop, reason}
    end
  end

  @doc false
  def handle_info({:udp, _socket, _ip, _from_port, packet},
      %State{pending: pending} = state) do
    [cookie, data] = String.split(packet, " ", parts: 2)

    %{^cookie => {timer, client}} = pending

    result =
      case Bento.decode(data) do
        {:error, reason} ->
          Logger.warn("invalid rtpengine message: #{inspect data}")
          {:error, reason}
        {:ok, data} ->
          data
      end

    GenServer.reply(client, parse_result(result))
    Process.cancel_timer(timer)
    {:noreply, %{state | pending: pending |> Map.delete(cookie)}}
  end

  def handle_info({:timeout, cookie}, %State{pending: pending} = state) do
    %{^cookie => {_timer, client}} = pending
    GenServer.reply(client, {:error, :timeout})
    {:noreply, %{state | pending: pending |> Map.delete(cookie)}}
  end

  def handle_info(msg, state), do: super(msg, state)

  @doc false
  def handle_call({:send, data, timeout}, from,
      %State{pending: pending} = state) do
    %{socket: socket, address: address, port: port} = state

    cookie = pending |> new_cookie()
    message = [cookie, " ", Bento.encode!(data)]

    state =
      case Socket.Datagram.send(socket, message, {address, port}) do
        :ok ->
          timer = self() |> Process.send_after({:timeout, cookie}, timeout)
          %{state | pending: pending |> Map.put(cookie, {timer, from})}
        {:error, reason} ->
          Logger.warn("#{inspect self()} rtpengine plug error: " <>
                      "#{inspect reason}")
          state
      end

    {:noreply, state}
  end

  def handle_call(msg, from, state), do: super(msg, from, state)

  defp new_cookie(pending) do
    cookie =
      :crypto.strong_rand_bytes(8)
      |> Base.url_encode64(padding: false)

    if not Map.has_key?(pending, cookie) do
      cookie
    else
      pending |> new_cookie()
    end
  end

  defp parse_result(result) do
    case result do
      %{"result" => "ok", "sdp" => sdp} ->
        {:ok, sdp}
      %{"result" => "ok", "calls" => calls} ->
        {:ok, calls}
      %{"result" => "ok", "created" => created, "last signal" => last_signal,
        "tags" => tags, "totals" => totals} ->
        {:ok, %{
          created: created,
          last_signal: last_signal,
          tags: tags,
          totals: totals
        }}
      %{"result" => "ok", "warning" => reason} ->
        Logger.warn("delete operation resulted in #{inspect reason}")
        :ok
      %{"result" => "ok"} ->
        :ok
      %{"result" => "pong"} ->
        :ok
      %{"result" => "error", "error-reason" => reason} ->
        {:error, reason}
    end
  end

  defp translate_options(options, allowed),
    do: translate_options(options, allowed, [])

  defp translate_options([], _, options), do: Map.new(options)
  defp translate_options([{k, v} | t], allowed, options) do
    if not Enum.member?(allowed, k) do
      raise ArgumentError, "invalid option #{inspect k}"
    end
    translate_options(t, allowed, [translate_option(k, v) | options])
  end

  defp translate_option(:branch, value) when is_binary(value),
    do: {"via-branch", value}

  defp translate_option(:flags, flags),
    do: {"flags", translate_flags(flags)}

  defp translate_option(:replace, options),
    do: {"replace", translate_replace_options(options)}

  defp translate_option(:direction, {:round_robin_calls, :round_robin_calls}),
    do: {"direction", ["round-robin-calls", "round-robin-calls"]}
  defp translate_option(:direction, {external, :round_robin_calls})
    when is_binary(external),
    do: {"direction", [external, "round-robin-calls"]}
  defp translate_option(:direction, {:round_robin_calls, internal})
    when is_binary(internal),
    do: {"direction", ["round-robin-calls", internal]}
  defp translate_option(:direction, {external, internal})
    when is_binary(external) and is_binary(internal),
    do: {"direction", [external, internal]}

  defp translate_option(:received_from, {family, source_address})
      when is_binary(source_address) do
    family =
      case family do
        :inet -> "IP4"
        :inet6 -> "IP6"
      end

    {"received from", [family, source_address]}
  end

  defp translate_option(:received_from, source_address)
      when is_tuple(source_address) do
    family =
      case source_address do
        {_, _, _, _} -> "IP4"
        {_, _, _, _, _, _, _, _} -> "IP6"
      end

    {"received from", [family, Kernel.to_string(:inet.ntoa(source_address))]}
  end

  defp translate_option(:ICE, :remove), do: {"ICE", "remove"}
  defp translate_option(:ICE, :force), do: {"ICE", "force"}
  defp translate_option(:ICE, :force_relay), do: {"ICE", "force-relay"}

  defp translate_option(:transport_protocol, transport_protocol) do
    transport_protocol =
      case transport_protocol do
        "RTP/AVP" -> transport_protocol
        "RTP/AVPF" -> transport_protocol
        "RTP/SAVP" -> transport_protocol
        "RTP/SAVPF" -> transport_protocol
      end

    {"transport protocol", transport_protocol}
  end

  defp translate_option(:media_address, media_address)
      when is_binary(media_address) do
    {"media address", media_address}
  end

  defp translate_option(:media_address, media_address)
      when is_tuple(media_address) do
    media_address =
      case media_address do
        {_, _, _, _} -> :inet.ntoa(media_address)
        {_, _, _, _, _, _, _, _} -> :inet.ntoa(media_address)
      end

    {"media address", Kernel.to_string(media_address)}
  end

  defp translate_option(:address_family, family) do
    family =
      case family do
        :inet -> "IP4"
        :inet6 -> "IP6"
      end
      
    {"address family", family}
  end

  defp translate_option(:rtcp_mux, options),
    do: {"rtcp-mux", translate_rtcpmux_options(options)}

  defp translate_option(:tos, tos) when is_integer(tos),
    do: {"TOS", tos}

  defp translate_option(:dtls, false), do: {"DTLS", "off"}
  defp translate_option(:dtls, :passive), do: {"DTLS", "passive"}

  defp translate_option(:sdes, options),
    do: {"SDES", translate_sdes_options(options)}

  defp translate_option(:record_call, true),
    do: {"record call", "on"}
  defp translate_option(:record_call, false),
    do: {"record call", "off"}

  defp translate_option(:metadata, metadata) when is_binary(metadata),
    do: {"metadata", metadata}

  defp translate_flags(flags), do: translate_flags(flags, [])

  defp translate_flags([], flags), do: flags
  defp translate_flags([h | t], flags),
    do: translate_flags(t, [translate_flag(h) | flags])

  defp translate_flag(:sip_source_address), do: "SIP source address"
  defp translate_flag(:trust_address), do: "trust address"
  defp translate_flag(:symmetric), do: "symmetric"
  defp translate_flag(:asymmetric), do: "asymmetric"
  defp translate_flag(:unidirectional), do: "unidirectional"
  defp translate_flag(:strict_source), do: "strict source"
  defp translate_flag(:media_handover), do: "media handover"
  defp translate_flag(:reset), do: "reset"
  defp translate_flag(:port_latching), do: "port latching"
  defp translate_flag(:record_call), do: "record call"

  defp translate_replace_options(options),
    do: translate_replace_options(options, [])

  defp translate_replace_options([], options), do: options
  defp translate_replace_options([h | t], options),
    do: translate_replace_options(t, [translate_replace_option(h) | options])

  defp translate_replace_option(:origin), do: "origin"
  defp translate_replace_option(:session_connection), do: "session connection"

  defp translate_rtcpmux_options(options),
    do: translate_rtcpmux_options(options, [])

  defp translate_rtcpmux_options([], options), do: options
  defp translate_rtcpmux_options([h | t], options),
    do: translate_rtcpmux_options(t, [translate_rtcpmux_option(h) | options])

  defp translate_rtcpmux_option(:offer), do: "offer"
  defp translate_rtcpmux_option(:demux), do: "demux"
  defp translate_rtcpmux_option(:accept), do: "accept"
  defp translate_rtcpmux_option(:reject), do: "reject"

  defp translate_sdes_options(false),
    do: ["off"]
  defp translate_sdes_options(options) when is_list(options),
    do: translate_sdes_options(options, [])

  defp translate_sdes_options([], options), do: options
  defp translate_sdes_options([h | t], options),
    do: translate_sdes_options(t, [translate_sdes_option(h) | options])

  defp translate_sdes_option(value) when is_atom(value),
    do: Kernel.to_string(value)

  defp translate_delete_options(options),
    do: translate_delete_options(options, [])

  defp translate_delete_options([], options), do: Map.new(options)
  defp translate_delete_options([{k, v} | t], options),
    do: translate_delete_options(t, [translate_delete_option(k, v) | options])

  defp translate_delete_option(:to_tag, to_tag) when is_binary(to_tag),
    do: {"to-tag", to_tag}

  defp translate_delete_option(:branch, branch) when is_binary(branch),
    do: {"via-branch", branch}

  defp translate_delete_option(:flags, flags),
    do: {"flags", translate_delete_flags(flags)}

  defp translate_delete_option(:delay, seconds) when is_integer(seconds),
    do: {"delete delay", seconds}

  defp translate_delete_flags(flags), do: translate_delete_flags(flags, [])

  defp translate_delete_flags([], flags), do: flags
  defp translate_delete_flags([h | t], flags),
    do: translate_delete_flags(t, [translate_delete_flag(h) | flags])

  defp translate_delete_flag(:fatal), do: "fatal"
end
