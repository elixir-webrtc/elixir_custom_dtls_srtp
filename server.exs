defmodule CustomDTLSServer do
  def run(protection_profile) do
    options = [
      cb_info: {CustomUDPTransport, :udp, :udp_closed, :udp_error},
      log_level: :debug,
      protocol: :dtls,
      certs_keys: [
        %{certfile: "cert.pem", keyfile: "key.pem"}
      ],
      use_srtp: %{protection_profiles: [<<protection_profile::16>>]}
    ]

    # {:ok, socket} = :gen_udp.open(4444) # can't use plain UDP socket
    {:ok, socket} = :ssl.listen(4444, options)
    {:ok, socket} = :ssl.transport_accept(socket)
    :ssl.handshake(socket)
  end
end

defmodule CustomUDPTransport do
  def open(port, opts) do
    :gen_udp.open(port, opts)
  end

  def controlling_process(socket, pid) do
    :gen_udp.controlling_process(socket, pid)
  end

  def setopts(socket, opts) do
    :inet.setopts(socket, opts)
  end

  def getopts(socket, opts) do
    :inet.getopts(socket, opts)
  end

  def port(socket) do
    :inet.port(socket)
  end

  def send(socket, host, port, packet) do
    :gen_udp.send(socket, host, port, packet)
  end

  def recv(socket, length, timeout) do
    :gen_udp.recv(socket, length, timeout)
  end

  def close(socket) do
    :gen_udp.close(socket)
  end
end

defmodule KeyMaterial do
  def export(socket, protection_profile) do
    {master_key_len, master_salt_len} = get_length(protection_profile)

    # See RFC 5764 sec. 4.2 for label and parsing explanation
    {:ok, key_materials} =
      :ssl.export_key_materials(socket, ["EXTRACTOR-dtls_srtp"], [:no_context], [
        2 * (master_key_len + master_salt_len)
      ])

    <<client_master_key::binary-size(master_key_len),
      server_master_key::binary-size(master_key_len),
      client_master_salt::binary-size(master_salt_len),
      server_master_salt::binary-size(master_salt_len)>> =
      key_materials

    client_key_material = <<client_master_key::binary, client_master_salt::binary>>
    server_key_material = <<server_master_key::binary, server_master_salt::binary>>

    {client_key_material, server_key_material}
  end

  # RFC 3711 sec. 8.2
  def get_length(0x01), do: {16, 14}
  def get_length(0x02), do: {16, 14}
  # RFC 7714 sec. 12
  def get_length(0x07), do: {16, 12}
  def get_length(0x08), do: {32, 12}
end

:ssl.start()

protection_profile = 0x01

{:ok, socket} = CustomDTLSServer.run(protection_profile)

{client_key_material, server_key_material} = KeyMaterial.export(socket, protection_profile)
dbg({byte_size(client_key_material), client_key_material})
dbg({byte_size(server_key_material), server_key_material})

:ok = :ssl.send(socket, "hello")

receive do
  :ok -> :ok
  other -> dbg(other)
end
