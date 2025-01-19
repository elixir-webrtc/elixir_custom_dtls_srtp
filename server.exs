defmodule CustomDTLSServer do
  def run() do
    options = [
      cb_info: {CustomUDPTransport, :udp, :udp_closed, :udp_error},
      log_level: :debug,
      protocol: :dtls,
      certs_keys: [
        %{certfile: "cert.pm", keyfile: "key.pem"}
      ]
    ]

    {:ok, socket} = :ssl.listen(4001, options)
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

:ssl.start()

CustomDTLSServer.run()

receive do
  :ok -> :ok
end
