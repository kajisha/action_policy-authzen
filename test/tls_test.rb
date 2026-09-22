require_relative "test_helper"
require "socket"
require "tempfile"
require "openssl"

class TLSTest < Minitest::Test
  def with_tls_server(hostname: "127.0.0.1")
    key = OpenSSL::PKey::RSA.new(2048)
    certificate = OpenSSL::X509::Certificate.new
    certificate.version = 2
    certificate.serial = 1
    certificate.subject = OpenSSL::X509::Name.parse("/CN=AuthZEN local test")
    certificate.issuer = certificate.subject
    certificate.public_key = key.public_key
    certificate.not_before = Time.now - 60
    certificate.not_after = Time.now + 3600
    factory = OpenSSL::X509::ExtensionFactory.new
    factory.subject_certificate = certificate
    factory.issuer_certificate = certificate
    certificate.add_extension(factory.create_extension("basicConstraints", "CA:TRUE", true))
    certificate.add_extension(factory.create_extension("keyUsage", "keyCertSign,digitalSignature,keyEncipherment", true))
    certificate.add_extension(factory.create_extension("subjectAltName", "IP:#{hostname}"))
    certificate.sign(key, OpenSSL::Digest::SHA256.new)
    ca = Tempfile.new("authzen-test-ca")
    ca.write(certificate.to_pem)
    ca.flush
    tcp = TCPServer.new("127.0.0.1", 0)
    context = OpenSSL::SSL::SSLContext.new
    context.cert = certificate
    context.key = key
    server = OpenSSL::SSL::SSLServer.new(tcp, context)
    thread = Thread.new do
      socket = server.accept
      headers = {}
      next unless socket.gets
      while (line = socket.gets) && line != "\r\n"
        key_name, value = line.split(":", 2)
        headers[key_name.downcase] = value.strip
      end
      socket.read(headers.fetch("content-length").to_i)
      body = '{"decision":true}'
      socket.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n#{body}")
    rescue OpenSSL::SSL::SSLError
      nil
    ensure
      socket&.close
    end
    yield "https://127.0.0.1:#{tcp.addr[1]}", ca.path
  ensure
    thread&.kill
    thread&.join
    tcp&.close
    ca&.close!
  end

  def request(client)
    client.allowed?(subject: {type: "user", id: "anne"}, action: "reader", resource: {type: "document", id: "one"})
  end

  def test_https_with_trusted_ca
    with_tls_server do |base_url, ca_file|
      assert request(ActionPolicy::AuthZEN::Client.new(base_url: base_url, ca_file: ca_file))
    end
  end

  def test_plain_http_requires_explicit_local_testing_opt_in
    assert_raises(ArgumentError) do
      ActionPolicy::AuthZEN::Client.new(base_url: "http://127.0.0.1:18080")
    end
    assert_raises(ArgumentError) do
      ActionPolicy::AuthZEN::Client.discover(base_url: "http://127.0.0.1:18080")
    end
  end

  def test_untrusted_certificate_fails_closed
    with_tls_server do |base_url, _ca_file|
      error = assert_raises(ActionPolicy::AuthZEN::TransportError) do
        request(ActionPolicy::AuthZEN::Client.new(base_url: base_url))
      end
      assert_kind_of OpenSSL::SSL::SSLError, error.cause
    end
  end

  def test_hostname_mismatch_fails_even_with_trusted_ca
    with_tls_server(hostname: "127.0.0.2") do |base_url, ca_file|
      assert_raises(ActionPolicy::AuthZEN::TransportError) do
        request(ActionPolicy::AuthZEN::Client.new(base_url: base_url, ca_file: ca_file))
      end
    end
  end
end
