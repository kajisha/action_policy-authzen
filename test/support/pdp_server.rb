require "socket"

module PDPServer
  def with_pdp(responses, base_path: "", **options)
    server = TCPServer.new("127.0.0.1", 0)
    origin = "http://127.0.0.1:#{server.addr[1]}"
    base_url = "#{origin}#{base_path}"
    requests = []
    thread = Thread.new do
      socket = nil
      responses.each do |reply|
        socket = server.accept
        request_line = socket.gets
        headers = {}
        while (line = socket.gets) && line != "\r\n"
          key, value = line.split(":", 2)
          headers[key.downcase] = value.strip
        end
        body = socket.read(headers.fetch("content-length", "0").to_i)
        requests << {line: request_line, headers: headers, body: body.empty? ? nil : JSON.parse(body)}
        response = reply.respond_to?(:call) ? reply.call(base_url, requests.last) : reply
        payload = JSON.generate(response.fetch(:body))
        content_type = response.fetch(:content_type, "application/json")
        socket.write("HTTP/1.1 #{response.fetch(:status, 200)} Test\r\nContent-Type: #{content_type}\r\nContent-Length: #{payload.bytesize}\r\nConnection: close\r\n\r\n#{payload}")
        socket.close
      end
    ensure
      socket&.close
    end
    yield ActionPolicy::AuthZEN::Client.new(base_url: base_url, allow_http: true, **options), requests, base_url
  ensure
    thread&.kill
    thread&.join
    server&.close
  end
end
