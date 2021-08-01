require 'socket'
require 'ostruct'

class Fuzzer
    def initialize(host, port, user, passwd, stopafter, delay, length, cyclic)
        @error = Array.new
        @buffer = Array.new
        @count = 10
        @commands = %w(CWD DELE MDTM PASV MKD NLST PORT PWD RMD RNFR RNTO SITE SIZE ACCT APPE CDUP HELP MODE NOOP REIN STAT STOU STRU SYST ABOR TYPE)
        @host = host
        @user = user unless user.nil?
        @passwd = passwd unless passwd.nil?
        @delay = delay.nil? ? 1 : delay.to_f 
        @stopafter = stopafter.nil? ? 1 : stopafter.to_i
        @port = port.nil? ? 21 : port.to_i
        @length = length.nil? ? 2000 : length.to_i
        @socket = nil
        @cyclic = cyclic
    end

    def cyclic_pattern()
        buffer = ""
        while true
            for i in 0..25 do
                for j in 0..25 do
                    for k in 0..9 do
                        buffer += (65 + i).chr + (97 + j).chr  + (48 + k).chr
                        if buffer.length >= @length
                            return buffer[0..@length - 1]
                        end
                    end
                end
            end
        end
    end

    def create_cyclic_buffer()
        pattern = self.cyclic_pattern
        while @count <= @length
            @buffer.push(pattern[0..@count - 1])
            @count += 10
        end
    end

    def create_buffer()
        if @cyclic
            self.create_cyclic_buffer
            return
        end
        while @buffer.length < @length / 10
            @buffer.push("A" * @count)
            @count += 10
        end        
    end

    def add_error(command, length)
        error = OpenStruct.new
        error.command = command
        error.length = length
        @error.push error
    end

    def send_command(command, buf, log = false)
        send = ""
        if buf.nil?
            send = "#{command}\r\n"
            @socket.write send 
        else
            send = "#{command} #{buf}\r\n"
            @socket.write send
        end
        data = @socket.gets 

        unless !log
            print send + " " + data
        end
    end

    def fuzzer_loop_without_command(log = false)
        for buf in @buffer do
            sleep @delay
            begin
                @socket = TCPSocket.new @host, @port
                data = @socket.gets 
                unless !log
                    print data
                end
            rescue => exception
                print "Connection to server #{@host} failed\n"
                return
            end

            begin
                print "[*] Fuzzing without command with length #{buf.length.to_s}\n"
                send_command(buf, nil, log)
                send_command("QUIT", nil, log)
                @socket.close
            rescue => exception
                print "Crash String: Without command with length of #{buf.length.to_s}\n"
                add_error("NONE", buf.length.to_s)
                if @stopafter - 1 == 0
                    print "Program not responding exiting now"
                    return
                end
                @stopafter -= 1
            end
        end
    end

    def fuzzer_loop_pre_auth(log = false)
        for buf in @buffer do
            sleep @delay
            begin
                @socket = TCPSocket.new @host, @port
                data = @socket.gets
                unless !log
                    print data
                end
            rescue => exception
                print "Connection to server #{@host} failed\n"
            end
            begin
                print "[*] Fuzzing USER with length #{buf.length.to_s}\n"
                send_command("USER", buf, log)
                send_command("QUIT", nil, log)
                @socket.close
            rescue => exception
                print "Crash String: command USER with length of #{buf.length.to_s}\n"
                add_error("NONE", buf.length.to_s)
                if @stopafter - 1 == 0
                    print "Program not responding exiting now"
                    return
                end
                @stopafter -= 1         
            end
        end

        if @user.nil?
            return
        end

        for buf in @buffer do
            sleep @delay
            begin
                @socket = Socket.new Socket::AF_INET, Socket::SOCK_STREAM
                @socket.connect Socket.pack_sockaddr_in(@port, @host)
                data = @socket.gets
                unless !log
                    print data
                end
            rescue => exception
                print "Connection to server #{@host} failed\n"
                return
            end
            begin
                print "[*] Fuzzing PASS with length #{buf.length.to_s}\n"
                send_command("USER", @user, log)
                send_command("PASS", buf, log)
                send_command("QUIT", nil, log)
                @socket.close
            rescue => exception
                print "Crash String: command PASS with length of #{buf.length.to_s}\n"
                add_error("NONE", buf.length.to_s)
                if @stopafter - 1 == 0
                    print "Program not responding exiting now"
                    return
                end
                @stopafter -= 1
            end            
        end
    end

    def fuzzer_loop_post_auth(log = false)
        for command in @commands do
            for buf in @buffer do
                sleep @delay
                begin
                    @socket = Socket.new Socket::AF_INET, Socket::SOCK_STREAM
                    @socket.connect Socket.pack_sockaddr_in(@port, @host)
                    data = @socket.gets
                    unless !log
                        print data
                    end
                rescue => exception
                    print "Connection to server #{@host} failed\n"
                    return
                end
                begin
                    print "[*] Fuzzing #{command} with length #{buf.length.to_s}\n"
                    send_command("USER", @user, log)
                    send_command("PASS", @passwd, log)
                    send_command(command, buf, log)
                    send_command("QUIT", nil, log)
                    @socket.close
                rescue => exception
                    print "Crash String: command #{command} with length of #{buf.length.to_s}\n"
                    add_error(command, buf.length.to_s)
                    if @stopafter - 1 == 0
                        print "Program not responding exiting now"
                        return
                    end
                    @stopafter -= 1
                end 
            end
        end
    end
end
