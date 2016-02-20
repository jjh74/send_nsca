module SendNsca

  STATUS_OK = 0 
  STATUS_WARNING = 1
  STATUS_CRITICAL = 2
  STATUS_UNKNOWN = 3

  class NscaConnection

    require 'socket'      # Sockets are in standard library
    
    # todo: replace timeout with a better method of handling communication timeouts.
    require 'timeout'
    require 'zlib'
    require 'rubygems'
    require 'mcrypt'
    
    # params for connecting to the nsca/nagios server
    attr_accessor  :nscahost
    attr_accessor  :port
    
    #  connection status and error if one found
    attr_reader   :connected
    attr_reader   :error
    
    # read from the nsca/nagios server
    attr_accessor  :iv_and_timestamp

    # converted from :iv_and_timestamp
    attr_accessor  :iv_and_timestamp_str
    attr_accessor  :iv_string
    attr_accessor  :iv
    attr_accessor  :password
    attr_accessor  :encryption_mode

    attr_accessor  :timestring    
    attr_accessor  :timestamp_hex
    attr_accessor  :timestamp

    # status data to send to nagios
    # Currently all 4 are required, meaning we only support 'service' passive checkins. 
    # hostcheck: leave :service empty --> host check
    attr_accessor  :hostname
    attr_accessor  :service
    attr_accessor  :return_code
    attr_accessor  :status

    # for sending to nsca
    attr_accessor  :crc
    PACKET_VERSION = 3
    INITIAL_PACKET_LEN = 132
    CONNECT_TIMEOUT = 3
    PACK_STRING = "nxx N a4 n a64 a128 a512xx"

    # MCRYPT parameters
    @@MCRYPT_PARAMS = {
      3 => { :algorithm => 'tripledes', :key_size => 24, :iv_size => 8},
      8 => { :algorithm => 'blowfish', :key_size => 56, :iv_size => 8},
      14 => { :algorithm => 'rijndael-128', :key_size => 32, :iv_size => 16},
      15 => { :algorithm => 'rijndael-192', :key_size => 32, :iv_size => 24},
      16 => { :algorithm => 'rijndael-256', :key_size => 32, :iv_size => 32},
    }

    def initialize(args)
      
      # connecting to nagios
      @nscahost = args[:nscahost]
      @port = args[:port]
      @hostname = args[:hostname]
      @service = args[:service]
      @return_code = args[:return_code]
      @status = args[:status]
      @password = args[:password]
      @encryption_mode = args[:encryption_mode] ? args[:encryption_mode] : 1
      @connected = false

    end

    def connect_and_get_iv
      # Don't reconnect if connected.
      if ! @connected
        begin
          timeout(CONNECT_TIMEOUT) do #the server has one second to answer
            @tcp_client = TCPSocket.open(@nscahost, @port)
            @connected = true
            @iv_and_timestamp = @tcp_client.recv(INITIAL_PACKET_LEN)
        end
        rescue
          @connected = false
          @error = "send_ncsa - error connecting to nsca/nagios: #{$!}"
          puts  @error
          raise # re-raise same exception
        end
      end
    end
    
    def convert_timestamp
      # convert timestamp for use in comm to nagios
      @timestring = @iv_and_timestamp[@iv_and_timestamp.length-4,@iv_and_timestamp.length]
    end

    def timestamp_for_logging
      # convert timestamp in a format we can log
      @iv_and_timestamp_str = @iv_and_timestamp.unpack("H*")
      @timestring_for_log = @iv_and_timestamp_str[0][256,8]
      @timestamp_hex = @timestring_for_log.hex
      @timestamp = Time.at(@timestamp_hex)
    end

    def convert_iv
      # strip off the last 4 characters which are the timestamp
      @iv = @iv_and_timestamp[0,@iv_and_timestamp.length-4]
    end

    def intialize_nsca_connection
      connect_and_get_iv
      convert_timestamp
      convert_iv
    end
 
    def encrypt_packet(returncode, hostname, service, status)
      @crc = 0 
      nsca_params = [PACKET_VERSION, @crc, @timestring, returncode, hostname, service, status ]
      string_to_send_without_crc = nsca_params.pack(PACK_STRING)
      
      @crc = Zlib::crc32(string_to_send_without_crc)

      nsca_params = [PACKET_VERSION, @crc, @timestring, returncode, hostname, service, status ]
      string_to_send_with_crc = nsca_params.pack(PACK_STRING)

      encrypted_string_to_send = ''

      if @encryption_mode == 1
        encrypted_string_to_send = SendNsca::NscaConnection.xor(@password, @iv, string_to_send_with_crc)
      elsif @@MCRYPT_PARAMS[@encryption_mode]
        encrypted_string_to_send = SendNsca::NscaConnection.encrypt(@iv, string_to_send_with_crc, @password, @@MCRYPT_PARAMS[@encryption_mode][:algorithm], @@MCRYPT_PARAMS[@encryption_mode][:key_size], @@MCRYPT_PARAMS[@encryption_mode][:iv_size])
      else
        raise "ERROR: unsupported encryption mode: #{@encryption_mode}"
      end
      return encrypted_string_to_send
    end

    def send_nsca
      checks = [ { :return_code => @return_code,
                   :hostname => @hostname,
                   :service => @service,
                   :status => @status,
                 }
      ]
      send_multi(checks)
    end

    def send_multi(checks)
      checks.each do |res|
        intialize_nsca_connection
        encrypted_str = encrypt_packet(res[:return_code], res[:hostname], res[:service], res[:status])
        @tcp_client.send(encrypted_str, 0)
        @tcp_client.close
        @connected = false
      end
    end

    def self.xor(password, iv, str)
      str_a = str.unpack("C*")
      iv_a = iv.unpack("C*")
      
      result = []
      iv_index = 0
      str_index = 0
      # rotate over IV we received from the server
      str_a.each do |c|
        result[str_index] = str_a[str_index] ^ iv_a[iv_index]
        str_index += 1
        iv_index = iv_index == iv.length-1 ? 0 : iv_index += 1
      end
      # if password defined rotate over password
      if password && password.length > 1
        pw_a = password.unpack("C*")
        pw_index = 0
        str_index = 0
        str_a.each do |c|
          result[str_index] = result[str_index] ^ pw_a[pw_index]
          str_index += 1
          pw_index = pw_index == password.length-1 ? 0 : pw_index += 1
        end
      end
      return result.pack("C*")
    end

    def self.encrypt(iv, str, password, algorithm, key_len, iv_len)
      key = ''
      if password.length < key_len
        key = "\0" * key_len
        key[0,password.length] = password
      elsif password.length > key_len
        key = password[0,key_len]
      else
        key = password
      end
      crypto = Mcrypt.new(algorithm, :cfb, key, iv[0,iv_len], false)
      return crypto.encrypt(str)
    end

  end
end
