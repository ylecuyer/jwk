module JWK
  module Utils
    class << self
      def hex_string_to_binary(s)
        s.scan(/.{2}/).map { |n| n.to_i(16).chr }.join
      end

      def int_to_binary(n)
        num_octets = (n.to_s(16).length / 2.0).ceil

        shifted = n << 8
        Array.new(num_octets) do
          ((shifted >>= 8) & 0xFF).chr
        end.join.reverse
      end

      def binary_to_int(s)
        s.chars.inject(0) do |val, char|
          (val << 8) | char[0].ord
        end
      end

      def decode_ub64(data)
        clean = data.gsub(/[[:space:]]/, '')

        len = clean.length
        padded = (len % 4).zero? ? clean : clean + '=' * (4 - len % 4)

        Base64.urlsafe_decode64(padded)
      end

      def decode_ub64_int(data)
        Utils.binary_to_int(decode_ub64(data))
      end

      def encode_ub64_int(n)
        Base64.urlsafe_encode64(Utils.int_to_binary(n))
      end
    end
  end
end
