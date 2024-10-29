import struct    

class RabbitCipher:
    def __init__(self, key, iv=None):
        if len(key) != 16:
            raise ValueError("Key must be 16 bytes (128 bits) long")
        self.key = key
        self.iv = iv
        self._init_state()

    def _init_state(self):
        # Key setup
        key_parts = struct.unpack('<8H', self.key)
        self.x = [0] * 8
        self.c = [0] * 8
        # counter carry bit initialized to 0
        self.b = 0

        for i in range(8):
            if i % 2 == 0:
                self.x[i] = (key_parts[(i + 1) % 8] << 16) | key_parts[i]
                self.c[i] = (key_parts[(i + 4) % 8] << 16) | key_parts[(i + 5) % 8]
            else:
                self.x[i] = (key_parts[(i + 5) % 8] << 16) | key_parts[(i + 4) % 8]
                self.c[i] = (key_parts[i] << 16) | key_parts[(i + 1) % 8]

        for _ in range(4):
            self._next_state()

        for i in range(8):
            self.c[i] ^= self.x[(i + 4) % 8]

        # IV setup
        if self.iv:
            if len(self.iv) != 8:
                raise ValueError("IV must be 8 bytes (64 bits) long")
            iv_parts = struct.unpack('<2L', self.iv)
            iv0, iv1 = iv_parts[0], iv_parts[1]
            # counter variables
            self.c[0] ^= iv0
            self.c[1] ^= (iv1 >> 16) | (iv0 << 16)
            self.c[2] ^= iv1
            self.c[3] ^= (iv0 >> 16) | (iv1 << 16)
            self.c[4] ^= iv0
            self.c[5] ^= (iv1 >> 16) | (iv0 << 16)
            self.c[6] ^= iv1
            self.c[7] ^= (iv0 >> 16) | (iv1 << 16)

            for _ in range(4):
                self._next_state()

    def _next_state(self):
        g = [0] * 8
        for i in range(8):
            g[i] = self._g_func(self.x[i] + self.c[i])
        # state variables
        self.x[0] = (g[0] + self._rotate_left(g[7], 16) + self._rotate_left(g[6], 16)) & 0xFFFFFFFF
        self.x[1] = (g[1] + self._rotate_left(g[0], 8) + g[7]) & 0xFFFFFFFF
        self.x[2] = (g[2] + self._rotate_left(g[1], 16) + self._rotate_left(g[0], 16)) & 0xFFFFFFFF
        self.x[3] = (g[3] + self._rotate_left(g[2], 8) + g[1]) & 0xFFFFFFFF
        self.x[4] = (g[4] + self._rotate_left(g[3], 16) + self._rotate_left(g[2], 16)) & 0xFFFFFFFF
        self.x[5] = (g[5] + self._rotate_left(g[4], 8) + g[3]) & 0xFFFFFFFF
        self.x[6] = (g[6] + self._rotate_left(g[5], 16) + self._rotate_left(g[4], 16)) & 0xFFFFFFFF
        self.x[7] = (g[7] + self._rotate_left(g[6], 8) + g[5]) & 0xFFFFFFFF

        self._update_counters()

    def _g_func(self, x):
        x = x & 0xFFFFFFFF
        return (x * x) ^ (x >> 32)

    def _update_counters(self):
        A = [0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3, 0x34D34D34, 0x4D34D34D, 0xD34D34D3]
        # counter carry bit 'b'
        carry = self.b
        for i in range(8):
            sum_val = self.c[i] + A[i] + carry
            carry = 1 if sum_val > 0xFFFFFFFF else 0
            self.c[i] = sum_val & 0xFFFFFFFF
        self.b = carry

    def _rotate_left(self, x, bits):
        return ((x << bits) | (x >> (32 - bits))) & 0xFFFFFFFF

    def _extract_block(self):
        s = [0] * 8
        s[0] = self.x[0] ^ (self.x[5] >> 16)
        s[1] = self.x[0] >> 16 ^ self.x[3]
        s[2] = self.x[2] ^ (self.x[7] >> 16)
        s[3] = self.x[2] >> 16 ^ self.x[5]
        s[4] = self.x[4] ^ (self.x[1] >> 16)
        s[5] = self.x[4] >> 16 ^ self.x[7]
        s[6] = self.x[6] ^ (self.x[3] >> 16)
        s[7] = self.x[6] >> 16 ^ self.x[1]

        return struct.pack('<8L', *s)

    def encrypt(self, plaintext):
        self._init_state()  # Reinitialize state to ensure key stream consistency
        plaintext = bytearray(plaintext)
        ciphertext = bytearray(len(plaintext))

        for i in range(0, len(plaintext), 16):
            block = self._extract_block()
            for j in range(16):
                if i + j < len(plaintext):
                    ciphertext[i + j] = plaintext[i + j] ^ block[j]

            self._next_state()

        return bytes(ciphertext)

    def decrypt(self, ciphertext):
        return self.encrypt(ciphertext)  # Reinitialize state for decryption

# Example usage:
key = b'\x00' * 16  # 128-bit key
iv = b'\x00' * 8    # 64-bit IV
cipher = RabbitCipher(key, iv)

plaintext = b"Hello, Rabbit!"
ciphertext = cipher.encrypt(plaintext)
decrypted = cipher.decrypt(ciphertext)

print("Plaintext:", plaintext)
print("Ciphertext:", ciphertext.hex())
print("Decrypted:", decrypted)
