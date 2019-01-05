from PIL import Image


class Hash:

    @staticmethod
    def _load_image(path):
        return Image.open(path)

    @staticmethod
    def similar_per(hashA, hashB):
        if len(hashA) != len(hashB):
            raise ValueError("Undefined for sequences of unequal length")
        s = sum(el1 == el2 for el1, el2 in zip(hashA, hashB))
        return s / len(hashB) * 100

    @staticmethod
    def img_hash(path, hash_size=8):
        image = Hash._load_image(path)
        # Grayscale and shrink the image in one step.
        image = image.convert('L').resize(
            (hash_size + 1, hash_size),
            Image.ANTIALIAS,
        )
        difference = []
        for row in range(hash_size):
            for col in range(hash_size):
                pixel_left = image.getpixel((col, row))
                pixel_right = image.getpixel((col + 1, row))
                difference.append(pixel_left > pixel_right)
        # Convert the binary array to a hexadecimal string.
        decimal_value = 0
        hex_string = []
        for index, value in enumerate(difference):
            if value:
                decimal_value += 2 ** (index % 8)
            if (index % 8) == 7:
                hex_string.append(hex(decimal_value)[2:].rjust(2, '0'))
                decimal_value = 0
        return ''.join(hex_string)
