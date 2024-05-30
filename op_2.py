from Crypto.Hash import SHA256
import os

BLOCK_SIZE = 16   # размер блока данных

# таблица прямого нелинейного преобразования (для S преобразования)
Pi = [
    0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16,
    0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
    0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA,
    0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
    0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21,
    0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
    0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0,
    0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,
    0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB,
    0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,
    0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12,
    0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
    0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7,
    0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,
    0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E,
    0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,
    0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9,
    0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
    0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC,
    0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
    0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44,
    0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,
    0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F,
    0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
    0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7,
    0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
    0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE,
    0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
    0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B,
    0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
    0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0,
    0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6
]

# вектор линейного преобразования (для L преобразования)
l_vec = [1, 148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148]

# массив для хранения итерационных констант
iter_C = [[0] * BLOCK_SIZE for _ in range(32)]

# массив для хранения раундовых ключей
iter_key = [[0] * 64 for _ in range(10)]


def kuz_x(a, b):    # побитовый XOR (преобразование X)
    if len(a) != len(b):    # выравнивание массивов до одинаковой длины
        max_len = max(len(a), len(b))
        a += bytearray(max_len - len(a))
        b += bytearray(max_len - len(b))
    c = bytearray(len(a))
    for i in range(len(a)):   # выполнение самого XOR
        c[i] = a[i] ^ b[i]
    return c


def kuz_s(in_data):   # преобразование S
    out_data = bytearray(BLOCK_SIZE)
    for i in range(BLOCK_SIZE):
        out_data[i] = Pi[in_data[i]]    # производит замену в соответствии с таблицей
    return bytes(out_data)


def kuz_l(in_data):   # преобразование L
    out_data = bytearray(in_data)
    for _ in range(16):
        a_15 = out_data[-1]   # циклический сдвиг байтов
        for i in range(BLOCK_SIZE - 1, 0, -1):
            out_data[i] = out_data[i - 1]
            a_15 ^= gf_mul(out_data[i], l_vec[i])   # умножение в поле Галуа
        a_15 %= 256   # ограничение значения a_15 до диапазона от 0 до 255, так как умножение происходит по модулю 256
        out_data[0] = a_15
    return bytes(out_data)


def gf_mul(a, b):   # функция умножения в поле Галуа
    c = 0
    for _ in range(8): # так как байт состоит из 8 битов
        if b & 1:   # если младший бит b равен 1 к результату ксорим a
            c ^= a
        hi_bit = a & 0x80   # проверяем установлен ли старший бит
        a <<= 1   # сдвигаемся на 1 бит влево (эквивалентно умножению a на 2)
        if hi_bit:  # если старший бит был установлен ксорим с полиномом x^8 + x^7 + x^6 + x + 1
            a ^= 0xc3
        b >>= 1   # сдвигаемся на 1 бит вправо (эквивалентно делению b на 2)
    return c


def get_iter_C():   # функция расчета констант
    iter_num = [[0] * BLOCK_SIZE for _ in range(32)]
    for i in range(32):
        iter_num[i][0] = i + 1  # считаем порядковый номер константы и записываем его
    for i in range(32):
        iter_C[i] = kuz_l(iter_num[i])  # с помощью Lреобразования получаем искомую константу


def kuz_f(in_key_1, in_key_2, iter_const):  # функция, выполняющая преобразования ячейки Фейстеля
    internal = kuz_x(in_key_1, iter_const)  # применяем X преобразование к первому ключу и итерационной константе
    internal = kuz_s(internal)  # применяем S преобразование
    internal = kuz_l(internal)  # применяем L преобразование
    out_key_1 = kuz_x(internal, in_key_2)   # применяем X преобразование к полученному значению и второму ключу
    out_key_2 = in_key_1    # меняем местами
    return out_key_1, out_key_2


def expand_key(key_1, key_2):   # функция расчета раундовых ключей
    get_iter_C()    # получем итерационные константы
    iter_key[0] = key_1
    iter_key[1] = key_2
    iter12 = [key_1, key_2]
    for i in range(4):  # с помощью 8 итераций сети Фейстеля получаем искомые 10 итерационных ключей
        iter34 = kuz_f(iter12[0], iter12[1], iter_C[0 + 8 * i])
        iter12 = kuz_f(iter34[0], iter34[1], iter_C[1 + 8 * i])
        iter34 = kuz_f(iter12[0], iter12[1], iter_C[2 + 8 * i])
        iter12 = kuz_f(iter34[0], iter34[1], iter_C[3 + 8 * i])
        iter34 = kuz_f(iter12[0], iter12[1], iter_C[4 + 8 * i])
        iter12 = kuz_f(iter34[0], iter34[1], iter_C[5 + 8 * i])
        iter34 = kuz_f(iter12[0], iter12[1], iter_C[6 + 8 * i])
        iter12 = kuz_f(iter34[0], iter34[1], iter_C[7 + 8 * i])
        iter_key[2 * i + 2] = iter12[0]
        iter_key[2 * i + 3] = iter12[1]


def kuz_encrypt_block(blk):   # шифрование одного блока данных
    out_blk = blk
    for i in range(9):  # 9 раундов одинаковы
        out_blk = kuz_x(iter_key[i], out_blk)   # применяем X преобразование к блоку и итерационному ключу
        out_blk = kuz_s(out_blk)    # применяем S преобразование
        out_blk = kuz_l(out_blk)    # приемняем L преобразование
    # 10 раунд это просто X преобразование полученного результата и последнего итерационного ключа
    out_blk = kuz_x(out_blk, iter_key[9])
    return out_blk


def encrypt_message(key, message):  # функция шифрующая данные
    key_bytes = bytes.fromhex(key)  # конвертируем ключ в байты
    message_bytes = message.encode('windows-1251')   # используем кодировку данных windows-1251
    if len(message_bytes) % BLOCK_SIZE != 0:    # дополняем длину данных до кратного размеру блока
        message_bytes += bytes(BLOCK_SIZE - len(message_bytes) % BLOCK_SIZE)
    # первые 2 итерационных ключа это половины исходного ключа
    expand_key(key_bytes[:32], key_bytes[32:])
    encrypted_message = b''
    for i in range(0, len(message_bytes), BLOCK_SIZE):  # шифруем каждый блок с помощью уже созданной функции
        block = message_bytes[i:i+BLOCK_SIZE]   # выделяем очередной блок
        encrypted_block = kuz_encrypt_block(block)  # применяем функцию kuz_encrypt_block
        encrypted_message += encrypted_block
    return encrypted_message


def calculate_checksum(file_path):
    key = '0123456789abcdef' * 2   # Ключ для шифрования (256 бит - 32 байта)
    with open(file_path, 'r') as f:
        data = f.read()
    encrypted_data = encrypt_message(key, data)
    hasher = SHA256.new()   # создаем новый hash-объект
    hasher.update(encrypted_data)   # обновляет hash-объект, добавляя новые данные
    checksum = hasher.hexdigest()
    # hasher.hexdigest() вычисляет и возвращаев контрольную сумму в виде шестнадцатеричной строки
    return checksum


def calculate_checksum_for_directory(directory):
    checksums = {}
    for dirpath, _, filenames in os.walk(directory):
        # os.walk(directory) генерирует имена файлов в дереве каталогов, перемещаясь по нему
        # dirpath - это строка, путь к каталогу
        # dirnames - это список имен подкаталогов в dirpath, т.к. нам это не нужно заменим на _
        # filenames - это список имен файлов, не относящихся к каталогам, в dirpath.
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            # os.path.join(directory, filename) объединяет путь к каталогу и название файла
            checksum = calculate_checksum(file_path)
            checksums[file_path] = checksum
    return checksums


def main():
    path = input("Введите путь к файлу или каталогу: ")
    if os.path.isfile(path):    # указывает ли данный путь на файл
        checksum = calculate_checksum(path)
        print(f"Контрольная сумма для файла '{path}': {checksum}")
    elif os.path.isdir(path):   # указывает ли данный путь на папку
        checksums = calculate_checksum_for_directory(path)
        print("Контрольные суммы для файлов в каталоге:")
        for file_path, checksum in checksums.items():
            print(f"{file_path}: {checksum}")
    else:
        print("Указанный путь не существует или не является файлом или каталогом.")


if __name__ == "__main__":
    main()