COUNTS_BYTES = 1
PROGRAM_KEY = '8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef'


def xor_bait(first, second):
    """
    Производит операцию XOR между двумя байтами побитово
    :param first: первый байт в виде десятичного числа числа
    :param second: второй байт в виде десятичного числа
    :return: результат операции XOR в виде числа
    """
    first = bin(first)[2:]
    second = bin(second)[2:]
    chislo = 0
    if (len(first) < 8):
        first = '0' * (8 - len(first)) + first
    elif (len(first) > 8):
        first = first[len(first) - 8:]
    if (len(second) < 8):
        second = '0' * (8 - len(second)) + second
    elif (len(second) > 8):
        second = second[len(first) - 8:]
    for i in range(8):
        chislo *= 2
        if (first[i] != second[i]):
            chislo += 1
    return chislo


def get_shestnad(chislo):
    """
    Переводит число из десятичной в шестнадцетиричную СС
    :param chislo: число в десятичной форме
    :return: строка в виде числа переведенного в шестнадцетиричную форму
    """
    chislo = hex(chislo)[2:]
    if (len(chislo) == 1):
        chislo = '0' + chislo
    chislo = chislo.upper()
    return chislo


def get_10_out_of_16(chislo):
    """
        Переводит число из шестнадцетиричной в десятичную СС
        :param chislo: число в шестнадцетиричной форме в виде строки
        :return: число переведенное в десятичную форму
        """
    chislo = int(chislo, 16)
    return chislo


def xor_16_bait(first, second):
    """
    Приозводит операцию XOR 16 раз между двумя числами.
    Используется для наложение констант на ключи
    :param first: Первая строка в виде 16-чных чисел
    :param second: Вторая строка в виде 16-ных чисел
    :return: строка, результат выполнения операции
    """
    answer = ''
    for i in range(16):
        one = int(first[i * 2:i * 2 + 2], 16)
        two = int(second[i * 2:i * 2 + 2], 16)
        one = xor_bait(one, two)
        answer += get_shestnad(one)
    return answer


def operator_S(stroka):
    """
    Производит нелинейное преобразование над входной строкой, то есть делает замену байт
    :param stroka: Строка подлежащая нелинейному преобразованию
    :return: Строка - результат преобразования
    """
    Nonlinear_transformation_table = [252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233,
                                      119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249, 24,
                                      101,
                                      90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79, 5, 132, 2, 174, 227, 106,
                                      143,
                                      160, 6, 11, 237, 152, 127, 212, 211, 31, 235, 52, 44, 81, 234, 200, 72, 171, 242,
                                      42,
                                      104, 162, 253, 58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71,
                                      156,
                                      183, 93, 135, 21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158,
                                      178,
                                      177, 50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87, 223,
                                      245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3, 224, 15, 236,
                                      222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 167, 151, 96, 115, 30,
                                      0,
                                      98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70, 146, 39, 94, 85, 47, 140,
                                      163,
                                      165, 125, 105, 213, 149, 59, 7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228,
                                      136,
                                      217, 231, 137, 225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216,
                                      133,
                                      97, 32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89,
                                      166,
                                      116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182]
    answer = ''
    for i in range(16):
        chislo = get_10_out_of_16(stroka[i * 2:i * 2 + 2])
        chislo = Nonlinear_transformation_table[chislo]
        answer += get_shestnad(chislo)
    return answer


def operator_S_reverse(stroka):
    """
    Операция обратная к операции S
    :param stroka: строка подлежащая обратному нелинейному преобразованию
    :return: результат обратного преобразования
    """
    Nonlinear_transformation_table = [252, 238, 221, 17, 207, 110, 49, 22, 251, 196, 250, 218, 35, 197, 4, 77, 233,
                                      119, 240, 219, 147, 46, 153, 186, 23, 54, 241, 187, 20, 205, 95, 193, 249, 24,
                                      101,
                                      90, 226, 92, 239, 33, 129, 28, 60, 66, 139, 1, 142, 79, 5, 132, 2, 174, 227, 106,
                                      143,
                                      160, 6, 11, 237, 152, 127, 212, 211, 31, 235, 52, 44, 81, 234, 200, 72, 171, 242,
                                      42,
                                      104, 162, 253, 58, 206, 204, 181, 112, 14, 86, 8, 12, 118, 18, 191, 114, 19, 71,
                                      156,
                                      183, 93, 135, 21, 161, 150, 41, 16, 123, 154, 199, 243, 145, 120, 111, 157, 158,
                                      178,
                                      177, 50, 117, 25, 61, 255, 53, 138, 126, 109, 84, 198, 128, 195, 189, 13, 87, 223,
                                      245, 36, 169, 62, 168, 67, 201, 215, 121, 214, 246, 124, 34, 185, 3, 224, 15, 236,
                                      222, 122, 148, 176, 188, 220, 232, 40, 80, 78, 51, 10, 74, 167, 151, 96, 115, 30,
                                      0,
                                      98, 68, 26, 184, 56, 130, 100, 159, 38, 65, 173, 69, 70, 146, 39, 94, 85, 47, 140,
                                      163,
                                      165, 125, 105, 213, 149, 59, 7, 88, 179, 64, 134, 172, 29, 247, 48, 55, 107, 228,
                                      136,
                                      217, 231, 137, 225, 27, 131, 73, 76, 63, 248, 254, 141, 83, 170, 144, 202, 216,
                                      133,
                                      97, 32, 113, 103, 164, 45, 43, 9, 91, 203, 155, 37, 208, 190, 229, 108, 82, 89,
                                      166,
                                      116, 210, 230, 244, 180, 192, 209, 102, 175, 194, 57, 75, 99, 182]
    answer = ''
    for i in range(16):
        chislo = get_10_out_of_16(stroka[i * 2:i * 2 + 2])
        chislo = Nonlinear_transformation_table.index(chislo)
        answer += get_shestnad(chislo)
    return answer


def operator_R(stroka):
    chislo = 0
    for i in range(0, 32, 2):  # Проход по всем 16 байтом
        if (int(stroka[i:i + 2], 16) == 0):
            continue
        chislo_by_ci = int(stroka[i:i + 2], 16)
        peremennay = (pole_galua.index(chislo_by_ci) + pole_galua.index(koef[i // 2])) % 255
        peremennay = pole_galua[peremennay]
        chislo = xor_bait(peremennay, chislo)
    stroka = get_shestnad(chislo) + stroka[:-2]
    return stroka


def operator_R_reverse(stroka):
    chislo = 0
    stroka = stroka[2:] + stroka[:2]
    for i in range(0, 32, 2):  # Проход по всем 16 байтом
        if (int(stroka[i:i + 2], 16) == 0):
            continue
        chislo_by_ci = int(stroka[i:i + 2], 16)
        peremennay = (pole_galua.index(chislo_by_ci) + pole_galua.index(koef[i // 2])) % 255
        peremennay = pole_galua[peremennay]
        chislo = xor_bait(peremennay, chislo)
    stroka = stroka[:-2] + get_shestnad(chislo)
    return stroka


def operator_L(stroka):
    """
    Производится линейное преобразование L с входной строкой из 16 байт
    :param stroka:строка для преобразования
    :return:строка - результат линейного преобразования
    """
    for iteration in range(16):  # Проход 16 вычислений
        stroka = operator_R(stroka)
    return stroka


def operator_L_reverse(stroka):
    """
    Операция обратная к L
    :param stroka:строка для обратного преобразования
    :return:результат преобразования
    """
    for iteration in range(16):
        stroka = operator_R_reverse(stroka)
    return stroka


def gen_key(key):
    """
    Генерирация итерационных констант и ключей
    :param key: ключ, введенный пользователем
    :return: массив ключей
    """
    keys = []
    keys.append(key[0:32])
    keys.append(key[32:])
    # Генерируем все константы
    C = []
    for number_const in range(1, 32 + 1):  # Вычисление 32 итерационных констант
        ci = get_shestnad(number_const)
        ci = '00' * 15 + ci
        ci = operator_L(ci)
        C.append(ci)
    # Все константы сгенерированы в массиве С
    # Генерируем ключи на основе констант
    znach = [keys[0], keys[1]]
    for i in range(4):
        for j in range(8):
            key = xor_16_bait(znach[0], C[j + 8 * i])
            key = operator_S(key)
            key = operator_L(key)
            key = xor_16_bait(key, znach[1])
            znach = [key, znach[0]]
        keys.append(znach[0])
        keys.append(znach[1])
    return keys


def get_mas_bait(symbol):
    """
    Возращает массив со значениями байтов символа
    :param symbol: символ
    :return: массив байтов
    """
    massiv = []
    symbol = ord(symbol)
    while symbol != 0:
        massiv.append(symbol % 256)
        symbol = symbol // 256
    answer = []
    for i in range(len(massiv) - 1, -1, - 1):
        answer.append(massiv[i])
    return answer


def get_symbol_code(symbol,flag):
    """
    Возращает шестанадцетиричный код символа
    :param symbol: один символ
    :param flag: True - зашифрование
    :return: строка, содержащая 4 байта в шестнадцетиричном виде
    """
    if (len(symbol) != 1):
        return 'ERROR'
    mas_znach = get_mas_bait(symbol)
    if (len(mas_znach) < COUNTS_BYTES):
        copiy = [0] * (COUNTS_BYTES - len(mas_znach))
        for i in mas_znach:
            copiy.append(i)
        mas_znach = copiy[:]
    elif (len(mas_znach)>COUNTS_BYTES and flag):
        copiy = []
        for i in range(COUNTS_BYTES):
            copiy.append(mas_znach[i])
        mas_znach = copiy[:]
        print('!'*30, '\nБЫЛА ПОТЕРЯ БАЙТ. ДЛЯ ИЗБЕЖАНИЯ ПОТЕРЬ УВЕЛИЧЬТЕ COUNTS_BYTES\n', '!'*30)
    answer = ''
    for i in mas_znach:
        answer += get_shestnad(i)
    return answer


def get_string_of_character_codes(stroka):
    """
    Переводит шестнадцетиричную строку в символьную
    :param stroka: входная строка с 16-ными числами
    :return: строка с символами алфавита
    """
    temp = 0
    summa = 0
    answer = ''
    for i in range(0, len(stroka), 2):
        chislo = get_10_out_of_16(stroka[i:i + 2])
        temp += 1
        summa = summa * 256 + chislo
        if (temp == COUNTS_BYTES):
            temp = 0
            answer += chr(summa)
            summa = 0
    return answer


def encryption_block(block):
    """
    Шифрование блока
    :param block:блок открытого текста в шестнадцетиричном виде, длины 16 байт
    :return:Результат шифрования
    """
    for i in range(9):
        block = xor_16_bait(block, ROUND_KEY[i])
        block = operator_S(block)
        block = operator_L(block)
    block = xor_16_bait(block, ROUND_KEY[9])
    return block


def decryption_block(block):
    """
    Расшифрование блока
    :param block: блок шифртекста в шестнадцетиричном виде, длины 16 байт
    :return: результат расшифрования, блок открытого текста
    """
    block = xor_16_bait(block, ROUND_KEY[9])
    for i in range(8, -1, -1):
        block = operator_L_reverse(block)
        block = operator_S_reverse(block)
        block = xor_16_bait(block, ROUND_KEY[i])
    return block


def shifrovanie():
    """
    Функция шифрования по шифру Кузнечик
    """
    global ROUND_KEY
    text = input('Введите открытый текст - ')
    key = int(input('Хотите использовать свой ключ или программный:\n1 - свой\n2 - программный\nВыбор - '))
    if (key == 1):
        key = input('Введите ключ в шестнадцетиричном виде:')
    else:
        key = PROGRAM_KEY
    ROUND_KEY = gen_key(key)
    # Подгонка открытого текста
    if (len(text) % (16 // COUNTS_BYTES) != 0):
        text += ' ' * ((16 // COUNTS_BYTES) - len(text) % (16 // COUNTS_BYTES))
    text_16 = ''
    vvod = int(input(
        'Текст был введен в текстовом или шестнадцетиричном виде? 1 - текстовый, 2 - шестнадцетиричный\nВыбор - '))
    if (vvod == 2):
        vvod = False
    elif vvod == 1:
        vvod = True
    else:
        print('ОШИБКА ВВОДА')
        return 1
    print('Результат шифрования в 16-чном виде:')
    rez = ''
    for i in text:
        if vvod:
            text_16 += get_symbol_code(i,True)
        else:
            text_16 += i
        if (len(text_16) == 32):
            rez += encryption_block(text_16)
            text_16 = ''
    print(rez)
    try:
        print('Результат расшифрования в текстовом виде:')
        print(get_string_of_character_codes(rez))
    except:
        print('При переводе в текст могут возникнуть проблемы отображения символов')

def deshifrovanie():
    """
    Функция расшифрования шифртекста, зашированного по шифру Кузнечик
    """
    global ROUND_KEY
    text = input('Введите шифртекст - ')
    key = int(input('Хотите использовать свой ключ или программный:\n1 - свой\n2 - программный\nВыбор - '))
    if (key == 1):
        key = input('Введите ключ в шестнадцетиричном виде:')
    else:
        key = PROGRAM_KEY
    ROUND_KEY = gen_key(key)
    text_16 = ''
    vvod = int(input(
        'Шифрекст был введен в текстовом или шестнадцетиричном виде? 1 - текстовый, 2 - шестнадцетиричный\nВыбор - '))
    if (vvod == 2):
        vvod = False
    elif vvod == 1:
        vvod = True
    else:
        print('ОШИБКА ВВОДА')
        return 1
    print('Результат расшифрования в 16-чном виде:')
    rez = ''
    for i in text:
        if vvod:
            text_16 += get_symbol_code(i, False)
        else:
            text_16 += i

        if (len(text_16) == 32):
            rez += decryption_block(text_16)
            text_16 = ''
    print(rez)
    print('Результат расшифрования в текстовом виде:')
    print(get_string_of_character_codes(rez))


ROUND_KEY = []
koef = [148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1]
pole_galua = []
stepen = 1
for i in range(255):
    pole_galua.append(stepen)
    stepen *= 2
    if (stepen > 255):
        stepen = xor_bait(stepen, 195)



choice = int(input('Выберите, что необходимо сделать: \n1 - зашифровать\n2 - расшифровать\nВыбор - '))
if (choice == 1):
    shifrovanie()
elif (choice == 2):
    deshifrovanie()
else:
    print('Неверная команда')
