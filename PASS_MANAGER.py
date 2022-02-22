import os
from datetime import datetime as date
import sqlite3
import sys
from random import choice

def BASE_encode(plain_text):
    numbers = '0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63'
    characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    encode_ref = dict(zip(numbers.split(),list(characters)))     #DICTIONARY THAT WILL BE USED FOR ENCODED TEXT
    decode_ref = dict(zip(list(characters),numbers.split()))     #DICTIONARY THAT WILL BE USED FOR DECODED TEXT
    binary = []
    total_bin = ''
    divisions_six = []
    final = ''
    
    for ch in plain_text:
        a = bin(ord(ch))[2:]
        extra = 8 - len(a)
        binary += [(extra * '0') + a]
    for i in binary:
        total_bin += i

    total_bin_list = list(total_bin)    #CREATES LIST OF THE COMBINED BITS

    length = len(total_bin_list)        #TO CHECK THE LENGTH FOR 6 DIVISION
    leftover = length % 6               #IF NUMBER NOT PROPERLY DIVISIBLE BY 6
    extra = 6 - leftover
    length -= leftover                  #REMAINING LENGTH IN MULTIPLE OF 6
    leftover_list = total_bin_list[-(leftover):]    #LIST OF EXTRA ELEMENTS

    for dlt in range(leftover):         #TO REMOVE EXTRA ELEMENTS
        total_bin_list.pop()

    if extra < 6:                       #TO DEAL WITH THE EXTRA BITS THAT ARE LESS THAN 6
        for m in range(extra):
            leftover_list.append('0')

    m = 0
    for i in range(6,length + 1,6):     #FOR CREATING 6 BITS
        n = i
        divisions_six += [''.join(total_bin_list[m:n])]
        m = n
        if m == length + 1:
            break

    for sm in divisions_six:
        total = 0
        total = total + int(sm[0])*32 + int(sm[1])*16 + int(sm[2])*8 + int(sm[3])*4 + int(sm[4])*2 + int(sm[5])
        final += encode_ref[str(total)]
    if len(leftover_list) == 6:
        total = 0
        total = total + int(leftover_list[0])*32 + int(leftover_list[1])*16 + int(leftover_list[2])*8 + int(leftover_list[3])*4 + int(leftover_list[4])*2 + int(leftover_list[5])
        final += encode_ref[str(total)]

    return final

def BASE_decode(plain_text):
    numbers = '0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63'
    characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
    encode_ref = dict(zip(numbers.split(),list(characters)))     #DICTIONARY THAT WILL BE USED FOR ENCODED TEXT
    decode_ref = dict(zip(list(characters),numbers.split()))     #DICTIONARY THAT WILL BE USED FOR DECODED TEXT
    binary = []
    total_bin = ''
    divisions_eight = []
    final = ''

    for ch in plain_text:
        a = bin(int(decode_ref[ch]))[2:]
        extra = 6 - len(a)
        binary += [(extra * '0') + a]
    for i in binary:
        total_bin += i

    total_bin_list = list(total_bin)

    length = len(total_bin)
    leftover = length % 8
    length -= leftover
    for j in range(leftover):
        total_bin_list.pop()

    m = 0
    for k in range(8,length + 1,8):     #FOR CREATING 8 BITS
        n = k
        divisions_eight += [''.join(total_bin_list[m:n])]
        m = n
        if m == length + 1:
            break

    for sm in divisions_eight:
        total = 0
        total = total + int(sm[0])*128 + int(sm[1])*64 + int(sm[2])*32 + int(sm[3])*16 + int(sm[4])*8 + int(sm[5])*4 + int(sm[6])*2 + int(sm[7])
        final += chr(total)

    return final

def ROT_encode(data):      #encrypt data
    dic = {'a': 'n', 'b': 'o', 'c': 'p', 'd': 'q', 'e': 'r', 'f': 's', 'g': 't', 'h': 'u', 'i': 'v', 'j': 'w', 'k': 'x', 'l': 'y', 'm': 'z', 'n': 'a', 'o': 'b', 'p': 'c', 'q': 'd', 'r': 'e', 's': 'f', 't': 'g', 'u': 'h', 'v': 'i', 'w': 'j', 'x': 'k', 'y': 'l', 'z': 'm', '1': '!', '2': '@', '3': '#', '4': '$', '5': '%', '6': '^', '7': '&', '8': '*', '9': '(', '0': ')', '!': '1', '@': '2', '#': '3', '$': '4', '%': '5', '^': '6', '&': '7', '*': '8', '(': '9', ')': '0', 'A': 'N', 'B': 'O', 'C': 'P', 'D': 'Q', 'E': 'R', 'F': 'S', 'G': 'T', 'H': 'U', 'I': 'V', 'J': 'W', 'K': 'X', 'L': 'Y', 'M': 'Z', 'N': 'A', 'O': 'B', 'P': 'C', 'Q': 'D', 'R': 'E', 'S': 'F', 'T': 'G', 'U': 'H', 'V': 'I', 'W': 'J', 'X': 'K', 'Y': 'L', 'Z': 'M', '-': '-', '_': '_', '=': '=', '+': '+', '.': '.', ',': ',', '<': '<', '>': '>', '/': '/', ' ': ' ', '\\': '\\', '|': '|', '?': '?'}
    encrypted = ''
    for i in data:
        encrypted += dic[i]
    return encrypted

def ROT_decode(data):      #decrypt data
    dic = {'a': 'n', 'b': 'o', 'c': 'p', 'd': 'q', 'e': 'r', 'f': 's', 'g': 't', 'h': 'u', 'i': 'v', 'j': 'w', 'k': 'x', 'l': 'y', 'm': 'z', 'n': 'a', 'o': 'b', 'p': 'c', 'q': 'd', 'r': 'e', 's': 'f', 't': 'g', 'u': 'h', 'v': 'i', 'w': 'j', 'x': 'k', 'y': 'l', 'z': 'm', '1': '!', '2': '@', '3': '#', '4': '$', '5': '%', '6': '^', '7': '&', '8': '*', '9': '(', '0': ')', '!': '1', '@': '2', '#': '3', '$': '4', '%': '5', '^': '6', '&': '7', '*': '8', '(': '9', ')': '0', 'A': 'N', 'B': 'O', 'C': 'P', 'D': 'Q', 'E': 'R', 'F': 'S', 'G': 'T', 'H': 'U', 'I': 'V', 'J': 'W', 'K': 'X', 'L': 'Y', 'M': 'Z', 'N': 'A', 'O': 'B', 'P': 'C', 'Q': 'D', 'R': 'E', 'S': 'F', 'T': 'G', 'U': 'H', 'V': 'I', 'W': 'J', 'X': 'K', 'Y': 'L', 'Z': 'M', '-': '-', '_': '_', '=': '=', '+': '+', '.': '.', ',': ',', '<': '<', '>': '>', '/': '/', ' ': ' ', '\\': '\\', '|': '|', '?': '?'}
    decrypted = ''
    for i in data:
        decrypted += dic[i]
    return decrypted

def ALGO(user):
    lower_dic = {'a': '01', 'b': '02', 'c': '03', 'd': '04', 'e': '05', 'f': '06', 'g': '07', 'h': '08', 'i': '09', 'j': '10', 'k': '11', 'l': '12', 'm': '13', 'n': '14', 'o': '15', 'p': '16', 'q': '17', 'r': '18', 's': '19', 't': '20', 'u': '21', 'v': '22', 'w': '23', 'x': '24', 'y': '25', 'z': '26'}
    upper_dic = {'A': '01', 'B': '02', 'C': '03', 'D': '04', 'E': '05', 'F': '06', 'G': '07', 'H': '08', 'I': '09', 'J': '10', 'K': '11', 'L': '12', 'M': '13', 'N': '14', 'O': '15', 'P': '16', 'Q': '17', 'R': '18', 'S': '19', 'T': '20', 'U': '21', 'V': '22', 'W': '23', 'X': '24', 'Y': '25', 'Z': '26'}
    lower = 'abcdefghijklmnopqrstuvwxyz'
    upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    output = ''
    summ = 0
    mod = 0

    for i in user:
        if i.isupper() == True:
            summ += (2 * int(upper_dic[i])) + int(upper_dic[i][1])
            mod = summ % 26
            output += upper[mod - 1]
            summ = 0
        elif i.islower() == True:
            summ += (2 * int(lower_dic[i])) + int(lower_dic[i][1])
            mod = summ % 26
            output += lower[mod - 1]
            summ = 0
        else:
            output += i

    return output

def os_db():
    if os.name.lower() == 'nt':
        return 'nt'
    elif os.name.lower() == 'posix':
        return 'linux'

def db_check():
    if os_db() == 'nt':
        if 'db.db' not in os.listdir(os.getenv('HOME')):
            #f = open(os.getenv('HOME') + '\\db.db','x')
            #f.close()
            services = ['AMAZON_PRIME', 'ATM_PIN', 'BANKING_APP', 'DISCORD', 'FACEBOOK', 'GOOGLE', 'HOTSTAR', 'INSTAGRAM', 'MICROSOFT', 'NETFLIX', 'SNAPCHAT', 'SPOTIFY', 'TELEGRAM', 'TWITTER', 'UPI_PIN']
            conn = sqlite3.connect(os.getenv('HOME') + '\\db.db')
            cur = conn.cursor()
            for i in services:
                cur.execute('CREATE TABLE ' + i.upper() + '(user text, password text, month integer ,date integer)')
                cur.execute('INSERT INTO ' + i.upper() + ' VALUES("null" , "null", 0, 0)')
                conn.commit()
            conn.close()
    
        else:
            pass
    elif os_db() == 'linux':
        if 'db.db' not in os.listdir(os.getenv('HOME') + '/Documents/'):
            #f = open(os.getenv('HOME') + '/Documents/db.db','x')
            #f.close()
            services = ['AMAZON_PRIME', 'ATM_PIN', 'BANKING_APP', 'DISCORD', 'FACEBOOK', 'GOOGLE', 'HOTSTAR', 'INSTAGRAM', 'MICROSOFT', 'NETFLIX', 'SNAPCHAT', 'SPOTIFY', 'TELEGRAM', 'TWITTER', 'UPI_PIN']
            conn = sqlite3.connect(os.getenv('HOME') + '/Documents/db.db')
            cur = conn.cursor()
            for i in services:
                cur.execute('CREATE TABLE ' + i.upper() + '(user text, password text, month integer ,date integer)')
                cur.execute('INSERT INTO ' + i.upper() + ' VALUES("null" , "null", 0, 0)')
                conn.commit()
            conn.close()
        else:
            pass

def creds():
    if os_db() == 'nt':
        if 'creds.txt' not in os.listdir(os.getenv('HOME') + '\\'):
            print('LOOKS LIKE YOU ARE NEW HERE !!')
            print('ENTER A PASSWORD, YOU\'LL BE ASKED TO ENTER IT EVERYTIME YOU RUN THIS SCRIPT (MIN 8 CHARACTERS)')
            new_password = input('Enter a password (make me complex please): ')
            while len(new_password) < 8:
                new_password = input('Enter a password (make me complex please)')
            else:
                password = input('Enter the same password again: ')
                while password != new_password:
                    password = input('Passwords don\'t match, enter again: ')
                else:
                    f = open(os.getenv('HOME') + '\\creds.txt','w')
                    encode = ALGO(ROT_encode(BASE_encode(new_password)))
                    begin = ''
                    end = ''
                    for i in range(500):
                        begin += choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+.:|')
                    for j in range(500):
                        end += choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+.:|')

                    final = begin + encode + end
                    f.write(final)
                    f.close()
        else:
            print('WELCOME BACK !!')
            password = input('Password: ')
            f = open(os.getenv('HOME') + '\\creds.txt','r')
            check = f.read()
            f.close()
            fail = 0
            while ALGO(ROT_encode(BASE_encode(password))) not in check:
                if fail < 2:
                    fail += 1
                    password = input("Password: ")
                else:
                    print('3 WRONG ATTEMPTS ^_^')
                    sys.exit()
            else:
                return 'success'

    elif os_db() == 'linux':
        if 'creds.txt' not in os.listdir(os.getenv('HOME') + '/Documents/'):
            print('LOOKS LIKE YOU ARE NEW HERE !!')
            print('ENTER A PASSWORD, YOU\'LL BE ASKED TO ENTER IT EVERYTIME YOU RUN THIS SCRIPT (MIN 8 CHARACTERS)')
            new_password = input('Enter a password (make me complex please): ')
            while len(new_password) < 8:
                new_password = input('Enter a password (make me complex please)')
            else:
                password = input('Enter the same password again: ')
                while password != new_password:
                    password = input('Passwords don\'t match, enter again: ')
                else:
                    f = open(os.getenv('HOME') + '/Documents/creds.txt','w')
                    encode = ALGO(ROT_encode(BASE_encode(new_password)))
                    begin = ''
                    end = ''
                    for i in range(500):
                        begin += choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+.:|')
                    for j in range(500):
                        end += choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+.:|')

                    final = begin + encode + end
                    f.write(final)
                    f.close()
        else:
            print('WELCOME BACK !!')
            password = input('Password: ')
            f = open(os.getenv('HOME') + '/Documents/creds.txt','r')
            check = f.read()
            f.close()
            fail = 0
            while ALGO(ROT_encode(BASE_encode(password))) not in check:
                if fail < 2:
                    fail += 1
                    password = input("Password: ")
                else:
                    print('3 WRONG ATTEMPTS ^_^')
                    sys.exit()
            else:
                return 'success'

def addition():
    if os_db() == 'nt':
        conn = sqlite3.connect(os.getenv('HOME') + '\\db.db')
        cur = conn.cursor()
        tables = []
        num_range = ''
        
        for i in cur.execute("SELECT name FROM sqlite_master WHERE type='table';"):
            tables += [i[0]]
        for i in range(len(tables)):
            print(str(i) + ') ' + tables[i])
            num_range += str(i)

        option = input('Select Service: ')
        while option not in num_range:
            print('Invalid Option')
            option = input('Select Service: ')
        else:
            user = input('Enter username: ')
            password = input('Enter Password for the service: ')
            while len(password) < 8:
                print('Password length less than 8 check your password')
                password = input('Enter password for the service: ')
            else:
                encoded = ROT_encode(BASE_encode(password))
                old_creds = []
                for j in cur.execute('SELECT password FROM ' + tables[int(option)]):
                    old_creds += [j[0][:len(encoded)]]
                while encoded in old_creds:
                    print('This password has already been used in the past. Add another one')
                    password = input('Enter password for the service: ')
                    encoded = ROT_encode(BASE_encode(password))
                else:
                    rand = ''
                    for i in range(200 - len(encoded)):
                        rand += choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-=_+()!@#$%^&*;:.|')
                    final = encoded + '$$$$' + rand
                    ex_values = [ROT_encode(BASE_encode(user)), final, date.now().month, date.now().day]
                    cur.execute('INSERT INTO ' + tables[int(option)] + ' VALUES(?, ?, ?, ?)',ex_values)
                    conn.commit()
                    conn.close()

    elif os_db() == 'linux':
        conn = sqlite3.connect(os.getenv('HOME') + '/Documents/db.db')
        cur = conn.cursor()
        tables = []
        num_range = ''
        
        for i in cur.execute("SELECT name FROM sqlite_master WHERE type='table';"):
            tables += [i[0]]
        for i in range(len(tables)):
            print(str(i) + ') ' + tables[i])
            num_range += str(i)

        option = input('Select Service: ')
        while option not in num_range:
            print('Invalid Option')
            option = input('Select Service: ')
        else:
            user = input('Enter Username: ')
            password = input('Enter Password for the service: ')
            while len(password) < 8:
                print('Password length less than 8 check your password')
                password = input('Enter password for the service: ')
            else:
                encoded = ROT_encode(BASE_encode(password))
                old_creds = []
                for j in cur.execute('SELECT password FROM ' + tables[int(option)]):
                    old_creds += [j[0][:len(encoded)]]
                while encoded in old_creds:
                    print('This password has already been used in the past. Add another one')
                    password = input('Enter password for the service: ')
                    encoded = ROT_encode(BASE_encode(password))
                else:
                    rand = ''
                    for i in range(200 - len(encoded)):
                        rand += choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-=_+()!@#$%^&*;:.|')
                    final = encoded + '$$$$' + rand
                    ex_values = [ROT_encode(BASE_encode(user)), final, date.now().month, date.now().day]
                    cur.execute('INSERT INTO ' + tables[int(option)] + ' VALUES(?, ?, ?, ?)',ex_values)
                    conn.commit()
                    conn.close()

def view():
    if os_db() == 'nt':
        conn = sqlite3.connect(os.getenv('HOME') + '\\db.db')
        cur = conn.cursor()
        tables = []
        for i in cur.execute("SELECT name FROM sqlite_master WHERE type='table';"):
            tables += [i[0]]

        user = []
        password = []
        month = []
        day = []
        t_day = date.now().day
        t_month = date.now().month
        for i in tables:
            for j in cur.execute('SELECT * FROM ' + i):
                user += [j[0]]
                pass_string = j[1]
                password += [pass_string[:pass_string.find('$$$$')]]
                month += [j[2]]
                day += [j[3]]
            if password[-1] in 'null':
                print(i + ': credentials not yet saved')
            else:
                if (t_month - day[-1]) >= 3:
                    print('WARNING! PASSWORD IS OLDER THAN 3 MONTHS')
                    print("IT'LL BE A GOOD PRACTICE TO CHANGE IT\n")
                    print(i + ': ' + BASE_decode(ROT_decode(user[-1])) + ':' + BASE_decode(ROT_decode(password[-1])) + ' is ' + str(t_month - month[-1]) + ' month(s) and ' + str(abs(t_day - day[-1])) + ' day(s) old')
                else:
                    print(i + ': ' + BASE_decode(ROT_decode(user[-1])) + ':' + BASE_decode(ROT_decode(password[-1])) + ' is ' + str(t_month - month[-1]) + ' month(s) and ' + str(abs(t_day - day[-1])) + ' day(s) old')

        conn.close()

    elif os_db() == 'linux':
        conn = sqlite3.connect(os.getenv('HOME') + '/Documents/db.db')
        cur = conn.cursor()
        tables = []
        for i in cur.execute("SELECT name FROM sqlite_master WHERE type='table';"):
            tables += [i[0]]

        user = []
        password = []
        month = []
        day = []
        t_day = date.now().day
        t_month = date.now().month
        for i in tables:
            for j in cur.execute('SELECT * FROM ' + i):
                user += [j[0]]
                pass_string = j[1]
                password += [pass_string[:pass_string.find('$$$$')]]
                month += [j[2]]
                day += [j[3]]
            if password[-1] in 'null':
                print(i + ': credentials not yet saved')
            else:
                if (t_month - day[-1]) >= 3:
                    print('WARNING! PASSWORD IS OLDER THAN 3 MONTHS')
                    print("IT'LL BE A GOOD PRACTICE TO CHANGE IT\n")
                    print(i + ': ' + BASE_decode(ROT_decode(user[-1])) + ':' + BASE_decode(ROT_decode(password[-1])) + ' is ' + str(t_month - month[-1]) + ' month(s) and ' + str(abs(t_day - day[-1])) + ' day(s) old')
                else:
                    print(i + ': ' + BASE_decode(ROT_decode(user[-1])) + ':' + BASE_decode(ROT_decode(password[-1])) + ' is ' + str(t_month - month[-1]) + ' month(s) and ' + str(abs(t_day - day[-1])) + ' day(s) old')

        conn.close()

def service():
    if os_db() == 'nt':
        conn = sqlite3.connect(os.getenv('HOME') + '\\db.db')
        cur = conn.cursor()
        print('These are the available services\n')
        for i in cur.execute("SELECT name FROM sqlite_master WHERE type='table';"):
            print(i[0])

        ser = input('Enter the name of service: ')
        cur.execute('CREATE TABLE ' + ser.upper() + '(user text, password text, month integer, day integer)')
        cur.execute('INSERT INTO ' + ser.upper() + ' VALUES("null", "null", 0, 0)')
        print('Service ' + ser.upper() + ' added!\n')
        conn.commit()
        conn.close()

    elif os_db() == 'linux':
        conn = sqlite3.connect(os.getenv('HOME') + '/Documents/db.db')
        cur = conn.cursor()
        print('These are the available services\n')
        for i in cur.execute("SELECT name FROM sqlite_master WHERE type='table';"):
            print(i[0])

        ser = input('Enter the name of service: ')
        cur.execute('CREATE TABLE ' + ser.upper() + '(user text, password text, month integer, day integer)')
        cur.execute('INSERT INTO ' + ser.upper() + ' VALUES("null", "null", 0, 0)')
        print('Service ' + ser.upper() + ' added!\n')
        conn.commit()
        conn.close()

def drop():
    if os_db() == 'nt':
        conn = sqlite3.connect(os.getenv('HOME') + '\\db.db')
        cur = conn.cursor()
        tables = []
        num_range = ''
        for i in cur.execute("SELECT name FROM sqlite_master WHERE type='table';"):
            tables += [i[0]]

        for i in range(len(tables)):
            print(str(i) + ')' + tables[i])
            num_range += str(i)

        opt = input('Which service do you want to remove: ')
        while opt not in num_range:
            print('Invalid Choice')
            opt = input('Which service do you want to remove: ')
        else:
            cur.execute('DROP TABLE ' + tables[int(opt)])
            conn.commit()
            conn.close()
            print('Service ' + tables[int(opt)] + ' removed!')

    elif os_db() == 'linux':
        conn = sqlite3.connect(os.getenv('HOME') + '/Documents/db.db')
        cur = conn.cursor()
        tables = []
        num_range = ''
        for i in cur.execute("SELECT name FROM sqlite_master WHERE type='table';"):
            tables += [i[0]]

        for i in range(len(tables)):
            print(str(i) + ')' + tables[i])
            num_range += str(i)

        opt = input('Which service do you want to remove: ')
        while opt not in num_range:
            print('Invalid Choice')
            opt = input('Which service do you want to remove: ')
        else:
            cur.execute('DROP TABLE ' + tables[int(opt)])
            conn.commit()
            conn.close()
            print('Service ' + tables[int(opt)] + ' removed!')

db_check()
creds()

while True:
    print('\r')
    print('A)ADD PASSWORD')
    print('B)VIEW PASSWORDS')
    print('C)ADD SERVICE')
    print('D)REMOVE SERVICE')
    print('E)EXIT')
    option = input('> ')
    while option not in 'ABCDEabcde':
        print('Invalid Option')
        option = input('> ')
    else:
        if option in 'aA':
            addition()
        elif option in 'bB':
            view()
        elif option in 'cC':
            service()
        elif option in 'dD':
            drop()
        elif option in 'eE':
            sys.exit()
