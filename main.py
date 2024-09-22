import PySimpleGUI as sg  # import library to make GUI
from cryptography.fernet import Fernet  # import chosen encryption algorithm
import os  # import library to work with files


def generate_key():  # Generates an encryption key and puts it in key.key
    key = Fernet.generate_key()
    with open('key.key', 'wb') as key_file:
        key_file.write(key)
    return key


def load_key():  # reads the encryption key from the "key.key" file and returns it.
    with open('key.key', 'rb') as key_file:
        key = key_file.read()
    return key


def encrypt_file(file_path):                # encrypts a file specified by file_path using the Fernet algorithm.
    with open(file_path, 'rb') as file:     # encrypts the file, saves the encrypted data in a new file
        file_data = file.read()             # with the ".encrypted" extension, and removes the original file.
                                            # Uses 'rb' to open the file in binary mode to be able to use this
    key = Fernet.generate_key()             # on other types of files like pictures
    fernet = Fernet(key)
    encrypted_data = fernet.encrypt(file_data)

    encrypted_file_path = file_path + '.encrypted'      # make the file an encrypted file

    with open(encrypted_file_path, 'wb') as file:
        file.write(encrypted_data)

    os.remove(file_path)                    # deletes the old, unencrypted file

    return encrypted_file_path, key


def decrypt_file(file_path, key):           # decrypts a file specified by file_path using the Fernet algorithm.
    with open(file_path, 'rb') as file:     # reads the encrypted data from the file, decrypts it using the provided key,
        encrypted_data = file.read()        # saves the decrypted data in a new file with the original extension

    fernet = Fernet(key)
    decrypted_data = fernet.decrypt(encrypted_data)

    decrypted_file_path = os.path.splitext(file_path)[0]  # Remove the file extension

    with open(decrypted_file_path, 'wb') as file:
        file.write(decrypted_data)

    # os.remove(file_path)

    return decrypted_file_path


def encrypt_own(filename, key, file_path):  # performs a custom encryption operation on a file.
    file = open(filename, "rb")             # It opens the file, reads its content, performs an XOR operation between each byte of the file and the provided key,
    data = file.read()                      # and saves the modified data in a new file with the ".encrypted" extension. The original file is then removed.
    file.close()

    data = bytearray(data)                  # Converts the data that was read into an array of bytes
    for index, value in enumerate(data):    # Goes over every byte in a for loop and performs an XOR operation between the byte and the key that the user provides
        data[index] = value ^ key           # Stores the result of the operation back into the data array

    file = open(filename + '.encrypted', "wb")   # Opens a new file with the original file name and adds the .encrypted extension to it. Opened in binary write mode
    file.write(data)                        # Writes the modified data into the new file
    file.close()                            # Closes the file

    os.remove(file_path)                    # Removes the original file


def decrypt_own(filename, key, file_path):  # performs a custom decryption operation on a file specified by file_path.
    file = open(filename, "rb")             # It opens the file, reads its content, performs a bitwise XOR operation between each byte of the file and the provided key,
    data = file.read()                      # and saves the modified data in a new file with the original extension (by removing the ".encrypted" extension).
    file.close()

    data = bytearray(data)                  # Exactly the same as the encryption, it turns it back into readable files using the same key
    for index, value in enumerate(data):
        data[index] = value ^ key

    decrypted_file_path = os.path.splitext(file_path)[0]

    file = open(decrypted_file_path, "wb")
    file.write(data)
    file.close()

    # os.remove(file_path)


def main():
    if not os.path.exists('key.key'):       # Check if the key file exists, generate one if not
        generate_key()

    key = load_key()                        # Load the key

    layout = [[sg.Text("File:"), sg.Input(key='-FILE-', enable_events=True), sg.FileBrowse()],  # how the GUI looks

              [sg.Text("Method:"),
               sg.Radio('Fernet algorithm', "RADIO1", default=False, key="-Chosen-"),
               sg.Radio('Own Algorithm', "RADIO1", default=False, key="-Own-")],

              [sg.Text("Key:"),
               sg.Input(key="-IN-")],

              [sg.Radio('Encrypt', "RADIO2", default=False, key="-Encrypt-"),
               sg.Radio('Decrypt', "RADIO2", default=False, key="-Decrypt-")],

              [sg.Multiline(size=(30, 10), key='-OUTPUT-')],

              [sg.Button("Run"), sg.Button("Close")]]
    window = sg.Window("Encryption and Decryption", layout, size=(500, 400))        # GUI name and Size

    while True:         # The while loop continues until the "Close" button is clicked or the window is closed.
        event, values = window.read()

        if event == "Run":                              # if Run button is clicked
            if values["-Encrypt-"]:                     # and encrypt radio button is chosen
                if values["-Chosen-"]:                  # and chosen algorithm is selected
                    file_path = values['-FILE-']        # Gets the file path from where the user browsed for a file
                    password = values['-IN-']           # Get the password input

                    if file_path and password:          # If both are provided by the user
                        encrypted_file_path, key = encrypt_file(file_path)    # Calls the encrypt_file function
                        window['-OUTPUT-'].update(
                            f'File encrypted successfully. Encrypted file saved as: {encrypted_file_path}')     # Gives confirmation that the file has been encrypted

                elif values["-Own-"]:                   # If own algorithm is selected
                    file_path = values['-FILE-']        # gets the file path from the browse
                    filename = os.path.basename(file_path)      # gets the filename from the file path
                    key = values['-IN-']
                    encrypt_own(filename, int(key), file_path)  # call the function to encrypt using our own method

                    window['-OUTPUT-'].update(
                        f'File encrypted successfully. Encrypted file saved as: ' + filename + '.encrypted')        # confirm that the data has been encrypted

            elif values["-Decrypt-"]:                   # if decrypt is selected
                if values["-Chosen-"]:                  # if chosen algorithm is selected
                    file_path = values['-FILE-']
                    password = values['-IN-']

                    if file_path and password:
                        file_extension = os.path.splitext(file_path)[1]     # Assigns the extension of the file to the variable
                        if file_extension == '.encrypted':                  # only be able to decrypt if the file is encrypted
                            decrypted_file_path = decrypt_file(file_path, key)
                            window['-OUTPUT-'].update(
                                f'File decrypted successfully. Decrypted file saved as: {decrypted_file_path}')
                        else:
                            window['-OUTPUT-'].update('Please select an encrypted file.')

                elif values["-Own-"]:                   # if own algorithm is selected

                    file_path = values['-FILE-']
                    filename = os.path.basename(file_path)
                    key = values['-IN-']
                    decrypt_own(filename, int(key), file_path)

                    window['-OUTPUT-'].update(f'File decrypted successfully. Decrypted file saved as: ' + filename)

        if event == "Close" or event == sg.WINDOW_CLOSED:       # if window is closed or close button is clicked
            break

    window.close()


if __name__ == '__main__':
    main()
