# 50005Lab5

## Tasks for Part [15pt]

Question 1 (1pt): Try to print to your screen the content of the input files, i.e., the plaintexts, using System.out.println().
What do you see? Are the files printable and human readable?<br>
**<span style="color:blue">Your answer: </span>The shorttext.txt contains a poem, and the longtext.txt contains an eBook.
Yes they are printable and human readable**

Question 2 (1pt): Store the output ciphertext (in byte[] format) to a variable, say cipherBytes.
**<span style="color:blue">Your answer: </span>It contains a string of gibberish, with most chars not visualized and not
human readable.**

ϋ�Z@�͗J}�:s�;��&0`U��w��[�Y��o �B5bf�iՈܓ=�W�������0^�٫	ԃ!*�m�B��3~.�u�%
���� �p���}�M��;Q�%�K��	����������!<y��hc˯��t�
�F�9m���(�;cB+�Q����Cn�\6+ ���Q���t�Ӟ��������XQ��7E�W�6D�34ѕ'�(;�!��E�J���wy:W ʒ{�ϩ/�[�ƾ��Үt�8<�Q��eu
px��?m[��%9�_P��Y@�]d

Question 3 (3pt): Now convert the ciphertext in Question 2 into Base64 format and print it to the screen. Describe this output with comparison to question (2). What changed?
**<span style="color:blue">Your answer: </span>The string remains gibberish, but all chars are now visualized as ASCII string format.**

ltHWDoKU4D1Sfz6zXQM4Yq4Bb62hLiclUC34FcixdD3l36NnpVrrFG0ZATdGRk0gNrAUjg+2Z2BEITZdpBR1DjjSQlj7iS/OjES6EJbjyvzR6+ke2X89mjPwlnK2hslRID9jVw9dazKj5NXwrz16HWmI6TdkzzziK

Question 4 (3pt): Is Base64 encoding a cryptographic operation? Why or why not?
**<span style="color:blue">Your answer: </span>No, encoding is reversible and a keyless transformation of information. Encoding
helps to represent not human-readable text.**

Question 5 (3pt): Print out the decrypted ciphertext for the small file. Is the output the same as the output for question 1?
**<span style="color:blue">Your answer: </span>Yes, the string is the same**

Question 6 (4pt): Compare the lengths of the encryption result (in byte[] format) for shorttext.txt and longtext.txt. Does a larger file give a larger encrypted byte array? Why?
**<span style="color:blue">Your answer: </span>Length of shorttext.txt & longtext.txt is 1480 and 17360 respectively. Yes,
a larger file gives a larger encrypted byte array, as the input data is divided in block size of 64 bits and encrypted.
A longer file would have a larger number of bits, and thus the encryption length is longer.**
