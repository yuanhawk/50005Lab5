# 50005Lab5

## Tasks for Part 1 [15pt]

Question 1 (1pt): Try to print to your screen the content of the input files, i.e., the plaintexts, using System.out.println().
What do you see? Are the files printable and human readable?<br>
**Your answer: The shorttext.txt contains a poem, and the longtext.txt contains an eBook.
Yes they are printable and human readable**

Question 2 (1pt): Store the output ciphertext (in byte[] format) to a variable, say cipherBytes.<br>
**Your answer: It contains a string of gibberish, with most chars not visualized and not
human readable.**

ϋ�Z@�͗J}�:s�;��&0`U��w��[�Y��o �B5bf�iՈܓ=�W�������0^�٫	ԃ!*�m�B��3~.�u�%
���� �p���}�M��;Q�%�K��	����������!<y��hc˯��t�
�F�9m���(�;cB+�Q����Cn�\6+ ���Q���t�Ӟ��������XQ��7E�W�6D�34ѕ'�(;�!��E�J���wy:W ʒ{�ϩ/�[�ƾ��Үt�8<�Q��eu
px��?m[��%9�_P��Y@�]d

Question 3 (3pt): Now convert the ciphertext in Question 2 into Base64 format and print it to the screen. Describe this 
output with comparison to question (2). What changed?<br>
**Your answer: The string remains gibberish, but all chars are now visualized as ASCII string format.**

ltHWDoKU4D1Sfz6zXQM4Yq4Bb62hLiclUC34FcixdD3l36NnpVrrFG0ZATdGRk0gNrAUjg+2Z2BEITZdpBR1DjjSQlj7iS/OjES6EJbjyvzR6+ke2X89mjPwlnK2hslRID9jVw9dazKj5NXwrz16HWmI6TdkzzziK

Question 4 (3pt): Is Base64 encoding a cryptographic operation? Why or why not?<br>
**Your answer: No, encoding is reversible and a keyless transformation of information. Encoding
helps to represent not human-readable text.**

Question 5 (3pt): Print out the decrypted ciphertext for the small file. Is the output the same as the output for question 
1?<br>
**Your answer: Yes, the string is the same**

Question 6 (4pt): Compare the lengths of the encryption result (in byte[] format) for shorttext.txt and longtext.txt. 
Does a larger file give a larger encrypted byte array? Why?<br>
**Your answer: Length of shorttext.txt & longtext.txt is 1480 and 17360 respectively. Yes,
a larger file gives a larger encrypted byte array, as the input data is divided in block size of 64 bits and encrypted.
A longer file would have a larger number of bits, and thus the encryption length is longer.**

## Tasks for Part 2 [15pt]

Question 1 (4pt): Compare the original image with the encrypted image. List at least 2 similarities and 1 difference. 
Also, can you identify the original image from the encrypted one?<br>
**Your answer: For the triangle encrypted image, the triangular shape is seen like the original image. The color appear
to have changed from white to green, and the background from black to pink
In the case of the SUTD logo, I was able to discern the SUTD logo like in the original picture.**

Question 2 (3pt): Why do those similarities that you describe in the above question exist? Explain the reason based on 
what you find out about how the ECB mode works. Your answer here should be as concise as possible. Remember, this is a 
5pt question.<br>
**Your answer: The ECB mode of operation takes identical input blocks and encrypts to the same output block and this allows
for the same triangular feature as seen in that of the encrypted triangle bitmap. In addition, the encryption of the same
output block would lead to the same color (black to purple, white to green).**

Question 3 (6pt): Now try to encrypt the image using the CBC mode instead (i.e., by specifying "DES/CBC/PKCS5Padding"). 
Compare the result with that obtained using ECB mode). State 2 differences that you observe. For each of the differences, 
explain its cause based on what you find out about how CBC mode works. Your answer should refer to ecb.bmp output that you 
produce.<br>
**Your answer: The CBC tends to generate an indiscernible SUTD logo, whereas the ECB generates an image with the logo seen.
The CBC tends to generate color in strips with a different hue, whereas ECB view the image with of the same color.
In the CBC mode, the block is combined with the ciphertext of the previous block via a xor operation. As such the current
block is different from the previous block, and thus the image encrypted seems more pixelated and have more stripes.**

Question 4 (3pt): Do you observe any security issue with image obtained from CBC mode encryption of “SUTD.bmp”? What is
the reason for such an issue to surface?<br>
**Your answer: No, CBC is typically more resistive towards cryptanalysis than ECB, and the reversal of the pixels are more
difficult in the CBC than in the ECB.**

Question 5 (4pt): Can you explain and try on what would be the result if the data were to be taken from bottom to top
along the columns of the image? (As opposed to top to bottom).  Can you try your new approach on “triangle.bmp” and comment
on observation? Name the resulting image as triangle_new.bmp.<br> 
**Your answer: The encrypted image has more of yellow tinge as opposed to the purple background with green triangle for
ECB mode encryption**

## Tasks for Part 3 [15pt]
Question 1 (2pt): What are the sizes in bytes of the message digests that you created for the two different files?<br>
**Your answer: Both are 16 bytes.**

Question 2 (3pt): Compare the sizes of the signed message digests (in byte[] encryptedBytes = eCipher.doFinal(data.getBytes());
format) for shorttext.txt and longtext.txt. Does a larger file size give a longer signed message digest? Why or why not?
Explain your answer concisely.<br>
**Your answer: No a larger file does not give a longer signed message digest. The message digest algorithm is a hash function
that maps the input data to an arbitrary length of fixed length. The length of the output of a message digest is constant
and in the case of the MD5, it always output 16 bytes as seen in the hash code below.**

UERkP8pWz1n9gUPf+l4TyQ==
