using AesEncryption.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace AesEncryption.Services
{
    public class AesServices
    {
        private readonly SBox _sBox;
        private readonly RConstants _rConstants;
        private readonly GaloisMultiplicationLookupTables _galoisMultiplicationLookupTables;

        public AesServices()
        {
            _sBox = new SBox();
            _rConstants = new RConstants();
            _galoisMultiplicationLookupTables = new GaloisMultiplicationLookupTables();
        }

        public byte[,] Encrypt(string plainText, string keyText, int nOfRounds, int nOfWords)
        {
            string cipherText = string.Empty;
            byte[,] cipherText_inBytes;

            var plainTextInBytes = TranslateTextToBlockByteArray(4, plainText);
            var keyTextInBytes = TranslateTextToBlockByteArray(nOfWords, keyText);
            var generatedExpansionKey = GenerateExpensionKeys(keyTextInBytes, nOfRounds, nOfWords);

            // PRE-ROUND = 0
            byte[,] firstKey = generatedExpansionKey.Values.First();
            cipherText_inBytes = AddRoundKeys(plainTextInBytes, firstKey);

            for (int i = 1; i <= nOfRounds; i++)
            {
                // 1 - Sub Byte
                cipherText_inBytes = ForwardSubstituteBytes(cipherText_inBytes);

                // 2 - Shift Row
                cipherText_inBytes = ForwardShiftRows(cipherText_inBytes);

                if (i != nOfRounds)
                {
                    // 3 - Mix Column
                    cipherText_inBytes = ForwardMixColumns(cipherText_inBytes);
                }

                // 4 - Add Round Key
                byte[,] expansionKey; generatedExpansionKey.TryGetValue(i, out expansionKey);
                cipherText_inBytes = AddRoundKeys(cipherText_inBytes, expansionKey);
            }              

            return cipherText_inBytes;
        }

        public byte[,] Decrypt(byte[,] cipherText, string keyText, int nOfRounds, int nOfWords)
        {
            string decryptedCipherText = string.Empty;
            var decryptedCipherText_InBytes = cipherText;
            var keyTextInBytes = TranslateTextToBlockByteArray(nOfWords, keyText);
            var generatedExpansionKey = GenerateExpensionKeys(keyTextInBytes, nOfRounds, nOfWords);

            // PRE-ROUND = 0
            byte[,] lastKey = generatedExpansionKey.Values.Last();
            decryptedCipherText_InBytes = AddRoundKeys(decryptedCipherText_InBytes, lastKey);

            for (int i = nOfRounds; i > 0; i--)
            {
                // 1 - Invers Shift Row
                decryptedCipherText_InBytes = InverseShiftRows(decryptedCipherText_InBytes);

                // 2 - Inverse Sub Byte
                decryptedCipherText_InBytes = InverseSubstituteBytes(decryptedCipherText_InBytes);

                // 3 - Add Round Key
                byte[,] expansionKey; generatedExpansionKey.TryGetValue(i - 1, out expansionKey);
                decryptedCipherText_InBytes = AddRoundKeys(decryptedCipherText_InBytes, expansionKey);

                if (i > 1)
                {
                    // 4 - Inverse Mix Column
                    decryptedCipherText_InBytes = InverseMixColumns(decryptedCipherText_InBytes);
                }
            }
            
            return decryptedCipherText_InBytes;
        }

        #region PRIVATE METHODS
        private byte ForwardSubByte(byte key)
        {
            var _key = BitConverter.ToString(new byte[] { key }).ToLower();
            return _sBox.forwardSbox.GetValueOrDefault(_key);
        }

        private byte InverseSubByte(byte key)
        {
            var _key = BitConverter.ToString(new byte[] { key }).ToLower();
            return _sBox.inverseSbox.GetValueOrDefault(_key);
        }
        #endregion

        public byte[,] TranslateTextToBlockByteArray(int numberOfColumns, string text)
        {
            var resultBlockArray = new byte[4, numberOfColumns];

            var textBytes = Encoding.UTF8.GetBytes(text);
            int resultRowIndex = 0, resultColumnIndex = 0;
            foreach (var textByte in textBytes)
            {
                resultBlockArray[resultRowIndex, resultColumnIndex] = textByte;

                if (resultRowIndex == resultBlockArray.GetLength(0) - 1)
                    resultColumnIndex++;

                if (resultRowIndex != resultBlockArray.GetLength(0) - 1)
                    resultRowIndex++;
                else
                    resultRowIndex = 0;
            }

            return resultBlockArray;
        }        

        public Dictionary<int, byte[,]> GenerateExpensionKeys(byte[,] key, int nOfRounds, int nOfWords)
        {
            var blockSize = 4;
            var resultExpensionKeys = new Dictionary<int, byte[,]>();
            var resultExpensionKeys_inBlock = new Dictionary<int, byte[,]>();

            #region GENERATION KEYS
            for (int i = 0; i < nOfWords; i++)
            {
                var word = new byte[blockSize, 1];
                for (int iRow = 0; iRow < word.GetLength(0); iRow++)
                {
                    word[iRow, word.GetLength(1) - 1] = key[iRow, i];
                }

                resultExpensionKeys.Add(i, word);
            }

            for (int i = nOfWords; i < blockSize * (nOfRounds + 1); i++)
            {
                var word = resultExpensionKeys.Values.Last();
                if (i % nOfWords == 0)
                {
                    // ROTATION + SUB BYTE
                    for (int iRow = 0; iRow < word.GetLength(0); iRow++)
                    {
                        var selectedItem = word[iRow, word.GetLength(1) - 1];
                        var iRowNew = iRow - 1;

                        if (iRowNew < 0)
                            word[word.GetLength(0) - 1, word.GetLength(1) - 1] = ForwardSubByte(selectedItem);
                        else
                            word[iRowNew, word.GetLength(1) - 1] = ForwardSubByte(selectedItem);
                    }

                    // RCON
                    word[0, 0] = (byte)(word[0, 0] ^ _rConstants.rCon[i / nOfWords][0, 0]);
                }
                else if (nOfWords > 6 && i % blockSize == 4)
                {
                    // SUB BYTE
                    for (int iRow = 0; iRow < word.GetLength(0); iRow++)
                    {
                        var selectedItem = word[iRow, word.GetLength(1) - 1];
                        word[iRow, word.GetLength(1) - 1] = ForwardSubByte(selectedItem);
                    }
                }

                var temp = new byte[blockSize, 1];
                for (int iRow = 0; iRow < word.GetLength(0); iRow++)
                {
                    temp[iRow, 0] = (byte)(resultExpensionKeys[i - nOfWords][iRow, 0] ^ word[iRow, 0]);
                }

                resultExpensionKeys.Add(i, temp);
            }
            #endregion

            #region SPLIT TO BLOCK
            int indexResult = 0, columnIndex = 0;
            var expandedKey = new byte[blockSize, blockSize];
            foreach (var item in resultExpensionKeys)
            {
                for (int i = 0; i < blockSize; i++)
                    expandedKey[i, columnIndex] = item.Value[i, 0];

                if (columnIndex != expandedKey.GetLength(1) - 1)
                {
                    columnIndex++;
                }
                else
                {
                    resultExpensionKeys_inBlock.Add(indexResult, expandedKey);
                    columnIndex = 0;
                    indexResult++;
                }
            }
            #endregion

            return resultExpensionKeys_inBlock;
        }

        public byte[,] AddRoundKeys(byte[,] array1, byte[,] array2)
        {
            var resultBlockArray = new byte[array1.GetLength(0), array1.GetLength(1)];

            for (int row = 0; row < array1.GetLength(0); row++)
            {
                for (int column = 0; column < array1.GetLength(1); column++)
                {
                    resultBlockArray[row, column] = (byte)(array1[row, column] ^ array2[row, column]);
                }
            }

            return resultBlockArray;
        }

        public byte[,] ForwardSubstituteBytes(byte[,] array1)
        {
            for (int row = 0; row < array1.GetLength(0); row++)
            {
                for (int col = 0; col < array1.GetLength(1); col++)
                {
                    array1[row, col] = ForwardSubByte(array1[row, col]);
                }
            }

            return array1;
        }

        public byte[,] ForwardShiftRows(byte[,] array1)
        {            
            for (int row = 1; row < array1.GetLength(0); row++)
            {
                var k = 0;

                while (k < row)
                {
                    byte temp = array1[row, 0];
                    for (int col = 0; col < array1.GetLength(1) - 1; col++)
                    {
                        array1[row, col] = array1[row, col + 1];
                    }
                    array1[row, array1.GetLength(1) - 1] = temp;

                    k++;
                }
            }

            return array1;
        }

        public byte[,] ForwardMixColumns(byte[,] array1)
        {
            var resultArray = new byte[array1.GetLength(0), array1.GetLength(1)];

            byte[,] matrix =
            {
                { 0x02, 0x03, 0x01, 0x01 },
                { 0x01, 0x02, 0x03, 0x01 },
                { 0x01, 0x01, 0x02, 0x03 },
                { 0x03, 0x01, 0x01, 0x02 }
            };

            for (int col = 0; col < resultArray.GetLength(1); col++)
            {
                resultArray[0, col] = (byte)(
                    _galoisMultiplicationLookupTables.Calculate(array1[0, col], 0x02) ^
                    _galoisMultiplicationLookupTables.Calculate(array1[1, col], 0x03) ^
                    _galoisMultiplicationLookupTables.Calculate(array1[2, col], 0x01) ^
                    _galoisMultiplicationLookupTables.Calculate(array1[3, col], 0x01)
                );
                resultArray[1, col] = (byte)(
                    _galoisMultiplicationLookupTables.Calculate(array1[0, col], 0x01) ^ 
                    _galoisMultiplicationLookupTables.Calculate(array1[1, col], 0x02) ^
                    _galoisMultiplicationLookupTables.Calculate(array1[2, col], 0x03) ^
                    _galoisMultiplicationLookupTables.Calculate(array1[3, col], 0x01)
                );
                resultArray[2, col] = (byte)(
                    _galoisMultiplicationLookupTables.Calculate(array1[0, col], 0x01) ^
                    _galoisMultiplicationLookupTables.Calculate(array1[1, col], 0x01) ^
                    _galoisMultiplicationLookupTables.Calculate(array1[2, col], 0x02) ^
                    _galoisMultiplicationLookupTables.Calculate(array1[3, col], 0x03)
                );
                resultArray[3, col] = (byte)(
                    _galoisMultiplicationLookupTables.Calculate(array1[0, col], 0x03) ^
                    _galoisMultiplicationLookupTables.Calculate(array1[1, col], 0x01) ^
                    _galoisMultiplicationLookupTables.Calculate(array1[2, col], 0x01) ^
                    _galoisMultiplicationLookupTables.Calculate(array1[3, col], 0x02)
                );
            }

            return resultArray;
        }

        public byte[,] InverseShiftRows(byte[,] array1)
        {
            for (int row = 1; row < array1.GetLength(0); row++)
            {
                var k = 0;

                while (k < row)
                {
                    byte temp = array1[row, array1.GetLength(1) - 1];
                    for (int col = array1.GetLength(1) - 1; col > 0 ; col--)
                    {
                        array1[row, col] = array1[row, col - 1];
                    }
                    array1[row, 0] = temp;

                    k++;
                }
            }

            return array1;
        }

        public byte[,] InverseMixColumns(byte[,] array1)
        {
            var resultArray = new byte[array1.GetLength(0), array1.GetLength(1)];

            byte[,] matrix =
            {
                { 0x0e, 0x0b, 0x0d, 0x09 },
                { 0x09, 0x0e, 0x0b, 0x0d },
                { 0x0d, 0x09, 0x0e, 0x0b },
                { 0x0b, 0x0d, 0x09, 0x0e }
            };

            for (int col = 0; col < resultArray.GetLength(1); col++)
            {
                for (int row = 0; row < resultArray.GetLength(0); row++)
                {
                    resultArray[0, col] = (byte)(
                    _galoisMultiplicationLookupTables.Calculate(array1[0, col], 0x0e) ^
                    _galoisMultiplicationLookupTables.Calculate(array1[1, col], 0x0b) ^
                    _galoisMultiplicationLookupTables.Calculate(array1[2, col], 0x0d) ^
                    _galoisMultiplicationLookupTables.Calculate(array1[3, col], 0x09)
                );
                resultArray[1, col] = (byte)(
                    _galoisMultiplicationLookupTables.Calculate(array1[0, col], 0x09) ^
                    _galoisMultiplicationLookupTables.Calculate(array1[1, col], 0x0e) ^
                    _galoisMultiplicationLookupTables.Calculate(array1[2, col], 0x0b) ^
                    _galoisMultiplicationLookupTables.Calculate(array1[3, col], 0x0d)
                );
                resultArray[2, col] = (byte)(
                    _galoisMultiplicationLookupTables.Calculate(array1[0, col], 0x0d) ^
                    _galoisMultiplicationLookupTables.Calculate(array1[1, col], 0x09) ^
                    _galoisMultiplicationLookupTables.Calculate(array1[2, col], 0x0e) ^
                    _galoisMultiplicationLookupTables.Calculate(array1[3, col], 0x0b)
                );
                resultArray[3, col] = (byte)(
                    _galoisMultiplicationLookupTables.Calculate(array1[0, col], 0x0b) ^
                    _galoisMultiplicationLookupTables.Calculate(array1[1, col], 0x0d) ^
                    _galoisMultiplicationLookupTables.Calculate(array1[2, col], 0x09) ^
                    _galoisMultiplicationLookupTables.Calculate(array1[3, col], 0x0e)
                );
                }
            }

            return resultArray;
        }

        public byte[,] InverseSubstituteBytes(byte[,] array1)
        {
            for (int row = 0; row < array1.GetLength(0); row++)
            {
                for (int col = 0; col < array1.GetLength(1); col++)
                {
                    array1[row, col] = InverseSubByte(array1[row, col]);
                }
            }

            return array1;
        }
    }
}
