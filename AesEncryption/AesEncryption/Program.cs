using AesEncryption.Model;
using AesEncryption.Services;
using System;
using System.Linq;
using System.Text;

namespace AesEncryption
{
    class Program
    {
        static void Main(string[] args)
        {
            var aesService = new AesServices();

            var plainText = "1227714949306433";

            // 128
            //var keyText = "GKI sokagki SOKA";
            //var numberOfRound = 10;
            //var numberOfWords = 4;

            // 192
            var keyText = "GKI Soka Salatiga 050714";
            var numberOfRound = 12;
            var numberOfWords = 6;

            // 256
            //var keyText = "GKI Soka Salatiga 50714 No. B-2A";
            //var numberOfRound = 14;
            //var numberOfWords = 8;

            var plainTextInBytes = aesService.TranslateTextToBlockByteArray(4, plainText);

            Console.WriteLine("===== PLAIN TEXT =====");
            foreach (var pTextInBytes in plainTextInBytes)
                Console.Write("{0} ", BitConverter.ToString(new byte[] { pTextInBytes }));
            Console.WriteLine();
            //foreach (var pTextInBytes in plainTextInBytes)
            //    Console.Write("{0} ", pTextInBytes);
            //Console.WriteLine();

            var keyTextInBytes = aesService.TranslateTextToBlockByteArray(numberOfWords, keyText);

            Console.WriteLine("===== KEY =====");
            foreach (var kTextInBytes in keyTextInBytes)
                Console.Write("{0} ", BitConverter.ToString(new byte[] { kTextInBytes }));
            Console.WriteLine();
            //foreach (var kTextInBytes in keyTextInBytes)
            //    Console.Write("{0} ", kTextInBytes);
            //Console.WriteLine();

            #region ENCRYPT
            var cipherText = aesService.Encrypt(plainText, keyText, numberOfRound, numberOfWords);            
            Console.WriteLine("===== CIPHER TEXT =====");
            foreach (var cText in cipherText)
                Console.Write("{0} ", BitConverter.ToString(new byte[] { cText }));
            Console.WriteLine();
            //foreach (var cText in cipherText)
            //    Console.Write("{0} ", cText);
            //Console.WriteLine();
            #endregion

            #region DECRYPT
            var decryptedCipherText = aesService.Decrypt(cipherText, keyText, numberOfRound, numberOfWords);
            Console.WriteLine("===== DECRYPTED TEXT =====");
            foreach (var dCText in decryptedCipherText)
                Console.Write("{0} ", BitConverter.ToString(new byte[] { dCText }));
            Console.WriteLine();
            //foreach (var dCText in decryptedCipherText)
            //    Console.Write("{0} ", dCText);
            //Console.WriteLine();
            #endregion
        }
    }
}
