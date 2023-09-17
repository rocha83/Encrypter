using System;
using System.Text;
using System.Collections;
using System.Security.Cryptography;
using Rochas.Extensions;

namespace Rochas.Security.Encryption
{
    public class Encrypter : IDisposable
    {
        #region Declarations

        private readonly AesCryptoServiceProvider _cryptoProvider;
        private readonly SHA512 _hashProvider;
        private readonly MD5 _auxHashProvider;

        #endregion

        #region Constructors

        public Encrypter()
        {
            _hashProvider = SHA512.Create();
            _auxHashProvider = MD5.Create();
        }

        public Encrypter(string cryptoKey, string cryptoVector)
        {
            _hashProvider = SHA512.Create();
            _auxHashProvider = MD5.Create();

            if (!string.IsNullOrWhiteSpace(cryptoKey) && !string.IsNullOrWhiteSpace(cryptoKey))
            {
                _cryptoProvider = new AesCryptoServiceProvider
                {
                    IV = Convert.FromBase64String(cryptoVector),
                    Key = Convert.FromBase64String(cryptoKey)
                };
            }
            else
                throw new ArgumentNullException("Crypto config keys");
        }

        #endregion

        #region Public Cryptography Methods

        public byte[] EncryptAsBinary(string text)
        {
            if (_cryptoProvider == null)
                throw new ArgumentNullException("Crypto config keys");

            char[] contentToConvert = text.ToCharArray();
            byte[] convertedContent = new byte[contentToConvert.Length];

            int cont = 0;
            foreach (char token in contentToConvert)
            {
                convertedContent[cont] = Convert.ToByte(token);
                cont++;
            }

            return _cryptoProvider.CreateEncryptor().TransformFinalBlock(convertedContent, 0, convertedContent.Length);
        }

        public byte[] EncryptAsBinary(byte[] sourceArray)
        {
            if (_cryptoProvider == null)
                throw new ArgumentNullException("Crypto config keys");

            byte[] convertedContent = _cryptoProvider.CreateEncryptor().TransformFinalBlock(sourceArray, 0, sourceArray.Length);

            return convertedContent;
        }

        public byte[] EncryptBinary(BitArray sourceArray, int arraySize)
        {
            if (_cryptoProvider == null)
                throw new ArgumentNullException("Crypto config keys");

            byte[] destinArray = new byte[arraySize];

            sourceArray.CopyTo(destinArray, 0);

            return _cryptoProvider.CreateEncryptor().TransformFinalBlock(destinArray, 0, destinArray.Length);
        }

        public byte[] DecryptAsBinary(byte[] encryptedArray)
        {
            if (_cryptoProvider == null)
                throw new ArgumentNullException("Crypto config keys");

            return _cryptoProvider.CreateDecryptor().TransformFinalBlock(encryptedArray, 0, encryptedArray.Length);
        }

        public BitArray DecryptBinary(byte[] encryptedArray, int arraySize)
        {
            if (_cryptoProvider == null)
                throw new ArgumentNullException("Crypto config keys");

            BitArray destinArray = new BitArray(_cryptoProvider.CreateDecryptor().TransformFinalBlock(encryptedArray, 0, encryptedArray.Length))
            {
                Length = arraySize
            };

            return destinArray;
        }

        public byte[] DecryptAsBinary(string encryptedText)
        {
            if (_cryptoProvider == null)
                throw new ArgumentNullException("Crypto config keys");

            byte[] encryptedArray = Convert.FromBase64String(encryptedText);

            byte[] destinArray = _cryptoProvider.CreateDecryptor().TransformFinalBlock(encryptedArray, 0, encryptedArray.Length);

            return destinArray;
        }

        public string EncryptAsString(BitArray sourceArray, int arraySize)
        {
            if (_cryptoProvider == null)
                throw new ArgumentNullException("Crypto config keys");

            byte[] encryptedArray;
            byte[] arrayToConvert = new byte[arraySize];

            sourceArray.CopyTo(arrayToConvert, 0);

            encryptedArray = _cryptoProvider.CreateEncryptor().TransformFinalBlock(arrayToConvert, 0, arrayToConvert.Length);

            return Convert.ToBase64String(encryptedArray);
        }

        public string DecryptFromString(byte[] encryptedArray)
        {
            if (_cryptoProvider == null)
                throw new ArgumentNullException("Crypto config keys");

            byte[] arrayToConvert = _cryptoProvider.CreateDecryptor().TransformFinalBlock(encryptedArray, 0, encryptedArray.Length);
            StringBuilder destinText = new StringBuilder();

            foreach (byte token in arrayToConvert)
                destinText.Append(Convert.ToChar(token));

            return destinText.ToString();
        }

        public string EncryptAsText(string sourceText)
        {
            if (_cryptoProvider == null)
                throw new ArgumentNullException("Crypto config keys");

            char[] arrayToConvert = sourceText.ToCharArray();
            byte[] encryptedArray = new byte[arrayToConvert.Length];

            int cont = 0;
            foreach (char token in arrayToConvert)
            {
                encryptedArray[cont] = Convert.ToByte(token);
                cont++;
            }

            byte[] destinArray = _cryptoProvider.CreateEncryptor().TransformFinalBlock(encryptedArray, 0, encryptedArray.Length);

            return Convert.ToBase64String(destinArray);
        }

        public string DecryptAsText(string encryptedText)
        {
            if (_cryptoProvider == null)
                throw new ArgumentNullException("Crypto config keys");

            byte[] encryptedArray = Convert.FromBase64String(encryptedText);

            byte[] arrayToConvert = _cryptoProvider.CreateDecryptor().TransformFinalBlock(encryptedArray, 0, encryptedArray.Length);
            StringBuilder destinText = new StringBuilder();

            foreach (byte simbolo in arrayToConvert)
                destinText.Append(Convert.ToChar(simbolo));

            return destinText.ToString();
        }

        #endregion

        #region Public Hashing Methods

        public string GenerateHash(string sourceText)
        {
            return _hashProvider.ComputeHash(sourceText.ToByteArray()).ToNewString();
        }

        public string GenerateAuxHash(string sourceText)
        {
            return _auxHashProvider.ComputeHash(sourceText.ToByteArray()).ToNewString();
        }

        public string GenerateBase64Hash(string sourceText)
        {
            return _hashProvider.ComputeHash(sourceText.ToByteArray()).ToNewBase64String();
        }

        public string GenerateBase64AuxHash(string sourceText)
        {
            return _auxHashProvider.ComputeHash(sourceText.ToByteArray()).ToNewBase64String();
        }

        public string GenerateHexStringHash(string sourceText)
        {
            return _hashProvider.ComputeHash(sourceText.ToByteArray()).ToNewHexString();
        }

        public string GenerateHexStringAuxHash(string sourceText)
        {
            return _auxHashProvider.ComputeHash(sourceText.ToByteArray()).ToNewHexString();
        }

        #endregion

        #region Public Data Generation Methods

        public string GeneratePassword()
        {
            var result = Guid.NewGuid().ToString();
            return result[..8];
        }

        public int GenerateVerifyDigits()
        {
            return new Random().Next(99999);
        }

        #endregion

        #region Helper Methods

        public void Dispose()
        {
            GC.ReRegisterForFinalize(this);
        }

        #endregion
    }
}
