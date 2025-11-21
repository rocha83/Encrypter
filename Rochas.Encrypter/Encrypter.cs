using Rochas.Encrypter.Interfaces;
using Rochas.Extensions;
using System;
using System.Collections;
using System.Security.Cryptography;
using System.Text;

namespace Rochas.Security.Encryption
{
    public class Encrypter : IEncrypter, IDisposable
    {
        #region Declarations
        
        private readonly byte[] _cryptoKey;

        #endregion

        #region Constructors

        public Encrypter()
        {
        }

        public Encrypter(string cryptoKey)
        {
            if (string.IsNullOrWhiteSpace(cryptoKey))
                throw new ArgumentNullException("Crypto config key");

            _cryptoKey = Convert.FromBase64String(cryptoKey);
        }

        #endregion

        #region Public Cryptography Methods

        public byte[] EncryptAsBinary(string text)
        {
            EnsureCryptoKey();

            byte[] textBytes = Encoding.UTF8.GetBytes(text);
            
            return EncryptContent(textBytes);
        }

        public byte[] EncryptAsBinary(byte[] sourceArray)
        {
            EnsureCryptoKey();

            return EncryptContent(sourceArray);
        }

        public byte[] EncryptBinary(BitArray sourceArray, int arraySize)
        {
            EnsureCryptoKey();

            byte[] destinArray = new byte[arraySize];
            sourceArray.CopyTo(destinArray, 0);

            return EncryptContent(destinArray);
        }

        public byte[] DecryptAsBinary(byte[] encryptedArray)
        {
            EnsureCryptoKey();

            return DecryptContent(encryptedArray);
        }

        public BitArray DecryptBinary(byte[] encryptedArray, int arraySize)
        {
            EnsureCryptoKey();

            BitArray destinArray = new BitArray(DecryptContent(encryptedArray))
            {
                Length = arraySize
            };

            return destinArray;
        }

        public byte[] DecryptAsBinary(string encryptedText)
        {
            EnsureCryptoKey();

            byte[] encryptedArray = Convert.FromBase64String(encryptedText);
            byte[] destinArray = DecryptContent(encryptedArray);

            return destinArray;
        }

        public string EncryptAsString(BitArray sourceArray, int arraySize)
        {
            EnsureCryptoKey();

            byte[] encryptedArray;
            byte[] arrayToConvert = new byte[arraySize];

            sourceArray.CopyTo(arrayToConvert, 0);

            encryptedArray = EncryptContent(arrayToConvert);

            return Convert.ToBase64String(encryptedArray);
        }

        public string DecryptBinary(byte[] encryptedArray)
        {
            EnsureCryptoKey();

            byte[] arrayToConvert = DecryptContent(encryptedArray);
            StringBuilder destinText = new StringBuilder();

            foreach (byte token in arrayToConvert)
                destinText.Append(Convert.ToChar(token));

            return destinText.ToString();
        }

        public string EncryptAsText(string sourceText)
        {
            EnsureCryptoKey();

            byte[] encryptedArray = Encoding.UTF8.GetBytes(sourceText);

            byte[] destinArray = EncryptContent(encryptedArray);

            return Convert.ToBase64String(destinArray);
        }

        public string DecryptAsText(string encryptedText)
        {
            EnsureCryptoKey();

            byte[] encryptedArray = Convert.FromBase64String(encryptedText);

            byte[] arrayToConvert = DecryptContent(encryptedArray);
            StringBuilder destinText = new StringBuilder();

            foreach (byte simbolo in arrayToConvert)
                destinText.Append(Convert.ToChar(simbolo));

            return destinText.ToString();
        }

        #endregion

        #region Public Hashing Methods

        public string GenerateHash(string sourceText)
        {
            using var hash = SHA512.Create();
            return hash.ComputeHash(sourceText.ToByteArray()).ToNewString();
        }

        public string GenerateBase64Hash(string sourceText)
        {
            using var hash = SHA512.Create();
            return hash.ComputeHash(sourceText.ToByteArray()).ToNewBase64String();
        }

        public string GenerateHexStringHash(string sourceText)
        {
            using var hash = SHA512.Create();
            return hash.ComputeHash(sourceText.ToByteArray()).ToNewHexString();
        }

        public string GenerateAuxHash(string sourceText)
        {
            using var auxHash = MD5.Create();
            return auxHash.ComputeHash(sourceText.ToByteArray()).ToNewString();
        }

        public string GenerateBase64AuxHash(string sourceText)
        {
            using var auxHash = MD5.Create();
            return auxHash.ComputeHash(sourceText.ToByteArray()).ToNewBase64String();
        }

        public string GenerateHexStringAuxHash(string sourceText)
        {
            using var auxHash = MD5.Create();
            return auxHash.ComputeHash(sourceText.ToByteArray()).ToNewHexString();
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

        private void EnsureCryptoKey()
        {
            if (_cryptoKey == null)
                throw new ArgumentNullException("Crypto config key");
        }

        private byte[] EncryptContent(byte[] plainBytes)
        {
            if ((plainBytes == null) || (plainBytes.Length == 0))
                throw new ArgumentNullException(nameof(plainBytes));

            byte[] cipherBytes = new byte[plainBytes.Length];
            var nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
            var tag = new byte[AesGcm.TagByteSizes.MaxSize];
            RandomNumberGenerator.Fill(nonce);

            var cryptoProvider = new AesGcm(_cryptoKey);
            cryptoProvider.Encrypt(nonce, plainBytes, cipherBytes, tag);

            byte[] result = new byte[nonce.Length + tag.Length + cipherBytes.Length];
            Buffer.BlockCopy(nonce, 0, result, 0, nonce.Length);
            Buffer.BlockCopy(tag, 0, result, nonce.Length, tag.Length);
            Buffer.BlockCopy(cipherBytes, 0, result, nonce.Length + tag.Length, cipherBytes.Length);

            CryptographicOperations.ZeroMemory(plainBytes);
            CryptographicOperations.ZeroMemory(cipherBytes);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(tag);

            return result;
        }

        private byte[] DecryptContent(byte[] encryptedBytes)
        {
            if ((encryptedBytes == null) || (encryptedBytes.Length == 0))
                throw new ArgumentNullException(nameof(encryptedBytes));

            int nonceSize = AesGcm.NonceByteSizes.MaxSize;
            int tagSize = AesGcm.TagByteSizes.MaxSize;
            int cipherSize = encryptedBytes.Length - nonceSize - tagSize;
            var nonce = new byte[AesGcm.NonceByteSizes.MaxSize];
            var tag = new byte[AesGcm.TagByteSizes.MaxSize];

            if (cipherSize < 0)
                throw new Exception("Invalid encrypted data length");

            byte[] cipherBytes = new byte[cipherSize];

            Buffer.BlockCopy(encryptedBytes, 0, nonce, 0, nonceSize);
            Buffer.BlockCopy(encryptedBytes, nonceSize, tag, 0, tagSize);
            Buffer.BlockCopy(encryptedBytes, nonceSize + tagSize, cipherBytes, 0, cipherSize);

            byte[] result = new byte[cipherBytes.Length];

            var cryptoProvider = new AesGcm(_cryptoKey);
            cryptoProvider.Decrypt(nonce, cipherBytes, tag, result);

            CryptographicOperations.ZeroMemory(encryptedBytes);
            CryptographicOperations.ZeroMemory(cipherBytes);
            CryptographicOperations.ZeroMemory(nonce);
            CryptographicOperations.ZeroMemory(tag);

            return result;
        }

        public void Dispose()
        {
            GC.SuppressFinalize(this);
        }

        #endregion
    }
}
