using System.Collections;

namespace Rochas.Encrypter.Interfaces
{
    public interface IEncrypter
    {
        byte[] DecryptAsBinary(byte[] encryptedArray);
        byte[] DecryptAsBinary(string encryptedText);
        string DecryptAsText(string encryptedText);
        BitArray DecryptBinary(byte[] encryptedArray, int arraySize);
        string DecryptFromString(byte[] encryptedArray);
        void Dispose();
        byte[] EncryptAsBinary(byte[] sourceArray);
        byte[] EncryptAsBinary(string text);
        string EncryptAsString(BitArray sourceArray, int arraySize);
        string EncryptAsText(string sourceText);
        byte[] EncryptBinary(BitArray sourceArray, int arraySize);
        string GenerateAuxHash(string sourceText);
        string GenerateBase64AuxHash(string sourceText);
        string GenerateBase64Hash(string sourceText);
        string GenerateHash(string sourceText);
        string GenerateHexStringAuxHash(string sourceText);
        string GenerateHexStringHash(string sourceText);
        string GeneratePassword();
        int GenerateVerifyDigits();
    }
}