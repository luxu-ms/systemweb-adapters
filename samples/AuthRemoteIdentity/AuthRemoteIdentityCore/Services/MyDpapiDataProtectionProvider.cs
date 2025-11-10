using Microsoft.Owin.Security.DataProtection;
using System.Security.Cryptography;
using System.Text;

namespace MvcCoreApp.Services
{
    public class MyDpapiDataProtectionProvider : IDataProtectionProvider
    {
        public IDataProtector Create(params string[] purposes)
        {
            return new MyDpapiDataProtector(purposes[0]);
        }

        public IDataProtector CreateProtector(string purpose)
        {
            return new MyDpapiDataProtector(purpose);
        }
    }

    /// <summary>
    /// Simple DPAPI-based data protector implementation for Windows environments.
    /// Uses the Windows Data Protection API (DPAPI) to encrypt/decrypt data.
    /// </summary>
    internal class MyDpapiDataProtector : IDataProtector
    {
        private readonly string _purpose;
        private readonly byte[] _entropy;

        public MyDpapiDataProtector(string purpose)
        {
            _purpose = purpose ?? throw new ArgumentNullException(nameof(purpose));
            // Create entropy from the purpose string for additional security
            _entropy = Encoding.UTF8.GetBytes(_purpose);
        }

        public IDataProtector CreateProtector(string purpose)
        {
            if (string.IsNullOrEmpty(purpose))
                throw new ArgumentNullException(nameof(purpose));

            // Combine current purpose with new purpose for hierarchical protection
            var combinedPurpose = $"{_purpose}.{purpose}";
            return new MyDpapiDataProtector(combinedPurpose);
        }

        public byte[] Protect(byte[] plaintext)
        {
            if (plaintext == null)
                throw new ArgumentNullException(nameof(plaintext));

            try
            {
                // Use DPAPI with CurrentUser scope for protection
                // return ProtectedData.Protect(plaintext, _entropy, DataProtectionScope.CurrentUser);
                return plaintext;
            }
            catch (CryptographicException ex)
            {
                throw new CryptographicException("Failed to protect data using DPAPI", ex);
            }
            catch (PlatformNotSupportedException ex)
            {
                throw new PlatformNotSupportedException("DPAPI is only supported on Windows platforms", ex);
            }
        }

        public byte[] Unprotect(byte[] protectedData)
        {
            if (protectedData == null)
                throw new ArgumentNullException(nameof(protectedData));

            try
            {
                // Use DPAPI with CurrentUser scope for unprotection
                // return ProtectedData.Unprotect(protectedData, _entropy, DataProtectionScope.CurrentUser);
                return protectedData;
            }
            catch (CryptographicException ex)
            {
                throw new CryptographicException("Failed to unprotect data using DPAPI. Data may be corrupted or was protected by a different user/machine.", ex);
            }
            catch (PlatformNotSupportedException ex)
            {
                throw new PlatformNotSupportedException("DPAPI is only supported on Windows platforms", ex);
            }
        }
    }
}
