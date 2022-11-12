using Microsoft.AspNetCore.SignalR;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Text;
using System.Runtime.Serialization.Formatters.Binary;
using System.Diagnostics;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.IO;

namespace WebSocketServer
{
    public class MyHub : Hub
    {
        public static KeysContainer keyContainer = new KeysContainer();

        /// <summary>
        /// establish connection to client
        /// </summary>
        /// <returns></returns>
        public override Task OnConnectedAsync()
        {
            Clients.Caller.SendAsync("connected", Context.ConnectionId);
            return base.OnConnectedAsync();

        }


        /// <summary>
        /// handling for disconnections
        /// </summary>
        /// <param name="exception"></param>
        /// <returns></returns>
        public override Task OnDisconnectedAsync(Exception exception)
        {
            // do the logging here
            //Trace.WriteLine(Context.ConnectionId + ' - disconnected');
            
            return base.OnDisconnectedAsync(exception);
        }


        /// <summary>
        /// encrypts keys and send to client using asymmetric encryption
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public async Task ReturnSecureKeys(string data)
        {
            // Debug.WriteLine(data);
            // return base.OnConnectedAsync();


            //convert string to key
            var publicKey = ConvertStringToKey(data);


            //generate symmetric encryption keys
            SymmetricAlgorithm al = Aes.Create();

            //get encryption keys and convert to string
            string key = Convert.ToBase64String(al.Key);
            string iv = Convert.ToBase64String(al.IV);

            //add keys to container for persistance
            KeysContainer container = new KeysContainer() { Key = key, Iv = iv };

            //convert data to byte array 
            byte[] dataToBeEncrypted = ConvertObjectToBytes(container);
            byte[] encryptedData;


            //encrypt and send message to client
            try
            {
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    rsa.ImportParameters(publicKey);
                    encryptedData = EncryptAsymmetric(dataToBeEncrypted, rsa.ExportParameters(false), false);
                }
                await Clients.All.SendAsync("RecieveKeys", encryptedData);
                keyContainer.Key = container.Key;
                keyContainer.Iv = container.Iv;
            }
            catch (ArgumentNullException)
            {

                Console.WriteLine("encryption failed");
            }
        }

        /// <summary>
        /// method recieves data from client and decrypts using symmetric encryption
        /// </summary>
        /// <param name="messageData"></param>
        /// <returns></returns>
        public async Task RecieveMessage(byte[] messageData)
        {
            string decryptedMessage;

            using (SymmetricAlgorithm al = Aes.Create())
            {
                al.KeySize = 256;
                al.IV = Convert.FromBase64String(keyContainer.Iv);
                al.Key = Convert.FromBase64String(keyContainer.Key);

                ICryptoTransform decryptor = al.CreateDecryptor();

                using (MemoryStream stream = new MemoryStream(messageData))
                {
                    using (CryptoStream crypto = new CryptoStream(stream, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader reader = new StreamReader(crypto))
                        {
                            decryptedMessage = reader.ReadToEnd();
                            Debug.WriteLine(decryptedMessage);
                        }
                    }

                }
            }

            //enrypt and return message to client
            byte[] newEncryption = EncryptSymmetric(decryptedMessage);
            await Clients.All.SendAsync("ReturnMessage", newEncryption);

        }

        /// <summary>
        /// Encrypts string message using symmetric algorithm
        /// </summary>
        /// <param name="message"></param>
        /// <returns></returns>
        public static byte[] EncryptSymmetric(string message)
        {
            using (SymmetricAlgorithm al = Aes.Create())
            {
                al.KeySize = 256;
                al.IV = Convert.FromBase64String(keyContainer.Iv);
                al.Key = Convert.FromBase64String(keyContainer.Key);
                byte[] encryptedMessage;
                ICryptoTransform decryptor = al.CreateEncryptor();

                using (MemoryStream stream = new MemoryStream())
                {
                    using (CryptoStream crypto = new CryptoStream(stream, decryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter writer = new StreamWriter(crypto))
                        {
                            writer.Write(message);
                        }
                    }
                    return encryptedMessage = stream.ToArray();
                }
            }
        }


        /// <summary>
        /// Encrypts data using asymmetric algorithm
        /// </summary>
        /// <param name="data"></param>
        /// <param name="keyInfo"></param>
        /// <param name="padding"></param>
        /// <returns></returns>
        public static byte[] EncryptAsymmetric(byte[] data, RSAParameters keyInfo, bool padding)
        {
            try
            {
                byte[] encryptedData;
                using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider())
                {
                    rsa.ImportParameters(keyInfo);
                    encryptedData = rsa.Encrypt(data, padding);
                }
                return encryptedData;
            }
            catch (CryptographicException cry)
            {
                Console.Write(cry.Message);
                return null;
            }
        }


        /// <summary>
        /// serializes encryption keys to json string, encoded as UTF8
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public static byte[] ConvertObjectToBytes(KeysContainer data)
        {
            var options = new JsonSerializerOptions { IncludeFields = true };
            var json = JsonSerializer.SerializeToUtf8Bytes(data, options);

            return json; 
        }


        /// <summary>
        /// converts a public key string to RSA parameters
        /// </summary>
        /// <param name="publicKey"></param>
        /// <returns></returns>
        public static RSAParameters ConvertStringToKey(string publicKey)
        {
            var reader = new StringReader(publicKey);
            var xml = new System.Xml.Serialization.XmlSerializer(typeof(RSAParameters));
            var rsaKey = (RSAParameters)xml.Deserialize(reader);
            return rsaKey;
        }
    }
}
