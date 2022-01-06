using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Web;

namespace ConsoleApp_InstagramUploadImg
{
    internal class Program
    {
        private static readonly string _userAgent = "Instagram 6.21.2 Android (19/4.4.2; 480dpi; 1152x1920; Meizu; MX4; mx4; mt6595; en_US)";

        private static readonly string _instagramSignature = "25eace5393646842f0d0c3fb2ac7d3cfa15c052436ee86b5406a8433f54d24a5";

        static void Main(string[] args)
        {
            var configuration = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json", false) // \ConsoleApp_InstagramUploadImg\bin\bin\Debug\net5.0\appsettings,json
                .Build();

            string username = configuration.GetSection("usernameOrEmailOrPhone").Value;
            string password = configuration.GetSection("password").Value;

            Console.WriteLine("Upload image with caption to Instagram");
            string imagePath = null;
            string caption,
                ext;
            while (string.IsNullOrEmpty(imagePath))
            {
                Console.WriteLine("Please enter src image with format jpeg:");
                imagePath = Console.ReadLine();
                if (!string.IsNullOrEmpty(imagePath))
                {
                    ext = Path.GetExtension(imagePath);
                    if (!(ext.Contains("jpeg") || ext.Contains("jpg")))
                    {
                        Console.WriteLine("Not valid type of image (" + ext + ")");
                        imagePath = null;
                    }
                }
            }

            Console.WriteLine("Please enter caption:");
            caption = Console.ReadLine();

            UploadImage(username, password, imagePath, caption);

            while (!string.IsNullOrEmpty(imagePath))
            {
                Console.WriteLine("---------------------");

                Console.WriteLine("Please enter src image with format jpeg(jpg):");
                imagePath = Console.ReadLine();
                if (!string.IsNullOrEmpty(imagePath))
                {
                    ext = Path.GetExtension(imagePath);
                    while (!(ext.Contains("jpeg") || ext.Contains("jpg")))
                    {
                        Console.WriteLine("Not valid type of image ("+ ext + "), Please enter src image with format jpeg(jpg):");
                        imagePath = Console.ReadLine();
                        if (string.IsNullOrEmpty(imagePath))
                        {
                            return;
                        }
                        ext = Path.GetExtension(imagePath);
                    }
                    Console.WriteLine("Please enter caption:");
                    caption = Console.ReadLine();
                    UploadImage(username, password, imagePath, caption);
                }
            }
        }

        private static string SecureString(string strPassword)
        {
            var secureStr = new SecureString();
            foreach (var c in strPassword.ToCharArray())
            {
                secureStr.AppendChar(c);
            }

            var valuePtr = IntPtr.Zero;
            try
            {
                valuePtr = Marshal.SecureStringToGlobalAllocUnicode(secureStr);
                return Marshal.PtrToStringUni(valuePtr);
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(valuePtr);
            }
        }

        private static string GenerateSignature(string data)
        {
            var keyByte = Encoding.UTF8.GetBytes(_instagramSignature);
            using (var hmacsha256 = new HMACSHA256(keyByte))
            {
                hmacsha256.ComputeHash(Encoding.UTF8.GetBytes(data));
                return hmacsha256.Hash.Aggregate("", (current, t) => current + t.ToString("X2")).ToLower();
            }
        }

        private static void UploadImage(string username, string password, string imagePath, string caption)
        {
            var instagramApi = new InstagramApi();
            try
            {
                string guid = Guid.NewGuid().ToString();
                string deviceId = $"android-{guid}";

                var data = new Dictionary<string, string>
                {
                    {"device_id", deviceId},
                    {"guid", guid},
                    {"username", username},
                    {"password", SecureString(password)},
                    {"Content-Type", "application/x-www-form-urlencoded; charset=UTF-8"}
                };
                var loginData = JsonSerializer.Serialize(data);
                var signature = GenerateSignature(loginData);
                var signedLoginData = $"signed_body={signature}.{HttpUtility.UrlEncode(loginData)}&ig_sig_key_version=6";

                Console.WriteLine("Event fired for login: Logging in please wait.");

                var loginResponse = instagramApi.PostData("accounts/login/", signedLoginData, _userAgent);
                if (string.IsNullOrEmpty(loginResponse))
                {
                    Console.WriteLine("Error Empty response received from the server while trying to login");
                    return;
                }
                try
                {
                    var loginJson = JObject.Parse(loginResponse);
                    var status = (string)loginJson["status"];
                    if (status.Equals("ok"))
                    {
                        Console.WriteLine("Logged in successfull, your name is: " + (string)loginJson["logged_in_user"]["full_name"]);

                        Console.WriteLine("Attempting to upload image");

                        var uploadResponse = instagramApi.PostImage(imagePath, _userAgent);
                        if (string.IsNullOrEmpty(uploadResponse))
                        {
                            Console.WriteLine("Error Empty response received from the server while trying to post the image");
                            return;
                        }
                        try
                        {
                            var uploadJson = JObject.Parse(uploadResponse);
                            var uploadStatus = (string)uploadJson["status"];
                            if (uploadStatus.Equals("ok"))
                            {
                                Console.WriteLine("The image was uploaded, but has not been configured yet.");

                                Console.WriteLine("The image has started to be configured");

                                var newLineStripper = new Regex(@"/\r|\n/", RegexOptions.IgnoreCase);

                                caption = newLineStripper.Replace(caption, "");

                                var mediaId = (string)uploadJson["media_id"];
                                var configureData = new Dictionary<string, string>
                                {
                                    {"device_id", deviceId},
                                    {"guid", guid},
                                    {"media_id", mediaId},
                                    {"caption", caption.Trim()},
                                    {"device_timestamp", DateTime.Now.Ticks.ToString()},
                                    {"source_type", "5"},
                                    {"filter_type", "0"},
                                    {"extra", "{}"},
                                    {"Content-Type", "application/x-www-form-urlencoded; charset=UTF-8"}
                                };
                                var configureDataString = JsonSerializer.Serialize(configureData);
                                var configureSignature = GenerateSignature(configureDataString);
                                var signedConfigureBody = $"signed_body={configureSignature}.{HttpUtility.UrlEncode(configureDataString)}&ig_sig_key_version=4";
                                var configureResults = instagramApi.PostData("media/configure/", signedConfigureBody, _userAgent);
                                if (string.IsNullOrEmpty(configureResults))
                                {
                                    Console.WriteLine("Error Empty response received from the server while trying to configure the image");
                                }
                                else
                                {
                                    try
                                    {
                                        var configureJson = JObject.Parse(configureResults);
                                        var configureStatus = (string)configureJson["status"];
                                        if (configureStatus.Equals("fail"))
                                        {
                                            Console.WriteLine("Error " + (string)configureJson["message"]);
                                        }
                                        else
                                        {
                                            Console.WriteLine("Image posted to Instagram.");
                                        }
                                    }
                                    catch (Exception)
                                    {
                                        Console.WriteLine("Error Could not decode the configure response");
                                    }
                                }
                            }
                            else
                            {
                                Console.WriteLine("Error " + (string)uploadJson["message"]);
                            }
                        }
                        catch (Exception)
                        {
                            Console.WriteLine("Error Could not decode the upload response");
                        }
                    }
                    else
                    {
                        var message = (string)loginJson["message"];
                        Console.WriteLine("Error while logging " + message);
                    }
                }
                catch (Exception)
                {
                    Console.WriteLine("Error Could not decode the login response");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error " + ex.Message);
            }
        }
    }
}
