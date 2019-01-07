using System;
using System.Configuration;

namespace CRUD_API_JWT.Models
{
    public static class ApplicationConstants
    {
        public static string CryptoKey
        {
            get
            {
                string key = "CryptoKey";
                if (ConfigurationManager.AppSettings[key] != null && !string.IsNullOrEmpty(ConfigurationManager.AppSettings[key] as string))
                {
                    return ConfigurationManager.AppSettings[key] as string;
                }
                else
                {
                    return null;
                }
            }
        }

        public static string JWTSecretKey
        {
            get
            {
                string key = "JWTSecretKey";
                if (ConfigurationManager.AppSettings[key] != null && !string.IsNullOrEmpty(ConfigurationManager.AppSettings[key] as string))
                {
                    return ConfigurationManager.AppSettings[key] as string;
                }
                else
                {
                    return null;
                }
            }
        }

        public static int JWTExpireTime
        {
            get
            {
                string key = "JWTExpireTime";
                if (ConfigurationManager.AppSettings[key] != null && !string.IsNullOrEmpty(ConfigurationManager.AppSettings[key] as string))
                {
                    return Convert.ToInt32(ConfigurationManager.AppSettings[key]);
                }
                else
                {
                    return 5; //default time 5 minutes
                }
            }
        }

    }
}