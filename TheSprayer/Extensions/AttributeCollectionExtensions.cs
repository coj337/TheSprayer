using System;
using System.DirectoryServices.Protocols;
using System.Globalization;

namespace TheSprayer.Extensions
{
    public static class AttributeCollectionExtensions
    {
        public static string GetIfExists(this SearchResultAttributeCollection attributes, string attributeName)
        {
            return attributes.Contains(attributeName) ? attributes[attributeName][0].ToString() : null;
        }

        public static T GetIfExists<T>(this SearchResultAttributeCollection attributes, string attributeName)
        {
            //Handle DateTime and nullable DateTime
            if(typeof(T) == typeof(DateTime?) || typeof(T) == typeof(DateTime))
            {
                DateTime? parsedDate = null;
                var timeString = attributes.GetIfExists(attributeName);
                if (!string.IsNullOrEmpty(timeString) && timeString != "0")
                {
                    if (!timeString.EndsWith(".0Z"))
                    {
                        //Usually timestamps are LDAP Timestamps
                        var fileTime = Convert.ToInt64(timeString);
                        if (!fileTime.Equals(long.MaxValue))
                        {
                            parsedDate = DateTime.FromFileTimeUtc(fileTime);
                        }
                    }
                    else
                    {
                        //But sometimes it's "Generalized-Time", thanks Microsoft
                        var formats = new string[] { "yyyyMMddHHmmss.fZ", "yyyyMMddHHmmss.fzzz" };
                        parsedDate = DateTime.ParseExact(timeString, formats, CultureInfo.InvariantCulture).ToUniversalTime();
                    }
                }

                var t = typeof(T);
                t = Nullable.GetUnderlyingType(t) ?? t; //Magic to prevent DateTime? throwing an exception when returning DateTime
                return (parsedDate == null) ? default : (T)Convert.ChangeType(parsedDate, t);
            }

            //Anything else returns default if it doesn't exist
            return attributes.Contains(attributeName) ? (T)Convert.ChangeType(attributes[attributeName][0], typeof(T)) : default;
        }
    }
}
