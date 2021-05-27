using System;

namespace TheSprayer.Models
{
    [Flags]
    public enum PasswordProperties
    {
        DOMAIN_PASSWORD_COMPLEX = 1,
        DOMAIN_PASSWORD_NO_ANON_CHANGE = 2,
        DOMAIN_PASSWORD_NO_CLEAR_CHANGE = 4,
        DOMAIN_LOCKOUT_ADMINS = 8,
        DOMAIN_PASSWORD_STORE_CLEARTEXT = 16,
        DOMAIN_REFUSE_PASSWORD_CHANGE = 32
    }
}
