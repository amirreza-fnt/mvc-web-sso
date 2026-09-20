namespace SSOLoginService.Web.Services;

public static class PhoneMasking
{
    public static string FormatForDisplay(string? phone)
    {
        var digits = NormalizeDigits(phone);
        if (digits.Length >= 11)
            return $"{digits[..4]}xxxx{digits[^3..]}";

        if (digits.Length >= 7)
            return $"{digits[..3]}xxxx{digits[^2..]}";

        return "xxxxxxxxx";
    }

    public static string NormalizeDigits(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return string.Empty;

        var persian = "۰۱۲۳۴۵۶۷۸۹";
        var arabic = "٠١٢٣٤٥٦٧٨٩";
        var chars = value.Trim().Select(ch =>
        {
            var p = persian.IndexOf(ch);
            if (p >= 0) return (char)('0' + p);
            var a = arabic.IndexOf(ch);
            if (a >= 0) return (char)('0' + a);
            return ch;
        });

        return new string(chars.Where(char.IsDigit).ToArray());
    }
}
