namespace PassCodeManager.Payloads
{
    public class EncodePayload
    {
        public string Password { get; set; }

        public string Salt { get; set; }
    }
}