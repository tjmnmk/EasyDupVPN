def split_string_to_chunks(s, n):
    """Splits string s into chunks of size n."""
    
    return [s[i:i+n] for i in range(0, len(s), n)]