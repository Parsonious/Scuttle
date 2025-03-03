using System.Text;

internal class AdaptiveSequential
{
    private Dictionary<char, (ulong, ulong)> probabilityTable;
    private Dictionary<char, ulong> frequencyTable;
    private ulong totalSymbols;
    private const ulong Precision = 1UL << 32; // 32-bit fixed precision
    private const char EOM_SYMBOL = '\0';

    internal AdaptiveSequential()
    {
        frequencyTable = new Dictionary<char, ulong>
        {
            { EOM_SYMBOL, 1 } // Initialize with EOM symbol
        };

        totalSymbols = 1;
        probabilityTable = new Dictionary<char, (ulong, ulong)>();
        UpdateProbabilityTable();
    }

    private void UpdateProbabilityTable()
    {
        ulong cumulative = 0;
        foreach ( var kvp in frequencyTable.OrderBy(x => x.Key) )
        {
            ulong freq = kvp.Value;
            ulong rangeLow = cumulative;
            cumulative += freq;
            ulong rangeHigh = cumulative;
            probabilityTable[kvp.Key] = (rangeLow, rangeHigh);
        }
    }

    public List<bool> Encode(string input)
    {
        input += EOM_SYMBOL;

        List<bool> bitStream = new List<bool>();
        ulong low = 0, high = Precision - 1;
        ulong mask = 1UL << 31; // For 32-bit precision

        foreach ( char c in input )
        {
            // Update frequency and probability tables before processing the symbol
            if ( frequencyTable.ContainsKey(c) )
                frequencyTable[c]++;
            else
            {
                frequencyTable[c] = 1;
            }
            totalSymbols++;
            UpdateProbabilityTable();

            ulong range = high - low + 1;
            (ulong rangeLow, ulong rangeHigh) = probabilityTable[c];

            high = low + (range * rangeHigh) / totalSymbols - 1;
            low = low + (range * rangeLow) / totalSymbols;

            // Output bits while high and low share the same MSB
            while ( (high & mask) == (low & mask) )
            {
                bool msb = (high & mask) != 0;
                bitStream.Add(msb);

                low = (low << 1) & (Precision - 1);
                high = ((high << 1) & (Precision - 1)) | 1;
            }
        }

        // Handle underflow by flushing remaining bits
        // Add termination bits if necessary
        for ( int i = 0; i < 32; i++ )
        {
            bool msb = (low & mask) != 0;
            bitStream.Add(msb);
            low = (low << 1) & (Precision - 1);
        }

        return bitStream;
    }

    public string Decode(List<bool> bitStream)
    {
        ulong low = 0, high = Precision - 1;
        ulong value = 0;
        ulong mask = 1UL << 31; // For 32-bit precision
        int bitIndex = 0;

        // Initialize `value` with enough bits from the bit stream
        for ( int i = 0; i < 32 && bitIndex < bitStream.Count; i++, bitIndex++ )
        {
            value = (value << 1) | (bitStream[bitIndex] ? 1UL : 0);
        }

        StringBuilder output = new StringBuilder();
        bool endOfMessage = false;

        while ( !endOfMessage )
        {
            ulong range = high - low + 1;
            ulong scaledValue = ((value - low + 1) * totalSymbols - 1) / range;

            // Find the symbol corresponding to the scaled value
            char symbol = '\0';
            foreach ( var kvp in probabilityTable.OrderBy(x => x.Key) )
            {
                char currentSymbol = kvp.Key;
                (ulong rangeLow, ulong rangeHigh) = probabilityTable[currentSymbol];

                if ( scaledValue >= rangeLow && scaledValue < rangeHigh )
                {
                    symbol = currentSymbol;
                    break;
                }
            }

            if ( symbol == EOM_SYMBOL )
            {
                endOfMessage = true;
                continue;
            }

            output.Append(symbol);

            // Update frequency and probability tables before processing the symbol
            if ( frequencyTable.ContainsKey(symbol) )
                frequencyTable[symbol]++;
            else
            {
                frequencyTable[symbol] = 1;
            }
            totalSymbols++;
            UpdateProbabilityTable();

            // Update `low` and `high` for the next symbol
            (ulong symbolLow, ulong symbolHigh) = probabilityTable[symbol];
            high = low + (range * symbolHigh) / totalSymbols - 1;
            low = low + (range * symbolLow) / totalSymbols;

            // Read bits from the bit stream as needed
            while ( (high & mask) == (low & mask) )
            {
                low = (low << 1) & (Precision - 1);
                high = ((high << 1) & (Precision - 1)) | 1;

                if ( bitIndex < bitStream.Count )
                {
                    value = ((value << 1) & (Precision - 1)) | (bitStream[bitIndex] ? 1UL : 0);
                    bitIndex++;
                }
                else
                {
                    value = (value << 1) & (Precision - 1);
                }
            }
        }

        return output.ToString();
    }
}