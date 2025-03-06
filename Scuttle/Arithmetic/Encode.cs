using System.Collections.Concurrent;

namespace Scuttle.Arithmetic
{
    internal class Encode
    {
        internal ProbabilityTable _probabilityTable;
        private int _availableCores = Environment.ProcessorCount;

        public Encode(ProbabilityTable probabilityTable)
        {
            _probabilityTable = probabilityTable;
        }
        public List<bool> EncodeSequential(string input)
        {
            var output = new List<bool>();

            foreach ( var symbol in input )
            {
                var bits = EncodeSymbol(symbol);
                output.AddRange(bits);
            }

            return output;
        }
        public static List<List<bool>> EncodeMultipleStrings(List<string> inputs)
        {
            var results = new List<bool>[inputs.Count];

            Parallel.For(0, inputs.Count, i =>
            {
                var encoder = new Encode(new ProbabilityTable
                {
                    _probabilityTable = new ConcurrentDictionary<char, (ulong, ulong)>(),
                    _frequencyTable = new ConcurrentDictionary<char, ulong>()
                });
                results[i] = encoder.EncodeSequential(inputs[i]);
            });

            return [.. results];
        }

        public List<bool> EncodeSymbol(char symbol)
        {
            _probabilityTable._frequencyTable.AddOrUpdate(symbol, 1, (_, count) => count + 1);
            _probabilityTable.totalSymbols++;

            _probabilityTable.Update();

            ulong low = 0, high = ProbabilityTable.Precision;
            List<bool> bitStream = new List<bool>();

            (ulong rangeLow, ulong rangeHigh) = _probabilityTable._probabilityTable[symbol];
            ulong range = high - low;

            high = low + (range * rangeHigh / ProbabilityTable.Precision);
            low = low + (range * rangeLow / ProbabilityTable.Precision);

            while ( (high & 0x80000000) == (low & 0x80000000) )
            {
                bitStream.Add((high & 0x80000000) != 0);
                low <<= 1;
                high = (high << 1) | 1;
            }

            bitStream.Add(true); // Finalize
            return bitStream;
        }
    }
}
