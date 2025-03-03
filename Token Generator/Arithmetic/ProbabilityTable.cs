using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Token_Generator.Arithmetic
{
    internal class ProbabilityTable
    {
        internal ProbabilityTable()
        {
            _probabilityTable = new ConcurrentDictionary<char, (ulong, ulong)>();
            _frequencyTable = new ConcurrentDictionary<char, ulong>();
        }
        internal ulong totalSymbols;
        internal const ulong Precision = 1UL << 32; //fixed point precision
        internal required ConcurrentDictionary<char, (ulong, ulong)> _probabilityTable;
        internal required ConcurrentDictionary<char, ulong> _frequencyTable;
        internal void Update()
        {
            ulong cumulative = 0;
            foreach ( var kvp in _frequencyTable.OrderBy(x => x.Key) )
            {
                ulong frequency = kvp.Value;
                _probabilityTable[kvp.Key] = (cumulative, cumulative + (frequency * Precision / totalSymbols));
                cumulative += frequency * Precision / totalSymbols;
            }
        }
    }
}
