using System;
using System.Collections.Generic;
using System.Text;

namespace AesEncryption.Model
{
    public class RConstants
    {
        public IReadOnlyDictionary<int, byte[,]> rCon = new Dictionary<int, byte[,]>
        {
            { 
                1, 
                new byte[4,1] 
                {
                    { 0x01 },
                    { 0x00 },
                    { 0x00 },
                    { 0x00 }
                } 
            },
            { 
                2,
                new byte[4,1] 
                {
                    { 0x02 },
                    { 0x00 },
                    { 0x00 },
                    { 0x00 }
                }                 
            },
            { 
                3,
                new byte[4,1]
                {
                    { 0x04 },
                    { 0x00 },
                    { 0x00 },
                    { 0x00 }
                }                 
            },
            { 
                4,
                new byte[4,1] 
                {
                    { 0x08 },
                    { 0x00 },
                    { 0x00 },
                    { 0x00 }
                }                
            },
            { 
                5,
                new byte[4,1] 
                {
                    { 0x10 },
                    { 0x00 },
                    { 0x00 },
                    { 0x00 }
                }                 
            },
            { 
                6,
                new byte[4,1] 
                {
                    { 0x20 },
                    { 0x00 },
                    { 0x00 },
                    { 0x00 }
                }                 
            },
            { 
                7,
                new byte[4,1] 
                {
                    { 0x40 },
                    { 0x00 },
                    { 0x00 },
                    { 0x00 }
                }                 
            },
            { 
                8,
                new byte[4,1] 
                {
                    { 0x80 },
                    { 0x00 },
                    { 0x00 },
                    { 0x00 }
                }
            },
            { 
                9,
                new byte[4,1] 
                {
                    { 0x1b },
                    { 0x00 },
                    { 0x00 },
                    { 0x00 }
                }
            },
            { 
                10,
                new byte[4,1] 
                {
                    { 0x36 },
                    { 0x00 },
                    { 0x00 },
                    { 0x00 }
                }
            },
            {
                11,
                new byte[4,1]
                {
                    { 0x6c },
                    { 0x00 },
                    { 0x00 },
                    { 0x00 }
                }
            },
            {
                12,
                new byte[4,1]
                {
                    { 0xd8 },
                    { 0x00 },
                    { 0x00 },
                    { 0x00 }
                }
            },
            {
                13,
                new byte[4,1]
                {
                    { 0xab },
                    { 0x00 },
                    { 0x00 },
                    { 0x00 }
                }
            },
            {
                14,
                new byte[4,1]
                {
                    { 0x4d },
                    { 0x00 },
                    { 0x00 },
                    { 0x00 }
                }
            },
        };
    }
}
