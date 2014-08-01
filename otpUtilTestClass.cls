/**
 * @author  Leo Kermes lkermes@salesforce.com
 
 ========================================

 Redistribution and use of this software in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
 * Neither the name of salesforce.com, inc. nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission of salesforce.com, inc.


 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

 */




@isTest
public class otpUtilTestClass {

    static testMethod void validate_MAX() {
        final string Base16 = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF';
    	final string Base32 = '77777777777777777777777777777777';
        System.assertEquals(Base32,otpUtil.keyB16toB32(Base16));
        System.assertEquals(Base16,otpUtil.keyB32toB16(Base32));
    }
    
    static testMethod void validate_MIN() {
        final string Base16 = '0000000000000000000000000000000000000000';
    	final string Base32 = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
        System.assertEquals(Base32,otpUtil.keyB16toB32(Base16));
        System.assertEquals(Base16,otpUtil.keyB32toB16(Base32));
    }
    
    static testMethod void validate_Pattern_10() {
        final string Base16 = 'DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD';
    	final string Base32 = '3XO53XO53XO53XO53XO53XO53XO53XO5';
        System.assertEquals(Base32,otpUtil.keyB16toB32(Base16));
        System.assertEquals(Base16,otpUtil.keyB32toB16(Base32));
    }
    
    static testMethod void validate_Pattern_01() {
        final string Base16 = '5555555555555555555555555555555555555555';
    	final string Base32 = 'KVKVKVKVKVKVKVKVKVKVKVKVKVKVKVKV';
        System.assertEquals(Base32,otpUtil.keyB16toB32(Base16));
        System.assertEquals(Base16,otpUtil.keyB32toB16(Base32));
    }
    
    static testMethod void validate_Random() {
        final string Base16 = '02A6FFC209CB208673AEFCBB021FE45398D68CA9';
    	final string Base32 = 'AKTP7QQJZMQIM45O7S5QEH7EKOMNNDFJ';
        System.assertEquals(Base32,otpUtil.keyB16toB32(Base16));
        System.assertEquals(Base16,otpUtil.keyB32toB16(Base32));
    }
    
    
    static testMethod void validate_Dynamic(){
        String Base16 = '';
        String Base32 = '';
        for (Integer i = 0; i < 10; i++) {
            Base16 = otpUtil.generateBase16Key();
        	Base32 = otpUtil.keyB16toB32(Base16);
        	System.assertEquals(Base16.toUpperCase(),otpUtil.keyB32toB16(Base32));
        	Base32 = otpUtil.generateBase32Key();
        	Base16 = otpUtil.keyB32toB16(Base32);
        	System.assertEquals(Base32,otpUtil.keyB16toB32(Base16));
    	}
    }
    
    static testMethod void Validate_RFC4226() {
        final String RFC_HEX_KEY = '3132333435363738393031323334353637383930';
        System.assert(otpUtil.validateHOTP('755224', otpUtil.keyB16toB32(RFC_HEX_KEY), 0L, 0));
        System.assert(otpUtil.validateHOTP('287082', otpUtil.keyB16toB32(RFC_HEX_KEY), 1L, 0));
        System.assert(otpUtil.validateHOTP('359152', otpUtil.keyB16toB32(RFC_HEX_KEY), 2L, 0));
        System.assert(otpUtil.validateHOTP('969429', otpUtil.keyB16toB32(RFC_HEX_KEY), 3L, 0));
        System.assert(otpUtil.validateHOTP('338314', otpUtil.keyB16toB32(RFC_HEX_KEY), 4L, 0));
        System.assert(otpUtil.validateHOTP('254676', otpUtil.keyB16toB32(RFC_HEX_KEY), 5L, 0));
        System.assert(otpUtil.validateHOTP('287922', otpUtil.keyB16toB32(RFC_HEX_KEY), 6L, 0));
        System.assert(otpUtil.validateHOTP('162583', otpUtil.keyB16toB32(RFC_HEX_KEY), 7L, 0));
        System.assert(otpUtil.validateHOTP('399871', otpUtil.keyB16toB32(RFC_HEX_KEY), 8L, 0));
        System.assert(otpUtil.validateHOTP('520489', otpUtil.keyB16toB32(RFC_HEX_KEY), 9L, 0));
    }
    
    static testMethod void Validate_RFC6238() {
        final String RFC_HEX_KEY = '3132333435363738393031323334353637383930';
        System.assert(
            otpUtil.validateTOTP(
                '94287082',
                otpUtil.keyB16toB32(RFC_HEX_KEY),
                DateTime.newInstanceGmt(1970, 1, 1, 0, 0, 59)
            )
        );
        System.assert(
            otpUtil.validateTOTP(
                '07081804', 
                otpUtil.keyB16toB32(RFC_HEX_KEY),
                DateTime.newInstanceGmt(2005, 3, 18, 1, 58, 29)
            )
        );
        System.assert(
            otpUtil.validateTOTP(
                '14050471', 
                otpUtil.keyB16toB32(RFC_HEX_KEY),
                DateTime.newInstanceGmt(2005, 3, 18, 1, 58, 31)
            )
        );
        System.assert(
            otpUtil.validateTOTP(
                '89005924', 
            	otpUtil.keyB16toB32(RFC_HEX_KEY),
            	DateTime.newInstanceGmt(2009, 2, 13, 23, 31, 30)
        	)
        );
        System.assert(
            otpUtil.validateTOTP(
                '69279037', 
                otpUtil.keyB16toB32(RFC_HEX_KEY),
                DateTime.newInstanceGmt(2033, 5, 18, 3, 33, 20)
            )
        );
        System.assert(
            otpUtil.validateTOTP(
                '65353130', 
                otpUtil.keyB16toB32(RFC_HEX_KEY),
                DateTime.newInstanceGmt(2603, 10, 11, 11, 33, 20)
            )
        );
    }
    
}