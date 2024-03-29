//
// HipPacketI2 - HIP I2 packet
//
// Authors:
//      Juho V�h�-Herttua  <juhovh@iki.fi>
//
// Copyright (C) 2011  Aalto University
//
// This program is free software; you can redistribute it and/or
// modify it under the terms of the GNU General Public License
// as published by the Free Software Foundation; either version 2
// of the License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
//

package fi.aalto.spothip.protocol;

public class HipPacketI2 extends HipPacket {
    protected HipPacketI2() {
        super(HipPacket.TYPE_I2);
    }
    
    public HipPacketI2(HipSolution solution, HipHostId hostId, HipEncryptedKey encryptedKey) {
        super(HipPacket.TYPE_I2);

        addParameter(solution);
        addParameter(new HipHipCipher());
        addParameter(encryptedKey);
        addParameter(hostId);
        addParameter(new HipHipMac3());
    }
}
