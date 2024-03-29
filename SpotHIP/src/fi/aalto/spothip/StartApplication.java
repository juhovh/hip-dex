//
// StartApplication
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

package fi.aalto.spothip;

import javax.microedition.midlet.MIDlet;
import javax.microedition.midlet.MIDletStateChangeException;

/**
 * The startApp method of this class is called by the VM to start the
 * application.
 *
 * The manifest specifies this class as MIDlet-1, which means it will
 * be selected for execution.
 */
public class StartApplication extends MIDlet {

    protected void startApp() throws MIDletStateChangeException {
        System.out.println("Started HipDex application ...");

        // Listen for downloads/commands over USB connection
	new com.sun.spot.service.BootloaderListenerService().getInstance().start();

        byte[] remoteHit = new byte[] {
            0x20, 0x01, 0x00, 0x15,
            (byte)0x5c, (byte)0x0e, (byte)0x5a, (byte)0x74,
            (byte)0x29, (byte)0x3f, (byte)0xbe, (byte)0x13,
            (byte)0xcb, (byte)0xfa, (byte)0xf6, (byte)0xbd
        };

        /*
        HipDexEngine server = new HipDexEngine(true);
        try { server.start(); }
        catch (Exception e) { e.printStackTrace(); }
        */
        HipDexEngine client = new HipDexEngine(false);
        try { client.start(); client.connectToHit(remoteHit); }
        catch (Exception e) { e.printStackTrace(); }
    }

    protected void pauseApp() {
        // This will never be called by the Squawk VM
    }

    protected void destroyApp(boolean arg0) throws MIDletStateChangeException {
        // Only called if startApp throws any exception other than MIDletStateChangeException
    }
}