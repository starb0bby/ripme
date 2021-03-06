package com.rarchives.ripme.tst.ripper.rippers;

import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

import com.rarchives.ripme.ripper.rippers.FineboxRipper;

public class FineboxRipperTest extends RippersTest {
    
    public void testVineboxAlbums() throws IOException {
        if (!DOWNLOAD_CONTENT) {
            return;
        }
        List<URL> contentURLs = new ArrayList<URL>();
        contentURLs.add(new URL("http://vinebox.co/u/wi57hMjc2Ka"));
        contentURLs.add(new URL("http://finebox.co/u/wi57hMjc2Ka"));
        for (URL url : contentURLs) {
            try {
                FineboxRipper ripper = new FineboxRipper(url);
                ripper.rip();
                assert(ripper.getWorkingDir().listFiles().length > 1);
                deleteDir(ripper.getWorkingDir());
            } catch (Exception e) {
                e.printStackTrace();
                fail("Error while ripping URL " + url + ": " + e.getMessage());
            }
        }
    }

}
