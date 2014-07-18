package com.rarchives.ripme.ripper.rippers;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import com.rarchives.ripme.ripper.AbstractHTMLRipper;
import com.rarchives.ripme.utils.Http;
import com.rarchives.ripme.utils.User;
import com.rarchives.ripme.utils.Utils;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.CookieStore;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.ClientContext;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HTTP;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;
import org.jsoup.Jsoup;

public class ExposedForumsRipper extends AbstractHTMLRipper {

    private static final String DOMAIN = "exposedforums.com", HOST = "exposedforums";
    private static final DefaultHttpClient httpclient = getThreadSafeClient();

    public ExposedForumsRipper(URL url) throws IOException {
        super(url);
    }

    @Override
    public String getHost() {
        return HOST;
    }

    @Override
    public String getDomain() {
        return DOMAIN;
    }

    @Override
    public String getGID(URL url) throws MalformedURLException {
        Pattern p = Pattern.compile("^https?://[w.]*exposedforums.com/forums/showthread.php\\?([a-zA-Z0-9_\\-]+).*$");
        Matcher m = p.matcher(url.toExternalForm());
        if (m.matches()) {
            return m.group(1);
        }
        throw new MalformedURLException("Expected exposedforums.com URL format: "
                + "exposedforums.com/forums/showthread.php?... - got " + url + "instead");
    }

    @Override
    public Document getFirstPage() throws IOException {
        return Http.url(url).get();
    }

    @Override
    public List<String> getURLsFromPage(Document doc) {
        List<String> imageURLs = new ArrayList<String>();
        for (Element thumb : doc.select("a.highslide")) {
            String image = thumb.attr("href");
            imageURLs.add(image);
        }
        return imageURLs;
    }

    @Override
    public void downloadURL(URL url, int index) {
        addURLToDownload(url, getPrefix(index));
    }

    @Override
    public void rip() throws IOException {
        String gid = getGID(this.url), theurl = "http://www.exposedforums.com/forums/showthread.php?" + gid;
        Document doc = login(theurl, "", "");
        logger.info(doc);
    }

    /**
     * Constructs and submits a POST with the appropriate parameters to login to a vbulletin.
     *
     * @param rootURL Base or root URL for the site to log into
     * @param username User's login name
     * @param password User's password
     * @throws IOException
     * @return Document object initialised with a HttpContext
     * 
     */
    public Document login(String rootURL, String username, String password) throws IOException {
        Utils.debug("login");

        User ret = new User(username, password);
        CookieStore cookieStore = new BasicCookieStore();
        HttpContext localContext = new BasicHttpContext();
        localContext.setAttribute(ClientContext.COOKIE_STORE, cookieStore);

        // set up the POST
        HttpPost httppost = new HttpPost("http://" + getDomain() + "/forums/login.php");
        List<NameValuePair> nvps = new ArrayList<NameValuePair>();
        nvps.add(new BasicNameValuePair("do", "login"));
        nvps.add(new BasicNameValuePair("vb_login_username", username));
        nvps.add(new BasicNameValuePair("vb_login_password", password));
        nvps.add(new BasicNameValuePair("s", ""));
        nvps.add(new BasicNameValuePair("securitytoken", "guest"));
        nvps.add(new BasicNameValuePair("do", "login"));
        nvps.add(new BasicNameValuePair("vb_login_md5password", Utils.md5(password)));
        nvps.add(new BasicNameValuePair("vb_login_md5password_utf", Utils.md5(password)));
        nvps.add(new BasicNameValuePair("cookieuser", "1"));
        httppost.setEntity(new UrlEncodedFormEntity(nvps, HTTP.UTF_8));

        // execute the POST 
        Utils.debug("Executing POST");
        HttpResponse response = httpclient.execute(httppost, localContext);
        Utils.debug("POST response: " + response.getStatusLine());
        assert response.getStatusLine().getStatusCode() == 200;

        // get all headers		
        // Header[] headers = response.getAllHeaders();
        // for (Header header : headers) {
        //     System.out.println("Key : " + header.getName()
        //             + " ,Value : " + header.getValue());
        // }
        
        // TODO: store the cookies
        // http://bit.ly/e7yY5i (CookieStore javadoc)
        Utils.printCookieStore(cookieStore);

        // confirm we are logged in 
        HttpGet httpget = new HttpGet(rootURL);
        response = httpclient.execute(httpget, localContext);
        HttpEntity entity = response.getEntity();
        Document page = Jsoup.parse(EntityUtils.toString(entity));
        EntityUtils.consume(entity);
        assert page != null;

        Utils.debug("Checking that we are logged in..");
        Element username_box = page.select("input[name=vb_login_username]").first();
        assert username_box == null;
        Element password_box = page.select("input[name=vb_login_password]").first();
        assert password_box == null;

        // parse the user's new securitytoken
        Element el_security_token = page.select("input[name=securitytoken]").first();
        assert el_security_token != null;
        String security_token = el_security_token.attr("value");
        assert security_token != null;
        String[] token_array = security_token.split("-");
        assert token_array.length == 2;
        ret.vb_security_token = token_array[1];
        assert ret.vb_security_token.length() == 40;
        ret.httpContext = localContext;
        
        Utils.debug("securitytoken: " + ret.vb_security_token);
        Utils.debug("Login seems ok");
        Utils.debug("end login");
        
        return page;
    }

    public static DefaultHttpClient getThreadSafeClient() {

        DefaultHttpClient client = new DefaultHttpClient();
        ClientConnectionManager mgr = client.getConnectionManager();
        HttpParams params = client.getParams();
        client = new DefaultHttpClient(new ThreadSafeClientConnManager(params,
                mgr.getSchemeRegistry()), params);
        return client;
    }

}
