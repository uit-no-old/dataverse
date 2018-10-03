package edu.harvard.iq.dataverse.authorization.providers.oauth2.impl;

import com.github.scribejava.apis.DataportenApi;
import com.github.scribejava.core.builder.api.BaseApi;
import edu.emory.mathcs.backport.java.util.Collections;
import edu.harvard.iq.dataverse.authorization.AuthenticatedUserDisplayInfo;
import edu.harvard.iq.dataverse.authorization.providers.oauth2.AbstractOAuth2AuthenticationProvider;
import edu.harvard.iq.dataverse.authorization.providers.oauth2.OAuth2Exception;
import edu.harvard.iq.dataverse.authorization.providers.oauth2.OAuth2TokenData;
import edu.harvard.iq.dataverse.authorization.providers.oauth2.OAuth2UserRecord;
import edu.harvard.iq.dataverse.authorization.providers.shib.ShibUserNameFields;
import edu.harvard.iq.dataverse.authorization.providers.shib.ShibUtil;
import edu.harvard.iq.dataverse.util.BundleUtil;

import java.io.IOException;
import java.io.StringReader;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonArray;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.github.scribejava.core.model.OAuth2AccessToken;
import com.github.scribejava.core.model.OAuthRequest;
import com.github.scribejava.core.model.Response;
import com.github.scribejava.core.model.Verb;
import com.github.scribejava.core.oauth.OAuth20Service;

/**
 *
 * @author ran033@uit.no (Ruben Andreassen)
 */
public class DataportenOAuth2AP extends AbstractOAuth2AuthenticationProvider {
    
    final static Logger logger = Logger.getLogger(DataportenOAuth2AP.class.getName());
    
    public DataportenOAuth2AP(String aClientId, String aClientSecret, String userEndpoint) {
        id = "dataporten";
        title = BundleUtil.getStringFromBundle("auth.providers.title.dataporten");
        clientId = aClientId;
        clientSecret = aClientSecret;
        baseUserEndpoint = userEndpoint;
    }
    
    @Override
    public BaseApi getApiInstance() {
        return DataportenApi.instance();
    }

    /*
    GET https://groups-api.dataporten.no/groups/me/groups

    [
        {
            ...
            "id": "fc:org:uit.no",
            "type": "fc:org",
            "eduOrgLegalName": "UiT Norges Arktiske Universitet",
            ...
        }
    ]
    */
    protected String getUserAffiliation(OAuth20Service service, OAuth2AccessToken accessToken) {        
        final OAuthRequest request = new OAuthRequest(Verb.GET, "https://groups-api.dataporten.no/groups/me/groups", service);
        request.addHeader("Authorization", "Bearer " + accessToken.getAccessToken());
        request.setCharset("UTF-8");
        
        final Response response = request.send();
        int responseCode = response.getCode();
        final String body;
        try {
            body = response.getBody();   
        } catch(IOException e) {
            return "";
        }
        logger.log(Level.FINE, "In getUserAffiliation. Body: {0}", body);  

        if ( responseCode == 200 ) {
            try ( StringReader rdr = new StringReader(body);
                JsonReader jrdr = Json.createReader(rdr) )  {
                JsonArray groups = jrdr.readArray();

                for (int i = 0; i < groups.size(); i++) {
                    JsonObject group = groups.getJsonObject(i);
                    // Skip all other group types
                    String type = group.getString("type", "");
                    if (!type.equals("fc:org")) {
                        continue;
                    }
                    
                    String affiliation = getUserAffiliationEN(service, group.getString("id", ""));
                    if (affiliation.length() == 0) {
                        return group.getString("eduOrgLegalName", "");
                    }
                    return affiliation;
                }
            }
        }
        return "";
    }

    /*
    GET https://api.dataporten.no/orgs/fc:org:uit.no

    {
        ...
        "name": "UiT The Arctic University of Norway"
    }
    */
    protected String getUserAffiliationEN(OAuth20Service service, String id) {
        final OAuthRequest request = new OAuthRequest(Verb.GET, "https://api.dataporten.no/orgs/"+id, service);
        request.addHeader("Accept-Language", "en-US");
        request.setCharset("UTF-8");
        
        final Response response = request.send();
        int responseCode = response.getCode();
        final String body;
        try {
            body = response.getBody();   
        } catch(IOException e) {
            return "";
        }
        logger.log(Level.FINE, "In getUserAffiliationEN. Body: {0}", body);  

        if ( responseCode == 200 ) {
            try ( StringReader rdr = new StringReader(body);
                JsonReader jrdr = Json.createReader(rdr) )  {
                JsonObject jobj = jrdr.readObject();

                return jobj.getString("name", "");
            }
        }
        return "";
    }

    @Override
    protected ParsedUserResponse parseUserResponse( String responseBody ) {
        /*
        ATTENTION! This function is not used
        */
        try ( StringReader rdr = new StringReader(responseBody);
            JsonReader jrdr = Json.createReader(rdr) )  {
            JsonObject responseObject = jrdr.readObject();
            JsonObject userObject = responseObject.getJsonObject("user");
            JsonArray userid_secArray = userObject.getJsonArray("userid_sec");
             
            String username = userid_secArray.getString(0).replace("feide:", "");
            String affiliation = "";
            String position = "";
                        
            // Extract ad username using regexp
            Pattern p = Pattern.compile("^feide:([0-9a-zA-Z]+?)@([0-9a-zA-Z]*).*$");
            Matcher m = p.matcher(userid_secArray.getString(0));
            if(m.matches()) {
                affiliation = m.group(2);
            }
            
            ShibUserNameFields shibUserNameFields = ShibUtil.findBestFirstAndLastName(null, null, userObject.getString("name",""));
            AuthenticatedUserDisplayInfo displayInfo = new AuthenticatedUserDisplayInfo(
                    shibUserNameFields.getFirstName(),
                    shibUserNameFields.getLastName(),
                    userObject.getString("email",""),
                    affiliation,
                    position
            );
            
            return new ParsedUserResponse(
                    displayInfo, 
                    userObject.getString("userid"), //persistentUserId 
                    username, //username
                    displayInfo.getEmailAddress().length()>0 ? Collections.singletonList(displayInfo.getEmailAddress())
                                                             : Collections.emptyList() );

        }
    }
    
    protected ParsedUserResponse parseUserResponse( String responseBody, OAuth20Service service, OAuth2AccessToken accessToken ) {
        /*
        Example reponse
        {
            "user": {
                "userid": "76a7a061-3c55-430d-8ee0-6f82ec42501f",
                "userid_sec": ["feide:andreas@uninett.no"],
                "name": "Andreas \u00c5kre Solberg",
                "email": "andreas.solberg@uninett.no",
                "profilephoto": "p:a3019954-902f-45a3-b4ee-bca7b48ab507"
            },
            "audience": "e8160a77-58f8-4006-8ee5-ab64d17a5b1e"
        }
        */
        try ( StringReader rdr = new StringReader(responseBody);
            JsonReader jrdr = Json.createReader(rdr) )  {
            JsonObject responseObject = jrdr.readObject();
            JsonObject userObject = responseObject.getJsonObject("user");
            JsonArray userid_secArray = userObject.getJsonArray("userid_sec");
            
            String username = userid_secArray.getString(0).replace("feide:", "");
            String affiliation = getUserAffiliation(service, accessToken);
            String position = "";
            String email = userObject.getString("email","");
            String displayName = userObject.getString("name","");
            String firstName = displayName;
            String lastName = "";
                        
            // Extract ad username using regexp
            Pattern p = Pattern.compile("^feide:([0-9a-zA-Z]+?)@([0-9a-zA-Z]*).*$");
            Matcher m = p.matcher(userid_secArray.getString(0));
            if(m.matches() && affiliation.length() == 0) {
                affiliation = m.group(2);
            }

            // Extract first and last name
            String[] parts = displayName.split(" ");
            if (parts.length > 1) {
                firstName = parts[0];
                lastName = parts[parts.length-1];
            }
            
            AuthenticatedUserDisplayInfo displayInfo = new AuthenticatedUserDisplayInfo(
                    firstName,
                    lastName,
                    email,
                    affiliation,
                    position
            );
            
            return new ParsedUserResponse(
                    displayInfo, 
                    userObject.getString("userid"), //persistentUserId 
                    username, //username
                    displayInfo.getEmailAddress().length()>0 ? Collections.singletonList(displayInfo.getEmailAddress())
                                                             : Collections.emptyList() );

        }
        
    }
    
    @Override
    public OAuth2UserRecord getUserRecord(String code, String state, String redirectUrl) throws IOException, OAuth2Exception {
        OAuth20Service service = getService(state, redirectUrl);
        OAuth2AccessToken accessToken = service.getAccessToken(code);

        final String userEndpoint = getUserEndpoint(accessToken);
        
        final OAuthRequest request = new OAuthRequest(Verb.GET, userEndpoint, service);
        request.addHeader("Authorization", "Bearer " + accessToken.getAccessToken());
        request.setCharset("UTF-8");
        
        final Response response = request.send();
        int responseCode = response.getCode();
        final String body = response.getBody();        
        logger.log(Level.FINE, "In getUserRecord. Body: {0}", body);

        if ( responseCode == 200 ) {
            final ParsedUserResponse parsed = parseUserResponse(body, service, accessToken);
            return new OAuth2UserRecord(getId(), parsed.userIdInProvider,
                                        parsed.username, 
                                        OAuth2TokenData.from(accessToken),
                                        parsed.displayInfo,
                                        parsed.emails);
        } else {
            throw new OAuth2Exception(responseCode, body, "Error getting the user info record.");
        }
    }

    @Override
    public boolean isDisplayIdentifier() {
        return false;
    }

    @Override
    public String getPersistentIdName() {
        return BundleUtil.getStringFromBundle("auth.providers.persistentUserIdName.dataporten");
    }

    @Override
    public String getPersistentIdDescription() {
        return BundleUtil.getStringFromBundle("auth.providers.persistentUserIdTooltip.dataporten");
    }

    @Override
    public String getPersistentIdUrlPrefix() {
        return null;
    }

    @Override
    public String getLogo() {
        return null;
    }
}
