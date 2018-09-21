package edu.harvard.iq.dataverse.authorization.providers.oauth2.impl;

import com.github.scribejava.apis.DataportenApi;
import com.github.scribejava.core.builder.api.BaseApi;
import edu.emory.mathcs.backport.java.util.Collections;
import edu.harvard.iq.dataverse.authorization.AuthenticatedUserDisplayInfo;
import edu.harvard.iq.dataverse.authorization.providers.oauth2.AbstractOAuth2AuthenticationProvider;
import edu.harvard.iq.dataverse.authorization.providers.shib.ShibUserNameFields;
import edu.harvard.iq.dataverse.authorization.providers.shib.ShibUtil;
import edu.harvard.iq.dataverse.util.BundleUtil;
import java.io.StringReader;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.JsonArray;

/**
 *
 * @author ran033@uit.no (Ruben Andreassen)
 */
public class DataportenOAuth2AP extends AbstractOAuth2AuthenticationProvider {
    
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
            "displayName": "dataverse-ns9999k",
            "membership": {
                "basic": "member"
            },
            "id": "fc:adhoc:b7d0fd8d-6e63-4314-b356-7832a7eac3b3",
            "type": "voot:ad-hoc",
            "description": "management of dataverse-ns9999k on the SP."
        },
        {
            "membership": {
                "affiliation": [
                    "employee",
                    "staff",
                    "member"
                ],
                "primaryAffiliation": "staff",
                "displayName": "Stab",
                "title": [
                    "Senioringeni\u00f8r"
                ],
                "basic": "admin"
            },
            "orgType": [
                "higher_education"
            ],
            "norEduOrgUniqueIdentifier": "00000186",
            "public": true,
            "mail": "postmottak@uit.no",
            "displayName": "UiT Norges Arktiske Universitet",
            "id": "fc:org:uit.no",
THIS-->     "type": "fc:org",
THIS-->     "eduOrgLegalName": "UiT Norges Arktiske Universitet",
            "norEduOrgNIN": "NO970422528"
        },
        {
            "membership": {
                "basic": "member",
                "primaryOrgUnit": true
            },
            "public": true,
            "displayName": "SUA",
            "id": "fc:org:uit.no:unit:262624",
            "type": "fc:orgunit",
            "parent": "fc:org:uit.no"
        }
    ]
    */
    protected String getUserAffiliation(OAuth2AccessToken accessToken) throws IOException, OAuth2Exception {        
        final OAuthRequest request = new OAuthRequest(Verb.GET, 'https://groups-api.dataporten.no/groups/me/groups');
        request.addHeader("Authorization", "Bearer " + accessToken.getAccessToken());
        request.setCharset("UTF-8");
        
        final Response response = request.send();
        int responseCode = response.getCode();
        final String body = response.getBody();        
        logger.log(Level.FINE, "In getUserAffiliation. Body: {0}", body);

        if ( responseCode == 200 ) {
            try ( StringReader rdr = new StringReader(responseBody);
                JsonReader jrdr = Json.createReader(rdr) )  {
                JsonArray groups = jrdr.getJsonArray();

                for (int i = 0; i < groups.size(); i++) {
                    JsonObject group = groups.getJsonObject(i);
                    // Skip all other group types
                    if (group.getString("type", "") != "fc:org") {
                        continue;
                    }
                    return group.getString("eduOrgLegalName", "");
                }
            }
        } else {
            throw new OAuth2Exception(responseCode, body, "Error getting the user groups.");
        }
    }
    
    @Override
    protected ParsedUserResponse parseUserResponse( String responseBody, OAuth2AccessToken accessToken ) {
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
            
            String username = "";
            String affiliation = getUserAffiliation(accessToken);
            String position = "";
                        
            // Extract ad username using regexp
            Pattern p = Pattern.compile("^feide:([0-9a-zA-Z]+?)@([0-9a-zA-Z]*).*$");
            Matcher m = p.matcher(userid_secArray.getString(0));
            if(m.matches()) {
                username = m.group(1);
                if (affiliation.length() == 0) {
                    affiliation = m.group(2);
                }
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
