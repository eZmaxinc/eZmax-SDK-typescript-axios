/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.4
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * A Ezsignfoldersignerassociation->User Object and children to create a complete structure
 * @export
 * @interface EzsignfoldersignerassociationResponseCompoundUser
 */
export interface EzsignfoldersignerassociationResponseCompoundUser {
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof EzsignfoldersignerassociationResponseCompoundUser
     */
    'pkiUserID': number;
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof EzsignfoldersignerassociationResponseCompoundUser
     */
    'fkiLanguageID': number;
    /**
     * The First name of the user
     * @type {string}
     * @memberof EzsignfoldersignerassociationResponseCompoundUser
     */
    'sUserFirstname': string;
    /**
     * The Last name of the user
     * @type {string}
     * @memberof EzsignfoldersignerassociationResponseCompoundUser
     */
    'sUserLastname': string;
    /**
     * The email address.
     * @type {string}
     * @memberof EzsignfoldersignerassociationResponseCompoundUser
     */
    'sEmailAddress': string;
}

