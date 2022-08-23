/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.10
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * A Ezsignsigner->Contact Object and children to create a complete structure
 * @export
 * @interface EzsignsignerResponseCompoundContact
 */
export interface EzsignsignerResponseCompoundContact {
    /**
     * The unique ID of the Contact
     * @type {number}
     * @memberof EzsignsignerResponseCompoundContact
     */
    'pkiContactID': number;
    /**
     * The First name of the contact
     * @type {string}
     * @memberof EzsignsignerResponseCompoundContact
     */
    'sContactFirstname': string;
    /**
     * The Last name of the contact
     * @type {string}
     * @memberof EzsignsignerResponseCompoundContact
     */
    'sContactLastname': string;
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof EzsignsignerResponseCompoundContact
     */
    'fkiLanguageID': number;
    /**
     * The email address.
     * @type {string}
     * @memberof EzsignsignerResponseCompoundContact
     */
    'sEmailAddress'?: string;
    /**
     * A phone number in E.164 Format
     * @type {string}
     * @memberof EzsignsignerResponseCompoundContact
     */
    'sPhoneE164'?: string;
    /**
     * The extension of the phone number.  The extension is the \"123\" section in this sample phone number: (514) 990-1516 x123.  It can also be used with international phone numbers
     * @type {string}
     * @memberof EzsignsignerResponseCompoundContact
     */
    'sPhoneExtension'?: string;
    /**
     * A phone number in E.164 Format
     * @type {string}
     * @memberof EzsignsignerResponseCompoundContact
     */
    'sPhoneE164Cell'?: string;
}

