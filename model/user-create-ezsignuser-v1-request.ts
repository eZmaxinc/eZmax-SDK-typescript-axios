/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.0.41
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * Request for the /1/module/user/createEzsignuser API Request
 * @export
 * @interface UserCreateEzsignuserV1Request
 */
export interface UserCreateEzsignuserV1Request {
    /**
     * The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English|
     * @type {number}
     * @memberof UserCreateEzsignuserV1Request
     */
    fkiLanguageID: number;
    /**
     * The First name of the user
     * @type {string}
     * @memberof UserCreateEzsignuserV1Request
     */
    sUserFirstname: string;
    /**
     * The Last name of the user
     * @type {string}
     * @memberof UserCreateEzsignuserV1Request
     */
    sUserLastname: string;
    /**
     * The email address.
     * @type {string}
     * @memberof UserCreateEzsignuserV1Request
     */
    sEmailAddress: string;
    /**
     * The region of the phone number. (For a North America Number only)  The region is the \"514\" section in this sample phone number: (514) 990-1516 x123
     * @type {string}
     * @memberof UserCreateEzsignuserV1Request
     */
    sPhoneRegion: string;
    /**
     * The exchange of the phone number. (For a North America Number only)  The exchange is the \"990\" section in this sample phone number: (514) 990-1516 x123
     * @type {string}
     * @memberof UserCreateEzsignuserV1Request
     */
    sPhoneExchange: string;
    /**
     * The number of the phone number. (For a North America Number only)  The number is the \"1516\" section in this sample phone number: (514) 990-1516 x123
     * @type {string}
     * @memberof UserCreateEzsignuserV1Request
     */
    sPhoneNumber: string;
    /**
     * The extension of the phone number.  The extension is the \"123\" section in this sample phone number: (514) 990-1516 x123.  It can also be used with international phone numbers
     * @type {string}
     * @memberof UserCreateEzsignuserV1Request
     */
    sPhoneExtension?: string;
}


